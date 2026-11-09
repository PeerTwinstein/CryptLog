package schluessel

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"io"
	"os"
	"sync"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

const hoechstalter = 60 * time.Second

// Sicht ist der öffentliche Stand eines Mandanten für den Schreibprozess.
// Die verschlüsselte private Kopie liegt nicht darin.
type Sicht struct {
	Vorhanden bool
	Pub       crypto.PublicKey
	Finger    protocol.Hash
	Pruef     crypto.PublicKey
	Status    map[protocol.Hash]Status
}

// Mandant ist die beim Schreibprozess hinterlegte Lage, getrennt von der Veröffentlichung.
type Mandant struct {
	Modus Modus
	Name  string
	Anker *x509.Certificate
}

// CacheKonfig startet den Cache. Alter 0 ist 60 Sekunden.
// Geheimnis ist 32 Byte und liegt nur im Speicher. Ohne Geheimnis und ohne Pfad
// gibt es keine persistente Fassung. Beides zusammen verschlüsselt sie mit AES-256-GCM.
type CacheKonfig struct {
	Quelle    Quelle
	Alter     time.Duration
	Geheimnis []byte
	Pfad      string
	Mandanten map[protocol.ID]Mandant
	Jetzt     func() time.Time
	Rand      io.Reader
}

type cacheEintrag struct {
	sicht   Sicht
	gelesen time.Time
	nummer  uint64
	roh     []byte
	sig     []byte
}

// Cache hält die öffentlichen Schlüssel und ihren Status.
// Gewrappt wird aus einem Eintrag, der höchstens das Höchstalter alt ist.
type Cache struct {
	quelle    Quelle
	alter     time.Duration
	geheimnis []byte
	pfad      string
	jetzt     func() time.Time
	rand      io.Reader
	mandanten map[protocol.ID]Mandant

	mu       sync.Mutex
	mem      map[protocol.ID]cacheEintrag
	platte   map[protocol.ID]cacheEintrag
	letzte   map[protocol.ID]uint64
	erreicht map[protocol.ID]bool
}

// NeuerCache liest die persistente Fassung, wenn das Geheimnis vorliegt.
// Eine Fassung, deren Authentisierung scheitert, wird nicht verwendet.
func NeuerCache(k CacheKonfig) (*Cache, error) {
	if k.Quelle == nil {
		return nil, ErrQuelle
	}
	if (len(k.Geheimnis) == 0) != (k.Pfad == "") {
		return nil, ErrGeheimnis
	}
	if len(k.Geheimnis) != 0 && len(k.Geheimnis) != 32 {
		return nil, ErrGeheimnis
	}
	alter := k.Alter
	if alter == 0 {
		alter = hoechstalter
	}
	if alter < 0 {
		return nil, ErrZeit
	}
	jetzt := k.Jetzt
	if jetzt == nil {
		jetzt = func() time.Time { return time.Now().UTC() }
	}
	rnd := k.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	c := &Cache{
		quelle: k.Quelle, alter: alter, pfad: k.Pfad, jetzt: jetzt, rand: rnd,
		mandanten: map[protocol.ID]Mandant{},
		mem:       map[protocol.ID]cacheEintrag{},
		platte:    map[protocol.ID]cacheEintrag{},
		letzte:    map[protocol.ID]uint64{},
		erreicht:  map[protocol.ID]bool{},
	}
	if len(k.Geheimnis) == 32 {
		c.geheimnis = append([]byte(nil), k.Geheimnis...)
	}
	for id, m := range k.Mandanten {
		if m.Modus != ModusEinfach && m.Modus != ModusSicher {
			return nil, ErrModus
		}
		if m.Modus == ModusSicher && (m.Anker == nil || m.Name == "") {
			return nil, ErrAnker
		}
		c.mandanten[id] = m
	}
	if err := c.laden(); err != nil {
		return nil, err
	}
	return c, nil
}

// Oeffentlich liefert den Stand. Ein Eintrag innerhalb des Höchstalters kommt aus dem Speicher.
// Danach wird der Schlüsselspeicher gelesen. Schlägt das fehl oder ist kein aktueller KEK erkennbar,
// ist Vorhanden falsch. Die persistente Fassung überbrückt nur den Start, solange der Speicher nicht antwortet.
func (c *Cache) Oeffentlich(id protocol.ID) (Sicht, error) {
	c.mu.Lock()
	m, ok := c.mandanten[id]
	if !ok {
		c.mu.Unlock()
		return Sicht{}, ErrMandant
	}
	if s, ok := c.frisch(id); ok {
		c.mu.Unlock()
		return s, nil
	}
	quelle := c.quelle
	c.mu.Unlock()

	pub, sig, da, err := quelle.Lesen(id)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if !c.erreicht[id] {
			if s, ok := c.ausBruecke(id, m); ok {
				return s, nil
			}
		}
		return Sicht{Status: map[protocol.Hash]Status{}}, nil
	}
	c.erreicht[id] = true
	if !da {
		delete(c.mem, id)
		if serr := c.speichern(); serr != nil {
			return Sicht{}, serr
		}
		return Sicht{Status: map[protocol.Hash]Status{}}, nil
	}
	sicht, nummer, perr := c.pruefen(m, id, pub, sig)
	if perr != nil || !c.nummerOK(id, nummer, pub) {
		return Sicht{Status: map[protocol.Hash]Status{}}, nil
	}
	if serr := c.merken(id, sicht, nummer, pub, sig); serr != nil {
		return Sicht{}, serr
	}
	return kopieSicht(sicht), nil
}

func (c *Cache) frisch(id protocol.ID) (Sicht, bool) {
	e, ok := c.mem[id]
	if !ok {
		return Sicht{}, false
	}
	if c.jetzt().After(e.gelesen.Add(c.alter)) {
		return Sicht{}, false
	}
	return kopieSicht(e.sicht), true
}

func (c *Cache) ausBruecke(id protocol.ID, m Mandant) (Sicht, bool) {
	e, ok := c.platte[id]
	if !ok {
		return Sicht{}, false
	}
	if m.Modus == ModusEinfach && c.jetzt().After(e.gelesen.Add(c.alter)) {
		return Sicht{}, false
	}
	sicht, nummer, err := c.pruefen(m, id, e.roh, e.sig)
	if err != nil || nummer != e.nummer || !c.nummerOK(id, nummer, e.roh) {
		return Sicht{}, false
	}
	e.gelesen = c.jetzt()
	e.sicht = sicht
	c.mem[id] = e
	_ = c.speichern()
	return kopieSicht(sicht), true
}

func (c *Cache) nummerOK(id protocol.ID, nummer uint64, pub []byte) bool {
	letzte := c.letzte[id]
	if letzte == 0 {
		return nummer >= 1
	}
	if nummer > letzte {
		return true
	}
	if nummer != letzte {
		return false
	}
	alt, ok := c.rohVon(id)
	return ok && bytesEqual(alt, pub)
}

func (c *Cache) rohVon(id protocol.ID) ([]byte, bool) {
	if e, ok := c.mem[id]; ok && e.nummer == c.letzte[id] {
		return e.roh, true
	}
	if e, ok := c.platte[id]; ok && e.nummer == c.letzte[id] {
		return e.roh, true
	}
	return nil, false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (c *Cache) merken(id protocol.ID, sicht Sicht, nummer uint64, pub, sig []byte) error {
	c.mem[id] = cacheEintrag{
		sicht: sicht, gelesen: c.jetzt(), nummer: nummer,
		roh: append([]byte(nil), pub...), sig: append([]byte(nil), sig...),
	}
	c.letzte[id] = nummer
	return c.speichern()
}

func (c *Cache) pruefen(m Mandant, id protocol.ID, pub, sig []byte) (Sicht, uint64, error) {
	gefasst, err := ParseVeroeffentlichung(pub)
	if err != nil || gefasst.Mandant != id {
		return Sicht{}, 0, ErrFormat
	}
	if m.Modus == ModusSicher {
		if m.Anker == nil || m.Name == "" || gefasst.Name != m.Name || !SignaturOK(m.Anker.PublicKey, pub, sig) {
			return Sicht{}, 0, ErrSignatur
		}
		jetzt := c.jetzt()
		if gefasst.Zeit.After(jetzt) || jetzt.Sub(gefasst.Zeit) > c.alter {
			return Sicht{}, 0, ErrZeit
		}
	} else if len(sig) != 0 {
		return Sicht{}, 0, ErrModus
	}
	list, err := parseCRL(gefasst.CRL)
	if err != nil {
		return Sicht{}, 0, err
	}
	if m.Modus == ModusSicher && list != nil && list.CheckSignatureFrom(m.Anker) != nil {
		return Sicht{}, 0, ErrZertifikat
	}
	sicht := Sicht{Status: map[protocol.Hash]Status{}}
	aktuell := 0
	for _, z := range gefasst.Zertifikate {
		cert, err := x509.ParseCertificate(z.DER)
		if err != nil {
			return Sicht{}, 0, ErrFormat
		}
		finger, err := crypt.FingerprintCertificate(cert)
		if err != nil {
			return Sicht{}, 0, err
		}
		if z.Status != StatusAktuell {
			sicht.Status[finger] = z.Status
			continue
		}
		aktuell++
		if c.blattOK(m, id, cert, list) {
			sicht.Vorhanden = true
			sicht.Pub = cert.PublicKey
			sicht.Finger = finger
		}
	}
	if aktuell > 1 {
		return Sicht{}, 0, ErrFormat
	}
	if len(gefasst.Pruef) > 0 {
		pruef, err := x509.ParsePKIXPublicKey(gefasst.Pruef)
		if err != nil || signaturAlgorithmus(pruef) != nil {
			return Sicht{}, 0, ErrZertifikat
		}
		sicht.Pruef = pruef
	}
	return sicht, gefasst.Nummer, nil
}

func (c *Cache) blattOK(m Mandant, id protocol.ID, cert *x509.Certificate, list *x509.RevocationList) bool {
	if m.Name != "" && cert.Subject.CommonName != m.Name {
		return false
	}
	if m.Anker != nil {
		_, _, err := pruefeBlatt(cert.Raw, m.Anker, id, cert.Subject.CommonName, c.jetzt(), list, true)
		return err == nil
	}
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 || wrapAlgorithmus(cert.PublicKey) != nil || nutzungKEK(cert) != nil {
		return false
	}
	jetzt := c.jetzt()
	if jetzt.Before(cert.NotBefore) || !jetzt.Before(cert.NotAfter) || !subjektOK(cert, id, cert.Subject.CommonName) {
		return false
	}
	return sperre(cert, nil, nil, jetzt) == nil
}

func kopieSicht(s Sicht) Sicht {
	st := map[protocol.Hash]Status{}
	for k, v := range s.Status {
		st[k] = v
	}
	s.Status = st
	return s
}

func (c *Cache) laden() error {
	if c.pfad == "" {
		return nil
	}
	b, err := os.ReadFile(c.pfad)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	klar, ok := c.oeffnen(b)
	if !ok {
		return nil
	}
	eintraege, err := parseCache(klar)
	if err != nil {
		return nil
	}
	for id, e := range eintraege {
		c.platte[id] = e
		if e.nummer > c.letzte[id] {
			c.letzte[id] = e.nummer
		}
	}
	return nil
}

func (c *Cache) speichern() error {
	if c.pfad == "" {
		return nil
	}
	klar, err := cacheBytes(c.mem)
	if err != nil {
		return err
	}
	versiegelt, err := c.versiegeln(klar)
	if err != nil {
		return err
	}
	return ersetzen(c.pfad, versiegelt)
}

func (c *Cache) versiegeln(klar []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.geheimnis)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, klar, protocol.Domain(domCache))
	for i := range klar {
		klar[i] = 0
	}
	return out, nil
}

func (c *Cache) oeffnen(b []byte) ([]byte, bool) {
	block, err := aes.NewCipher(c.geheimnis)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(b) < gcm.NonceSize() {
		return nil, false
	}
	klar, err := gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], protocol.Domain(domCache))
	if err != nil {
		return nil, false
	}
	return klar, true
}

func cacheBytes(mem map[protocol.ID]cacheEintrag) ([]byte, error) {
	buf := append([]byte(nil), protocol.Domain(domCache)...)
	buf = protocol.AppendU32(buf, uint32(len(mem)))
	for id, e := range mem {
		buf = append(buf, id[:]...)
		buf = protocol.AppendU64(buf, e.nummer)
		ms := e.gelesen.UTC().UnixMilli()
		if ms < 0 {
			return nil, ErrFormat
		}
		buf = protocol.AppendU64(buf, uint64(ms))
		var err error
		buf, err = appendLen(buf, e.roh)
		if err != nil {
			return nil, err
		}
		buf, err = appendLen(buf, e.sig)
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func parseCache(b []byte) (map[protocol.ID]cacheEintrag, error) {
	dom := protocol.Domain(domCache)
	if len(b) < len(dom) || string(b[:len(dom)]) != string(dom) {
		return nil, ErrFormat
	}
	rest := b[len(dom):]
	n, rest, err := takeU32(rest)
	if err != nil {
		return nil, err
	}
	out := map[protocol.ID]cacheEintrag{}
	for i := uint32(0); i < n; i++ {
		if len(rest) < protocol.IDLen {
			return nil, ErrFormat
		}
		var id protocol.ID
		copy(id[:], rest[:protocol.IDLen])
		rest = rest[protocol.IDLen:]
		var nummer, ms uint64
		nummer, rest, err = takeU64(rest)
		if err != nil {
			return nil, err
		}
		ms, rest, err = takeU64(rest)
		if err != nil {
			return nil, err
		}
		var roh, sig []byte
		roh, rest, err = takeLen(rest)
		if err != nil {
			return nil, err
		}
		sig, rest, err = takeLen(rest)
		if err != nil {
			return nil, err
		}
		out[id] = cacheEintrag{
			nummer: nummer, gelesen: time.UnixMilli(int64(ms)).UTC(),
			roh: roh, sig: sig,
		}
	}
	if len(rest) != 0 {
		return nil, ErrFormat
	}
	return out, nil
}
