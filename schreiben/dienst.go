package schreiben

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/strom"
)

// ErrKonfig heißt, die Datei oder ein Mandantenverzeichnis passt nicht.
var ErrKonfig = errors.New("schreiben: Konfiguration passt nicht")

// Dienst ist ein gestarteter Schreibprozess mit den beiden Adressen.
type Dienst struct {
	Prozess  *Prozess
	Ereignis string
	Metrik   string
}

// OeffnenDienst liest die Konfiguration und startet den Schreibprozess.
// Geheimnisse stehen in den genannten Dateien, nicht in der Konfiguration.
func OeffnenDienst(pfad string) (*Dienst, error) {
	basis := filepath.Dir(pfad)
	werte, err := liesWerte(pfad, konfigFelder, 1<<16)
	if err != nil {
		return nil, err
	}
	instanz, err := pflichtID(werte, "instanz")
	if err != nil {
		return nil, err
	}
	spool, err := pflichtPfad(basis, werte, "spool")
	if err != nil {
		return nil, err
	}
	ereignis, ok := werte["ereignis"]
	metrik, ok2 := werte["metrik"]
	if !ok || !ok2 || !adresse(ereignis) || !adresse(metrik) || ereignis == metrik {
		return nil, konfigFehler("adresse")
	}
	schwellen, err := schwellenAus(werte)
	if err != nil {
		return nil, err
	}
	plattform, err := schluesselAus(pflichtPfadWert(basis, werte, "plattform"), true, protocol.ID{}, "")
	if err != nil {
		return nil, konfigFehler("plattform")
	}
	index, err := schluesselAus(pflichtPfadWert(basis, werte, "index"), false, protocol.ID{}, "")
	if err != nil {
		return nil, konfigFehler("index")
	}
	signier, err := liesP256(pflichtPfadWert(basis, werte, "signatur"))
	if err != nil {
		return nil, konfigFehler("signatur")
	}
	mandanten, err := pflichtPfad(basis, werte, "mandanten")
	if err != nil {
		return nil, err
	}
	bestand, err := bestandAus(mandanten)
	if err != nil {
		return nil, err
	}
	ziel, art, err := zielAus(basis, werte)
	if err != nil {
		return nil, err
	}
	loesch, err := optionDauer(werte, "loesch", 0)
	if err != nil {
		return nil, err
	}
	aufbewahrung, err := optionDauer(werte, "aufbewahrung", 0)
	if err != nil {
		return nil, err
	}
	var vermerk Vermerke
	var einreichen func(protocol.ID, protocol.ID, []byte, protocol.Signature) error
	if roh, da := werte["vermerke"]; da && roh != "" {
		speicher, oerr := bestaetigung.Oeffnen(aufloesen(basis, roh))
		if oerr != nil {
			return nil, konfigFehler("vermerke")
		}
		vermerk = speicher
		pub := &signier.PublicKey
		einreichen = func(mandant, ablage protocol.ID, nutzlast []byte, sig protocol.Signature) error {
			_, err := speicher.Einreichen(mandant, ablage, nutzlast, sig, pub)
			return err
		}
	}
	p, err := Start(Konfig{
		Instanz:      instanz,
		Schwellen:    schwellen,
		Spool:        spool,
		Ziel:         ziel,
		Plattform:    plattform,
		Index:        index,
		Bestand:      bestand,
		Signatur:     func(payload []byte) (protocol.Signature, error) { return crypt.SignP256(signier, payload) },
		ZielArt:      art,
		Version:      werte["version"],
		Digest:       werte["digest"],
		Loeschzeit:   loesch,
		Aufbewahrung: aufbewahrung,
		Vermerk:      vermerk,
		Einreichen:   einreichen,
	})
	if err != nil {
		return nil, err
	}
	return &Dienst{Prozess: p, Ereignis: ereignis, Metrik: metrik}, nil
}

// Dienen spricht die Ereignisschnittstelle und den Metrikport, bis ctx endet.
// Danach beendet es den Schreibprozess geordnet.
func (d *Dienst) Dienen(ctx context.Context) error {
	if d == nil || d.Prozess == nil || !adresse(d.Ereignis) || !adresse(d.Metrik) {
		return ErrKonfig
	}
	ereignis := &http.Server{
		Addr:              d.Ereignis,
		Handler:           d.Prozess.Ereignisport(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	metrik := &http.Server{
		Addr:              d.Metrik,
		Handler:           d.Prozess.Metrik(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	fehl := make(chan error, 2)
	go func() { fehl <- ereignis.ListenAndServe() }()
	go func() { fehl <- metrik.ListenAndServe() }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-fehl:
	}
	halt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ereignis.Shutdown(halt)
	_ = metrik.Shutdown(halt)
	ende, endeCancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer endeCancel()
	if berr := d.Prozess.Beenden(ende); err == nil || errors.Is(err, http.ErrServerClosed) {
		err = berr
	}
	return err
}

func schwellenAus(werte map[string]string) (Schwellen, error) {
	s := Voreinstellung()
	var err error
	if s.Puffer, err = optionInt(werte, "puffer", s.Puffer); err != nil {
		return Schwellen{}, err
	}
	if s.PufferWarte, err = optionDauer(werte, "puffer_warte", s.PufferWarte); err != nil {
		return Schwellen{}, err
	}
	if s.Segment, err = optionInt(werte, "segment", s.Segment); err != nil {
		return Schwellen{}, err
	}
	if s.SegmentWarte, err = optionDauer(werte, "segment_warte", s.SegmentWarte); err != nil {
		return Schwellen{}, err
	}
	if s.Klasse, err = optionInt(werte, "klasse", s.Klasse); err != nil {
		return Schwellen{}, err
	}
	if s.Gruppe, err = optionDauer(werte, "gruppe", s.Gruppe); err != nil {
		return Schwellen{}, err
	}
	if s.Einzel, err = optionDauer(werte, "einzel", s.Einzel); err != nil {
		return Schwellen{}, err
	}
	if s.Sonstige, err = optionDauer(werte, "sonstige", s.Sonstige); err != nil {
		return Schwellen{}, err
	}
	if s.SpoolGrenze, err = pflichtInt(werte, "spool_grenze"); err != nil {
		return Schwellen{}, err
	}
	if s.Frist, err = optionDauer(werte, "frist", 0); err != nil || s.Frist <= 0 {
		return Schwellen{}, konfigFehler("frist")
	}
	if err := s.Pruefen(); err != nil {
		return Schwellen{}, err
	}
	return s, nil
}

func zielAus(basis string, werte map[string]string) (Ziel, string, error) {
	switch werte["ziel"] {
	case "platte":
		if werte["endpunkt"] != "" || werte["bucket"] != "" || werte["region"] != "" || werte["zugang"] != "" || werte["geheimnis"] != "" {
			return nil, "", konfigFehler("ziel")
		}
		wurzel, err := pflichtPfad(basis, werte, "wurzel")
		if err != nil {
			return nil, "", err
		}
		platte, err := OeffnenPlatte(wurzel)
		if err != nil {
			return nil, "", konfigFehler("wurzel")
		}
		return platte, "platte", nil
	case "s3":
		if werte["wurzel"] != "" {
			return nil, "", konfigFehler("ziel")
		}
		zugang, err := liesText(pflichtPfadWert(basis, werte, "zugang"), 4<<10)
		if err != nil {
			return nil, "", konfigFehler("zugang")
		}
		geheim, err := liesText(pflichtPfadWert(basis, werte, "geheimnis"), 4<<10)
		if err != nil {
			return nil, "", konfigFehler("geheimnis")
		}
		s3, err := OeffnenS3(S3Konfig{
			Endpunkt: werte["endpunkt"], Bucket: werte["bucket"], Region: werte["region"],
			Zugang: strings.TrimSpace(zugang), Geheimnis: strings.TrimSpace(geheim),
		})
		if err != nil {
			return nil, "", konfigFehler("s3")
		}
		return s3, "s3", nil
	default:
		return nil, "", konfigFehler("ziel")
	}
}

type dateiBestand struct {
	lagen map[protocol.ID]Lage
}

func (b dateiBestand) Mandant(id protocol.ID) (Lage, error) {
	lage, ok := b.lagen[id]
	if !ok {
		return Lage{}, ErrKonfig
	}
	return lage, nil
}

func (b dateiBestand) Mandanten() ([]protocol.ID, error) {
	out := make([]protocol.ID, 0, len(b.lagen))
	for id := range b.lagen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hex() < out[j].Hex() })
	return out, nil
}

func bestandAus(wurzel string) (dateiBestand, error) {
	eintraege, err := os.ReadDir(wurzel)
	if err != nil {
		return dateiBestand{}, konfigFehler("mandanten")
	}
	lagen := map[protocol.ID]Lage{}
	for _, ein := range eintraege {
		if !ein.IsDir() {
			return dateiBestand{}, konfigFehler("mandanten")
		}
		id, err := protocol.ParseID(ein.Name())
		if err != nil || id.Hex() != ein.Name() || id == (protocol.ID{}) {
			return dateiBestand{}, konfigFehler("mandanten")
		}
		lage, err := lageAus(filepath.Join(wurzel, ein.Name()), id)
		if err != nil {
			return dateiBestand{}, err
		}
		lagen[id] = lage
	}
	if len(lagen) == 0 {
		return dateiBestand{}, konfigFehler("mandanten")
	}
	return dateiBestand{lagen: lagen}, nil
}

func lageAus(dir string, mandant protocol.ID) (Lage, error) {
	werte, err := liesWerte(filepath.Join(dir, "lage"), lageFelder, 1<<16)
	if err != nil {
		return Lage{}, err
	}
	name := werte["name"]
	if name == "" || !utf8.ValidString(name) {
		return Lage{}, konfigFehler("name")
	}
	rahmen, err := pflichtInt(werte, "rahmen")
	if err != nil || rahmen < protocol.RahmenMin || rahmen > protocol.RahmenMax || rahmen&(rahmen-1) != 0 {
		return Lage{}, konfigFehler("rahmen")
	}
	verzeichnis, err := pflichtID(werte, "verzeichnis")
	if err != nil {
		return Lage{}, err
	}
	vorgang, err := pflichtID(werte, "vorgang")
	if err != nil {
		return Lage{}, err
	}
	auffang, err := pflichtID(werte, "auffang")
	if err != nil {
		return Lage{}, err
	}
	einzel, err := pflichtID(werte, "einzel")
	if err != nil {
		return Lage{}, err
	}
	katalog, err := pflichtID(werte, "katalog")
	if err != nil {
		return Lage{}, err
	}
	kek, err := schluesselAus(pflichtPfadWert(dir, werte, "kek"), true, mandant, name)
	if err != nil {
		return Lage{}, konfigFehler("kek")
	}
	pruef, err := schluesselAus(pflichtPfadWert(dir, werte, "pruef"), false, mandant, "")
	if err != nil {
		return Lage{}, konfigFehler("pruef")
	}
	key, ok := pruef.Pub.(*ecdsa.PublicKey)
	if !ok {
		return Lage{}, konfigFehler("pruef")
	}
	deck, err := anAus(werte["deck"], false)
	if err != nil {
		return Lage{}, err
	}
	var seit time.Time
	if roh := werte["cache_seit"]; roh != "" {
		seit, err = time.Parse(time.RFC3339, roh)
		if err != nil || seit.Location() != time.UTC {
			return Lage{}, konfigFehler("cache_seit")
		}
	}
	stand, err := katalogAus(filepath.Join(dir, "katalog"), name)
	if err != nil {
		return Lage{}, err
	}
	register, err := registerAus(filepath.Join(dir, "personen"), mandant, key)
	if err != nil {
		return Lage{}, err
	}
	return Lage{
		KEKVorhanden: true,
		KEK:          kek,
		Register:     register,
		Pruef:        pruef.Pub,
		Verzeichnis:  verzeichnis,
		Vorgang:      vorgang,
		Auffang:      auffang,
		Einzel:       einzel,
		Katalog:      katalog,
		Stand:        stand,
		Rahmen:       rahmen,
		Deck:         deck,
		CacheSeit:    seit,
	}, nil
}

func katalogAus(pfad, name string) (protocol.Stand, error) {
	zeilen, err := liesZeilen(pfad, 1<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return protocol.Stand{}, nil
		}
		return protocol.Stand{}, konfigFehler("katalog")
	}
	stand := protocol.Stand{Name: name}
	for _, zeile := range zeilen {
		felder := strings.Fields(zeile)
		if len(felder) != 5 {
			return protocol.Stand{}, konfigFehler("katalog")
		}
		rolle, ok := rollen[felder[0]]
		if !ok {
			return protocol.Stand{}, konfigFehler("katalog")
		}
		ablage, err := protocol.ParseID(felder[1])
		if err != nil {
			return protocol.Stand{}, konfigFehler("katalog")
		}
		bind, err := protocol.ParseID(felder[2])
		if err != nil {
			return protocol.Stand{}, konfigFehler("katalog")
		}
		kohorte := felder[3]
		if kohorte == "-" {
			kohorte = ""
		}
		aktiv, err := aktivAus(felder[4])
		if err != nil {
			return protocol.Stand{}, err
		}
		stand.Kennungen = append(stand.Kennungen, protocol.Kennung{
			Rolle: rolle, Ablage: ablage, Bind: bind, Kohorte: kohorte, Aktiv: aktiv,
		})
	}
	if _, err := protocol.KatalogBytes(stand); err != nil {
		return protocol.Stand{}, konfigFehler("katalog")
	}
	return stand, nil
}

type dateiRegister map[string]strom.Eintrag

func (m dateiRegister) Person(name string) (strom.Eintrag, bool, error) {
	e, ok := m[name]
	return e, ok, nil
}

func registerAus(dir string, mandant protocol.ID, pruef *ecdsa.PublicKey) (dateiRegister, error) {
	eintraege, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return dateiRegister{}, nil
		}
		return nil, konfigFehler("personen")
	}
	reg := dateiRegister{}
	for _, ein := range eintraege {
		name := ein.Name()
		if ein.IsDir() || name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, `/\`) {
			return nil, konfigFehler("personen")
		}
		person, err := personAus(filepath.Join(dir, name), mandant, name, pruef)
		if err != nil {
			return nil, err
		}
		reg[name] = person
	}
	return reg, nil
}

func personAus(pfad string, mandant protocol.ID, name string, pruef *ecdsa.PublicKey) (strom.Eintrag, error) {
	werte, err := liesWerte(pfad, personFelder, 1<<16)
	if err != nil {
		return strom.Eintrag{}, err
	}
	var merkmal protocol.Merkmal
	switch werte["merkmal"] {
	case "gruppe":
		merkmal = protocol.MerkmalGruppe
	case "einzeln":
		merkmal = protocol.MerkmalEinzeln
	default:
		return strom.Eintrag{}, konfigFehler("merkmal")
	}
	ablage, err := pflichtID(werte, "ablage")
	if err != nil {
		return strom.Eintrag{}, err
	}
	bind, err := pflichtID(werte, "bind")
	if err != nil {
		return strom.Eintrag{}, err
	}
	kohorte := werte["kohorte"]
	if merkmal == protocol.MerkmalGruppe {
		if bind != ablage || kohorte == "" || !utf8.ValidString(kohorte) {
			return strom.Eintrag{}, konfigFehler("kohorte")
		}
	} else if bind == ablage || kohorte != "" {
		return strom.Eintrag{}, konfigFehler("kohorte")
	}
	von, err := pflichtUint(werte, "von")
	if err != nil {
		return strom.Eintrag{}, err
	}
	bis, err := pflichtUint(werte, "bis")
	if err != nil || bis < von {
		return strom.Eintrag{}, konfigFehler("bis")
	}
	rolle := protocol.RollePerson
	if werte["rolle"] == "datenschuetzer" {
		rolle = protocol.RolleDatenschuetzer
	} else if werte["rolle"] != "" && werte["rolle"] != "person" {
		return strom.Eintrag{}, konfigFehler("rolle")
	}
	var finger protocol.Hash
	if roh := werte["finger"]; roh != "" {
		finger, err = hashAus(roh)
		if err != nil {
			return strom.Eintrag{}, konfigFehler("finger")
		}
	}
	sigRoh, err := hex.DecodeString(werte["signatur"])
	if err != nil || len(sigRoh) != protocol.SignatureLen {
		return strom.Eintrag{}, konfigFehler("signatur")
	}
	var sig protocol.Signature
	copy(sig[:], sigRoh)
	aussage := protocol.Aussage{Mandant: mandant, Person: name, Rolle: rolle, Von: von, Bis: bis, Finger: finger}
	nutz, err := protocol.AussageBytes(aussage)
	if err != nil || !crypt.VerifyP256(pruef, nutz, sig) {
		return strom.Eintrag{}, konfigFehler("signatur")
	}
	return strom.Eintrag{
		Merkmal: merkmal, Ablage: ablage, Bind: bind, Kohorte: kohorte,
		Rolle: rolle, Von: von, Bis: bis, Finger: finger, Signatur: append([]byte(nil), sigRoh...),
	}, nil
}

func schluesselAus(pfad string, kek bool, mandant protocol.ID, name string) (Schluessel, error) {
	if pfad == "" {
		return Schluessel{}, ErrKonfig
	}
	cert, err := liesZertifikat(pfad)
	if err != nil || !zeitOK(cert, time.Now().UTC()) {
		return Schluessel{}, ErrKonfig
	}
	if kek {
		if !kekOK(cert) {
			return Schluessel{}, ErrKonfig
		}
	} else if !signaturOK(cert) {
		return Schluessel{}, ErrKonfig
	}
	if mandant != (protocol.ID{}) && !mandantImZertifikat(cert, mandant) {
		return Schluessel{}, ErrKonfig
	}
	if name != "" && cert.Subject.CommonName != name {
		return Schluessel{}, ErrKonfig
	}
	finger, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		return Schluessel{}, ErrKonfig
	}
	return Schluessel{Pub: cert.PublicKey, Finger: finger}, nil
}

func liesZertifikat(pfad string) (*x509.Certificate, error) {
	roh, err := liesBeschraenkt(pfad, 1<<16)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(roh)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrKonfig
	}
	return x509.ParseCertificate(block.Bytes)
}

func liesP256(pfad string) (*ecdsa.PrivateKey, error) {
	if pfad == "" {
		return nil, ErrKonfig
	}
	roh, err := liesBeschraenkt(pfad, 1<<16)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(roh)
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrKonfig
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrKonfig
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || !p256(priv.Public()) {
		return nil, ErrKonfig
	}
	return priv, nil
}

func liesText(pfad string, max int) (string, error) {
	if pfad == "" {
		return "", ErrKonfig
	}
	roh, err := liesBeschraenkt(pfad, max)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(roh))
	if text == "" || strings.ContainsAny(text, "\r\n") {
		return "", ErrKonfig
	}
	return text, nil
}

func liesBeschraenkt(pfad string, max int) ([]byte, error) {
	f, err := os.Open(pfad)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	roh, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(roh) == 0 || len(roh) > max {
		return nil, ErrKonfig
	}
	return roh, nil
}

func liesWerte(pfad string, erlaubt map[string]struct{}, max int) (map[string]string, error) {
	zeilen, err := liesZeilen(pfad, max)
	if err != nil {
		return nil, konfigFehler(filepath.Base(pfad))
	}
	werte := map[string]string{}
	for _, zeile := range zeilen {
		key, wert, ok := strings.Cut(zeile, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		wert = strings.TrimSpace(wert)
		if !ok || key == "" || wert == "" {
			return nil, konfigFehler(key)
		}
		if _, da := erlaubt[key]; !da {
			return nil, konfigFehler(key)
		}
		if _, da := werte[key]; da {
			return nil, konfigFehler(key)
		}
		werte[key] = wert
	}
	return werte, nil
}

func liesZeilen(pfad string, max int) ([]string, error) {
	roh, err := liesBeschraenkt(pfad, max)
	if err != nil {
		return nil, err
	}
	var zeilen []string
	for _, zeile := range strings.Split(string(roh), "\n") {
		zeile = strings.TrimSpace(zeile)
		if zeile == "" || strings.HasPrefix(zeile, "#") {
			continue
		}
		zeilen = append(zeilen, zeile)
	}
	return zeilen, nil
}

func pflichtPfad(basis string, werte map[string]string, key string) (string, error) {
	pfad := pflichtPfadWert(basis, werte, key)
	if pfad == "" {
		return "", konfigFehler(key)
	}
	return pfad, nil
}

func pflichtPfadWert(basis string, werte map[string]string, key string) string {
	roh := werte[key]
	if roh == "" {
		return ""
	}
	return aufloesen(basis, roh)
}

func aufloesen(basis, roh string) string {
	if filepath.IsAbs(roh) {
		return roh
	}
	return filepath.Join(basis, roh)
}

func pflichtID(werte map[string]string, key string) (protocol.ID, error) {
	id, err := protocol.ParseID(werte[key])
	if err != nil || id == (protocol.ID{}) {
		return protocol.ID{}, konfigFehler(key)
	}
	return id, nil
}

func pflichtInt(werte map[string]string, key string) (int, error) {
	n, err := strconv.Atoi(werte[key])
	if err != nil || n <= 0 || strconv.Itoa(n) != werte[key] {
		return 0, konfigFehler(key)
	}
	return n, nil
}

func optionInt(werte map[string]string, key string, sonst int) (int, error) {
	if werte[key] == "" {
		return sonst, nil
	}
	return pflichtInt(werte, key)
}

func pflichtUint(werte map[string]string, key string) (uint64, error) {
	n, err := strconv.ParseUint(werte[key], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != werte[key] {
		return 0, konfigFehler(key)
	}
	return n, nil
}

func optionDauer(werte map[string]string, key string, sonst time.Duration) (time.Duration, error) {
	roh := werte[key]
	if roh == "" {
		return sonst, nil
	}
	d, err := time.ParseDuration(roh)
	if err != nil || d < 0 {
		return 0, konfigFehler(key)
	}
	return d, nil
}

func anAus(roh string, sonst bool) (bool, error) {
	switch roh {
	case "":
		return sonst, nil
	case "an":
		return true, nil
	case "aus":
		return false, nil
	default:
		return false, konfigFehler("deck")
	}
}

func aktivAus(roh string) (protocol.Aktiv, error) {
	switch roh {
	case "an":
		return protocol.KennungAn, nil
	case "aus":
		return protocol.KennungAus, nil
	default:
		return 0, konfigFehler("katalog")
	}
}

func hashAus(roh string) (protocol.Hash, error) {
	raw, err := hex.DecodeString(roh)
	if err != nil || len(raw) != len(protocol.Hash{}) {
		return protocol.Hash{}, ErrKonfig
	}
	var h protocol.Hash
	copy(h[:], raw)
	return h, nil
}

func adresse(s string) bool {
	host, port, err := net.SplitHostPort(s)
	return err == nil && host != "" && port != "" && !strings.ContainsAny(s, " \t")
}

func konfigFehler(grund string) error {
	if grund == "" {
		grund = "datei"
	}
	return fmt.Errorf("%w: %s", ErrKonfig, grund)
}

func kekOK(cert *x509.Certificate) bool {
	if cert == nil || cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return false
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k != nil && k.N != nil && k.N.BitLen() >= 3072 && k.E >= 3 && cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
	case *ecdsa.PublicKey:
		return p256(k) && cert.KeyUsage&x509.KeyUsageKeyAgreement != 0
	default:
		return false
	}
}

func signaturOK(cert *x509.Certificate) bool {
	return cert != nil && !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 && p256(cert.PublicKey)
}

func p256(pub crypto.PublicKey) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k != nil && k.Curve != nil && k.X != nil && k.Y != nil && k.Curve.Params().Name == "P-256" && k.Curve.Params().BitSize == 256
}

func zeitOK(cert *x509.Certificate, jetzt time.Time) bool {
	return cert != nil && !jetzt.Before(cert.NotBefore) && jetzt.Before(cert.NotAfter)
}

func mandantImZertifikat(cert *x509.Certificate, mandant protocol.ID) bool {
	want := mandant.Hex()
	for _, org := range cert.Subject.Organization {
		if org == want {
			return true
		}
	}
	return false
}

var rollen = map[string]protocol.StromRolle{
	"gruppe":            protocol.RolleGruppe,
	"einzel":            protocol.RolleEinzel,
	"auffang":           protocol.RolleAuffang,
	"verzeichnis":       protocol.RolleVerzeichnis,
	"vorgang":           protocol.RolleVorgang,
	"katalog":           protocol.RolleKatalog,
	"verzeichnis-summe": protocol.RolleVerzeichnisSumme,
	"vorgang-summe":     protocol.RolleVorgangSumme,
}

var konfigFelder = felder(
	"instanz", "spool", "ereignis", "metrik", "ziel", "wurzel", "endpunkt", "bucket", "region",
	"zugang", "geheimnis", "plattform", "index", "signatur", "mandanten", "version", "digest",
	"loesch", "aufbewahrung", "vermerke", "spool_grenze", "frist", "puffer", "puffer_warte",
	"segment", "segment_warte", "klasse", "gruppe", "einzel", "sonstige",
)

var lageFelder = felder(
	"name", "rahmen", "verzeichnis", "vorgang", "auffang", "einzel", "katalog", "kek", "pruef", "deck", "cache_seit",
)

var personFelder = felder("merkmal", "ablage", "bind", "kohorte", "von", "bis", "rolle", "finger", "signatur")

func felder(namen ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(namen))
	for _, name := range namen {
		out[name] = struct{}{}
	}
	return out
}
