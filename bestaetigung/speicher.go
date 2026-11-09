package bestaetigung

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

const (
	domSpeicher = "bestaetigungsspeicher"
	maxRec      = 1 << 16

	artFassung  byte = 1
	artSignatur byte = 2
	artVermerk  byte = 3
)

var (
	domBytes = protocol.Domain(domSpeicher)

	// ErrFassung heißt, dass diese Fassung nicht der Abschluss wird.
	ErrFassung = errors.New("bestaetigung: Fassung passt nicht")
	// ErrSignatur heißt, dass die HSM-Signatur oder die Signatur des Empfängers nicht hält.
	ErrSignatur = errors.New("bestaetigung: Signatur ungültig")
	// ErrVermerk heißt, dass der Löschvermerk nicht zu dieser Epoche gehört.
	ErrVermerk = errors.New("bestaetigung: Löschvermerk passt nicht")
	// ErrBestand heißt, dass das Protokoll nicht mehr gelesen werden kann.
	ErrBestand = errors.New("bestaetigung: Speicher beschädigt")
)

// Folge ist das Ergebnis eines eingereichten Manifests.
type Folge int

const (
	// FolgeAbschluss ist die eine Fassung dieser Epoche und dieses Vorgängers.
	FolgeAbschluss Folge = iota + 1
	// FolgeZweig ist eine weitere gültig signierte Fassung.
	FolgeZweig
)

// Fassung ist der Abschluss einer Epoche.
// Signiert heißt, dass die Signatur des Empfängers daneben liegt.
type Fassung struct {
	Epoch    protocol.EpochID
	Previous protocol.Hash
	Hash     protocol.Hash
	Signatur protocol.Signature
	Signiert bool
}

// Zweig ist eine weitere vom HSM signierte Fassung derselben Epoche.
type Zweig struct {
	Nutzlast []byte
	Signatur protocol.Signature
}

type epKey struct {
	mandant, ablage protocol.ID
	epoch           protocol.EpochID
}

type instKey struct {
	mandant, ablage, instanz protocol.ID
}

type prevKey struct {
	mandant, ablage, instanz protocol.ID
	previous                 protocol.Hash
}

type fassung struct {
	nutzlast []byte
	signatur protocol.Signature
	hash     protocol.Hash
	previous protocol.Hash
	epoch    protocol.EpochID
}

type empfang struct {
	sig  protocol.Signature
	spki []byte
}

type record struct {
	kind            byte
	mandant, ablage protocol.ID
	epoch           protocol.EpochID
	previous, hash  protocol.Hash
	nutz            []byte
	sig             protocol.Signature
	pub             *ecdsa.PublicKey
	spki            []byte
	tag             time.Time
}

// Speicher hängt Fassungen, Signaturen und Löschvermerke an.
type Speicher struct {
	mu        sync.Mutex
	pfad      string
	abschluss map[epKey]fassung
	zweige    map[epKey][]fassung
	vorher    map[prevKey]protocol.EpochID
	kopf      map[instKey]protocol.Hash
	signatur  map[epKey]empfang
	vermerk   map[epKey]time.Time
}

// Oeffnen liest den Speicher im Verzeichnis. Ein abgerissener Schluss
// fällt weg. Ein beschädigter Eintrag öffnet den Speicher nicht.
func Oeffnen(dir string) (*Speicher, error) {
	if dir == "" {
		return nil, ErrFassung
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	s := &Speicher{
		pfad:      filepath.Join(abs, "protokoll"),
		abschluss: map[epKey]fassung{},
		zweige:    map[epKey][]fassung{},
		vorher:    map[prevKey]protocol.EpochID{},
		kopf:      map[instKey]protocol.Hash{},
		signatur:  map[epKey]empfang{},
		vermerk:   map[epKey]time.Time{},
	}
	b, err := os.ReadFile(s.pfad)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	recs, n, err := lesen(b)
	if err != nil {
		return nil, ErrBestand
	}
	if n != len(b) {
		if err := kuerzen(s.pfad, int64(n)); err != nil {
			return nil, err
		}
	}
	for _, rec := range recs {
		if err := s.anwenden(rec); err != nil {
			return nil, ErrBestand
		}
	}
	return s, nil
}

// Einreichen hängt das vom HSM signierte Manifest an.
// Je Epoche und je Vorgänger wird das erste Glied der Kette der Abschluss.
// Dieselben Bytes ein zweites Mal ändern den Speicher nicht.
func (s *Speicher) Einreichen(mandant, ablage protocol.ID, nutzlast []byte, sig protocol.Signature, hsm *ecdsa.PublicKey) (Folge, error) {
	if s == nil {
		return 0, ErrFassung
	}
	if err := idsOK(mandant, ablage); err != nil {
		return 0, err
	}
	nutz := append([]byte(nil), nutzlast...)
	m, hash, err := pruefenManifest(nutz, sig, hsm)
	if err != nil {
		return 0, err
	}
	spki, err := x509.MarshalPKIXPublicKey(hsm)
	if err != nil {
		return 0, ErrSignatur
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	folge, neu := s.klassifizieren(mandant, ablage, m, nutz, sig)
	if !neu {
		return folge, nil
	}
	rec, err := fassungRecord(mandant, ablage, nutz, sig, spki)
	if err != nil {
		return 0, err
	}
	if err := anhaengen(s.pfad, rec); err != nil {
		return 0, err
	}
	s.merken(mandant, ablage, m, nutz, sig, hash, folge)
	return folge, nil
}

// Signieren hängt die Signatur des Empfängers an den Abschluss.
// Sie deckt den epoch_hash dieser einen Fassung. Eine abweichende Signatur bleibt draußen.
func (s *Speicher) Signieren(mandant, ablage protocol.ID, epoch protocol.EpochID, previous, hash protocol.Hash, sig protocol.Signature, key *ecdsa.PublicKey) error {
	if s == nil {
		return ErrFassung
	}
	if err := idsOK(mandant, ablage); err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ErrSignatur
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	schon, err := s.signaturPasst(mandant, ablage, epoch, previous, hash, sig, key, spki)
	if err != nil || schon {
		return err
	}
	rec, err := signaturRecord(mandant, ablage, epoch, previous, hash, sig, spki)
	if err != nil {
		return err
	}
	if err := anhaengen(s.pfad, rec); err != nil {
		return err
	}
	s.signatur[epKey{mandant, ablage, epoch}] = empfang{sig: sig, spki: append([]byte(nil), spki...)}
	return nil
}

// Vermerken hängt den Löschtag an. Die Fassung bleibt.
func (s *Speicher) Vermerken(mandant, ablage protocol.ID, epoch protocol.EpochID, tag time.Time) error {
	if s == nil {
		return ErrVermerk
	}
	if err := idsOK(mandant, ablage); err != nil {
		return ErrVermerk
	}
	body, err := protocol.VermerkBytes(epoch, tag)
	if err != nil {
		return ErrVermerk
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	schon, err := s.vermerkPasst(mandant, ablage, epoch, tag)
	if err != nil || schon {
		return err
	}
	if err := anhaengen(s.pfad, vermerkRecord(mandant, ablage, body)); err != nil {
		return err
	}
	s.vermerk[epKey{mandant, ablage, epoch}] = tag
	return nil
}

// Abschluss ist die eine Fassung dieser Epoche.
func (s *Speicher) Abschluss(mandant, ablage protocol.ID, epoch protocol.EpochID) (Fassung, bool) {
	if s == nil {
		return Fassung{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.abschluss[epKey{mandant, ablage, epoch}]
	if !ok {
		return Fassung{}, false
	}
	out := Fassung{Epoch: f.epoch, Previous: f.previous, Hash: f.hash}
	if sig, da := s.signatur[epKey{mandant, ablage, epoch}]; da {
		out.Signatur = sig.sig
		out.Signiert = true
	}
	return out, true
}

// Bestaetigung liefert die Signatur des Empfängers über den Abschluss.
func (s *Speicher) Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (protocol.Hash, protocol.Signature, bool, error) {
	f, ok := s.Abschluss(mandant, ablage, epoch)
	if !ok || !f.Signiert {
		return protocol.Hash{}, protocol.Signature{}, false, nil
	}
	return f.Hash, f.Signatur, true, nil
}

// Vermerk liefert den Löschtag.
func (s *Speicher) Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (time.Time, bool, error) {
	if s == nil {
		return time.Time{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tag, ok := s.vermerk[epKey{mandant, ablage, epoch}]
	return tag, ok, nil
}

// Zweige sind die weiteren Fassungen dieser Epoche, in der Reihenfolge des Protokolls.
func (s *Speicher) Zweige(mandant, ablage protocol.ID, epoch protocol.EpochID) ([]Zweig, error) {
	if s == nil {
		return nil, ErrFassung
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	liste := s.zweige[epKey{mandant, ablage, epoch}]
	out := make([]Zweig, len(liste))
	for i, z := range liste {
		out[i] = Zweig{Nutzlast: append([]byte(nil), z.nutzlast...), Signatur: z.signatur}
	}
	return out, nil
}

func (s *Speicher) anwenden(rec record) error {
	if idsOK(rec.mandant, rec.ablage) != nil {
		return ErrBestand
	}
	switch rec.kind {
	case artFassung:
		m, hash, err := pruefenManifest(rec.nutz, rec.sig, rec.pub)
		if err != nil {
			return err
		}
		folge, neu := s.klassifizieren(rec.mandant, rec.ablage, m, rec.nutz, rec.sig)
		if !neu {
			return ErrBestand
		}
		s.merken(rec.mandant, rec.ablage, m, rec.nutz, rec.sig, hash, folge)
		return nil
	case artSignatur:
		schon, err := s.signaturPasst(rec.mandant, rec.ablage, rec.epoch, rec.previous, rec.hash, rec.sig, rec.pub, rec.spki)
		if err != nil || schon {
			if schon {
				return ErrBestand
			}
			return err
		}
		s.signatur[epKey{rec.mandant, rec.ablage, rec.epoch}] = empfang{sig: rec.sig, spki: append([]byte(nil), rec.spki...)}
		return nil
	case artVermerk:
		schon, err := s.vermerkPasst(rec.mandant, rec.ablage, rec.epoch, rec.tag)
		if err != nil || schon {
			if schon {
				return ErrBestand
			}
			return err
		}
		s.vermerk[epKey{rec.mandant, rec.ablage, rec.epoch}] = rec.tag
		return nil
	default:
		return ErrBestand
	}
}

func (s *Speicher) klassifizieren(mandant, ablage protocol.ID, m protocol.Manifest, nutz []byte, sig protocol.Signature) (Folge, bool) {
	k := epKey{mandant, ablage, m.Epoch}
	if f, ok := s.abschluss[k]; ok && gleich(f, nutz, sig) {
		return FolgeAbschluss, false
	}
	for _, z := range s.zweige[k] {
		if gleich(z, nutz, sig) {
			return FolgeZweig, false
		}
	}
	instanz := m.Epoch.Instanz()
	_, hat := s.abschluss[k]
	_, belegt := s.vorher[prevKey{mandant, ablage, instanz, m.Previous}]
	if !hat && !belegt && m.Previous == s.erwartet(mandant, ablage, instanz) {
		return FolgeAbschluss, true
	}
	return FolgeZweig, true
}

func (s *Speicher) erwartet(mandant, ablage, instanz protocol.ID) protocol.Hash {
	if h, ok := s.kopf[instKey{mandant, ablage, instanz}]; ok {
		return h
	}
	return protocol.Genesis(ablage, instanz)
}

func (s *Speicher) merken(mandant, ablage protocol.ID, m protocol.Manifest, nutz []byte, sig protocol.Signature, hash protocol.Hash, folge Folge) {
	f := fassung{
		nutzlast: append([]byte(nil), nutz...),
		signatur: sig,
		hash:     hash,
		previous: m.Previous,
		epoch:    m.Epoch,
	}
	k := epKey{mandant, ablage, m.Epoch}
	if folge == FolgeAbschluss {
		s.abschluss[k] = f
		s.vorher[prevKey{mandant, ablage, m.Epoch.Instanz(), m.Previous}] = m.Epoch
		s.kopf[instKey{mandant, ablage, m.Epoch.Instanz()}] = hash
		return
	}
	s.zweige[k] = append(s.zweige[k], f)
}

func (s *Speicher) signaturPasst(mandant, ablage protocol.ID, epoch protocol.EpochID, previous, hash protocol.Hash, sig protocol.Signature, key *ecdsa.PublicKey, spki []byte) (bool, error) {
	f, ok := s.abschluss[epKey{mandant, ablage, epoch}]
	if !ok || f.hash != hash || f.previous != previous {
		return false, ErrFassung
	}
	if !crypt.VerifyP256(key, protocol.ConfirmationPayload(hash), sig) {
		return false, ErrSignatur
	}
	alt, da := s.signatur[epKey{mandant, ablage, epoch}]
	if !da {
		return false, nil
	}
	if alt.sig == sig && bytes.Equal(alt.spki, spki) {
		return true, nil
	}
	return false, ErrFassung
}

func (s *Speicher) vermerkPasst(mandant, ablage protocol.ID, epoch protocol.EpochID, tag time.Time) (bool, error) {
	if _, ok := s.abschluss[epKey{mandant, ablage, epoch}]; !ok {
		return false, ErrVermerk
	}
	alt, da := s.vermerk[epKey{mandant, ablage, epoch}]
	if !da {
		return false, nil
	}
	if alt.Equal(tag) {
		return true, nil
	}
	return false, ErrVermerk
}

func gleich(f fassung, nutz []byte, sig protocol.Signature) bool {
	return f.signatur == sig && bytes.Equal(f.nutzlast, nutz)
}

func idsOK(mandant, ablage protocol.ID) error {
	if mandant == (protocol.ID{}) || ablage == (protocol.ID{}) {
		return ErrFassung
	}
	return nil
}

func pruefenManifest(nutz []byte, sig protocol.Signature, pub *ecdsa.PublicKey) (protocol.Manifest, protocol.Hash, error) {
	if len(nutz) != protocol.ManifestPayloadLen {
		return protocol.Manifest{}, protocol.Hash{}, ErrFassung
	}
	m, err := protocol.ParseManifest(nutz)
	if err != nil {
		return protocol.Manifest{}, protocol.Hash{}, ErrFassung
	}
	raster, err := time.Parse("20060102T150405Z", m.Epoch.Raster())
	if err != nil {
		return protocol.Manifest{}, protocol.Hash{}, ErrFassung
	}
	wieder, err := protocol.NewEpochID(raster, m.Epoch.Instanz(), m.Epoch.Prefix())
	if err != nil || wieder != m.Epoch {
		return protocol.Manifest{}, protocol.Hash{}, ErrFassung
	}
	if !crypt.VerifyP256(pub, nutz, sig) {
		return protocol.Manifest{}, protocol.Hash{}, ErrSignatur
	}
	hash, err := protocol.EpochHash(nutz, sig)
	if err != nil {
		return protocol.Manifest{}, protocol.Hash{}, ErrFassung
	}
	return m, hash, nil
}

func fassungRecord(mandant, ablage protocol.ID, nutz []byte, sig protocol.Signature, spki []byte) ([]byte, error) {
	if len(nutz) > maxRec || len(spki) > maxRec {
		return nil, ErrFassung
	}
	body := make([]byte, 0, protocol.IDLen*2+8+len(nutz)+protocol.SignatureLen+len(spki))
	body = append(body, mandant[:]...)
	body = append(body, ablage[:]...)
	body = protocol.AppendU32(body, uint32(len(nutz)))
	body = append(body, nutz...)
	body = append(body, sig[:]...)
	body = protocol.AppendU32(body, uint32(len(spki)))
	body = append(body, spki...)
	return rahmen(artFassung, body), nil
}

func signaturRecord(mandant, ablage protocol.ID, epoch protocol.EpochID, previous, hash protocol.Hash, sig protocol.Signature, spki []byte) ([]byte, error) {
	if len(spki) == 0 || len(spki) > maxRec {
		return nil, ErrSignatur
	}
	body := make([]byte, 0, protocol.IDLen*2+protocol.EpochLen+protocol.HashLen*2+protocol.SignatureLen+4+len(spki))
	body = append(body, mandant[:]...)
	body = append(body, ablage[:]...)
	body = append(body, epoch[:]...)
	body = append(body, previous[:]...)
	body = append(body, hash[:]...)
	body = append(body, sig[:]...)
	body = protocol.AppendU32(body, uint32(len(spki)))
	body = append(body, spki...)
	return rahmen(artSignatur, body), nil
}

func vermerkRecord(mandant, ablage protocol.ID, body []byte) []byte {
	buf := make([]byte, 0, protocol.IDLen*2+4+len(body))
	buf = append(buf, mandant[:]...)
	buf = append(buf, ablage[:]...)
	buf = protocol.AppendU32(buf, uint32(len(body)))
	buf = append(buf, body...)
	return rahmen(artVermerk, buf)
}

func rahmen(kind byte, body []byte) []byte {
	buf := make([]byte, 0, len(domBytes)+1+len(body))
	buf = append(buf, domBytes...)
	buf = append(buf, kind)
	return append(buf, body...)
}

func lesen(b []byte) ([]record, int, error) {
	off := 0
	var out []record
	for off < len(b) {
		if len(b)-off < 4 {
			return out, off, nil
		}
		n := int(binary.BigEndian.Uint32(b[off : off+4]))
		if n == 0 {
			return nil, 0, ErrBestand
		}
		if len(b)-off-4 < n {
			return out, off, nil
		}
		if n > maxRec {
			return nil, 0, ErrBestand
		}
		rec, err := parseRecord(b[off+4 : off+4+n])
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
		off += 4 + n
	}
	return out, off, nil
}

func parseRecord(b []byte) (record, error) {
	if len(b) < len(domBytes)+1 || !bytes.Equal(b[:len(domBytes)], domBytes) {
		return record{}, ErrBestand
	}
	rest := b[len(domBytes)+1:]
	switch b[len(domBytes)] {
	case artFassung:
		return parseFassung(rest)
	case artSignatur:
		return parseSignatur(rest)
	case artVermerk:
		return parseVermerkRec(rest)
	default:
		return record{}, ErrBestand
	}
}

func parseFassung(rest []byte) (record, error) {
	rec := record{kind: artFassung}
	if err := takeID(&rest, &rec.mandant); err != nil {
		return record{}, err
	}
	if err := takeID(&rest, &rec.ablage); err != nil {
		return record{}, err
	}
	nutz, err := takeLen(&rest)
	if err != nil || len(nutz) != protocol.ManifestPayloadLen {
		return record{}, ErrBestand
	}
	rec.nutz = nutz
	if err := takeSig(&rest, &rec.sig); err != nil {
		return record{}, err
	}
	spki, err := takeLen(&rest)
	if err != nil || len(rest) != 0 {
		return record{}, ErrBestand
	}
	pub, err := schluessel(spki)
	if err != nil {
		return record{}, ErrBestand
	}
	rec.pub = pub
	rec.spki = spki
	return rec, nil
}

func parseSignatur(rest []byte) (record, error) {
	rec := record{kind: artSignatur}
	if err := takeID(&rest, &rec.mandant); err != nil {
		return record{}, err
	}
	if err := takeID(&rest, &rec.ablage); err != nil {
		return record{}, err
	}
	if err := takeEpoch(&rest, &rec.epoch); err != nil {
		return record{}, err
	}
	if err := takeHash(&rest, &rec.previous); err != nil {
		return record{}, err
	}
	if err := takeHash(&rest, &rec.hash); err != nil {
		return record{}, err
	}
	if err := takeSig(&rest, &rec.sig); err != nil {
		return record{}, err
	}
	spki, err := takeLen(&rest)
	if err != nil || len(rest) != 0 {
		return record{}, ErrBestand
	}
	pub, err := schluessel(spki)
	if err != nil {
		return record{}, ErrBestand
	}
	rec.pub = pub
	rec.spki = spki
	return rec, nil
}

func parseVermerkRec(rest []byte) (record, error) {
	rec := record{kind: artVermerk}
	if err := takeID(&rest, &rec.mandant); err != nil {
		return record{}, err
	}
	if err := takeID(&rest, &rec.ablage); err != nil {
		return record{}, err
	}
	body, err := takeLen(&rest)
	if err != nil || len(rest) != 0 {
		return record{}, ErrBestand
	}
	epoch, tag, err := protocol.ParseVermerk(body)
	if err != nil {
		return record{}, ErrBestand
	}
	rec.epoch = epoch
	rec.tag = tag
	return rec, nil
}

func schluessel(spki []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrSignatur
	}
	return key, nil
}

func takeID(rest *[]byte, id *protocol.ID) error {
	if len(*rest) < protocol.IDLen {
		return ErrBestand
	}
	copy(id[:], (*rest)[:protocol.IDLen])
	*rest = (*rest)[protocol.IDLen:]
	return nil
}

func takeEpoch(rest *[]byte, epoch *protocol.EpochID) error {
	if len(*rest) < protocol.EpochLen {
		return ErrBestand
	}
	copy(epoch[:], (*rest)[:protocol.EpochLen])
	*rest = (*rest)[protocol.EpochLen:]
	return nil
}

func takeHash(rest *[]byte, hash *protocol.Hash) error {
	if len(*rest) < protocol.HashLen {
		return ErrBestand
	}
	copy(hash[:], (*rest)[:protocol.HashLen])
	*rest = (*rest)[protocol.HashLen:]
	return nil
}

func takeSig(rest *[]byte, sig *protocol.Signature) error {
	if len(*rest) < protocol.SignatureLen {
		return ErrBestand
	}
	copy(sig[:], (*rest)[:protocol.SignatureLen])
	*rest = (*rest)[protocol.SignatureLen:]
	return nil
}

func takeLen(rest *[]byte) ([]byte, error) {
	if len(*rest) < 4 {
		return nil, ErrBestand
	}
	n := int(binary.BigEndian.Uint32((*rest)[:4]))
	*rest = (*rest)[4:]
	if n == 0 || n > len(*rest) || n > maxRec {
		return nil, ErrBestand
	}
	b := (*rest)[:n]
	*rest = (*rest)[n:]
	return b, nil
}

func anhaengen(pfad string, rec []byte) error {
	if len(rec) == 0 || len(rec) > maxRec {
		return ErrFassung
	}
	f, err := os.OpenFile(pfad, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(rec)))
	if _, err := f.Write(n[:]); err != nil {
		return err
	}
	if _, err := f.Write(rec); err != nil {
		return err
	}
	return f.Sync()
}

func kuerzen(pfad string, n int64) error {
	f, err := os.OpenFile(pfad, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(n); err != nil {
		return err
	}
	return f.Sync()
}
