package schluessel

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"time"
	"unicode/utf8"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

const (
	domVeroeffentlichung = "schluessel-veroeffentlichung"
	domProtokoll         = "schluessel-protokoll"
	domCache             = "schluessel-cache"
	maxFassung           = 1 << 20
)

// Zertifikatseintrag ist ein Zertifikat und seine Lage.
// DER ist die Kodierung des Zertifikats. Der Fingerabdruck ist SHA-256 darüber.
type Zertifikatseintrag struct {
	Status Status
	DER    []byte
}

// Veroeffentlichung ist die Fassung, die der Schreibprozess liest.
// Im sicheren Modus ist sie signiert. Die Signatur steht nicht in diesen Bytes.
type Veroeffentlichung struct {
	Mandant     protocol.ID
	Nummer      uint64
	Zeit        time.Time
	Name        string
	CRL         []byte
	Pruef       []byte
	Zertifikate []Zertifikatseintrag
}

// Eintrag ist eine angehängte Änderung. Er wird weder ersetzt noch gelöscht.
type Eintrag struct {
	Mandant protocol.ID
	Bisher  protocol.Hash
	Neu     protocol.Hash
	Status  Status
	Art     Art
	Zeit    time.Time
	Nummer  uint64
	Person  string
}

// Bytes ist die kanonische Veröffentlichung.
func (v Veroeffentlichung) Bytes() ([]byte, error) {
	if v.Mandant == (protocol.ID{}) || v.Nummer == 0 || v.Zeit.IsZero() || v.Zeit.Location() != time.UTC {
		return nil, ErrFormat
	}
	if err := personOK(v.Name); err != nil {
		return nil, err
	}
	buf := append([]byte(nil), protocol.Domain(domVeroeffentlichung)...)
	buf = append(buf, v.Mandant[:]...)
	buf = protocol.AppendU64(buf, v.Nummer)
	buf = protocol.AppendU64(buf, uint64(v.Zeit.UnixMilli()))
	buf = protocol.AppendText(buf, v.Name)
	var err error
	buf, err = appendLen(buf, v.CRL)
	if err != nil {
		return nil, err
	}
	buf, err = appendLen(buf, v.Pruef)
	if err != nil {
		return nil, err
	}
	if len(v.Zertifikate) > 1024 {
		return nil, ErrFormat
	}
	buf = protocol.AppendU32(buf, uint32(len(v.Zertifikate)))
	gesehen := map[protocol.Hash]struct{}{}
	aktuell := 0
	for _, z := range v.Zertifikate {
		if !z.Status.Gueltig() || len(z.DER) == 0 {
			return nil, ErrFormat
		}
		finger, ferr := crypt.FingerprintCertificate(&x509.Certificate{Raw: z.DER})
		if ferr != nil {
			return nil, ErrFormat
		}
		if _, ok := gesehen[finger]; ok {
			return nil, ErrFormat
		}
		gesehen[finger] = struct{}{}
		if z.Status == StatusAktuell {
			aktuell++
		}
		buf = append(buf, byte(z.Status))
		buf, err = appendLen(buf, z.DER)
		if err != nil {
			return nil, err
		}
	}
	if aktuell > 1 || len(buf) > maxFassung {
		return nil, ErrFormat
	}
	return buf, nil
}

// ParseVeroeffentlichung liest Bytes.
func ParseVeroeffentlichung(b []byte) (Veroeffentlichung, error) {
	dom := protocol.Domain(domVeroeffentlichung)
	if len(b) > maxFassung || !bytes.HasPrefix(b, dom) {
		return Veroeffentlichung{}, ErrFormat
	}
	rest := b[len(dom):]
	var v Veroeffentlichung
	if len(rest) < protocol.IDLen {
		return Veroeffentlichung{}, ErrFormat
	}
	copy(v.Mandant[:], rest[:protocol.IDLen])
	rest = rest[protocol.IDLen:]
	var nummer, ms uint64
	nummer, rest, err := takeU64(rest)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	ms, rest, err = takeU64(rest)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	var name string
	name, rest, err = takeText(rest)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	var crl, pruef []byte
	crl, rest, err = takeLen(rest)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	pruef, rest, err = takeLen(rest)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	var n uint32
	n, rest, err = takeU32(rest)
	if err != nil || n > 1024 {
		return Veroeffentlichung{}, ErrFormat
	}
	certs := make([]Zertifikatseintrag, 0, n)
	gesehen := map[protocol.Hash]struct{}{}
	aktuell := 0
	for i := uint32(0); i < n; i++ {
		if len(rest) < 1 {
			return Veroeffentlichung{}, ErrFormat
		}
		st := Status(rest[0])
		rest = rest[1:]
		var der []byte
		der, rest, err = takeLen(rest)
		if err != nil || len(der) == 0 || !st.Gueltig() {
			return Veroeffentlichung{}, ErrFormat
		}
		finger, ferr := crypt.FingerprintCertificate(&x509.Certificate{Raw: der})
		if ferr != nil {
			return Veroeffentlichung{}, ErrFormat
		}
		if _, ok := gesehen[finger]; ok {
			return Veroeffentlichung{}, ErrFormat
		}
		gesehen[finger] = struct{}{}
		if st == StatusAktuell {
			aktuell++
		}
		certs = append(certs, Zertifikatseintrag{Status: st, DER: der})
	}
	if len(rest) != 0 || aktuell > 1 || v.Mandant == (protocol.ID{}) || nummer == 0 {
		return Veroeffentlichung{}, ErrFormat
	}
	if err := personOK(name); err != nil {
		return Veroeffentlichung{}, err
	}
	v.Nummer = nummer
	v.Zeit = time.UnixMilli(int64(ms)).UTC()
	v.Name = name
	v.CRL = crl
	v.Pruef = pruef
	v.Zertifikate = certs
	return v, nil
}

// Bytes ist der Protokolleintrag.
func (e Eintrag) Bytes() ([]byte, error) {
	if e.Mandant == (protocol.ID{}) || e.Nummer == 0 || e.Zeit.IsZero() || e.Zeit.Location() != time.UTC {
		return nil, ErrFormat
	}
	if !e.Status.Gueltig() || !e.Art.gueltig() {
		return nil, ErrFormat
	}
	if err := personOK(e.Person); err != nil {
		return nil, err
	}
	buf := append([]byte(nil), protocol.Domain(domProtokoll)...)
	buf = append(buf, e.Mandant[:]...)
	buf = append(buf, e.Bisher[:]...)
	buf = append(buf, e.Neu[:]...)
	buf = append(buf, byte(e.Status), byte(e.Art))
	buf = protocol.AppendU64(buf, uint64(e.Zeit.UnixMilli()))
	buf = protocol.AppendU64(buf, e.Nummer)
	buf = protocol.AppendText(buf, e.Person)
	if len(buf) > maxFassung {
		return nil, ErrFormat
	}
	return buf, nil
}

// ParseEintrag liest einen Protokolleintrag.
func ParseEintrag(b []byte) (Eintrag, error) {
	dom := protocol.Domain(domProtokoll)
	if len(b) > maxFassung || !bytes.HasPrefix(b, dom) {
		return Eintrag{}, ErrFormat
	}
	rest := b[len(dom):]
	var e Eintrag
	if len(rest) < protocol.IDLen+protocol.HashLen+protocol.HashLen+2 {
		return Eintrag{}, ErrFormat
	}
	copy(e.Mandant[:], rest[:protocol.IDLen])
	rest = rest[protocol.IDLen:]
	copy(e.Bisher[:], rest[:protocol.HashLen])
	rest = rest[protocol.HashLen:]
	copy(e.Neu[:], rest[:protocol.HashLen])
	rest = rest[protocol.HashLen:]
	e.Status = Status(rest[0])
	e.Art = Art(rest[1])
	rest = rest[2:]
	var ms, nummer uint64
	var err error
	ms, rest, err = takeU64(rest)
	if err != nil {
		return Eintrag{}, err
	}
	nummer, rest, err = takeU64(rest)
	if err != nil {
		return Eintrag{}, err
	}
	person, rest, err := takeText(rest)
	if err != nil || len(rest) != 0 {
		return Eintrag{}, ErrFormat
	}
	if e.Mandant == (protocol.ID{}) || nummer == 0 || !e.Status.Gueltig() || !e.Art.gueltig() {
		return Eintrag{}, ErrFormat
	}
	if err := personOK(person); err != nil {
		return Eintrag{}, err
	}
	e.Zeit = time.UnixMilli(int64(ms)).UTC()
	e.Nummer = nummer
	e.Person = person
	return e, nil
}

// EntwurfFinger ist der Fingerabdruck einer Fassung ohne neuen Schlüssel.
// Hinterlegen und StatusSetzen nennen stattdessen den Fingerabdruck des Zertifikats.
func EntwurfFinger(raw []byte) protocol.Hash {
	return sha256.Sum256(raw)
}

func personOK(s string) error {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) || bytes.ContainsRune([]byte(s), 0) {
		return ErrFormat
	}
	return nil
}

func appendLen(dst, data []byte) ([]byte, error) {
	if len(data) > maxFassung {
		return nil, ErrFormat
	}
	return append(protocol.AppendU32(dst, uint32(len(data))), data...), nil
}

func takeU32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, ErrFormat
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], nil
}

func takeU64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, ErrFormat
	}
	return binary.BigEndian.Uint64(b[:8]), b[8:], nil
}

func takeLen(b []byte) ([]byte, []byte, error) {
	n, rest, err := takeU32(b)
	if err != nil || uint32(len(rest)) < n || n > maxFassung {
		return nil, nil, ErrFormat
	}
	out := append([]byte(nil), rest[:n]...)
	return out, rest[n:], nil
}

func takeText(b []byte) (string, []byte, error) {
	raw, rest, err := takeLen(b)
	if err != nil {
		return "", nil, err
	}
	if err := personOK(string(raw)); err != nil {
		return "", nil, err
	}
	return string(raw), rest, nil
}
