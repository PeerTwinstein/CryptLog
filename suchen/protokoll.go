package suchen

import (
	"encoding/binary"
	"math"
	"os"
	"unicode/utf8"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// protokollSchreiben hängt einen bestätigten Suchvorgang an.
// Das Protokoll nennt die Anfrage, keinen Logtext und keinen Indexeintrag.
func (p *Prozess) protokollSchreiben(ein werkzeug.Protokoll, sig protocol.Signature) error {
	roh, err := protokollBytes(ein, sig)
	if err != nil {
		return err
	}
	var laenge [4]byte
	binary.BigEndian.PutUint32(laenge[:], uint32(len(roh)))
	if _, err := p.datei.Write(laenge[:]); err != nil {
		return ErrProtokoll
	}
	if _, err := p.datei.Write(roh); err != nil {
		return ErrProtokoll
	}
	if err := p.datei.Sync(); err != nil {
		return ErrProtokoll
	}
	return nil
}

func protokollBytes(ein werkzeug.Protokoll, sig protocol.Signature) ([]byte, error) {
	if ein.Person == "" || ein.Schluessel == "" || !utf8.ValidString(ein.Person) || !utf8.ValidString(ein.Schluessel) {
		return nil, ErrProtokoll
	}
	switch ein.Art {
	case protocol.AnfrageVorgang, protocol.AnfragePerson:
	default:
		return nil, ErrProtokoll
	}
	buf := protocol.AppendText(nil, "suchprotokoll")
	buf = append(buf, ein.Mandant[:]...)
	buf = append(buf, ein.Finger[:]...)
	buf = protocol.AppendText(buf, ein.Person)
	buf = append(buf, byte(ein.Art))
	buf = protocol.AppendText(buf, ein.Schluessel)
	buf = protocol.AppendU64(buf, ein.Von)
	buf = protocol.AppendU64(buf, ein.Bis)
	buf = protocol.AppendU64(buf, ein.Zeitpunkt)
	buf = append(buf, sig[:]...)
	return buf, nil
}

func protokollBisher(pfad string) ([]byte, error) {
	roh, err := os.ReadFile(pfad)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return roh, nil
}

func (p *Prozess) protokollLaden(roh []byte) error {
	rest := roh
	for len(rest) > 0 {
		if len(rest) < 4 {
			return ErrProtokoll
		}
		n := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if n == 0 || uint64(n) > uint64(len(rest)) {
			return ErrProtokoll
		}
		ein, sig, err := parseProtokoll(rest[:n])
		if err != nil {
			return err
		}
		rest = rest[n:]
		if ein.Zeitpunkt > uint64(math.MaxInt64) {
			continue
		}
		p.gesehen.setzen(sig, int64(ein.Zeitpunkt))
	}
	return nil
}

func parseProtokoll(b []byte) (werkzeug.Protokoll, protocol.Signature, error) {
	c := cursor{b: b}
	name, err := c.text()
	if err != nil || name != "suchprotokoll" {
		return werkzeug.Protokoll{}, protocol.Signature{}, ErrProtokoll
	}
	var ein werkzeug.Protokoll
	mandant, err := c.fest(protocol.IDLen)
	if err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	copy(ein.Mandant[:], mandant)
	finger, err := c.fest(protocol.HashLen)
	if err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	copy(ein.Finger[:], finger)
	if ein.Person, err = c.text(); err != nil || ein.Person == "" {
		return werkzeug.Protokoll{}, protocol.Signature{}, ErrProtokoll
	}
	art, err := c.fest(1)
	if err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	ein.Art = protocol.AnfrageArt(art[0])
	if ein.Schluessel, err = c.text(); err != nil || ein.Schluessel == "" {
		return werkzeug.Protokoll{}, protocol.Signature{}, ErrProtokoll
	}
	if ein.Von, err = c.u64(); err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	if ein.Bis, err = c.u64(); err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	if ein.Zeitpunkt, err = c.u64(); err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	roh, err := c.fest(protocol.SignatureLen)
	if err != nil || len(c.b) != 0 {
		return werkzeug.Protokoll{}, protocol.Signature{}, ErrProtokoll
	}
	var sig protocol.Signature
	copy(sig[:], roh)
	if _, err := protokollBytes(ein, sig); err != nil {
		return werkzeug.Protokoll{}, protocol.Signature{}, err
	}
	return ein, sig, nil
}

type cursor struct {
	b []byte
}

func (c *cursor) text() (string, error) {
	n, err := c.u32()
	if err != nil {
		return "", err
	}
	roh, err := c.fest(int(n))
	if err != nil {
		return "", err
	}
	s := string(roh)
	if !utf8.ValidString(s) {
		return "", ErrProtokoll
	}
	return s, nil
}

func (c *cursor) u64() (uint64, error) {
	roh, err := c.fest(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(roh), nil
}

func (c *cursor) u32() (uint32, error) {
	roh, err := c.fest(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(roh), nil
}

func (c *cursor) fest(n int) ([]byte, error) {
	if n < 0 || len(c.b) < n {
		return nil, ErrProtokoll
	}
	roh := c.b[:n]
	c.b = c.b[n:]
	return roh, nil
}
