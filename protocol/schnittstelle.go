package protocol

import "unicode/utf8"

// EreignisAufruf ist der Körper von POST /ereignis.
// Aufruf ist die festgelegte Aufruffolge und geht so in den event_hash ein.
type EreignisAufruf struct {
	ID       ID
	Mandant  ID
	Angabe   string
	Zeit     uint64
	Vorgang  string
	Personen []string
	Text     []byte
}

// Bestaetigt ist die Antwort nach der Annahme.
type Bestaetigt struct {
	Event      ID
	Hash       Hash
	Seq        uint64
	Schluessel string
}

// EreignisBytes ist die Bytefolge der Ereignisschnittstelle.
//
//	L("ereignis") || "ereignis" || event_id || mandant_id || L(angabe) || angabe || L(aufruf) || aufruf
func EreignisBytes(a EreignisAufruf) ([]byte, error) {
	var zero ID
	if a.ID == zero || (a.Mandant != zero && a.Angabe != "") {
		return nil, ErrLength
	}
	if !utf8.ValidString(a.Angabe) {
		return nil, ErrUTF8
	}
	aufruf, err := AufrufBytes(a.Zeit, a.Vorgang, a.Personen, a.Text)
	if err != nil {
		return nil, err
	}
	buf := AppendText(nil, "ereignis")
	buf = append(buf, a.ID[:]...)
	buf = append(buf, a.Mandant[:]...)
	buf, err = appendUTF8(buf, a.Angabe)
	if err != nil {
		return nil, err
	}
	return appendLen(buf, aufruf)
}

// ParseEreignis liest eine vollständige Ereignisfolge.
func ParseEreignis(b []byte) (EreignisAufruf, error) {
	c := cursor{b: b}
	if err := c.domain("ereignis"); err != nil {
		return EreignisAufruf{}, err
	}
	var a EreignisAufruf
	var err error
	if a.ID, err = c.id(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.ID == (ID{}) {
		return EreignisAufruf{}, ErrLength
	}
	if a.Mandant, err = c.id(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Angabe, err = c.feld(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Mandant != (ID{}) && a.Angabe != "" {
		return EreignisAufruf{}, ErrLength
	}
	roh, err := c.lp()
	if err != nil {
		return EreignisAufruf{}, err
	}
	if err := c.done(); err != nil {
		return EreignisAufruf{}, err
	}
	innen := cursor{b: roh}
	if err := innen.domain("aufruf"); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Zeit, err = innen.u64(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Vorgang, err = innen.feld(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Personen, err = innen.personen(); err != nil {
		return EreignisAufruf{}, err
	}
	if a.Text, err = innen.lp(); err != nil {
		return EreignisAufruf{}, err
	}
	if err := innen.done(); err != nil {
		return EreignisAufruf{}, err
	}
	wieder, err := EreignisBytes(a)
	if err != nil || !bytesEqual(wieder, b) {
		return EreignisAufruf{}, ErrLength
	}
	return a, nil
}

// BestaetigtBytes ist die Antwort der Ereignisschnittstelle.
//
//	L("bestaetigt") || "bestaetigt" || event_id || annahme_hash || batch_seq || L(annahme_schluessel) || annahme_schluessel
func BestaetigtBytes(b Bestaetigt) ([]byte, error) {
	if b.Event == (ID{}) || b.Seq == 0 || b.Schluessel == "" || !utf8.ValidString(b.Schluessel) {
		return nil, ErrLength
	}
	buf := AppendText(nil, "bestaetigt")
	buf = append(buf, b.Event[:]...)
	buf = append(buf, b.Hash[:]...)
	buf = AppendU64(buf, b.Seq)
	return appendUTF8(buf, b.Schluessel)
}

// ParseBestaetigt liest eine vollständige Antwort.
func ParseBestaetigt(b []byte) (Bestaetigt, error) {
	c := cursor{b: b}
	if err := c.domain("bestaetigt"); err != nil {
		return Bestaetigt{}, err
	}
	var out Bestaetigt
	var err error
	if out.Event, err = c.id(); err != nil {
		return Bestaetigt{}, err
	}
	if out.Hash, err = c.hash(); err != nil {
		return Bestaetigt{}, err
	}
	if out.Seq, err = c.u64(); err != nil {
		return Bestaetigt{}, err
	}
	if out.Schluessel, err = c.text(); err != nil {
		return Bestaetigt{}, err
	}
	if err := c.done(); err != nil {
		return Bestaetigt{}, err
	}
	wieder, err := BestaetigtBytes(out)
	if err != nil || !bytesEqual(wieder, b) {
		return Bestaetigt{}, ErrLength
	}
	return out, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
