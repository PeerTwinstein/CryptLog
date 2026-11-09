package suchen

import (
	"unicode/utf8"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Treffer sind die Personen eines Vorgangs oder die Vorgänge einer Person.
// Eine Index-Epoche und ein Klartext-DEK stehen hier nicht.
type Treffer struct {
	Personen  []werkzeug.PersonTreffer
	Vorgaenge []werkzeug.VorgangTreffer
}

// TrefferBytes ist die Antwort der Suchschnittstelle.
// Sie nennt nur die Treffer der Anfrage.
func TrefferBytes(art protocol.AnfrageArt, t Treffer) ([]byte, error) {
	var namen []string
	var rollen []protocol.StromRolle
	var kohorten []string
	var erste, letzte []uint64
	switch art {
	case protocol.AnfrageVorgang:
		if len(t.Vorgaenge) != 0 {
			return nil, ErrFormat
		}
		for _, ein := range t.Personen {
			namen = append(namen, ein.Person)
			rollen = append(rollen, ein.Rolle)
			kohorten = append(kohorten, ein.Kohorte)
			erste = append(erste, ein.Erster)
			letzte = append(letzte, ein.Letzter)
		}
	case protocol.AnfragePerson:
		if len(t.Personen) != 0 {
			return nil, ErrFormat
		}
		for _, ein := range t.Vorgaenge {
			namen = append(namen, ein.Nummer)
			rollen = append(rollen, ein.Rolle)
			kohorten = append(kohorten, ein.Kohorte)
			erste = append(erste, ein.Erster)
			letzte = append(letzte, ein.Letzter)
		}
	default:
		return nil, ErrFormat
	}
	buf := protocol.AppendText(nil, "treffer")
	buf = append(buf, byte(art))
	buf = protocol.AppendU32(buf, uint32(len(namen)))
	for i, name := range namen {
		if name == "" || !utf8.ValidString(name) || !utf8.ValidString(kohorten[i]) {
			return nil, ErrFormat
		}
		buf = protocol.AppendText(buf, name)
		buf = append(buf, byte(rollen[i]))
		buf = protocol.AppendText(buf, kohorten[i])
		buf = protocol.AppendU64(buf, erste[i])
		buf = protocol.AppendU64(buf, letzte[i])
	}
	return buf, nil
}

// ParseTreffer liest eine Antwort der Suchschnittstelle.
func ParseTreffer(b []byte) (protocol.AnfrageArt, Treffer, error) {
	c := cursor{b: b}
	name, err := c.text()
	if err != nil || name != "treffer" {
		return 0, Treffer{}, ErrFormat
	}
	artRoh, err := c.fest(1)
	if err != nil {
		return 0, Treffer{}, ErrFormat
	}
	art := protocol.AnfrageArt(artRoh[0])
	n, err := c.u32()
	if err != nil {
		return 0, Treffer{}, ErrFormat
	}
	var out Treffer
	for i := uint32(0); i < n; i++ {
		bez, err := c.text()
		if err != nil || bez == "" {
			return 0, Treffer{}, ErrFormat
		}
		rolleRoh, err := c.fest(1)
		if err != nil {
			return 0, Treffer{}, ErrFormat
		}
		kohorte, err := c.text()
		if err != nil {
			return 0, Treffer{}, ErrFormat
		}
		erster, err := c.u64()
		if err != nil {
			return 0, Treffer{}, ErrFormat
		}
		letzter, err := c.u64()
		if err != nil {
			return 0, Treffer{}, ErrFormat
		}
		rolle := protocol.StromRolle(rolleRoh[0])
		switch art {
		case protocol.AnfrageVorgang:
			out.Personen = append(out.Personen, werkzeug.PersonTreffer{
				Person: bez, Rolle: rolle, Kohorte: kohorte, Erster: erster, Letzter: letzter,
			})
		case protocol.AnfragePerson:
			out.Vorgaenge = append(out.Vorgaenge, werkzeug.VorgangTreffer{
				Nummer: bez, Rolle: rolle, Kohorte: kohorte, Erster: erster, Letzter: letzter,
			})
		default:
			return 0, Treffer{}, ErrFormat
		}
	}
	if len(c.b) != 0 {
		return 0, Treffer{}, ErrFormat
	}
	again, err := TrefferBytes(art, out)
	if err != nil || string(again) != string(b) {
		return 0, Treffer{}, ErrFormat
	}
	return art, out, nil
}
