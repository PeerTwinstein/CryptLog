package werkzeug

import (
	"time"

	"cryptlog/protocol"
)

// KatalogLesen öffnet den Stromkatalog und liefert die Stände in der
// Abschlussreihenfolge. Der letzte Stand ist der aktuelle. Eine gelöschte
// Epoche trägt keinen Stand bei. Eine Lücke, eine Verzweigung oder ein Bruch
// zum Vorgänger bricht das Lesen ab.
func KatalogLesen(a Anfrage) ([]protocol.Stand, error) {
	if a.Rolle != protocol.RolleKatalog {
		return nil, ErrRolle
	}
	if a.Von.IsZero() && a.Bis.IsZero() {
		a.Von = time.Unix(0, 0).UTC()
		a.Bis = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	staende, err := Zeitraum(a)
	if err != nil {
		return nil, err
	}
	var out []protocol.Stand
	for _, stand := range staende {
		if stand.Geloescht {
			continue
		}
		if stand.Bericht.Luecke || stand.Bericht.VorgaengerBruch || stand.Bericht.Verzweigung || stand.Bericht.Verloren {
			return nil, ErrKette
		}
		if !stand.ImZeitraum {
			continue
		}
		for _, eintrag := range stand.Bericht.Eintraege {
			if eintrag.Katalog == nil || !eintrag.Gueltig {
				return nil, ErrInhalt
			}
			out = append(out, *eintrag.Katalog)
		}
	}
	return out, nil
}

// Aufloesen löst im letzten Stand einen Namen in die ablage_id auf.
// Bei RolleGruppe ist name der Kohortenname. Bei RolleEinzel ist name leer;
// zurück kommt der Präfix, Bind bleibt leer. Bei den übrigen Rollen ist name
// leer, und die Rolle bestimmt die eine Ablage. Abgeschaltete Kennungen bleiben auflösbar.
func Aufloesen(staende []protocol.Stand, rolle protocol.StromRolle, name string) (protocol.Kennung, error) {
	if len(staende) == 0 {
		return protocol.Kennung{}, ErrAufloesung
	}
	stand := staende[len(staende)-1]
	switch rolle {
	case protocol.RolleGruppe:
		if name == "" {
			return protocol.Kennung{}, ErrAufloesung
		}
		var treffer *protocol.Kennung
		for i := range stand.Kennungen {
			k := &stand.Kennungen[i]
			if k.Rolle != protocol.RolleGruppe || k.Kohorte != name {
				continue
			}
			if treffer != nil {
				return protocol.Kennung{}, ErrAufloesung
			}
			treffer = k
		}
		if treffer == nil {
			return protocol.Kennung{}, ErrAufloesung
		}
		return *treffer, nil
	case protocol.RolleEinzel:
		if name != "" {
			return protocol.Kennung{}, ErrAufloesung
		}
		var ablage protocol.ID
		gesehen := false
		for _, k := range stand.Kennungen {
			if k.Rolle != protocol.RolleEinzel {
				continue
			}
			if !gesehen {
				ablage = k.Ablage
				gesehen = true
				continue
			}
			if k.Ablage != ablage {
				return protocol.Kennung{}, ErrAufloesung
			}
		}
		if !gesehen {
			return protocol.Kennung{}, ErrAufloesung
		}
		return protocol.Kennung{Rolle: protocol.RolleEinzel, Ablage: ablage}, nil
	case protocol.RolleAuffang, protocol.RolleVerzeichnis, protocol.RolleVorgang,
		protocol.RolleKatalog, protocol.RolleVerzeichnisSumme, protocol.RolleVorgangSumme:
		if name != "" {
			return protocol.Kennung{}, ErrAufloesung
		}
		var treffer *protocol.Kennung
		for i := range stand.Kennungen {
			k := &stand.Kennungen[i]
			if k.Rolle != rolle {
				continue
			}
			if treffer != nil {
				return protocol.Kennung{}, ErrAufloesung
			}
			treffer = k
		}
		if treffer == nil {
			return protocol.Kennung{}, ErrAufloesung
		}
		return *treffer, nil
	default:
		return protocol.Kennung{}, ErrAufloesung
	}
}
