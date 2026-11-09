package werkzeug

import (
	"errors"
	"time"

	"cryptlog/protocol"
)

// ErrSuche fehlt Person und Vorgangsnummer. Eine von beiden trägt die Suche.
var ErrSuche = errors.New("werkzeug: Suche ohne Person und Vorgang")

// Suchanfrage liest das Verzeichnis des Zeitraums und öffnet die verwiesenen
// Logeinträge. Person, Vorgang oder beide grenzen die Treffer ein. Sind beide
// gesetzt, muss derselbe Logeintrag unter der Person und unter der Vorgangsnummer
// stehen. Ziele sind die Gruppen-, Einzel- und Auffang-Epochen, auf die Verweise
// zeigen können. Eine Epoche, die kein Verweis nennt, bleibt zu.
type Suchanfrage struct {
	Mandant     protocol.ID
	Frist       time.Duration
	Jetzt       time.Time
	Von         time.Time
	Bis         time.Time
	Person      string
	Vorgang     string
	Verzeichnis Strom
	// Summen ist der Strom verzeichnis-summe. Ohne Epochen liest die Suche
	// das Verzeichnis über seine eigenen Epochen.
	Summen Strom
	Ziele  []Strom
}

// Strom ist ein logischer Strom mit seinen Epochen in Abschlussreihenfolge.
type Strom struct {
	Ablage    protocol.ID
	Rolle     protocol.StromRolle
	Intervall time.Duration
	Epochen   []Lage
}

// Treffer ist ein Logeintrag, auf den ein Verweis der Suche zeigt.
// Bei Geloescht, Luecke oder Verloren bleibt der Eintrag leer.
type Treffer struct {
	Epoch       protocol.EpochID
	Seq         uint64
	Bind        protocol.ID
	Ablage      protocol.ID
	Rolle       protocol.StromRolle
	Geloescht   bool
	Luecke      bool
	Verloren    bool
	Vertraulich bool
	Eintrag     Eintrag
}

type zielOrt struct {
	ablage    protocol.ID
	rolle     protocol.StromRolle
	intervall time.Duration
	lage      Lage
	raster    time.Time
}

type zeiger struct {
	bind  protocol.ID
	epoch protocol.EpochID
	seq   uint64
}

// Suche prüft das Verzeichnis des Zeitraums und öffnet nur die verwiesenen
// ersten Sequenzen. Für einen abgeschlossenen Monat öffnet sie die Summenepoche,
// wenn deren Belege zu den bestätigten Manifest-Hashes passen. Sonst die
// Verzeichnis-Epochen dieses Monats. Ein Verweis auf eine gelöschte Epoche
// bleibt ein Treffer ohne Eintrag. Fehlt die Epoche vor dem Zugriffsschnitt,
// ist das eine Lücke.
func Suche(s Suchanfrage) ([]Treffer, error) {
	if s.Person == "" && s.Vorgang == "" {
		return nil, ErrSuche
	}
	if err := stromGueltig(s.Verzeichnis, protocol.RolleVerzeichnis); err != nil {
		return nil, err
	}
	orte := make(map[protocol.EpochID]zielOrt)
	for _, ziel := range s.Ziele {
		if err := stromGueltig(ziel, ziel.Rolle); err != nil {
			return nil, err
		}
		switch ziel.Rolle {
		case protocol.RolleGruppe, protocol.RolleEinzel, protocol.RolleAuffang:
		default:
			return nil, ErrRolle
		}
		for _, lage := range ziel.Epochen {
			zeit, _, err := lageGueltig(Anfrage{
				Mandant:   s.Mandant,
				Ablage:    ziel.Ablage,
				Rolle:     ziel.Rolle,
				Intervall: ziel.Intervall,
			}, lage, epochen(orte))
			if err != nil {
				return nil, err
			}
			orte[lage.Auftrag.Epoch] = zielOrt{
				ablage: ziel.Ablage, rolle: ziel.Rolle, intervall: ziel.Intervall,
				lage: lage, raster: zeit,
			}
		}
	}
	gesehen := epochen(orte)
	for _, lage := range s.Verzeichnis.Epochen {
		if _, ok := gesehen[lage.Auftrag.Epoch]; ok {
			return nil, ErrZeitraum
		}
		gesehen[lage.Auftrag.Epoch] = struct{}{}
	}
	for _, lage := range s.Summen.Epochen {
		if _, ok := gesehen[lage.Auftrag.Epoch]; ok {
			return nil, ErrZeitraum
		}
		gesehen[lage.Auftrag.Epoch] = struct{}{}
	}
	reihe, err := verzeichnisZeiger(s)
	if err != nil {
		return nil, err
	}
	return eintraegeOeffnen(s, reihe, orte)
}

func stromGueltig(s Strom, rolle protocol.StromRolle) error {
	if s.Rolle != rolle {
		return ErrRolle
	}
	if !intervallGueltig(s.Intervall) {
		return ErrIntervall
	}
	var leer protocol.ID
	if s.Ablage == leer {
		return ErrZeitraum
	}
	return nil
}

func epochen(orte map[protocol.EpochID]zielOrt) map[protocol.EpochID]struct{} {
	gesehen := make(map[protocol.EpochID]struct{}, len(orte))
	for id := range orte {
		gesehen[id] = struct{}{}
	}
	return gesehen
}

func sammeln(s Suchanfrage, staende []Stand, extra []Eintrag) []zeiger {
	var personen, vorgaenge []zeiger
	eintraege := append([]Eintrag(nil), extra...)
	for _, stand := range staende {
		if !stand.ImZeitraum || stand.Geloescht {
			continue
		}
		eintraege = append(eintraege, stand.Bericht.Eintraege...)
	}
	for _, eintrag := range eintraege {
		z, art, ok := verweisZeiger(s.Mandant, eintrag)
		if !ok {
			continue
		}
		switch art {
		case protocol.VerweisPerson:
			if s.Person != "" && eintrag.Verweis.Schluessel == s.Person {
				personen = append(personen, z)
			}
		case protocol.VerweisVorgang:
			if s.Vorgang != "" && eintrag.Verweis.Schluessel == s.Vorgang {
				vorgaenge = append(vorgaenge, z)
			}
		}
	}
	if s.Person != "" && s.Vorgang != "" {
		return schnitt(personen, vorgaenge)
	}
	if s.Person != "" {
		return eindeutig(personen)
	}
	return eindeutig(vorgaenge)
}

func verweisZeiger(mandant protocol.ID, eintrag Eintrag) (zeiger, protocol.VerweisArt, bool) {
	if eintrag.Verweis == nil || !eintrag.Gueltig || eintrag.Verweis.Mandant != mandant || eintrag.Verweis.Seq == 0 {
		return zeiger{}, 0, false
	}
	return zeiger{bind: eintrag.Verweis.Bind, epoch: eintrag.Verweis.Epoch, seq: eintrag.Verweis.Seq}, eintrag.Verweis.Art, true
}

func eindeutig(liste []zeiger) []zeiger {
	gesehen := make(map[zeiger]struct{}, len(liste))
	var out []zeiger
	for _, z := range liste {
		if _, ok := gesehen[z]; ok {
			continue
		}
		gesehen[z] = struct{}{}
		out = append(out, z)
	}
	return out
}

func schnitt(personen, vorgaenge []zeiger) []zeiger {
	haben := make(map[zeiger]struct{}, len(vorgaenge))
	for _, z := range vorgaenge {
		haben[z] = struct{}{}
	}
	var beide []zeiger
	for _, z := range personen {
		if _, ok := haben[z]; ok {
			beide = append(beide, z)
		}
	}
	return eindeutig(beide)
}

func eintraegeOeffnen(s Suchanfrage, reihe []zeiger, orte map[protocol.EpochID]zielOrt) ([]Treffer, error) {
	type gruppe struct {
		epoch protocol.EpochID
		seqs  []uint64
		binds map[uint64]protocol.ID
	}
	var gruppen []gruppe
	index := make(map[protocol.EpochID]int)
	for _, z := range reihe {
		i, ok := index[z.epoch]
		if !ok {
			i = len(gruppen)
			index[z.epoch] = i
			gruppen = append(gruppen, gruppe{epoch: z.epoch, binds: make(map[uint64]protocol.ID)})
		}
		if _, da := gruppen[i].binds[z.seq]; da {
			continue
		}
		gruppen[i].seqs = append(gruppen[i].seqs, z.seq)
		gruppen[i].binds[z.seq] = z.bind
	}
	var out []Treffer
	for _, g := range gruppen {
		ort, gefunden := orte[g.epoch]
		raster := time.Time{}
		var err error
		if gefunden {
			raster = ort.raster
		} else {
			raster, err = epochRaster(g.epoch)
			if err != nil {
				return nil, err
			}
		}
		geloescht, err := zielGeloescht(s, raster, ort, gefunden)
		if err != nil {
			return nil, err
		}
		if !gefunden || geloescht {
			if geloescht && gefunden && vollstaendig(ort.lage.Auftrag.Segmente) {
				auftrag := ort.lage.Auftrag
				auftrag.Mandant = s.Mandant
				auftrag.Ablage = ort.ablage
				auftrag.Rolle = ort.rolle
				auftrag.Auswahl = nil
				auftrag.Alles = false
				if _, err = Pruefen(auftrag); err != nil {
					return nil, err
				}
			}
			for _, seq := range g.seqs {
				out = append(out, Treffer{
					Epoch: g.epoch, Seq: seq, Bind: g.binds[seq],
					Ablage: ort.ablage, Rolle: ort.rolle,
					Geloescht: geloescht, Luecke: !gefunden && !geloescht,
				})
			}
			continue
		}
		auftrag := ort.lage.Auftrag
		auftrag.Mandant = s.Mandant
		auftrag.Ablage = ort.ablage
		auftrag.Rolle = ort.rolle
		auftrag.Auswahl = g.seqs
		auftrag.Alles = false
		auftrag.RasterEnde, err = rasterEnde(raster, ort.intervall)
		if err != nil {
			return nil, err
		}
		bericht, err := Pruefen(auftrag)
		if err != nil {
			return nil, err
		}
		if bericht.Verloren || bericht.Luecke || bericht.VorgaengerBruch || bericht.Verzweigung {
			for _, seq := range g.seqs {
				out = append(out, Treffer{
					Epoch: g.epoch, Seq: seq, Bind: g.binds[seq],
					Ablage: ort.ablage, Rolle: ort.rolle,
					Luecke: !bericht.Verloren, Verloren: bericht.Verloren,
				})
			}
			continue
		}
		nachSeq := make(map[uint64]Eintrag, len(bericht.Eintraege))
		for _, eintrag := range bericht.Eintraege {
			nachSeq[eintrag.Seq] = eintrag
		}
		for _, seq := range g.seqs {
			eintrag, ok := nachSeq[seq]
			if !ok {
				out = append(out, Treffer{
					Epoch: g.epoch, Seq: seq, Bind: g.binds[seq],
					Ablage: ort.ablage, Rolle: ort.rolle, Luecke: true,
				})
				continue
			}
			if eintrag.Bind != g.binds[seq] {
				eintrag.Gueltig = false
			}
			out = append(out, Treffer{
				Epoch: g.epoch, Seq: seq, Bind: g.binds[seq],
				Ablage: ort.ablage, Rolle: ort.rolle,
				Vertraulich: bericht.Vertraulich, Eintrag: eintrag,
			})
		}
	}
	return out, nil
}

func zielGeloescht(s Suchanfrage, raster time.Time, ort zielOrt, gefunden bool) (bool, error) {
	if gefunden && ort.lage.Vermerk != nil {
		return true, nil
	}
	schnitt, err := Schnitt(raster, s.Frist)
	if err != nil {
		return false, err
	}
	return !s.Jetzt.Before(schnitt), nil
}
