package schreiben

import (
	"sort"
	"time"

	"cryptlog/protocol"
)

// rasterSchluss merkt, dass für diesen Strom in diesem Raster eine Epoche
// entstanden ist. Dieselbe Ereignisepoche wird dadurch nicht ein zweites Mal
// als Füllung geschrieben.
type rasterSchluss struct {
	mandant protocol.ID
	ablage  protocol.ID
	bind    protocol.ID
	raster  int64
}

type deckZiel struct {
	ablage protocol.ID
	bind   protocol.ID
	rolle  protocol.StromRolle
}

// deckFuellen schreibt bei angeschaltetem Deckverkehr die Epoche eines Rasters,
// auch wenn darin kein Ereignis lag.
// Für jeden Gruppenstrom, den Auffangstrom und den Einzelpräfix entsteht je Raster
// eine Epoche. Liegt für den Strom schon eine offene Ereignisepoche in diesem Raster,
// wird sie geschlossen und nicht durch eine zweite ersetzt. Am Einzelpräfix ist die
// Füllepoch die des Präfixes; Epochen der Personen bleiben eigene Ströme daneben.
// einschliesslich schließt auch das laufende Raster. Das tut das Beenden.
// Ein Raster vor dem Start dieser Instanz bleibt leer.
func (p *Prozess) deckFuellen(einschliesslich bool) error {
	ids, err := p.bestand.Mandanten()
	if err != nil || len(ids) == 0 {
		return err
	}
	jetzt := p.jetzt()
	for _, id := range ids {
		lage, err := p.lageVon(id)
		if err != nil {
			return err
		}
		if !lage.Deck || !lage.KEKVorhanden || lage.KEK.Pub == nil {
			continue
		}
		if err := p.deckMandant(id, lage, jetzt, einschliesslich); err != nil {
			return err
		}
	}
	return nil
}

func (p *Prozess) deckMandant(mandant protocol.ID, lage Lage, jetzt time.Time, einschliesslich bool) error {
	for _, ziel := range deckZiele(lage) {
		if err := p.deckStrom(mandant, lage, ziel, jetzt, einschliesslich); err != nil {
			return err
		}
	}
	return nil
}

func (p *Prozess) deckStrom(mandant protocol.ID, lage Lage, ziel deckZiel, jetzt time.Time, einschliesslich bool) error {
	intervall := p.schwellen.intervall(ziel.rolle)
	anfang := rasterBeginn(p.start, intervall)
	aktuell := rasterBeginn(jetzt, intervall)
	var bis time.Time
	switch {
	case einschliesslich:
		bis = aktuell
	case aktuell.After(anfang):
		bis = aktuell.Add(-intervall)
	default:
		return nil
	}
	for raster := anfang; !raster.After(bis); raster = raster.Add(intervall) {
		if p.deckIst(mandant, ziel.ablage, ziel.bind, raster) {
			continue
		}
		if l := p.deckLauf(mandant, ziel.ablage, ziel.bind); l != nil && !l.raster.After(raster) {
			fertig := l.raster
			err := p.deckSchliessen(l)
			if l.ep == nil {
				p.deckMerken(mandant, ziel.ablage, ziel.bind, fertig)
			}
			if err != nil {
				return err
			}
			if fertig.Equal(raster) || p.deckIst(mandant, ziel.ablage, ziel.bind, raster) {
				continue
			}
		}
		if p.deckLauf(mandant, ziel.ablage, ziel.bind) != nil {
			continue
		}
		if err := p.deckLeer(mandant, ziel, lage, raster); err != nil {
			return err
		}
	}
	return nil
}

// deckSchliessen schließt die offene Epoche. Ist sie schon zu und ohne Manifest,
// fällt sie weg, damit das Raster eine neue Epoche bekommen kann.
func (p *Prozess) deckSchliessen(l *lauf) error {
	if l == nil || l.ep == nil {
		return nil
	}
	if !l.ep.Offen() && l.rest == nil {
		p.entfernen(l)
		return nil
	}
	return p.rotieren(l)
}

// deckLeer öffnet die Epoche auf diesem Raster und schließt sie sofort.
// Abschluss füllt sie auf ein Segment der kleinsten Klasse. Die Annahme nennt
// keine Ereignisse, acht Plätze und im Blob nur Füllsequenzen.
func (p *Prozess) deckLeer(mandant protocol.ID, ziel deckZiel, lage Lage, raster time.Time) error {
	key := stromSchluss{mandant: mandant, ablage: ziel.ablage, bind: ziel.bind, finger: lage.KEK.Finger}
	l, err := p.oeffnenRaster(key, ziel.rolle, lage.KEK, lage.Rahmen, raster)
	if err != nil {
		return err
	}
	if err := p.manifest(l); err != nil {
		return err
	}
	p.deckMerken(mandant, ziel.ablage, ziel.bind, raster)
	return p.hochladen(true)
}

func (p *Prozess) deckLauf(mandant, ablage, bind protocol.ID) *lauf {
	for _, l := range p.laeufe {
		if l != nil && l.ep != nil && l.key.mandant == mandant && l.key.ablage == ablage && l.key.bind == bind {
			return l
		}
	}
	return nil
}

func (p *Prozess) deckIst(mandant, ablage, bind protocol.ID, raster time.Time) bool {
	_, ok := p.gedeckt[rasterSchluss{mandant, ablage, bind, raster.UnixNano()}]
	return ok
}

func (p *Prozess) deckMerken(mandant, ablage, bind protocol.ID, raster time.Time) {
	if p.gedeckt == nil {
		p.gedeckt = map[rasterSchluss]struct{}{}
	}
	p.gedeckt[rasterSchluss{mandant, ablage, bind, raster.UnixNano()}] = struct{}{}
}

// deckZiele sind die Ströme, die bei Deckverkehr in jedem Raster eine Epoche tragen.
// Abgeschaltete Gruppenkennungen bleiben draußen. Auffang und Einzelpräfix kommen
// aus der Lage. Die Personen am Einzelpräfix sind keine eigenen Füllströme.
func deckZiele(lage Lage) []deckZiel {
	var ziele []deckZiel
	gesehen := map[protocol.ID]struct{}{}
	for _, k := range lage.Stand.Kennungen {
		if k.Rolle != protocol.RolleGruppe || k.Aktiv != protocol.KennungAn || k.Bind != k.Ablage || k.Ablage == (protocol.ID{}) {
			continue
		}
		if _, ok := gesehen[k.Ablage]; ok {
			continue
		}
		gesehen[k.Ablage] = struct{}{}
		ziele = append(ziele, deckZiel{ablage: k.Ablage, bind: k.Bind, rolle: protocol.RolleGruppe})
	}
	if lage.Auffang != (protocol.ID{}) {
		if _, ok := gesehen[lage.Auffang]; !ok {
			gesehen[lage.Auffang] = struct{}{}
			ziele = append(ziele, deckZiel{ablage: lage.Auffang, bind: lage.Auffang, rolle: protocol.RolleAuffang})
		}
	}
	if lage.Einzel != (protocol.ID{}) {
		if _, ok := gesehen[lage.Einzel]; !ok {
			ziele = append(ziele, deckZiel{ablage: lage.Einzel, bind: lage.Einzel, rolle: protocol.RolleEinzel})
		}
	}
	sort.Slice(ziele, func(i, j int) bool {
		if deckOrd(ziele[i].rolle) != deckOrd(ziele[j].rolle) {
			return deckOrd(ziele[i].rolle) < deckOrd(ziele[j].rolle)
		}
		return ziele[i].ablage.Hex() < ziele[j].ablage.Hex()
	})
	return ziele
}

func deckOrd(r protocol.StromRolle) int {
	switch r {
	case protocol.RolleGruppe:
		return 0
	case protocol.RolleAuffang:
		return 1
	default:
		return 2
	}
}
