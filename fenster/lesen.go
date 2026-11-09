package fenster

import (
	"sort"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

type segRef struct {
	nr  uint64
	key string
}

func (f *Fenster) katalogstand() (protocol.Stand, error) {
	if f.katalog != nil {
		return *f.katalog, nil
	}
	strom, err := f.strom(f.verb.Mandant, f.verb.Katalog, protocol.RolleKatalog, f.intervall)
	if err != nil {
		return protocol.Stand{}, err
	}
	staende, err := werkzeug.KatalogLesen(werkzeug.Anfrage{
		Mandant:   f.verb.Mandant,
		Ablage:    f.verb.Katalog,
		Rolle:     protocol.RolleKatalog,
		Intervall: f.intervall,
		Frist:     f.frist,
		Jetzt:     f.jetzt(),
		Epochen:   strom.Epochen,
	})
	if err != nil {
		return protocol.Stand{}, err
	}
	if len(staende) == 0 {
		return protocol.Stand{}, werkzeug.ErrAufloesung
	}
	stand := staende[len(staende)-1]
	f.katalog = &stand
	return stand, nil
}

func (f *Fenster) strom(mandant, ablage protocol.ID, rolle protocol.StromRolle, intervall time.Duration) (werkzeug.Strom, error) {
	ids, nach, err := f.gruppieren(mandant, ablage)
	if err != nil {
		return werkzeug.Strom{}, err
	}
	lagen := make([]werkzeug.Lage, 0, len(ids))
	for _, id := range ids {
		lage, err := f.lage(mandant, ablage, id, rolle, nach[id])
		if err != nil {
			return werkzeug.Strom{}, err
		}
		lagen = append(lagen, lage)
	}
	vorgaengerSetzen(ablage, lagen)
	strom := werkzeug.Strom{Ablage: ablage, Rolle: rolle, Intervall: intervall, Epochen: lagen}
	f.anheften(&strom)
	return strom, nil
}

func (f *Fenster) stromPassend(mandant, ablage protocol.ID, rolle protocol.StromRolle) (werkzeug.Strom, error) {
	ids, nach, err := f.gruppieren(mandant, ablage)
	if err != nil {
		return werkzeug.Strom{}, err
	}
	var lagen []werkzeug.Lage
	for _, id := range ids {
		refs := nach[id]
		if len(refs) == 0 || refs[0].nr != 1 {
			continue
		}
		passt, err := f.kopfPasst(refs[0].key)
		if err != nil || !passt {
			if err != nil {
				return werkzeug.Strom{}, err
			}
			continue
		}
		lage, err := f.lage(mandant, ablage, id, rolle, refs)
		if err != nil {
			return werkzeug.Strom{}, err
		}
		lagen = append(lagen, lage)
	}
	vorgaengerSetzen(ablage, lagen)
	strom := werkzeug.Strom{Ablage: ablage, Rolle: rolle, Intervall: f.intervall, Epochen: lagen}
	f.anheften(&strom)
	return strom, nil
}

// vorgaengerSetzen setzt den erwarteten Vorgänger je Instanz.
// Die gezielte Suche öffnet die Lage so, wie sie hier steht.
// Eine unbestätigte Epoche trägt die Kette nicht weiter.
func vorgaengerSetzen(ablage protocol.ID, lagen []werkzeug.Lage) {
	vorher := map[protocol.ID]protocol.Hash{}
	for i := range lagen {
		instanz := lagen[i].Auftrag.Epoch.Instanz()
		h, ok := vorher[instanz]
		if !ok {
			h = protocol.Genesis(ablage, instanz)
		}
		lagen[i].Auftrag.Vorgaenger = h
		if lagen[i].Auftrag.Bestaetigung != nil {
			vorher[instanz] = lagen[i].Auftrag.AbschlussHash
		}
	}
}

func (f *Fenster) lage(mandant, ablage protocol.ID, id protocol.EpochID, rolle protocol.StromRolle, refs []segRef) (werkzeug.Lage, error) {
	raster, err := rasterVon(id)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	tag, vermerkt, err := f.abschluss.Vermerk(mandant, ablage, id)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	var vermerk *time.Time
	if vermerkt {
		vermerk = &tag
	}
	weg, err := f.geloescht(raster, vermerk)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	var segs []werkzeug.Segment
	if !weg {
		segs = make([]werkzeug.Segment, len(refs))
		for i, ref := range refs {
			roh, err := f.lesen(ref.key)
			if err != nil {
				return werkzeug.Lage{}, err
			}
			segs[i] = werkzeug.Segment{Schluessel: ref.key, Bytes: roh}
		}
	}
	auftrag := f.belegen(werkzeug.Auftrag{
		Mandant: mandant, Ablage: ablage, Epoch: id, Rolle: rolle, Segmente: segs,
	})
	hash, sig, ok, err := f.abschluss.Bestaetigung(mandant, ablage, id)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	if ok {
		auftrag.Bestaetigung = f.bestPub
		auftrag.BestaetigungsSignatur = sig
		auftrag.AbschlussHash = hash
	}
	zweige, err := f.abschluss.Zweige(mandant, ablage, id)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	auftrag.Zweige = zweige
	return werkzeug.Lage{Auftrag: auftrag, Vermerk: vermerk}, nil
}

func (f *Fenster) anheften(strom *werkzeug.Strom) {
	if f.katalog == nil || strom == nil {
		return
	}
	if !standPasst(*f.katalog, strom.Rolle, strom.Ablage) {
		return
	}
	for i := range strom.Epochen {
		strom.Epochen[i].Auftrag.Katalog = f.katalog
	}
}

func standPasst(stand protocol.Stand, rolle protocol.StromRolle, ablage protocol.ID) bool {
	for _, k := range stand.Kennungen {
		if k.Rolle == rolle && k.Ablage == ablage {
			return true
		}
	}
	return false
}

func nameVon(stand protocol.Stand, ablage protocol.ID) string {
	for _, k := range stand.Kennungen {
		if k.Ablage == ablage && k.Rolle == protocol.RolleGruppe {
			return k.Kohorte
		}
	}
	return ""
}

func (f *Fenster) gruppieren(mandant, ablage protocol.ID) ([]protocol.EpochID, map[protocol.EpochID][]segRef, error) {
	keys, err := f.ziel.Liste(mandant.Hex() + "/" + ablage.Hex() + "/")
	if err != nil {
		return nil, nil, err
	}
	nach := map[protocol.EpochID][]segRef{}
	var ids []protocol.EpochID
	gesehen := map[protocol.EpochID]struct{}{}
	for _, key := range keys {
		gotMandant, gotAblage, epoch, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil || gotMandant != mandant || gotAblage != ablage || nr == 0 {
			return nil, nil, ErrZiel
		}
		if _, ok := gesehen[epoch]; !ok {
			gesehen[epoch] = struct{}{}
			ids = append(ids, epoch)
		}
		nach[epoch] = append(nach[epoch], segRef{nr: nr, key: key})
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for id, refs := range nach {
		sort.Slice(refs, func(i, j int) bool { return refs[i].nr < refs[j].nr })
		for i := 1; i < len(refs); i++ {
			if refs[i].nr == refs[i-1].nr {
				return nil, nil, ErrZiel
			}
		}
		nach[id] = refs
	}
	return ids, nach, nil
}

func (f *Fenster) lesen(key string) ([]byte, error) {
	roh, ok, err := f.ziel.Lesen(key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrZiel
	}
	return append([]byte(nil), roh...), nil
}

func (f *Fenster) kopfPasst(key string) (bool, error) {
	roh, err := f.lesen(key)
	if err != nil {
		return false, err
	}
	kek, _, _, _, err := protocol.ParseKopf(roh)
	if err != nil {
		return false, err
	}
	return kek == f.finger, nil
}

func (f *Fenster) geloescht(raster time.Time, vermerk *time.Time) (bool, error) {
	if vermerk != nil {
		return true, nil
	}
	schnitt, err := werkzeug.Schnitt(raster, f.frist)
	if err != nil {
		return false, err
	}
	return !f.jetzt().Before(schnitt), nil
}

func (f *Fenster) zaehlenStrom(mandant, ablage protocol.ID, intervall time.Duration, von, bis time.Time) (int, error) {
	ids, _, err := f.gruppieren(mandant, ablage)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		raster, err := rasterVon(id)
		if err != nil {
			return 0, err
		}
		if !trifft(raster, intervall, von, bis) {
			continue
		}
		tag, ok, err := f.abschluss.Vermerk(mandant, ablage, id)
		if err != nil {
			return 0, err
		}
		var vermerk *time.Time
		if ok {
			vermerk = &tag
		}
		weg, err := f.geloescht(raster, vermerk)
		if err != nil {
			return 0, err
		}
		if !weg {
			n++
		}
	}
	return n, nil
}

func lueckenlos(refs []segRef) bool {
	if len(refs) == 0 {
		return false
	}
	for i, ref := range refs {
		if ref.nr != uint64(i+1) {
			return false
		}
	}
	return true
}

func rasterVon(id protocol.EpochID) (time.Time, error) {
	zeit, err := time.Parse("20060102T150405Z", id.Raster())
	if err != nil {
		return time.Time{}, protocol.ErrRaster
	}
	return zeit, nil
}

func trifft(raster time.Time, intervall time.Duration, von, bis time.Time) bool {
	return raster.Before(bis) && von.Before(raster.Add(intervall))
}

func monatsbeginn(t time.Time) bool {
	return t.Location() == time.UTC && t.Day() == 1 && t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func monatTrifft(monat, von, bis time.Time) bool {
	return monat.Before(bis) && von.Before(monat.AddDate(0, 1, 0))
}

func monatZu(monat, jetzt time.Time) bool {
	return !jetzt.Before(monat.AddDate(0, 1, 0))
}

func monatVon(raster time.Time) time.Time {
	return time.Date(raster.Year(), raster.Month(), 1, 0, 0, 0, 0, time.UTC)
}
