package fenster

import (
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Zaehlen nennt, wie viele Epochen die Auswahl trifft, bevor ein Log-DEK aufgeht.
// Eine gelöschte Epoche zählt nicht. Den Bucket entschlüsselt dieser Aufruf nicht.
func (f *Fenster) Zaehlen(a Auswahl) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.entsperrt() {
		return 0, ErrFenster
	}
	return f.zaehlen(a)
}

// Pruefung öffnet nur die Auswahl und behält den Klartext bis Ende.
func (f *Fenster) Pruefung(a Auswahl) (Ergebnis, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.entsperrt() {
		return Ergebnis{}, ErrFenster
	}
	if f.sitzung != nil {
		return Ergebnis{}, ErrPruefung
	}
	erg, err := f.pruefen(a)
	if err != nil {
		f.sitzung = &erg
		f.ende()
		return Ergebnis{}, err
	}
	f.sitzung = &erg
	return erg, nil
}

// Ende verwirft den Klartext dieser Prüfung. Der Klartext-DEK ist schon weg.
func (f *Fenster) Ende() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ende()
}

func (f *Fenster) ende() {
	if f.sitzung == nil {
		return
	}
	for i := range f.sitzung.Befunde {
		for j := range f.sitzung.Befunde[i].Eintraege {
			z := &f.sitzung.Befunde[i].Eintraege[j]
			crypt.Wipe(z.Text)
			crypt.Wipe(z.Vorgang)
			crypt.Wipe(z.Angabe)
			for _, p := range z.Personen {
				crypt.Wipe(p)
			}
			z.Personen = nil
		}
		f.sitzung.Befunde[i].Eintraege = nil
	}
	f.sitzung.Befunde = nil
	f.sitzung = nil
}

func (f *Fenster) pruefen(a Auswahl) (Ergebnis, error) {
	switch a.Art {
	case ArtGruppe:
		return f.pruefungStrom(a, protocol.RolleGruppe, a.Kohorte)
	case ArtAuffang:
		return f.pruefungStrom(a, protocol.RolleAuffang, "")
	case ArtGezielt:
		return f.pruefungGezielt(a)
	case ArtPlattform:
		return f.pruefungPlattform(a)
	default:
		return Ergebnis{}, ErrArt
	}
}

func (f *Fenster) zaehlen(a Auswahl) (int, error) {
	von, bis, err := f.spanne(a)
	if err != nil {
		return 0, err
	}
	stand, err := f.katalogstand()
	if err != nil {
		return 0, err
	}
	switch a.Art {
	case ArtGruppe, ArtAuffang:
		rolle := protocol.RolleGruppe
		name := a.Kohorte
		if a.Art == ArtAuffang {
			rolle = protocol.RolleAuffang
			name = ""
		}
		kennung, err := werkzeug.Aufloesen([]protocol.Stand{stand}, rolle, name)
		if err != nil {
			return 0, err
		}
		return f.zaehlenStrom(f.verb.Mandant, kennung.Ablage, f.intervall, von, bis)
	case ArtGezielt:
		if a.Person == "" && a.Vorgang == "" {
			return 0, werkzeug.ErrSuche
		}
		return f.zaehlenVerzeichnis(stand, von, bis)
	case ArtPlattform:
		if !f.plattform {
			return 0, ErrArt
		}
		return f.zaehlenPlattform(stand, von, bis)
	default:
		return 0, ErrArt
	}
}

func (f *Fenster) pruefungStrom(a Auswahl, rolle protocol.StromRolle, name string) (Ergebnis, error) {
	von, bis, err := f.spanne(a)
	if err != nil {
		return Ergebnis{}, err
	}
	stand, err := f.katalogstand()
	if err != nil {
		return Ergebnis{}, err
	}
	kennung, err := werkzeug.Aufloesen([]protocol.Stand{stand}, rolle, name)
	if err != nil {
		return Ergebnis{}, err
	}
	strom, err := f.strom(f.verb.Mandant, kennung.Ablage, rolle, f.intervall)
	if err != nil {
		return Ergebnis{}, err
	}
	staende, err := werkzeug.Zeitraum(werkzeug.Anfrage{
		Mandant: f.verb.Mandant, Ablage: kennung.Ablage, Rolle: rolle,
		Intervall: f.intervall, Frist: f.frist, Jetzt: f.jetzt(),
		Von: von, Bis: bis, Epochen: strom.Epochen,
	})
	if err != nil {
		return Ergebnis{}, err
	}
	erg := befunde(a.Art, staende, strom, kennung.Kohorte)
	return erg, nil
}

func (f *Fenster) pruefungGezielt(a Auswahl) (Ergebnis, error) {
	if a.Person == "" && a.Vorgang == "" {
		return Ergebnis{}, werkzeug.ErrSuche
	}
	von, bis, err := f.spanne(a)
	if err != nil {
		return Ergebnis{}, err
	}
	stand, err := f.katalogstand()
	if err != nil {
		return Ergebnis{}, err
	}
	verzeichnis, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnis, "")
	if err != nil {
		return Ergebnis{}, err
	}
	vstrom, err := f.strom(f.verb.Mandant, verzeichnis.Ablage, protocol.RolleVerzeichnis, f.intervall)
	if err != nil {
		return Ergebnis{}, err
	}
	var summe werkzeug.Strom
	if kennung, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnisSumme, ""); err == nil {
		summe, err = f.strom(f.verb.Mandant, kennung.Ablage, protocol.RolleVerzeichnisSumme, 0)
		if err != nil {
			return Ergebnis{}, err
		}
	}
	ziele, err := f.ziele(stand)
	if err != nil {
		return Ergebnis{}, err
	}
	treffer, err := werkzeug.Suche(werkzeug.Suchanfrage{
		Mandant: f.verb.Mandant, Frist: f.frist, Jetzt: f.jetzt(), Von: von, Bis: bis,
		Person: a.Person, Vorgang: a.Vorgang, Verzeichnis: vstrom, Summen: summe, Ziele: ziele,
	})
	if err != nil {
		return Ergebnis{}, err
	}
	return trefferErgebnis(treffer, stand), nil
}

func (f *Fenster) ziele(stand protocol.Stand) ([]werkzeug.Strom, error) {
	gesehen := map[protocol.ID]struct{}{}
	var out []werkzeug.Strom
	for _, k := range stand.Kennungen {
		switch k.Rolle {
		case protocol.RolleGruppe, protocol.RolleEinzel, protocol.RolleAuffang:
		default:
			continue
		}
		if _, ok := gesehen[k.Ablage]; ok {
			continue
		}
		gesehen[k.Ablage] = struct{}{}
		strom, err := f.strom(f.verb.Mandant, k.Ablage, k.Rolle, f.intervall)
		if err != nil {
			return nil, err
		}
		out = append(out, strom)
	}
	return out, nil
}

type bund struct {
	mandant protocol.ID
	ablage  protocol.ID
	strom   werkzeug.Strom
}

func (f *Fenster) pruefungPlattform(a Auswahl) (Ergebnis, error) {
	if !f.plattform {
		return Ergebnis{}, ErrArt
	}
	von, bis, err := f.spanne(a)
	if err != nil {
		return Ergebnis{}, err
	}
	buendel, err := f.plattformBuendel()
	if err != nil {
		return Ergebnis{}, err
	}
	var erg Ergebnis
	erg.Art = ArtPlattform
	for _, b := range buendel {
		if len(b.strom.Epochen) == 0 {
			continue
		}
		staende, err := werkzeug.Zeitraum(werkzeug.Anfrage{
			Mandant: b.mandant, Ablage: b.ablage, Rolle: protocol.RolleAuffang,
			Intervall: f.intervall, Frist: f.frist, Jetzt: f.jetzt(),
			Von: von, Bis: bis, Epochen: b.strom.Epochen,
		})
		if err != nil {
			return Ergebnis{}, err
		}
		teil := befunde(ArtPlattform, staende, b.strom, "")
		erg.Epochen += teil.Epochen
		erg.Befunde = append(erg.Befunde, teil.Befunde...)
	}
	return erg, nil
}

func (f *Fenster) plattformBuendel() ([]bund, error) {
	stand, err := f.katalogstand()
	if err != nil {
		return nil, err
	}
	auffang, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleAuffang, "")
	if err != nil {
		return nil, err
	}
	strom, err := f.stromPassend(f.verb.Mandant, auffang.Ablage, protocol.RolleAuffang)
	if err != nil {
		return nil, err
	}
	out := []bund{{mandant: f.verb.Mandant, ablage: auffang.Ablage, strom: strom}}
	mandanten, err := f.ziel.Mandanten()
	if err != nil {
		return nil, err
	}
	for _, mandant := range mandanten {
		if mandant == f.verb.Mandant {
			continue
		}
		ablagen, err := f.ablagen(mandant)
		if err != nil {
			return nil, err
		}
		for _, ablage := range ablagen {
			strom, err := f.stromPassend(mandant, ablage, protocol.RolleAuffang)
			if err != nil {
				return nil, err
			}
			if len(strom.Epochen) == 0 {
				continue
			}
			out = append(out, bund{mandant: mandant, ablage: ablage, strom: strom})
		}
	}
	return out, nil
}

func (f *Fenster) ablagen(mandant protocol.ID) ([]protocol.ID, error) {
	keys, err := f.ziel.Liste(mandant.Hex() + "/")
	if err != nil {
		return nil, err
	}
	gesehen := map[protocol.ID]struct{}{}
	var out []protocol.ID
	for _, key := range keys {
		got, ablage, _, _, err := protocol.ParseObjektSchluessel(key)
		if err != nil || got != mandant {
			return nil, ErrZiel
		}
		if _, ok := gesehen[ablage]; ok {
			continue
		}
		gesehen[ablage] = struct{}{}
		out = append(out, ablage)
	}
	return out, nil
}

func (f *Fenster) zaehlenPlattform(stand protocol.Stand, von, bis time.Time) (int, error) {
	auffang, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleAuffang, "")
	if err != nil {
		return 0, err
	}
	n, err := f.zaehlenKopf(f.verb.Mandant, auffang.Ablage, von, bis)
	if err != nil {
		return 0, err
	}
	mandanten, err := f.ziel.Mandanten()
	if err != nil {
		return 0, err
	}
	for _, mandant := range mandanten {
		if mandant == f.verb.Mandant {
			continue
		}
		ablagen, err := f.ablagen(mandant)
		if err != nil {
			return 0, err
		}
		for _, ablage := range ablagen {
			m, err := f.zaehlenKopf(mandant, ablage, von, bis)
			if err != nil {
				return 0, err
			}
			n += m
		}
	}
	return n, nil
}

func (f *Fenster) zaehlenKopf(mandant, ablage protocol.ID, von, bis time.Time) (int, error) {
	ids, nach, err := f.gruppieren(mandant, ablage)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		refs := nach[id]
		if len(refs) == 0 || refs[0].nr != 1 {
			continue
		}
		passt, err := f.kopfPasst(refs[0].key)
		if err != nil || !passt {
			if err != nil {
				return 0, err
			}
			continue
		}
		raster, err := rasterVon(id)
		if err != nil {
			return 0, err
		}
		if !trifft(raster, f.intervall, von, bis) {
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

func (f *Fenster) zaehlenVerzeichnis(stand protocol.Stand, von, bis time.Time) (int, error) {
	verzeichnis, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnis, "")
	if err != nil {
		return 0, err
	}
	gedeckt := map[time.Time]struct{}{}
	if kennung, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnisSumme, ""); err == nil {
		ids, _, err := f.gruppieren(f.verb.Mandant, kennung.Ablage)
		if err != nil {
			return 0, err
		}
		for _, id := range ids {
			raster, err := rasterVon(id)
			if err != nil {
				return 0, err
			}
			if !monatsbeginn(raster) || !monatZu(raster, f.jetzt()) || !monatTrifft(raster, von, bis) {
				continue
			}
			tag, ok, err := f.abschluss.Vermerk(f.verb.Mandant, kennung.Ablage, id)
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
				gedeckt[raster] = struct{}{}
			}
		}
	}
	ids, _, err := f.gruppieren(f.verb.Mandant, verzeichnis.Ablage)
	if err != nil {
		return 0, err
	}
	n := len(gedeckt)
	for _, id := range ids {
		raster, err := rasterVon(id)
		if err != nil {
			return 0, err
		}
		if _, ok := gedeckt[monatVon(raster)]; ok || !trifft(raster, f.intervall, von, bis) {
			continue
		}
		tag, ok, err := f.abschluss.Vermerk(f.verb.Mandant, verzeichnis.Ablage, id)
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

func (f *Fenster) spanne(a Auswahl) (time.Time, time.Time, error) {
	switch a.Art {
	case ArtGruppe, ArtGezielt, ArtAuffang, ArtPlattform:
	default:
		return time.Time{}, time.Time{}, ErrArt
	}
	if a.Art == ArtPlattform && !f.plattform {
		return time.Time{}, time.Time{}, ErrArt
	}
	if a.Von.IsZero() && a.Bis.IsZero() {
		if a.Art != ArtGezielt {
			return time.Time{}, time.Time{}, werkzeug.ErrZeitraum
		}
		return time.Unix(0, 0).UTC(), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), nil
	}
	von, bis := a.Von.UTC(), a.Bis.UTC()
	if !bis.After(von) {
		return time.Time{}, time.Time{}, werkzeug.ErrZeitraum
	}
	return von, bis, nil
}

func befunde(art Art, staende []werkzeug.Stand, strom werkzeug.Strom, name string) Ergebnis {
	erg := Ergebnis{Art: art}
	for i, stand := range staende {
		if !stand.ImZeitraum {
			continue
		}
		b := Befund{
			Epoch:           strom.Epochen[i].Auftrag.Epoch,
			Ablage:          strom.Ablage,
			Name:            name,
			Rolle:           strom.Rolle,
			Luecke:          stand.Bericht.Luecke,
			Verzweigung:     stand.Bericht.Verzweigung,
			VorgaengerBruch: stand.Bericht.VorgaengerBruch,
			Geloescht:       stand.Geloescht,
			Kompromittiert:  stand.Bericht.Kompromittiert,
			Verloren:        stand.Bericht.Verloren,
			Vertraulich:     stand.Bericht.Vertraulich,
		}
		if !stand.Geloescht && !stand.Bericht.Verloren && !stand.Bericht.Luecke && !stand.Bericht.Verzweigung && !stand.Bericht.VorgaengerBruch {
			for _, eintrag := range stand.Bericht.Eintraege {
				b.Eintraege = append(b.Eintraege, zeileAus(eintrag))
			}
		}
		if !stand.Geloescht {
			erg.Epochen++
		}
		erg.Befunde = append(erg.Befunde, b)
	}
	return erg
}

func trefferErgebnis(treffer []werkzeug.Treffer, stand protocol.Stand) Ergebnis {
	erg := Ergebnis{Art: ArtGezielt}
	index := map[protocol.EpochID]int{}
	for _, treffer := range treffer {
		i, ok := index[treffer.Epoch]
		if !ok {
			i = len(erg.Befunde)
			index[treffer.Epoch] = i
			erg.Befunde = append(erg.Befunde, Befund{
				Epoch: treffer.Epoch, Ablage: treffer.Ablage, Name: nameVon(stand, treffer.Ablage),
				Rolle: treffer.Rolle, Luecke: treffer.Luecke, Geloescht: treffer.Geloescht,
				Verloren: treffer.Verloren, Vertraulich: treffer.Vertraulich,
			})
			if !treffer.Geloescht {
				erg.Epochen++
			}
		}
		if treffer.Geloescht || treffer.Verloren || treffer.Luecke {
			continue
		}
		erg.Befunde[i].Eintraege = append(erg.Befunde[i].Eintraege, zeileAus(treffer.Eintrag))
		erg.Befunde[i].Vertraulich = treffer.Vertraulich
		if !treffer.Vertraulich {
			erg.Befunde[i].Kompromittiert = true
		}
	}
	return erg
}

func zeileAus(e werkzeug.Eintrag) Zeile {
	z := Zeile{
		Seq: e.Seq, Zeit: e.Zeit,
		Text:         append([]byte(nil), e.Text...),
		Vorgang:      []byte(e.Vorgang),
		Grund:        e.Grund,
		Angabe:       []byte(e.Angabe),
		Unzugeordnet: e.Unzugeordnet,
		NachRaster:   e.NachRaster,
		Gueltig:      e.Gueltig,
	}
	for _, person := range e.Personen {
		z.Personen = append(z.Personen, []byte(person))
	}
	return z
}
