package werkzeug

import (
	"errors"
	"sort"
	"time"

	"cryptlog/protocol"
)

// ErrSumme passt der Monat oder eine Quelle nicht zur Summenepoche.
var ErrSumme = errors.New("werkzeug: Summe passt nicht")

// Quelle ist eine geöffnete Epoche eines Monats.
// Hash ist der bestätigte epoch_hash.
type Quelle struct {
	Epoch     protocol.EpochID
	Hash      protocol.Hash
	Eintraege []Eintrag
}

// Summenteil ist ein Inhalt der Summenepoche, noch ohne Ereignishülle.
type Summenteil struct {
	Zeit   uint64
	Inhalt []byte
}

type verweisZeit struct {
	verweis protocol.Verweis
	zeit    uint64
}

// VerzeichnisSumme fasst die Verweise eines abgeschlossenen Monats.
// Die Quellen stehen in Abschlussreihenfolge. Zuerst kommen die Belege,
// dann die Personenverweise, dann die Verweise auf Vorgangsnummern.
func VerzeichnisSumme(monat time.Time, quellen []Quelle) ([]Summenteil, error) {
	if !monatsbeginn(monat) || len(quellen) == 0 {
		return nil, ErrSumme
	}
	start := uint64(monat.UnixMilli())
	teile := make([]Summenteil, 0, len(quellen))
	var personen, vorgaenge []verweisZeit
	for _, q := range quellen {
		raster, err := epochRaster(q.Epoch)
		if err != nil || !imMonat(raster, monat) {
			return nil, ErrSumme
		}
		body, err := protocol.BelegBytes(protocol.Beleg{Epoch: q.Epoch, Hash: q.Hash})
		if err != nil {
			return nil, err
		}
		teile = append(teile, Summenteil{Zeit: start, Inhalt: body})
		for _, eintrag := range q.Eintraege {
			if !eintrag.Gueltig || eintrag.Verweis == nil {
				return nil, ErrSumme
			}
			z := verweisZeit{verweis: *eintrag.Verweis, zeit: eintrag.Zeit}
			if z.zeit == 0 {
				z.zeit = start
			}
			switch eintrag.Verweis.Art {
			case protocol.VerweisPerson:
				personen = append(personen, z)
			case protocol.VerweisVorgang:
				vorgaenge = append(vorgaenge, z)
			default:
				return nil, ErrSumme
			}
		}
	}
	sort.Slice(personen, func(i, j int) bool { return verweisVor(personen[i].verweis, personen[j].verweis) })
	sort.Slice(vorgaenge, func(i, j int) bool { return verweisVor(vorgaenge[i].verweis, vorgaenge[j].verweis) })
	for _, gruppe := range [][]verweisZeit{personen, vorgaenge} {
		for _, z := range gruppe {
			body, err := protocol.VerweisBytes(z.verweis)
			if err != nil {
				return nil, err
			}
			teile = append(teile, Summenteil{Zeit: z.zeit, Inhalt: body})
		}
	}
	return teile, nil
}

// VorgangSumme fasst die Indexeinträge eines abgeschlossenen Monats.
// Je Vorgangsnummer entstehen die Personen, je Person die Vorgangsnummern.
// Dieselbe Person in demselben Strom steht je Nummer nur einmal, mit dem
// ersten und dem letzten Zeitstempel.
func VorgangSumme(monat time.Time, quellen []Quelle) ([]Summenteil, error) {
	if !monatsbeginn(monat) || len(quellen) == 0 {
		return nil, ErrSumme
	}
	start := uint64(monat.UnixMilli())
	teile := make([]Summenteil, 0, len(quellen))
	spannen := make(map[bezugSchluss]*spanne)
	for _, q := range quellen {
		raster, err := epochRaster(q.Epoch)
		if err != nil || !imMonat(raster, monat) {
			return nil, ErrSumme
		}
		body, err := protocol.BelegBytes(protocol.Beleg{Epoch: q.Epoch, Hash: q.Hash})
		if err != nil {
			return nil, err
		}
		teile = append(teile, Summenteil{Zeit: start, Inhalt: body})
		for _, eintrag := range q.Eintraege {
			if !eintrag.Gueltig || eintrag.Index == nil {
				return nil, ErrSumme
			}
			idx := eintrag.Index
			schluss := bezugSchluss{
				nummer: idx.Nummer, person: idx.Person,
				rolle: idx.Rolle, kohorte: idx.Kohorte,
			}
			s := spannen[schluss]
			if s == nil {
				spannen[schluss] = &spanne{erster: idx.Zeitpunkt, letzter: idx.Zeitpunkt}
				continue
			}
			if idx.Zeitpunkt < s.erster {
				s.erster = idx.Zeitpunkt
			}
			if idx.Zeitpunkt > s.letzter {
				s.letzter = idx.Zeitpunkt
			}
		}
	}
	nachNummer := make(map[string][]protocol.Bezug)
	nachPerson := make(map[string][]protocol.Bezug)
	for schluss, s := range spannen {
		nachNummer[schluss.nummer] = append(nachNummer[schluss.nummer], protocol.Bezug{
			Name: schluss.person, Rolle: schluss.rolle, Kohorte: schluss.kohorte,
			Erster: s.erster, Letzter: s.letzter,
		})
		nachPerson[schluss.person] = append(nachPerson[schluss.person], protocol.Bezug{
			Name: schluss.nummer, Rolle: schluss.rolle, Kohorte: schluss.kohorte,
			Erster: s.erster, Letzter: s.letzter,
		})
	}
	nummern := schluessel(nachNummer)
	for _, nummer := range nummern {
		personen := nachNummer[nummer]
		sort.Slice(personen, func(i, j int) bool { return protocolBezugVor(personen[i], personen[j]) })
		body, err := protocol.VorgangSummeBytes(protocol.VorgangSumme{Nummer: nummer, Personen: personen})
		if err != nil {
			return nil, err
		}
		teile = append(teile, Summenteil{Zeit: start, Inhalt: body})
	}
	personen := schluessel(nachPerson)
	for _, person := range personen {
		liste := nachPerson[person]
		sort.Slice(liste, func(i, j int) bool { return protocolBezugVor(liste[i], liste[j]) })
		body, err := protocol.PersonSummeBytes(protocol.PersonSumme{Person: person, Nummern: liste})
		if err != nil {
			return nil, err
		}
		teile = append(teile, Summenteil{Zeit: start, Inhalt: body})
	}
	return teile, nil
}

type bezugSchluss struct {
	nummer  string
	person  string
	rolle   protocol.StromRolle
	kohorte string
}

type spanne struct {
	erster  uint64
	letzter uint64
}

func schluessel[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func protocolBezugVor(a, b protocol.Bezug) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Rolle != b.Rolle {
		return a.Rolle < b.Rolle
	}
	return a.Kohorte < b.Kohorte
}

func verweisVor(a, b protocol.Verweis) bool {
	if a.Schluessel != b.Schluessel {
		return a.Schluessel < b.Schluessel
	}
	for i := 0; i < len(a.Epoch); i++ {
		if a.Epoch[i] != b.Epoch[i] {
			return a.Epoch[i] < b.Epoch[i]
		}
	}
	return a.Seq < b.Seq
}

func monatsbeginn(t time.Time) bool {
	return t.Location() == time.UTC && t.Day() == 1 && t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func imMonat(raster, monat time.Time) bool {
	return !raster.Before(monat) && raster.Before(monat.AddDate(0, 1, 0))
}

func monatSchneidet(monat, von, bis time.Time) bool {
	return monat.Before(bis) && von.Before(monat.AddDate(0, 1, 0))
}

func monatGeschlossen(monat, jetzt time.Time) bool {
	return !jetzt.Before(monat.AddDate(0, 1, 0))
}

func monatsende(monat time.Time) (uint64, error) {
	ms := monat.AddDate(0, 1, 0).UnixMilli()
	if ms <= 0 {
		return 0, protocol.ErrRaster
	}
	return uint64(ms - 1), nil
}

type summenStand struct {
	auslassen map[protocol.EpochID]struct{}
	berichte  []Bericht
}

type summenAnfrage struct {
	Mandant protocol.ID
	Frist   time.Duration
	Jetzt   time.Time
	Von     time.Time
	Bis     time.Time
	Quellen []Lage
	Summen  Strom
}

func verzeichnisZeiger(s Suchanfrage) ([]zeiger, error) {
	var extra []Eintrag
	var aus map[protocol.EpochID]struct{}
	if summeVorhanden(s.Summen) {
		if err := summeStrom(s.Summen, protocol.RolleVerzeichnisSumme); err != nil {
			return nil, err
		}
		stand, err := summenLesen(summenAnfrage{
			Mandant: s.Mandant, Frist: s.Frist, Jetzt: s.Jetzt, Von: s.Von, Bis: s.Bis,
			Quellen: s.Verzeichnis.Epochen, Summen: s.Summen,
		})
		if err != nil {
			return nil, err
		}
		aus = stand.auslassen
		for _, bericht := range stand.berichte {
			extra = append(extra, bericht.Eintraege...)
		}
	}
	staende, err := zeitraum(Anfrage{
		Mandant:   s.Mandant,
		Ablage:    s.Verzeichnis.Ablage,
		Rolle:     protocol.RolleVerzeichnis,
		Intervall: s.Verzeichnis.Intervall,
		Frist:     s.Frist,
		Jetzt:     s.Jetzt,
		Von:       s.Von,
		Bis:       s.Bis,
		Epochen:   s.Verzeichnis.Epochen,
	}, aus)
	if err != nil {
		return nil, err
	}
	return sammeln(s, staende, extra), nil
}

func summeVorhanden(s Strom) bool {
	var leer protocol.ID
	return s.Rolle != 0 || s.Ablage != leer || len(s.Epochen) > 0
}

func summeStrom(s Strom, rolle protocol.StromRolle) error {
	if s.Rolle != rolle {
		return ErrRolle
	}
	var leer protocol.ID
	if s.Ablage == leer {
		return ErrZeitraum
	}
	return nil
}

func summenLesen(a summenAnfrage) (summenStand, error) {
	gesehen := make(map[protocol.EpochID]struct{}, len(a.Summen.Epochen))
	for _, lage := range a.Quellen {
		gesehen[lage.Auftrag.Epoch] = struct{}{}
	}
	ketten := make(map[protocol.ID]*kettenglied)
	var out summenStand
	for _, lage := range a.Summen.Epochen {
		if _, ok := gesehen[lage.Auftrag.Epoch]; ok {
			return summenStand{}, ErrZeitraum
		}
		gesehen[lage.Auftrag.Epoch] = struct{}{}
		raster, err := epochRaster(lage.Auftrag.Epoch)
		if err != nil {
			return summenStand{}, err
		}
		if !monatsbeginn(raster) {
			return summenStand{}, protocol.ErrRaster
		}
		instanz := lage.Auftrag.Epoch.Instanz()
		glied := ketten[instanz]
		if glied == nil {
			glied = &kettenglied{vorher: protocol.Genesis(a.Summen.Ablage, instanz), tragfaehig: true}
			ketten[instanz] = glied
		}
		geloescht, err := epocheGeloescht(raster, Anfrage{Frist: a.Frist, Jetzt: a.Jetzt}, lage)
		if err != nil {
			return summenStand{}, err
		}
		if glied.tragfaehig && !geloescht && monatGeschlossen(raster, a.Jetzt) && monatSchneidet(raster, a.Von, a.Bis) {
			bericht, err := summePruefen(a, lage, glied.vorher, raster)
			if err != nil {
				return summenStand{}, err
			}
			if !bericht.Luecke && !bericht.Verloren && !bericht.Verzweigung && !bericht.VorgaengerBruch {
				ids, ok, err := belegePassen(raster, bericht.Eintraege, a.Quellen)
				if err != nil {
					return summenStand{}, err
				}
				if ok {
					if out.auslassen == nil {
						out.auslassen = make(map[protocol.EpochID]struct{})
					}
					for id := range ids {
						out.auslassen[id] = struct{}{}
					}
					out.berichte = append(out.berichte, bericht)
				}
			}
		}
		ok, err := bestaetigungGueltig(lage.Auftrag)
		if err != nil {
			return summenStand{}, err
		}
		if ok {
			glied.vorher = lage.Auftrag.AbschlussHash
			glied.tragfaehig = true
		} else {
			glied.tragfaehig = false
		}
	}
	return out, nil
}

func summePruefen(a summenAnfrage, lage Lage, vorher protocol.Hash, raster time.Time) (Bericht, error) {
	ende, err := monatsende(raster)
	if err != nil {
		return Bericht{}, err
	}
	auftrag := lage.Auftrag
	auftrag.Mandant = a.Mandant
	auftrag.Ablage = a.Summen.Ablage
	auftrag.Rolle = a.Summen.Rolle
	auftrag.Auswahl = nil
	auftrag.Alles = true
	auftrag.Vorgaenger = vorher
	auftrag.RasterEnde = ende
	return Pruefen(auftrag)
}

func belegePassen(monat time.Time, eintraege []Eintrag, quellen []Lage) (map[protocol.EpochID]struct{}, bool, error) {
	haben := make(map[protocol.EpochID]Lage)
	for _, lage := range quellen {
		raster, err := epochRaster(lage.Auftrag.Epoch)
		if err != nil {
			return nil, false, err
		}
		if imMonat(raster, monat) {
			haben[lage.Auftrag.Epoch] = lage
		}
	}
	genannt := make(map[protocol.EpochID]struct{})
	for _, eintrag := range eintraege {
		if eintrag.Beleg == nil || !eintrag.Gueltig {
			continue
		}
		if _, doppelt := genannt[eintrag.Beleg.Epoch]; doppelt {
			return nil, false, nil
		}
		lage, ok := haben[eintrag.Beleg.Epoch]
		if !ok {
			return nil, false, nil
		}
		ok, err := bestaetigt(lage, eintrag.Beleg.Hash)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		genannt[eintrag.Beleg.Epoch] = struct{}{}
	}
	if len(haben) == 0 || len(genannt) != len(haben) {
		return nil, false, nil
	}
	return genannt, true, nil
}

func bestaetigt(lage Lage, hash protocol.Hash) (bool, error) {
	if lage.Auftrag.Bestaetigung == nil || lage.Auftrag.AbschlussHash != hash {
		return false, nil
	}
	return bestaetigungGueltig(lage.Auftrag)
}
