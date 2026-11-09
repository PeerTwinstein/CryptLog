package werkzeug

import (
	"errors"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

var (
	// ErrFrist heißt, die Aufbewahrungsfrist ist kein Vielfaches von 24 Stunden.
	ErrFrist = errors.New("werkzeug: Frist ungültig")
	// ErrIntervall heißt, das Epochenintervall liegt außerhalb der Grenzen.
	ErrIntervall = errors.New("werkzeug: Intervall ungültig")
	// ErrZeitraum heißt, Beginn und Ende des Zeitraums passen nicht.
	ErrZeitraum = errors.New("werkzeug: Zeitraum ungültig")
)

// Anfrage prüft die Manifestketten eines Gruppen-, Einzel-, Auffang-,
// Verzeichnis-, Vorgangs- oder Katalogstroms.
// Am Einzelpräfix ist die Ablage der Präfix. Die Epochen aller Personen
// dieser Instanz hängen an derselben Kette, in der Abschlussreihenfolge.
// Die Epochen einer Instanz stehen in dieser Reihenfolge. Instanzen dürfen
// sich abwechseln. Ein Eintrag in Vorgaenger ersetzt die Genesis dieser
// Instanz. Der Zeitraum ist halb offen, [Von, Bis). Eine Epoche trifft ihn,
// wenn ihr Fenster [Rasterbeginn, Rasterbeginn+Intervall) ihn schneidet.
type Anfrage struct {
	Mandant    protocol.ID
	Ablage     protocol.ID
	Rolle      protocol.StromRolle
	Intervall  time.Duration
	Frist      time.Duration
	Jetzt      time.Time
	Von        time.Time
	Bis        time.Time
	Vorgaenger map[protocol.ID]protocol.Hash
	Epochen    []Lage
}

// Lage ist eine Epoche der Anfrage. Ein gesetzter Vermerk ist der Löschvermerk.
// Die Epoche wird dann nicht geöffnet.
type Lage struct {
	Auftrag Auftrag
	Vermerk *time.Time
}

// Stand ist eine Epoche nach der Prüfung.
// ImZeitraum heißt, dass ihr Rasterfenster den Zeitraum schneidet.
// Geloescht heißt, dass der Zugriffsschnitt erreicht ist oder ein Löschvermerk vorliegt.
// Einträge trägt nur eine Epoche im Zeitraum, die nicht gelöscht ist und deren
// Bestätigung auf dem bestätigten Hash der vorherigen Epoche dieser Instanz aufsetzt.
type Stand struct {
	ImZeitraum bool
	Geloescht  bool
	Bericht    Bericht
}

type kettenglied struct {
	vorher     protocol.Hash
	tragfaehig bool
}

// Schnitt ist der Zugriffsschnitt: Beginn des UTC-Tages vor dem Löschtag.
// Der Löschtag ist der UTC-Tag, in den der Rasterbeginn plus die Frist fällt.
// Die Frist ist eine positive Anzahl ganzer UTC-Tage.
func Schnitt(raster time.Time, frist time.Duration) (time.Time, error) {
	if raster.Location() != time.UTC || raster.Nanosecond() != 0 {
		return time.Time{}, protocol.ErrRaster
	}
	if !fristGueltig(frist) {
		return time.Time{}, ErrFrist
	}
	summe := raster.Add(frist)
	tag := time.Date(summe.Year(), summe.Month(), summe.Day(), 0, 0, 0, 0, time.UTC)
	return tag.AddDate(0, 0, -1), nil
}

// Zeitraum prüft die übergebenen Epochen und öffnet die Auswahl des Zeitraums.
// Eine Epoche ab dem Zugriffsschnitt oder mit Löschvermerk bleibt zu.
// Fehlen ihre Segmente vorher und ohne Vermerk, ist das eine Lücke.
// Fehlen sie ab dem Schnitt, ist das eine Löschung. Die Bestätigung bleibt das
// Glied der Manifestkette. Ein Fehler der Kette oder einer Signatur bricht ab.
func Zeitraum(a Anfrage) ([]Stand, error) {
	return zeitraum(a, nil)
}

// auslassen nennt Epochen, deren bestätigter Hash die Kette fortsetzt und
// deren Einträge nicht geöffnet werden. Die Summenepoche hat sie ersetzt.
func zeitraum(a Anfrage, auslassen map[protocol.EpochID]struct{}) ([]Stand, error) {
	if err := anfrageGueltig(a); err != nil {
		return nil, err
	}
	gesehen := make(map[protocol.EpochID]struct{}, len(a.Epochen))
	raster := make([]time.Time, len(a.Epochen))
	ende := make([]uint64, len(a.Epochen))
	for i, lage := range a.Epochen {
		zeit, millis, err := lageGueltig(a, lage, gesehen)
		if err != nil {
			return nil, err
		}
		raster[i] = zeit
		ende[i] = millis
	}
	ketten := make(map[protocol.ID]*kettenglied)
	stand := make([]Stand, len(a.Epochen))
	for i, lage := range a.Epochen {
		instanz := lage.Auftrag.Epoch.Instanz()
		glied := ketten[instanz]
		if glied == nil {
			glied = &kettenglied{vorher: anfang(a, instanz), tragfaehig: true}
			ketten[instanz] = glied
		}
		geloest, err := epocheGeloescht(raster[i], a, lage)
		if err != nil {
			return nil, err
		}
		imZeitraum := trifft(raster[i], a.Intervall, a.Von, a.Bis)
		if _, weg := auslassen[lage.Auftrag.Epoch]; weg {
			ok, err := bestaetigungGueltig(lage.Auftrag)
			if err != nil {
				return nil, err
			}
			if ok {
				glied.vorher = lage.Auftrag.AbschlussHash
				glied.tragfaehig = true
			} else {
				glied.tragfaehig = false
			}
			stand[i] = Stand{}
			continue
		}
		auftrag := lage.Auftrag
		auftrag.Mandant = a.Mandant
		auftrag.Ablage = a.Ablage
		auftrag.Rolle = a.Rolle
		if auftrag.Annahmen != nil {
			_, segs, err := segmenteAusAnnahme(auftrag)
			if errors.Is(err, errObjektFehlt) {
				segs = nil
			} else if err != nil {
				return nil, err
			}
			auftrag.Segmente = segs
		}
		voll := vollstaendig(auftrag.Segmente)
		var bericht Bericht
		if voll {
			auftrag.Auswahl = nil
			auftrag.Alles = !geloest && imZeitraum && glied.tragfaehig
			auftrag.Vorgaenger = glied.vorher
			auftrag.RasterEnde = ende[i]
			bericht, err = Pruefen(auftrag)
			if err != nil {
				return nil, err
			}
			if !glied.tragfaehig {
				bericht.VorgaengerBruch = false
				bericht.Luecke = true
			}
		} else {
			ok, err := bestaetigungGueltig(lage.Auftrag)
			if err != nil {
				return nil, err
			}
			// Fehlende Segmente sind vor dem Schnitt eine Lücke und ab dem Schnitt
			// eine Löschung. Eine fehlende Bestätigung bleibt in beiden Fällen eine Lücke.
			bericht.Luecke = !geloest || !ok || !glied.tragfaehig
		}
		if lage.Auftrag.Bestaetigung != nil {
			glied.vorher = lage.Auftrag.AbschlussHash
			glied.tragfaehig = true
		} else {
			glied.tragfaehig = false
		}
		stand[i] = Stand{ImZeitraum: imZeitraum, Geloescht: geloest, Bericht: bericht}
	}
	return stand, nil
}

func anfrageGueltig(a Anfrage) error {
	switch a.Rolle {
	case protocol.RolleGruppe, protocol.RolleEinzel, protocol.RolleAuffang, protocol.RolleVerzeichnis,
		protocol.RolleVorgang, protocol.RolleKatalog:
	default:
		return ErrRolle
	}
	var leer protocol.ID
	if a.Mandant == leer || a.Ablage == leer {
		return ErrZeitraum
	}
	if !intervallGueltig(a.Intervall) {
		return ErrIntervall
	}
	if !fristGueltig(a.Frist) {
		return ErrFrist
	}
	if !utc(a.Jetzt) || a.Jetzt.IsZero() || !utc(a.Von) || !utc(a.Bis) || !a.Bis.After(a.Von) {
		return ErrZeitraum
	}
	return nil
}

func lageGueltig(a Anfrage, lage Lage, gesehen map[protocol.EpochID]struct{}) (time.Time, uint64, error) {
	var leer protocol.ID
	if (lage.Auftrag.Mandant != leer && lage.Auftrag.Mandant != a.Mandant) ||
		(lage.Auftrag.Ablage != leer && lage.Auftrag.Ablage != a.Ablage) {
		return time.Time{}, 0, ErrZeitraum
	}
	if lage.Auftrag.Rolle != 0 && lage.Auftrag.Rolle != a.Rolle {
		return time.Time{}, 0, ErrRolle
	}
	if lage.Vermerk != nil && !loeschtag(*lage.Vermerk) {
		return time.Time{}, 0, ErrZeitraum
	}
	zeit, err := epochRaster(lage.Auftrag.Epoch)
	if err != nil {
		return time.Time{}, 0, err
	}
	if !ausgerichtet(zeit, a.Intervall) {
		return time.Time{}, 0, protocol.ErrRaster
	}
	if _, ok := gesehen[lage.Auftrag.Epoch]; ok {
		return time.Time{}, 0, ErrZeitraum
	}
	gesehen[lage.Auftrag.Epoch] = struct{}{}
	millis, err := rasterEnde(zeit, a.Intervall)
	if err != nil {
		return time.Time{}, 0, err
	}
	return zeit, millis, nil
}

func epocheGeloescht(raster time.Time, a Anfrage, lage Lage) (bool, error) {
	if lage.Vermerk != nil {
		return true, nil
	}
	schnitt, err := Schnitt(raster, a.Frist)
	if err != nil {
		return false, err
	}
	return !a.Jetzt.Before(schnitt), nil
}

func loeschtag(t time.Time) bool {
	return t.Location() == time.UTC && t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func epochRaster(id protocol.EpochID) (time.Time, error) {
	zeit, err := time.Parse("20060102T150405Z", id.Raster())
	if err != nil {
		return time.Time{}, protocol.ErrRaster
	}
	return zeit, nil
}

func anfang(a Anfrage, instanz protocol.ID) protocol.Hash {
	if h, ok := a.Vorgaenger[instanz]; ok {
		return h
	}
	return protocol.Genesis(a.Ablage, instanz)
}

func bestaetigungGueltig(a Auftrag) (bool, error) {
	if a.Bestaetigung == nil {
		return false, nil
	}
	if !crypt.VerifyP256(a.Bestaetigung, protocol.ConfirmationPayload(a.AbschlussHash), a.BestaetigungsSignatur) {
		return false, ErrBestaetigung
	}
	return true, nil
}

func vollstaendig(segs []Segment) bool {
	if len(segs) == 0 {
		return false
	}
	for i, seg := range segs {
		_, _, _, nr, err := protocol.ParseObjektSchluessel(seg.Schluessel)
		if err != nil || nr != uint64(i+1) {
			return false
		}
	}
	return true
}

func trifft(raster time.Time, intervall time.Duration, von, bis time.Time) bool {
	return raster.Before(bis) && von.Before(raster.Add(intervall))
}

func ausgerichtet(raster time.Time, intervall time.Duration) bool {
	tag := time.Date(raster.Year(), raster.Month(), raster.Day(), 0, 0, 0, 0, time.UTC)
	return raster.Sub(tag)%intervall == 0
}

func rasterEnde(raster time.Time, intervall time.Duration) (uint64, error) {
	ms := raster.UnixMilli()
	if ms < 0 {
		return 0, protocol.ErrRaster
	}
	iv := intervall.Milliseconds()
	if iv <= 0 {
		return 0, ErrIntervall
	}
	return uint64(ms) + uint64(iv) - 1, nil
}

func intervallGueltig(d time.Duration) bool {
	if d < 15*time.Minute || d > 8*time.Hour {
		return false
	}
	return (24*time.Hour)%d == 0
}

func fristGueltig(d time.Duration) bool {
	return d > 0 && d%(24*time.Hour) == 0
}

func utc(t time.Time) bool { return t.Location() == time.UTC }
