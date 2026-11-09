package werkzeug

import (
	"time"

	"cryptlog/protocol"
)

// Lager ist das Ziel des Löschlaufs.
// Entfernen nimmt ein Objekt heraus. Ein fehlendes Objekt ist bereits entfernt.
type Lager interface {
	Lesen(schluessel string) ([]byte, bool, error)
	Schreiben(schluessel string, inhalt []byte) error
	Entfernen(schluessel string) error
}

// LoeschEpoche ist eine Epoche des Laufs.
// Vollstaendig heißt, dass die genannten Segmente die Nummern 1 bis n ohne Lücke sind.
// AnnahmeFirst und AnnahmeLast stammen aus dem Manifest. 0 und 0 nennen keine Annahme.
type LoeschEpoche struct {
	Mandant      protocol.ID
	Ablage       protocol.ID
	Epoch        protocol.EpochID
	Vollstaendig bool
	AnnahmeFirst uint64
	AnnahmeLast  uint64
	Segmente     []string
}

// LoeschAbschluss ist eine Annahme und ihre Vorbereitung.
// Beide fallen gemeinsam. Die Belegung bleibt.
type LoeschAbschluss struct {
	Instanz  protocol.ID
	BatchSeq uint64
}

// LoeschErgebnis nennt, was dieser Lauf geschrieben und entfernt hat.
type LoeschErgebnis struct {
	Vermerke []string
	Entfernt []string
}

type loeschStand struct {
	LoeschEpoche
	weg bool
}

// Loeschtag ist der UTC-Tag, in den der Rasterbeginn plus die Frist fällt.
func Loeschtag(raster time.Time, frist time.Duration) (time.Time, error) {
	schnitt, err := Schnitt(raster, frist)
	if err != nil {
		return time.Time{}, err
	}
	return schnitt.AddDate(0, 0, 1), nil
}

// Loeschen ist der Löschlauf. Am Löschtag legt er den Vermerk ab und entfernt
// danach die Segmente, wenn die Epoche noch vollständig und ohne Vermerk vorliegt.
// Liegt der Vermerk schon, entfernt er die restlichen Segmente. Eine unvollständige
// Epoche ohne Vermerk bleibt liegen. Eine Annahme und ihre Vorbereitung fallen,
// sobald jede Epoche gelöscht ist, deren Manifest die batch_seq einschließt.
// Die Belegung bleibt.
func Loeschen(jetzt time.Time, frist time.Duration, epochen []LoeschEpoche, abschluesse []LoeschAbschluss, lager Lager) (LoeschErgebnis, error) {
	if lager == nil || !utc(jetzt) || jetzt.IsZero() || !fristGueltig(frist) {
		return LoeschErgebnis{}, ErrLoeschen
	}
	staende := make([]loeschStand, len(epochen))
	gesehen := make(map[protocol.EpochID]struct{}, len(epochen))
	for i, e := range epochen {
		if _, ok := gesehen[e.Epoch]; ok {
			return LoeschErgebnis{}, ErrLoeschen
		}
		gesehen[e.Epoch] = struct{}{}
		if (e.AnnahmeFirst == 0) != (e.AnnahmeLast == 0) || e.AnnahmeLast < e.AnnahmeFirst {
			return LoeschErgebnis{}, ErrLoeschen
		}
		if _, err := epochRaster(e.Epoch); err != nil {
			return LoeschErgebnis{}, err
		}
		if err := schluesselDerEpoche(e); err != nil {
			return LoeschErgebnis{}, err
		}
		if e.Vollstaendig {
			if err := lueckenlos(e); err != nil {
				return LoeschErgebnis{}, err
			}
		}
		staende[i] = loeschStand{LoeschEpoche: e}
	}
	batches := make(map[protocol.ID]map[uint64]struct{}, len(abschluesse))
	for _, a := range abschluesse {
		var leer protocol.ID
		if a.Instanz == leer || a.BatchSeq == 0 {
			return LoeschErgebnis{}, ErrLoeschen
		}
		if batches[a.Instanz] == nil {
			batches[a.Instanz] = make(map[uint64]struct{})
		}
		if _, ok := batches[a.Instanz][a.BatchSeq]; ok {
			return LoeschErgebnis{}, ErrLoeschen
		}
		batches[a.Instanz][a.BatchSeq] = struct{}{}
		if _, err := protocol.AnnahmeSchluessel(a.Instanz, a.BatchSeq); err != nil {
			return LoeschErgebnis{}, err
		}
	}

	var erg LoeschErgebnis
	for i := range staende {
		e := &staende[i]
		raster, err := epochRaster(e.Epoch)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		tag, err := Loeschtag(raster, frist)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		key := protocol.VermerkSchluessel(e.Mandant, e.Ablage, e.Epoch)
		vorhanden, ok, err := lager.Lesen(key)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		if ok {
			id, _, err := protocol.ParseVermerk(vorhanden)
			if err != nil || id != e.Epoch {
				return LoeschErgebnis{}, ErrLoeschen
			}
			if err := segmenteEntfernen(lager, e.Segmente, &erg); err != nil {
				return LoeschErgebnis{}, err
			}
			e.weg = true
			continue
		}
		if jetzt.Before(tag) || !e.Vollstaendig {
			continue
		}
		body, err := protocol.VermerkBytes(e.Epoch, tag)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		if err := lager.Schreiben(key, body); err != nil {
			return LoeschErgebnis{}, err
		}
		erg.Vermerke = append(erg.Vermerke, key)
		if err := segmenteEntfernen(lager, e.Segmente, &erg); err != nil {
			return LoeschErgebnis{}, err
		}
		e.weg = true
	}
	for _, a := range abschluesse {
		if !abschlussFaellt(a, staende) {
			continue
		}
		ann, err := protocol.AnnahmeSchluessel(a.Instanz, a.BatchSeq)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		vor, err := protocol.VorbereitungSchluessel(a.Instanz, a.BatchSeq)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		if err := fallsVorhanden(lager, ann, &erg); err != nil {
			return LoeschErgebnis{}, err
		}
		if err := fallsVorhanden(lager, vor, &erg); err != nil {
			return LoeschErgebnis{}, err
		}
	}
	return erg, nil
}

func schluesselDerEpoche(e LoeschEpoche) error {
	var leer protocol.ID
	if e.Mandant == leer || e.Ablage == leer {
		return ErrLoeschen
	}
	for _, key := range e.Segmente {
		mandant, ablage, epoch, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil || mandant != e.Mandant || ablage != e.Ablage || epoch != e.Epoch || nr == 0 {
			return ErrLoeschen
		}
	}
	return nil
}

func lueckenlos(e LoeschEpoche) error {
	if len(e.Segmente) == 0 {
		return ErrLoeschen
	}
	gesehen := make(map[uint64]struct{}, len(e.Segmente))
	var max uint64
	for _, key := range e.Segmente {
		_, _, _, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil {
			return ErrLoeschen
		}
		if _, ok := gesehen[nr]; ok {
			return ErrLoeschen
		}
		gesehen[nr] = struct{}{}
		if nr > max {
			max = nr
		}
	}
	if uint64(len(gesehen)) != max {
		return ErrLoeschen
	}
	return nil
}

func segmenteEntfernen(lager Lager, schluessel []string, erg *LoeschErgebnis) error {
	for _, key := range schluessel {
		if err := fallsVorhanden(lager, key, erg); err != nil {
			return err
		}
	}
	return nil
}

func fallsVorhanden(lager Lager, schluessel string, erg *LoeschErgebnis) error {
	_, ok, err := lager.Lesen(schluessel)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := lager.Entfernen(schluessel); err != nil {
		return err
	}
	erg.Entfernt = append(erg.Entfernt, schluessel)
	return nil
}

func abschlussFaellt(a LoeschAbschluss, epochen []loeschStand) bool {
	deckt := false
	for _, e := range epochen {
		if e.Epoch.Instanz() != a.Instanz {
			continue
		}
		if e.AnnahmeFirst == 0 || a.BatchSeq < e.AnnahmeFirst || a.BatchSeq > e.AnnahmeLast {
			continue
		}
		deckt = true
		if !e.weg {
			return false
		}
	}
	return deckt
}
