package fenster

import (
	"crypto"
	"crypto/rand"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// VerzeichnisSumme schreibt die Summenepoche eines abgeschlossenen Monats.
// Den Vorgangsindex fasst das Fenster nicht zusammen.
func (f *Fenster) VerzeichnisSumme(monat time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.entsperrt() {
		return ErrFenster
	}
	if f.sitzung != nil {
		return ErrPruefung
	}
	if f.sign == nil || f.instanz == (protocol.ID{}) {
		return ErrSumme
	}
	monat = monat.UTC()
	if !monatsbeginn(monat) || !monatZu(monat, f.jetzt()) {
		return ErrSumme
	}
	stand, err := f.katalogstand()
	if err != nil {
		return err
	}
	verzeichnis, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnis, "")
	if err != nil {
		return err
	}
	summe, err := werkzeug.Aufloesen([]protocol.Stand{stand}, protocol.RolleVerzeichnisSumme, "")
	if err != nil || summe.Ablage == verzeichnis.Ablage {
		return ErrSumme
	}
	vorher, da, err := f.vorher(summe.Ablage, monat)
	if err != nil || da {
		return ErrSumme
	}
	strom, err := f.strom(f.verb.Mandant, verzeichnis.Ablage, protocol.RolleVerzeichnis, f.intervall)
	if err != nil {
		return err
	}
	bis := monat.AddDate(0, 1, 0)
	staende, err := werkzeug.Zeitraum(werkzeug.Anfrage{
		Mandant: f.verb.Mandant, Ablage: verzeichnis.Ablage, Rolle: protocol.RolleVerzeichnis,
		Intervall: f.intervall, Frist: f.frist, Jetzt: f.jetzt(),
		Von: monat, Bis: bis, Epochen: strom.Epochen,
	})
	if err != nil {
		return err
	}
	var quellen []werkzeug.Quelle
	for i, stand := range staende {
		if !stand.ImZeitraum {
			continue
		}
		if stand.Geloescht || stand.Bericht.Luecke || stand.Bericht.Verloren || stand.Bericht.Verzweigung || stand.Bericht.VorgaengerBruch {
			return ErrSumme
		}
		quellen = append(quellen, werkzeug.Quelle{
			Epoch: strom.Epochen[i].Auftrag.Epoch, Hash: stand.Bericht.EpochHash,
			Eintraege: stand.Bericht.Eintraege,
		})
	}
	teile, err := werkzeug.VerzeichnisSumme(monat, quellen)
	if err != nil {
		return ErrSumme
	}
	defer func() {
		for i := range teile {
			crypt.Wipe(teile[i].Inhalt)
		}
	}()
	bind := summe.Bind
	if bind == (protocol.ID{}) {
		bind = summe.Ablage
	}
	return f.summeSchreiben(summe.Ablage, bind, monat, vorher, teile)
}

func (f *Fenster) vorher(ablage protocol.ID, monat time.Time) (protocol.Hash, bool, error) {
	ids, nach, err := f.gruppieren(f.verb.Mandant, ablage)
	if err != nil {
		return protocol.Hash{}, false, err
	}
	var letzte protocol.EpochID
	var letzteZeit time.Time
	haben := false
	for _, id := range ids {
		if id.Instanz() != f.instanz {
			continue
		}
		zeit, err := rasterVon(id)
		if err != nil {
			return protocol.Hash{}, false, err
		}
		if zeit.Equal(monat) {
			return protocol.Hash{}, true, nil
		}
		if zeit.After(monat) {
			return protocol.Hash{}, false, ErrSumme
		}
		if !haben || zeit.After(letzteZeit) {
			letzte = id
			letzteZeit = zeit
			haben = true
		}
	}
	if !haben {
		return protocol.Genesis(ablage, f.instanz), false, nil
	}
	hash, err := f.manifestHash(nach[letzte])
	if err != nil {
		return protocol.Hash{}, false, err
	}
	return hash, false, nil
}

func (f *Fenster) manifestHash(refs []segRef) (protocol.Hash, error) {
	if len(refs) == 0 {
		return protocol.Hash{}, ErrSumme
	}
	letzter, err := f.lesen(refs[len(refs)-1].key)
	if err != nil {
		return protocol.Hash{}, err
	}
	_, _, manifest, err := protocol.Zerlegen(letzter, f.rahmen, len(refs) == 1, true)
	if err != nil {
		return protocol.Hash{}, err
	}
	nutz, sig, err := protocol.ParseManifestRahmen(manifest)
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.EpochHash(nutz, sig)
}

func (f *Fenster) summeSchreiben(ablage, bind protocol.ID, monat time.Time, vorher protocol.Hash, teile []werkzeug.Summenteil) error {
	pub, err := f.wrapSchluessel()
	if err != nil {
		return err
	}
	dek, prefix, err := crypt.NewDEK()
	if err != nil {
		return err
	}
	defer dek.Wipe()
	id, err := protocol.NewEpochID(monat, f.instanz, prefix)
	if err != nil {
		return err
	}
	wrapped, err := crypt.WrapDEK(nil, pub, dek, bind, protocol.WrapContext(f.verb.Mandant, ablage, id, f.finger))
	if err != nil {
		return err
	}
	var dekID protocol.ID
	if _, err = rand.Read(dekID[:]); err != nil {
		return err
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: f.verb.Mandant, Ablage: ablage, DekID: dekID, Epoch: id,
		KEK: f.finger, Wrapped: wrapped, DEK: dek, Rahmen: f.rahmen,
		Klasse: protocol.Segment256KiB,
	})
	if err != nil {
		return err
	}
	defer ep.Verwerfen()
	for _, teil := range teile {
		var event protocol.ID
		if _, err = rand.Read(event[:]); err != nil {
			return err
		}
		klar, err := protocol.EreignisKlartext(event, teil.Zeit, bind, teil.Inhalt)
		if err != nil {
			return err
		}
		_, _, err = ep.Ereignis(klar)
		crypt.Wipe(klar)
		if err != nil {
			return err
		}
	}
	erg, err := ep.Abschluss(vorher, 0, 0, protocol.Hash{}, f.sign)
	if err != nil {
		return err
	}
	for _, seg := range erg.Segmente {
		if err := f.ziel.Schreiben(seg.Schluessel, seg.Bytes); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fenster) wrapSchluessel() (crypto.PublicKey, error) {
	if f.traeger != nil {
		return f.traeger.Oeffentlich()
	}
	return oeffentlich(f.priv)
}
