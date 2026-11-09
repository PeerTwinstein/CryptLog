package suchen

import (
	"crypto/rand"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Fassen schreibt die Summenepoche eines abgeschlossenen Monats in die Ablage.
// Die Epoche, ihre Einträge und der Klartext-DEK bleiben in der Zone.
func (p *Prozess) Fassen(mandant protocol.ID, monat time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok, _ := p.bereit(); !ok || p.priv == nil || p.sign == nil || p.instanz == (protocol.ID{}) {
		return ErrSumme
	}
	jetzt := p.jetzt().UTC()
	if !monatsbeginn(monat) || jetzt.Before(monat.AddDate(0, 1, 0)) {
		return ErrSumme
	}
	st, ok, err := p.bestand.Index(mandant)
	if err != nil {
		return err
	}
	if !ok || st.Summe == (protocol.ID{}) {
		return ErrSumme
	}
	if err := st.gueltig(); err != nil {
		return err
	}
	vorher, da, err := p.vorher(mandant, st, monat)
	if err != nil || da {
		return err
	}
	index, _, err := p.laden(mandant, st)
	if err != nil {
		return err
	}
	bis := monat.AddDate(0, 1, 0)
	staende, err := werkzeug.Zeitraum(werkzeug.Anfrage{
		Mandant:   mandant,
		Ablage:    st.Vorgang,
		Rolle:     protocol.RolleVorgang,
		Intervall: st.Intervall,
		Frist:     st.Frist,
		Jetzt:     jetzt,
		Von:       monat,
		Bis:       bis,
		Epochen:   index.Epochen,
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
			Epoch:     index.Epochen[i].Auftrag.Epoch,
			Hash:      stand.Bericht.EpochHash,
			Eintraege: stand.Bericht.Eintraege,
		})
	}
	teile, err := werkzeug.VorgangSumme(monat, quellen)
	if err != nil {
		return ErrSumme
	}
	return p.summeSchreiben(mandant, st, monat, vorher, teile)
}

func (p *Prozess) summeSchreiben(mandant protocol.ID, st Stroeme, monat time.Time, vorher protocol.Hash, teile []werkzeug.Summenteil) error {
	dek, prefix, err := crypt.NewDEK()
	if err != nil {
		return err
	}
	defer dek.Wipe()
	id, err := protocol.NewEpochID(monat, p.instanz, prefix)
	if err != nil {
		return err
	}
	pub, err := oeffentlich(p.priv)
	if err != nil {
		return err
	}
	fp, err := crypt.FingerprintSPKI(pub)
	if err != nil {
		return err
	}
	bind := st.Bind
	if bind == (protocol.ID{}) {
		bind = st.Summe
	}
	wrapped, err := crypt.WrapDEK(nil, pub, dek, bind, protocol.WrapContext(mandant, st.Summe, id, fp))
	if err != nil {
		return err
	}
	dekID, err := zufallID()
	if err != nil {
		return err
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant,
		Ablage:  st.Summe,
		DekID:   dekID,
		Epoch:   id,
		KEK:     fp,
		Wrapped: wrapped,
		DEK:     dek,
		Rahmen:  st.Rahmen,
		Klasse:  protocol.Segment256KiB,
	})
	if err != nil {
		return err
	}
	defer ep.Verwerfen()
	for _, teil := range teile {
		event, err := zufallID()
		if err != nil {
			return err
		}
		klar, err := protocol.EreignisKlartext(event, teil.Zeit, bind, teil.Inhalt)
		if err != nil {
			return err
		}
		if _, _, err = ep.Ereignis(klar); err != nil {
			crypt.Wipe(klar)
			return err
		}
		crypt.Wipe(klar)
		crypt.Wipe(teil.Inhalt)
	}
	erg, err := ep.Abschluss(vorher, 0, 0, protocol.Hash{}, p.sign)
	if err != nil {
		return err
	}
	for _, seg := range erg.Segmente {
		if err := p.ziel.Schreiben(seg.Schluessel, seg.Bytes); err != nil {
			return err
		}
	}
	return nil
}

func (p *Prozess) vorher(mandant protocol.ID, st Stroeme, monat time.Time) (protocol.Hash, bool, error) {
	prefix := mandant.Hex() + "/" + st.Summe.Hex() + "/"
	keys, err := p.ziel.Liste(prefix)
	if err != nil {
		return protocol.Hash{}, false, err
	}
	ids, nach, err := gruppieren(keys, mandant, st.Summe)
	if err != nil {
		return protocol.Hash{}, false, err
	}
	var letzte protocol.EpochID
	var letzteZeit time.Time
	haben := false
	for _, id := range ids {
		if id.Instanz() != p.instanz {
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
		return protocol.Genesis(st.Summe, p.instanz), false, nil
	}
	hash, err := manifestHash(p.ziel, st.Rahmen, nach[letzte])
	if err != nil {
		return protocol.Hash{}, false, err
	}
	return hash, false, nil
}

func manifestHash(ziel Ziel, rahmen int, refs []segmentRef) (protocol.Hash, error) {
	if len(refs) == 0 {
		return protocol.Hash{}, ErrSumme
	}
	segs := make([][]byte, len(refs))
	for i, ref := range refs {
		roh, ok, err := ziel.Lesen(ref.key)
		if err != nil {
			return protocol.Hash{}, err
		}
		if !ok {
			return protocol.Hash{}, ErrZiel
		}
		segs[i] = roh
	}
	letzter := segs[len(segs)-1]
	_, _, manifest, err := protocol.Zerlegen(letzter, rahmen, len(segs) == 1, true)
	if err != nil {
		return protocol.Hash{}, err
	}
	nutz, sig, err := protocol.ParseManifestRahmen(manifest)
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.EpochHash(nutz, sig)
}

func rasterVon(id protocol.EpochID) (time.Time, error) {
	zeit, err := time.Parse("20060102T150405Z", id.Raster())
	if err != nil {
		return time.Time{}, protocol.ErrRaster
	}
	return zeit, nil
}

func monatsbeginn(t time.Time) bool {
	return t.Location() == time.UTC && t.Day() == 1 && t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func zufallID() (protocol.ID, error) {
	var id protocol.ID
	if _, err := rand.Read(id[:]); err != nil {
		return protocol.ID{}, err
	}
	if id == (protocol.ID{}) {
		return protocol.ID{}, ErrSumme
	}
	return id, nil
}
