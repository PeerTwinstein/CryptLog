package werkzeug_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestIndexMonat(t *testing.T) {
	w := basis(t)
	epoch := w.epoch
	roh := []protocol.IndexEintrag{
		{Nummer: "V-1", Person: "Ada", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Epoch: epoch, Seq: 1, Zeitpunkt: 1500},
		{Nummer: "V-1", Person: "Bea", Rolle: protocol.RolleEinzel, Epoch: epoch, Seq: 2, Zeitpunkt: 1800},
		{Nummer: "V-2", Person: "Ada", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Epoch: epoch, Seq: 3, Zeitpunkt: 1600},
	}
	index := w.indexSchreiben(t, roh)
	monat := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	dezember := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	offen := oeffneAlles(t, index, protocol.RolleVorgang)
	teile, err := werkzeug.VorgangSumme(monat, []werkzeug.Quelle{{
		Epoch: index.epoch, Hash: index.epochHash, Eintraege: offen.Eintraege,
	}})
	if err != nil {
		t.Fatal(err)
	}
	summe := index.andereAblage(t, fill(0x46), monat).summeSchreiben(t, teile)

	z := zoneAuf(t, index, protocol.AnfrageVorgang, "V-1", dezember)
	z.Index = zielStrom(index, protocol.RolleVorgang)
	z.Summen = summenStrom(summe, protocol.RolleVorgangSumme)
	z.Index.Epochen[0].Auftrag.Segmente = nil
	got, err := werkzeug.Index(z)
	if err != nil || len(got.Personen) != 2 || len(got.Vorgaenge) != 0 {
		t.Fatalf("personen %+v %v", got, err)
	}
	if got.Personen[0].Person != "Ada" || got.Personen[0].Kohorte != "Nord" || got.Personen[0].Erster != 1500 || got.Personen[0].Letzter != 1500 {
		t.Fatalf("ada %+v", got.Personen[0])
	}
	if got.Personen[1].Person != "Bea" || got.Personen[1].Rolle != protocol.RolleEinzel || got.Personen[1].Erster != 1800 {
		t.Fatalf("bea %+v", got.Personen[1])
	}
	if got.Protokoll.Person != "Dora" || got.Protokoll.Schluessel != "V-1" || got.Protokoll.Finger != z.Aussage.Finger {
		t.Fatalf("protokoll %+v", got.Protokoll)
	}

	z = zoneAuf(t, index, protocol.AnfragePerson, "Ada", dezember)
	z.Gesehen = neueMenge()
	z.Index = zielStrom(index, protocol.RolleVorgang)
	z.Index.Epochen[0].Auftrag.Segmente = nil
	z.Summen = summenStrom(summe, protocol.RolleVorgangSumme)
	got, err = werkzeug.Index(z)
	if err != nil || len(got.Vorgaenge) != 2 || got.Vorgaenge[0].Nummer != "V-1" || got.Vorgaenge[1].Nummer != "V-2" {
		t.Fatalf("vorgänge %+v %v", got.Vorgaenge, err)
	}
}

func TestIndexEpochen(t *testing.T) {
	w := basis(t).indexSchreiben(t, []protocol.IndexEintrag{
		{Nummer: "V-1", Person: "Ada", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Seq: 1, Zeitpunkt: 1500},
	})
	z := zoneAuf(t, w, protocol.AnfrageVorgang, "V-1", stunde8)
	z.Index = zielStrom(w, protocol.RolleVorgang)
	got, err := werkzeug.Index(z)
	if err != nil || len(got.Personen) != 1 || got.Personen[0].Person != "Ada" || got.Personen[0].Kohorte != "Nord" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := werkzeug.Index(z); !errors.Is(err, werkzeug.ErrEinmal) {
		t.Fatalf("erneut %v", err)
	}
}

func TestIndexAutorisierung(t *testing.T) {
	w := basis(t)
	z := zoneAuf(t, w, protocol.AnfrageVorgang, "V-1", stunde8)
	z.Aussage.Rolle = protocol.RollePerson
	z.Aussage.Finger = protocol.Hash{}
	if _, err := werkzeug.Index(z); !errors.Is(err, werkzeug.ErrAnfrage) {
		t.Fatalf("rolle %v", err)
	}
	z = zoneAuf(t, w, protocol.AnfrageVorgang, "V-1", stunde8)
	z.AnfrageSig[0] ^= 0xff
	if _, err := werkzeug.Index(z); !errors.Is(err, werkzeug.ErrAnfrage) {
		t.Fatalf("signatur %v", err)
	}
	z = zoneAuf(t, w, protocol.AnfrageVorgang, "V-1", stunde8)
	z.Jetzt = stunde8.Add(6 * time.Minute)
	if _, err := werkzeug.Index(z); !errors.Is(err, werkzeug.ErrAnfrage) {
		t.Fatalf("uhr %v", err)
	}
}

func (w welt) indexSchreiben(t *testing.T, liste []protocol.IndexEintrag) welt {
	t.Helper()
	ep := oeffnen(t, w)
	for i, eintrag := range liste {
		inhalt, err := protocol.IndexBytes(eintrag)
		if err != nil {
			t.Fatal(err)
		}
		var event protocol.ID
		event[0] = byte(0xC0 + i)
		klar, err := protocol.EreignisKlartext(event, eintrag.Zeitpunkt, w.bind, inhalt)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = ep.Ereignis(klar); err != nil {
			t.Fatal(err)
		}
	}
	w.abschluss(t, ep)
	return w
}

type menge map[protocol.Signature]bool

func neueMenge() menge { return menge{} }

func (m menge) Merken(s protocol.Signature) bool {
	if m[s] {
		return false
	}
	m[s] = true
	return true
}

func zoneAuf(t *testing.T, w welt, art protocol.AnfrageArt, frage string, jetzt time.Time) werkzeug.Zone {
	t.Helper()
	aufruf := schluessel(t)
	fp, err := crypt.FingerprintSPKI(&aufruf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nutz := protocol.Aussage{
		Mandant: w.mandant, Person: "Dora", Rolle: protocol.RolleDatenschuetzer,
		Von: 0, Bis: math.MaxUint64, Finger: fp,
	}
	raw, err := protocol.AussageBytes(nutz)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(w.pruef, raw)
	if err != nil {
		t.Fatal(err)
	}
	anfrage := protocol.Indexanfrage{
		Mandant: w.mandant, Zone: w.mandant, Person: "Dora", Art: art, Schluessel: frage,
		Von: uint64(stunde8.UnixMilli()), Bis: uint64(stunde10.UnixMilli()),
		Zeitpunkt: uint64(jetzt.UnixMilli()),
	}
	araw, err := protocol.IndexanfrageBytes(anfrage)
	if err != nil {
		t.Fatal(err)
	}
	asig, err := crypt.SignP256(aufruf, araw)
	if err != nil {
		t.Fatal(err)
	}
	return werkzeug.Zone{
		Aussage: nutz, AussageSig: sig, Aufruf: &aufruf.PublicKey,
		Anfrage: anfrage, AnfrageSig: asig, Pruef: &w.pruef.PublicKey,
		Jetzt: jetzt, Gesehen: neueMenge(), Frist: 400 * 24 * time.Hour,
	}
}
