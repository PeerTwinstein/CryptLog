package werkzeug_test

import (
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestVerzeichnisSummeOrdnung(t *testing.T) {
	monat := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	id, err := protocol.NewEpochID(stunde8, fill(0x44), protocol.Prefix{1})
	if err != nil {
		t.Fatal(err)
	}
	ada := protocol.Verweis{Art: protocol.VerweisPerson, Schluessel: "Ada", Mandant: fill(0x11), Bind: fill(0x22), Epoch: id, Seq: 1}
	bea := protocol.Verweis{Art: protocol.VerweisPerson, Schluessel: "Bea", Mandant: fill(0x11), Bind: fill(0x22), Epoch: id, Seq: 2}
	vorgang := protocol.Verweis{Art: protocol.VerweisVorgang, Schluessel: "V-1", Mandant: fill(0x11), Bind: fill(0x22), Epoch: id, Seq: 1}
	teile, err := werkzeug.VerzeichnisSumme(monat, []werkzeug.Quelle{{
		Epoch: id, Hash: protocol.Hash{7},
		Eintraege: []werkzeug.Eintrag{
			{Gueltig: true, Zeit: 3, Verweis: &bea},
			{Gueltig: true, Zeit: 2, Verweis: &vorgang},
			{Gueltig: true, Zeit: 1, Verweis: &ada},
		},
	}})
	if err != nil || len(teile) != 4 {
		t.Fatalf("%d %v", len(teile), err)
	}
	if _, err := protocol.ParseBeleg(teile[0].Inhalt); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"Ada", "Bea", "V-1"} {
		got, err := protocol.ParseVerweis(teile[i+1].Inhalt)
		if err != nil || got.Schluessel != want {
			t.Fatalf("%d %+v %v", i, got, err)
		}
	}
	if _, err := werkzeug.VerzeichnisSumme(stunde8, []werkzeug.Quelle{{Epoch: id}}); !errors.Is(err, werkzeug.ErrSumme) {
		t.Fatalf("monat %v", err)
	}
}

func TestSucheSumme(t *testing.T) {
	log := basis(t).texte(t, "eins", "zwei")
	verzeichnis := log.andereAblage(t, fill(0x33), stunde8).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Ada", log, 0),
	})
	offen := oeffneAlles(t, verzeichnis, protocol.RolleVerzeichnis)
	monat := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	dezember := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	aufZwei := offen.Eintraege[0]
	verweisZwei := *aufZwei.Verweis
	verweisZwei.Seq = log.seqs[1][0]
	aufZwei.Verweis = &verweisZwei
	falsch, err := werkzeug.VerzeichnisSumme(monat, []werkzeug.Quelle{{
		Epoch: verzeichnis.epoch, Hash: verzeichnis.epochHash, Eintraege: []werkzeug.Eintrag{aufZwei},
	}})
	if err != nil {
		t.Fatal(err)
	}
	summe := verzeichnis.andereAblage(t, fill(0x35), monat).summeSchreiben(t, falsch)
	s := suchanfrage(log, verzeichnis, "Ada", "")
	s.Jetzt = dezember
	s.Frist = 400 * 24 * time.Hour
	s.Summen = summenStrom(summe, protocol.RolleVerzeichnisSumme)
	got, err := werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "zwei" {
		t.Fatalf("summe %+v %v", got, err)
	}

	aufZwei.Verweis = &verweisZwei
	quelle := werkzeug.Quelle{Epoch: verzeichnis.epoch, Hash: protocol.Hash{9}, Eintraege: []werkzeug.Eintrag{aufZwei}}
	abweichend, err := werkzeug.VerzeichnisSumme(monat, []werkzeug.Quelle{quelle})
	if err != nil {
		t.Fatal(err)
	}
	s.Summen = summenStrom(verzeichnis.andereAblage(t, fill(0x36), monat).summeSchreiben(t, abweichend), protocol.RolleVerzeichnisSumme)
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "eins" {
		t.Fatalf("rückfall %+v %v", got, err)
	}

	echt, err := werkzeug.VerzeichnisSumme(monat, []werkzeug.Quelle{{
		Epoch: verzeichnis.epoch, Hash: verzeichnis.epochHash, Eintraege: offen.Eintraege,
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.Summen = summenStrom(verzeichnis.andereAblage(t, fill(0x37), monat).summeSchreiben(t, echt), protocol.RolleVerzeichnisSumme)
	s.Verzeichnis.Epochen[0].Auftrag.Segmente = nil
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "eins" {
		t.Fatalf("ohne segmente %+v %v", got, err)
	}

	s = suchanfrage(log, verzeichnis, "Ada", "")
	s.Frist = 400 * 24 * time.Hour
	s.Summen = summenStrom(summe, protocol.RolleVerzeichnisSumme)
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "eins" {
		t.Fatalf("laufender monat %+v %v", got, err)
	}
}

func oeffneAlles(t *testing.T, w welt, rolle protocol.StromRolle) werkzeug.Bericht {
	t.Helper()
	a := w.auftrag(werkzeug.StatusAktuell)
	a.Rolle = rolle
	a.Alles = true
	got, err := werkzeug.Pruefen(a)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func summenStrom(w welt, rolle protocol.StromRolle) werkzeug.Strom {
	lage := w.lage()
	lage.Auftrag.Rolle = rolle
	return werkzeug.Strom{Ablage: w.ablage, Rolle: rolle, Epochen: []werkzeug.Lage{lage}}
}

func (w welt) summeSchreiben(t *testing.T, teile []werkzeug.Summenteil) welt {
	t.Helper()
	ep := oeffnen(t, w)
	for i, teil := range teile {
		var event protocol.ID
		event[0] = byte(0xD0 + i)
		klar, err := protocol.EreignisKlartext(event, teil.Zeit, w.bind, teil.Inhalt)
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
