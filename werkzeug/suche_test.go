package werkzeug_test

import (
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestSuche(t *testing.T) {
	log := basis(t).texte(t, "eins", "zwei")
	verzeichnis := log.andereAblage(t, fill(0x33), stunde8).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Ada", log, 0),
		verweis(protocol.VerweisVorgang, "V-1", log, 0),
	})
	s := suchanfrage(log, verzeichnis, "Ada", "")
	got, err := werkzeug.Suche(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Eintrag.Text) != "eins" || !got[0].Eintrag.Gueltig || !got[0].Vertraulich || got[0].Seq != log.seqs[0][0] {
		t.Fatalf("person %+v", got)
	}
	for _, treffer := range got {
		if string(treffer.Eintrag.Text) == "zwei" {
			t.Fatal("zweiter Eintrag geöffnet")
		}
	}

	s.Person = ""
	s.Vorgang = "V-1"
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "eins" {
		t.Fatalf("vorgang %+v %v", got, err)
	}

	s.Person = "Ada"
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || got[0].Eintrag.Vorgang != "V-1" {
		t.Fatalf("beide %+v %v", got, err)
	}

	s.Vorgang = "andere"
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 0 {
		t.Fatalf("schnitt %d %v", len(got), err)
	}
	s.Person = "Bea"
	s.Vorgang = ""
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 0 {
		t.Fatalf("fremd %d %v", len(got), err)
	}
}

func TestSucheZeitraum(t *testing.T) {
	log := basis(t).schreiben(t, "eins")
	verzeichnis := log.andereAblage(t, fill(0x33), stunde9).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Ada", log, 0),
	})
	s := suchanfrage(log, verzeichnis, "Ada", "")
	s.Von = stunde9
	s.Bis = stunde10
	got, err := werkzeug.Suche(s)
	if err != nil || len(got) != 1 || string(got[0].Eintrag.Text) != "eins" || got[0].Epoch != log.epoch {
		t.Fatalf("verweis %+v %v", got, err)
	}

	frueh := log.andereAblage(t, fill(0x34), stunde8).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Ada", log, 0),
	})
	s.Verzeichnis = verzeichnisStrom(frueh)
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 0 {
		t.Fatalf("ausserhalb %d %v", len(got), err)
	}
}

func TestSucheLoeschen(t *testing.T) {
	log := basis(t).schreiben(t, "eins")
	früher := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	fehlend, err := protocol.NewEpochID(früher, log.epoch.Instanz(), protocol.Prefix{9})
	if err != nil {
		t.Fatal(err)
	}
	nix := protocol.Verweis{
		Art: protocol.VerweisPerson, Schluessel: "Nix", Mandant: log.mandant,
		Bind: log.bind, Epoch: fehlend, Seq: 1,
	}
	verzeichnis := log.andereAblage(t, fill(0x33), stunde8).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Ada", log, 0),
		nix,
	})
	s := suchanfrage(log, verzeichnis, "Nix", "")
	got, err := werkzeug.Suche(s)
	if err != nil || len(got) != 1 || !got[0].Luecke || got[0].Geloescht || len(got[0].Eintrag.Text) != 0 {
		t.Fatalf("lücke %+v %v", got, err)
	}

	schnitt, err := werkzeug.Schnitt(früher, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.Jetzt = schnitt
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || !got[0].Geloescht || got[0].Luecke {
		t.Fatalf("ohne epoche %+v %v", got, err)
	}

	s.Jetzt = stunde8
	s.Person = "Ada"
	lage := log.lage()
	tag := time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)
	lage.Vermerk = &tag
	s.Ziele[0].Epochen = []werkzeug.Lage{lage}
	got, err = werkzeug.Suche(s)
	if err != nil || len(got) != 1 || !got[0].Geloescht || len(got[0].Eintrag.Text) != 0 || got[0].Rolle != protocol.RolleGruppe {
		t.Fatalf("vermerk %+v %v", got, err)
	}
}

func TestAuffangSuche(t *testing.T) {
	log := basis(t).auffangen(t)
	verzeichnis := log.andereAblage(t, fill(0x33), stunde8).verweisen(t, []protocol.Verweis{
		verweis(protocol.VerweisPerson, "Cleo", log, 0),
	})
	s := suchanfrage(log, verzeichnis, "Cleo", "")
	s.Ziele[0].Rolle = protocol.RolleAuffang
	s.Ziele[0].Epochen[0].Auftrag.Rolle = protocol.RolleAuffang
	got, err := werkzeug.Suche(s)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	eintrag := got[0].Eintrag
	if !eintrag.Gueltig || !eintrag.Unzugeordnet || eintrag.Grund != protocol.GrundUnbekannt || string(eintrag.Text) != "tot" {
		t.Fatalf("%+v", eintrag)
	}
}

func TestSucheGrenzen(t *testing.T) {
	if _, err := werkzeug.Suche(werkzeug.Suchanfrage{}); !errors.Is(err, werkzeug.ErrSuche) {
		t.Fatalf("leer %v", err)
	}
	s := werkzeug.Suchanfrage{Person: "Ada", Verzeichnis: werkzeug.Strom{Rolle: protocol.RolleGruppe}}
	if _, err := werkzeug.Suche(s); !errors.Is(err, werkzeug.ErrRolle) {
		t.Fatalf("rolle %v", err)
	}
}

func suchanfrage(log, verzeichnis welt, person, vorgang string) werkzeug.Suchanfrage {
	return werkzeug.Suchanfrage{
		Mandant:     log.mandant,
		Frist:       30 * 24 * time.Hour,
		Jetzt:       stunde8,
		Von:         stunde8,
		Bis:         stunde10,
		Person:      person,
		Vorgang:     vorgang,
		Verzeichnis: verzeichnisStrom(verzeichnis),
		Ziele:       []werkzeug.Strom{zielStrom(log, protocol.RolleGruppe)},
	}
}

func verzeichnisStrom(w welt) werkzeug.Strom {
	lage := w.lage()
	lage.Auftrag.Rolle = protocol.RolleVerzeichnis
	return werkzeug.Strom{
		Ablage:    w.ablage,
		Rolle:     protocol.RolleVerzeichnis,
		Intervall: time.Hour,
		Epochen:   []werkzeug.Lage{lage},
	}
}

func zielStrom(w welt, rolle protocol.StromRolle) werkzeug.Strom {
	lage := w.lage()
	lage.Auftrag.Rolle = rolle
	return werkzeug.Strom{
		Ablage:    w.ablage,
		Rolle:     rolle,
		Intervall: time.Hour,
		Epochen:   []werkzeug.Lage{lage},
	}
}

func verweis(art protocol.VerweisArt, schluessel string, ziel welt, n int) protocol.Verweis {
	return protocol.Verweis{
		Art:        art,
		Schluessel: schluessel,
		Mandant:    ziel.mandant,
		Bind:       ziel.bind,
		Epoch:      ziel.epoch,
		Seq:        ziel.seqs[n][0],
	}
}

func (w welt) andereAblage(t *testing.T, ablage protocol.ID, raster time.Time) welt {
	t.Helper()
	n := w.naechste(t, raster, w.epoch.Instanz(), protocol.Hash{})
	n.ablage = ablage
	n.bind = ablage
	n.previous = protocol.Genesis(ablage, n.epoch.Instanz())
	return n
}

func (w welt) verweisen(t *testing.T, liste []protocol.Verweis) welt {
	t.Helper()
	ep := oeffnen(t, w)
	for i, v := range liste {
		inhalt, err := protocol.VerweisBytes(v)
		if err != nil {
			t.Fatal(err)
		}
		var event protocol.ID
		event[0] = byte(0xA0 + i)
		klar, err := protocol.EreignisKlartext(event, 1500, w.bind, inhalt)
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
