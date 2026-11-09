package werkzeug_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestZeitraumKette(t *testing.T) {
	w1 := basis(t).schreiben(t, "eins")
	w2 := w1.naechste(t, stunde9, w1.epoch.Instanz(), w1.epochHash).schreiben(t, "zwei")
	got, err := werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, stunde8, w1.lage(), w2.lage()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].ImZeitraum || !got[1].ImZeitraum || got[0].Geloescht || got[1].Geloescht {
		t.Fatalf("%+v %+v", got[0].ImZeitraum, got[1].ImZeitraum)
	}
	if got[0].Bericht.Previous != protocol.Genesis(w1.ablage, w1.epoch.Instanz()) || got[0].Bericht.EpochHash != w1.epochHash {
		t.Fatal("anfang")
	}
	if got[1].Bericht.Previous != w1.epochHash || got[1].Bericht.VorgaengerBruch || got[1].Bericht.Luecke {
		t.Fatal("folge")
	}
	if len(got[0].Bericht.Eintraege) != 1 || string(got[0].Bericht.Eintraege[0].Text) != "eins" || !got[0].Bericht.Eintraege[0].Gueltig || got[0].Bericht.Eintraege[0].NachRaster {
		t.Fatalf("eins %+v", got[0].Bericht.Eintraege)
	}
	if len(got[1].Bericht.Eintraege) != 1 || string(got[1].Bericht.Eintraege[0].Text) != "zwei" || !got[1].Bericht.Eintraege[0].Gueltig {
		t.Fatalf("zwei %+v", got[1].Bericht.Eintraege)
	}

	andere := w1.naechste(t, stunde8, fill(0x45), protocol.Genesis(w1.ablage, fill(0x45))).schreiben(t, "andere")
	got, err = werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde9, stunde8, w1.lage(), andere.lage()))
	if err != nil || len(got[0].Bericht.Eintraege) != 1 || len(got[1].Bericht.Eintraege) != 1 || got[1].Bericht.VorgaengerBruch {
		t.Fatalf("instanz %v %+v", err, got)
	}
}

func TestZeitraumAusserhalb(t *testing.T) {
	w1 := basis(t).schreiben(t, "eins")
	w2 := w1.naechste(t, stunde9, w1.epoch.Instanz(), w1.epochHash).schreiben(t, "zwei")
	got, err := werkzeug.Zeitraum(stromAnfrage(w1, stunde9, stunde10, stunde8, w1.lage(), w2.lage()))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ImZeitraum || len(got[0].Bericht.Eintraege) != 0 || got[0].Bericht.EpochHash != w1.epochHash {
		t.Fatalf("ausserhalb %+v", got[0])
	}
	if !got[1].ImZeitraum || len(got[1].Bericht.Eintraege) != 1 || string(got[1].Bericht.Eintraege[0].Text) != "zwei" {
		t.Fatalf("innerhalb %+v", got[1].Bericht.Eintraege)
	}
}

func TestLoeschen(t *testing.T) {
	w1 := basis(t).schreiben(t, "eins")
	w2 := w1.naechste(t, stunde9, w1.epoch.Instanz(), w1.epochHash).schreiben(t, "zwei")
	schnitt, err := werkzeug.Schnitt(stunde8, 30*24*time.Hour)
	if err != nil || !schnitt.Equal(time.Date(2026, 12, 6, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("schnitt %v %v", schnitt, err)
	}
	mitternacht, err := werkzeug.Schnitt(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), 24*time.Hour)
	if err != nil || !mitternacht.Equal(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("mitternacht %v %v", mitternacht, err)
	}

	got, err := werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, schnitt, w1.lage(), w2.lage()))
	if err != nil || !got[0].Geloescht || !got[1].Geloescht || len(got[0].Bericht.Eintraege) != 0 || len(got[1].Bericht.Eintraege) != 0 {
		t.Fatalf("schnitt %+v %v", got, err)
	}
	if got[0].Bericht.EpochHash != w1.epochHash || got[1].Bericht.Previous != w1.epochHash || got[1].Bericht.VorgaengerBruch {
		t.Fatal("kette am schnitt")
	}
	davor := stromAnfrage(w1, stunde8, stunde10, schnitt.Add(-time.Nanosecond), w1.lage(), w2.lage())
	offen, err := werkzeug.Zeitraum(davor)
	if err != nil || offen[0].Geloescht || len(offen[0].Bericht.Eintraege) != 1 {
		t.Fatalf("vor dem schnitt %+v %v", offen, err)
	}

	vermerkt := w1.lage()
	tag := time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)
	vermerkt.Vermerk = &tag
	got, err = werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, stunde8, vermerkt, w2.lage()))
	if err != nil || !got[0].Geloescht || len(got[0].Bericht.Eintraege) != 0 || got[1].Geloescht || len(got[1].Bericht.Eintraege) != 1 {
		t.Fatalf("vermerk %+v %v", got, err)
	}
	if got[1].Bericht.Previous != w1.epochHash {
		t.Fatal("vermerk kette")
	}

	luecke := w1.lage()
	luecke.Auftrag.Segmente = nil
	got, err = werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, stunde8, luecke, w2.lage()))
	if err != nil || !got[0].Bericht.Luecke || got[0].Geloescht || len(got[0].Bericht.Eintraege) != 0 || len(got[1].Bericht.Eintraege) != 1 {
		t.Fatalf("lücke %+v %v", got, err)
	}

	got, err = werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, schnitt, luecke, w2.lage()))
	if err != nil || !got[0].Geloescht || got[0].Bericht.Luecke || len(got[1].Bericht.Eintraege) != 0 || !got[1].Geloescht {
		t.Fatalf("gelöscht ohne segmente %+v %v", got, err)
	}
}

func TestKetteUnterbrochen(t *testing.T) {
	w1 := basis(t).schreiben(t, "eins")
	bruch := w1.naechste(t, stunde9, w1.epoch.Instanz(), protocol.Hash{1}).schreiben(t, "zwei")
	got, err := werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, stunde8, w1.lage(), bruch.lage()))
	if err != nil || len(got[0].Bericht.Eintraege) != 1 || !got[1].Bericht.VorgaengerBruch || got[1].Bericht.Luecke || len(got[1].Bericht.Eintraege) != 0 {
		t.Fatalf("bruch %+v %v", got, err)
	}

	ohne := w1.lage()
	ohne.Auftrag.Bestaetigung = nil
	folge := w1.naechste(t, stunde9, w1.epoch.Instanz(), w1.epochHash).schreiben(t, "zwei")
	got, err = werkzeug.Zeitraum(stromAnfrage(w1, stunde8, stunde10, stunde8, ohne, folge.lage()))
	if err != nil || !got[0].Bericht.Luecke || len(got[0].Bericht.Eintraege) != 0 || !got[1].Bericht.Luecke || got[1].Bericht.VorgaengerBruch || len(got[1].Bericht.Eintraege) != 0 {
		t.Fatalf("ohne bestätigung %+v %v", got, err)
	}

	fremd := basis(t)
	fremd.previous = protocol.Hash{9}
	fremd = fremd.schreiben(t, "eins")
	a := stromAnfrage(fremd, stunde8, stunde9, stunde8, fremd.lage())
	a.Vorgaenger = map[protocol.ID]protocol.Hash{fremd.epoch.Instanz(): protocol.Hash{9}}
	got, err = werkzeug.Zeitraum(a)
	if err != nil || len(got[0].Bericht.Eintraege) != 1 || got[0].Bericht.VorgaengerBruch {
		t.Fatalf("vorgänger %+v %v", got, err)
	}
	a.Vorgaenger = nil
	got, err = werkzeug.Zeitraum(a)
	if err != nil || !got[0].Bericht.VorgaengerBruch || len(got[0].Bericht.Eintraege) != 0 {
		t.Fatalf("genesis %+v %v", got, err)
	}
}

func TestAuffangZeitraum(t *testing.T) {
	w := basis(t).auffangen(t)
	lage := w.lage()
	lage.Auftrag.Rolle = protocol.RolleAuffang
	a := stromAnfrage(w, stunde8, stunde9, stunde8, lage)
	a.Rolle = protocol.RolleAuffang
	got, err := werkzeug.Zeitraum(a)
	if err != nil || len(got) != 1 || !got[0].ImZeitraum || got[0].Geloescht {
		t.Fatalf("%v %+v", err, got)
	}
	eintrag := got[0].Bericht.Eintraege
	if len(eintrag) != 1 || !eintrag[0].Gueltig || !eintrag[0].Unzugeordnet || eintrag[0].Grund != protocol.GrundUnbekannt || string(eintrag[0].Text) != "tot" {
		t.Fatalf("%+v", eintrag)
	}
}

func TestZeitraumGrenzen(t *testing.T) {
	w := basis(t)
	a := stromAnfrage(w, stunde8, stunde10, stunde8)
	a.Intervall = 10 * time.Minute
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrIntervall) {
		t.Fatalf("intervall %v", err)
	}
	a.Intervall = 45 * time.Minute
	if got, err := werkzeug.Zeitraum(a); err != nil || len(got) != 0 {
		t.Fatalf("45 min %v %d", err, len(got))
	}
	a = stromAnfrage(w, stunde8, stunde10, stunde8)
	a.Frist = 12 * time.Hour
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrFrist) {
		t.Fatalf("frist %v", err)
	}
	a = stromAnfrage(w, stunde8, stunde8, stunde8)
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrZeitraum) {
		t.Fatalf("leer %v", err)
	}
	a = stromAnfrage(w, stunde8, stunde10, stunde8)
	a.Rolle = protocol.RolleVerzeichnisSumme
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrRolle) {
		t.Fatalf("rolle %v", err)
	}
	id, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 30, 0, 0, time.UTC), w.epoch.Instanz(), w.epoch.Prefix())
	if err != nil {
		t.Fatal(err)
	}
	a = stromAnfrage(w, stunde8, stunde10, stunde8, werkzeug.Lage{Auftrag: werkzeug.Auftrag{Epoch: id}})
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, protocol.ErrRaster) {
		t.Fatalf("raster %v", err)
	}
	lage := w.lage()
	a = stromAnfrage(w, stunde8, stunde10, stunde8, lage, lage)
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrZeitraum) {
		t.Fatalf("doppelt %v", err)
	}
	kaputt := lage
	kaputt.Auftrag.Segmente = nil
	kaputt.Auftrag.BestaetigungsSignatur[0] ^= 0xff
	a = stromAnfrage(w, stunde8, stunde10, stunde8, kaputt)
	if _, err := werkzeug.Zeitraum(a); !errors.Is(err, werkzeug.ErrBestaetigung) {
		t.Fatalf("bestätigung %v", err)
	}
}

var (
	stunde8  = time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	stunde9  = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	stunde10 = time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
)

func stromAnfrage(w welt, von, bis, jetzt time.Time, lagen ...werkzeug.Lage) werkzeug.Anfrage {
	return werkzeug.Anfrage{
		Mandant:   w.mandant,
		Ablage:    w.ablage,
		Rolle:     protocol.RolleGruppe,
		Intervall: time.Hour,
		Frist:     30 * 24 * time.Hour,
		Jetzt:     jetzt,
		Von:       von,
		Bis:       bis,
		Epochen:   lagen,
	}
}

func (w welt) naechste(t *testing.T, raster time.Time, instanz protocol.ID, previous protocol.Hash) welt {
	t.Helper()
	var prefix protocol.Prefix
	if _, err := rand.Read(prefix[:]); err != nil {
		t.Fatal(err)
	}
	id, err := protocol.NewEpochID(raster, instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	n := w
	n.epoch = id
	n.previous = previous
	n.segs = nil
	n.seqs = nil
	n.epochHash = protocol.Hash{}
	n.kette = protocol.Hash{}
	n.confirm = protocol.Signature{}
	return n
}

func (w welt) schreiben(t *testing.T, text string) welt {
	t.Helper()
	return w.texte(t, text)
}

func (w welt) texte(t *testing.T, texte ...string) welt {
	t.Helper()
	ep := oeffnen(t, w)
	w.seqs = nil
	for i, text := range texte {
		var event protocol.ID
		event[0] = byte(0x10 + i)
		klar, err := protocol.EreignisKlartext(event, 1500, w.bind, logInhalt(t, text, aussage(t, w, true)))
		if err != nil {
			t.Fatal(err)
		}
		_, glieder, err := ep.Ereignis(klar)
		if err != nil {
			t.Fatal(err)
		}
		var seqs []uint64
		for _, g := range glieder {
			seqs = append(seqs, g.Seq)
		}
		w.seqs = append(w.seqs, seqs)
	}
	w.abschluss(t, ep)
	return w
}

func (w welt) auffangen(t *testing.T) welt {
	t.Helper()
	ep := oeffnen(t, w)
	inhalt, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:    protocol.GrundUnbekannt,
		Text:     []byte("tot"),
		Personen: []string{"Cleo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.ID
	event[0] = 0x61
	klar, err := protocol.EreignisKlartext(event, 1500, w.bind, inhalt)
	if err != nil {
		t.Fatal(err)
	}
	_, glieder, err := ep.Ereignis(klar)
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, g := range glieder {
		seqs = append(seqs, g.Seq)
	}
	w.seqs = [][]uint64{seqs}
	w.abschluss(t, ep)
	return w
}

func (w welt) lage() werkzeug.Lage {
	return werkzeug.Lage{Auftrag: w.auftrag(werkzeug.StatusAktuell)}
}
