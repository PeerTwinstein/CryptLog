package werkzeug_test

import (
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestKatalogAufloesen(t *testing.T) {
	katalog, gruppe, praefix, person, auffang := fill(0x61), fill(0x62), fill(0x63), fill(0x64), fill(0x65)
	alt := protocol.Stand{
		Name: "Nord",
		Kennungen: []protocol.Kennung{
			{Rolle: protocol.RolleGruppe, Ablage: gruppe, Bind: gruppe, Kohorte: "alt", Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleKatalog, Ablage: katalog, Bind: katalog, Aktiv: protocol.KennungAn},
		},
	}
	neu := protocol.Stand{
		Name: "Nord",
		Kennungen: []protocol.Kennung{
			{Rolle: protocol.RolleGruppe, Ablage: gruppe, Bind: gruppe, Kohorte: "vertrieb", Aktiv: protocol.KennungAus},
			{Rolle: protocol.RolleEinzel, Ablage: praefix, Bind: person, Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleAuffang, Ablage: auffang, Bind: auffang, Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleKatalog, Ablage: katalog, Bind: katalog, Aktiv: protocol.KennungAn},
		},
	}
	w := basis(t)
	w.ablage, w.bind = katalog, katalog
	w.previous = protocol.Genesis(w.ablage, w.epoch.Instanz())
	erste := w.katalogSchreiben(t, alt)
	zweite := erste.naechste(t, stunde9, erste.epoch.Instanz(), erste.epochHash).katalogSchreiben(t, neu)
	l1, l2 := erste.lage(), zweite.lage()
	l1.Auftrag.Rolle, l2.Auftrag.Rolle = protocol.RolleKatalog, protocol.RolleKatalog
	anfrage := stromAnfrage(erste, stunde8, stunde10, stunde8, l1, l2)
	anfrage.Rolle = protocol.RolleKatalog
	anfrage.Ablage = katalog
	staende, err := werkzeug.KatalogLesen(anfrage)
	if err != nil || len(staende) != 2 || staende[1].Name != "Nord" {
		t.Fatalf("stände %d %v", len(staende), err)
	}
	got, err := werkzeug.Aufloesen(staende, protocol.RolleGruppe, "vertrieb")
	if err != nil || got.Ablage != gruppe || got.Bind != gruppe {
		t.Fatalf("gruppe %+v %v", got, err)
	}
	if _, err := werkzeug.Aufloesen(staende, protocol.RolleGruppe, "alt"); !errors.Is(err, werkzeug.ErrAufloesung) {
		t.Fatalf("alter name %v", err)
	}
	einzel, err := werkzeug.Aufloesen(staende, protocol.RolleEinzel, "")
	if err != nil || einzel.Ablage != praefix || einzel.Bind != (protocol.ID{}) {
		t.Fatalf("präfix %+v %v", einzel, err)
	}
	auf, err := werkzeug.Aufloesen(staende, protocol.RolleAuffang, "")
	if err != nil || auf.Ablage != auffang {
		t.Fatalf("auffang %+v %v", auf, err)
	}

	log := logEpoche(t, []string{"eins"}, true, false)
	pruef := log.auftrag(werkzeug.StatusAktuell)
	pruef.Auswahl = []uint64{log.seqs[0][0]}
	pruef.Katalog = &protocol.Stand{Name: "Nord", Kennungen: []protocol.Kennung{{
		Rolle: protocol.RolleGruppe, Ablage: log.ablage, Bind: log.bind, Kohorte: "vertrieb", Aktiv: protocol.KennungAn,
	}}}
	offen, err := werkzeug.Pruefen(pruef)
	if err != nil || !offen.Eintraege[0].Gueltig {
		t.Fatalf("katalog %+v %v", offen.Eintraege, err)
	}
	pruef.Katalog.Kennungen[0].Bind = fill(0x99)
	fremd, err := werkzeug.Pruefen(pruef)
	if err != nil || fremd.Eintraege[0].Gueltig {
		t.Fatalf("fremde bindung %+v %v", fremd.Eintraege, err)
	}
}

func (w welt) katalogSchreiben(t *testing.T, stand protocol.Stand) welt {
	t.Helper()
	ep := oeffnen(t, w)
	inhalt, err := protocol.KatalogBytes(stand)
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.ID
	event[0] = 0x31
	klar, err := protocol.EreignisKlartext(event, 1500, w.bind, inhalt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ep.Ereignis(klar); err != nil {
		t.Fatal(err)
	}
	w.abschluss(t, ep)
	return w
}

func TestEinzelpraefix(t *testing.T) {
	w := basis(t)
	w.bind = fill(0x71)
	ada := w.schreiben(t, "ada")
	beaWelt := ada.naechste(t, stunde9, ada.epoch.Instanz(), ada.epochHash)
	beaWelt.bind = fill(0x72)
	bea := beaWelt.schreiben(t, "bea")
	l1, l2 := ada.lage(), bea.lage()
	l1.Auftrag.Rolle, l2.Auftrag.Rolle = protocol.RolleEinzel, protocol.RolleEinzel
	anfrage := stromAnfrage(ada, stunde8, stunde10, stunde8, l1, l2)
	anfrage.Rolle = protocol.RolleEinzel
	got, err := werkzeug.Zeitraum(anfrage)
	if err != nil || len(got) != 2 || len(got[0].Bericht.Eintraege) != 1 || len(got[1].Bericht.Eintraege) != 1 {
		t.Fatalf("kette %+v %v", got, err)
	}
	if !got[0].Bericht.Eintraege[0].Gueltig || got[0].Bericht.Eintraege[0].Bind != ada.bind ||
		!got[1].Bericht.Eintraege[0].Gueltig || got[1].Bericht.Eintraege[0].Bind != bea.bind ||
		got[0].Bericht.Bind == anfrage.Ablage {
		t.Fatalf("personen %+v %+v", got[0].Bericht.Eintraege[0], got[1].Bericht.Eintraege[0])
	}
	if string(got[0].Bericht.Eintraege[0].Text) != "ada" || string(got[1].Bericht.Eintraege[0].Text) != "bea" {
		t.Fatal("text")
	}

	gleich := basis(t)
	eine := gleich.schreiben(t, "gleich")
	lage := eine.lage()
	lage.Auftrag.Rolle = protocol.RolleEinzel
	anfrage = stromAnfrage(gleich, stunde8, stunde10, stunde8, lage)
	anfrage.Rolle = protocol.RolleEinzel
	got, err = werkzeug.Zeitraum(anfrage)
	if err != nil || got[0].Bericht.Eintraege[0].Gueltig || got[0].Bericht.Eintraege[0].Bind != gleich.ablage {
		t.Fatalf("präfix als bindung %+v %v", got, err)
	}
}

func TestLoeschlauf(t *testing.T) {
	mandant, ablage, instanz := fill(0x11), fill(0x22), fill(0x44)
	var prefix protocol.Prefix
	prefix[0] = 7
	raster := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	epoch, err := protocol.NewEpochID(raster, instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.ID
	event[0] = 0x90
	seg, err := protocol.ObjektSchluessel(mandant, ablage, epoch, 1)
	if err != nil {
		t.Fatal(err)
	}
	beleg := protocol.BelegungSchluessel(event)
	ann, err := protocol.AnnahmeSchluessel(instanz, 1)
	if err != nil {
		t.Fatal(err)
	}
	vor, err := protocol.VorbereitungSchluessel(instanz, 1)
	if err != nil {
		t.Fatal(err)
	}
	epoche := werkzeug.LoeschEpoche{
		Mandant: mandant, Ablage: ablage, Epoch: epoch,
		Vollstaendig: true, AnnahmeFirst: 1, AnnahmeLast: 1,
		Segmente: []string{seg},
	}
	abschluss := werkzeug.LoeschAbschluss{Instanz: instanz, BatchSeq: 1}
	frist := 24 * time.Hour
	davor := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := neuLager(seg, []byte("segment"), beleg, []byte("belegung"), ann, []byte("annahme"), vor, []byte("vorbereitung"))
	erg, err := werkzeug.Loeschen(davor, frist, []werkzeug.LoeschEpoche{epoche}, []werkzeug.LoeschAbschluss{abschluss}, store)
	if err != nil || len(erg.Vermerke) != 0 || len(erg.Entfernt) != 0 || !store.hat(seg) || !store.hat(beleg) {
		t.Fatalf("vor dem tag %+v %v", erg, err)
	}

	tag := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	erg, err = werkzeug.Loeschen(tag, frist, []werkzeug.LoeschEpoche{epoche}, []werkzeug.LoeschAbschluss{abschluss}, store)
	if err != nil || len(erg.Vermerke) != 1 || store.hat(seg) || store.hat(ann) || store.hat(vor) || !store.hat(beleg) {
		t.Fatalf("löschtag %+v %v hat seg %v beleg %v", erg, err, store.hat(seg), store.hat(beleg))
	}
	vermerk, ok := store.lesen(erg.Vermerke[0])
	id, gelesen, perr := protocol.ParseVermerk(vermerk)
	if !ok || perr != nil || id != epoch || !gelesen.Equal(tag) {
		t.Fatalf("vermerk %v %v", gelesen, perr)
	}

	nochmal, err := werkzeug.Loeschen(tag, frist, []werkzeug.LoeschEpoche{epoche}, []werkzeug.LoeschAbschluss{abschluss}, store)
	if err != nil || len(nochmal.Vermerke) != 0 || len(nochmal.Entfernt) != 0 || !store.hat(beleg) {
		t.Fatalf("zweiter lauf %+v %v", nochmal, err)
	}

	rest := neuLager(seg, []byte("segment"), beleg, []byte("belegung"), ann, []byte("annahme"))
	body, err := protocol.VermerkBytes(epoch, tag)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.VermerkSchluessel(mandant, ablage, epoch)
	rest.schreiben(key, body)
	erg, err = werkzeug.Loeschen(davor, frist, []werkzeug.LoeschEpoche{epoche}, []werkzeug.LoeschAbschluss{abschluss}, rest)
	if err != nil || len(erg.Vermerke) != 0 || rest.hat(seg) || rest.hat(ann) || !rest.hat(beleg) || !rest.hat(key) {
		t.Fatalf("fortsetzen %+v %v", erg, err)
	}

	luecke := epoche
	luecke.Vollstaendig = false
	liegen := neuLager(seg, []byte("segment"), ann, []byte("annahme"))
	erg, err = werkzeug.Loeschen(tag, frist, []werkzeug.LoeschEpoche{luecke}, []werkzeug.LoeschAbschluss{abschluss}, liegen)
	if err != nil || len(erg.Entfernt) != 0 || !liegen.hat(seg) || !liegen.hat(ann) {
		t.Fatalf("unvollständig %+v %v", erg, err)
	}

	prefix[0] = 8
	spaeter, err := protocol.NewEpochID(raster.Add(24*time.Hour), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	zweiter, err := protocol.ObjektSchluessel(mandant, ablage, spaeter, 1)
	if err != nil {
		t.Fatal(err)
	}
	haelt := werkzeug.LoeschEpoche{
		Mandant: mandant, Ablage: ablage, Epoch: spaeter,
		Vollstaendig: true, AnnahmeFirst: 1, AnnahmeLast: 2,
		Segmente: []string{zweiter},
	}
	beide := neuLager(seg, []byte("segment"), zweiter, []byte("spaeter"), ann, []byte("annahme"))
	erg, err = werkzeug.Loeschen(tag, frist, []werkzeug.LoeschEpoche{epoche, haelt}, []werkzeug.LoeschAbschluss{abschluss}, beide)
	if err != nil || beide.hat(seg) || !beide.hat(zweiter) || !beide.hat(ann) {
		t.Fatalf("eine epoche bleibt %+v %v", erg, err)
	}
}

type memLager struct {
	obj map[string][]byte
}

func neuLager(paare ...interface{}) *memLager {
	m := &memLager{obj: map[string][]byte{}}
	for i := 0; i < len(paare); i += 2 {
		m.schreiben(paare[i].(string), paare[i+1].([]byte))
	}
	return m
}

func (m *memLager) Lesen(schluessel string) ([]byte, bool, error) {
	b, ok := m.obj[schluessel]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func (m *memLager) Schreiben(schluessel string, inhalt []byte) error {
	m.schreiben(schluessel, inhalt)
	return nil
}

func (m *memLager) Entfernen(schluessel string) error {
	delete(m.obj, schluessel)
	return nil
}

func (m *memLager) schreiben(schluessel string, inhalt []byte) {
	m.obj[schluessel] = append([]byte(nil), inhalt...)
}

func (m *memLager) hat(schluessel string) bool {
	_, ok := m.obj[schluessel]
	return ok
}

func (m *memLager) lesen(schluessel string) ([]byte, bool) {
	b, ok := m.obj[schluessel]
	return b, ok
}
