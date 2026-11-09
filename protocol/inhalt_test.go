package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"cryptlog/protocol"
)

func TestPlattformMandant(t *testing.T) {
	id := protocol.PlattformMandant()
	if string(id[:9]) != "plattform" || id[9] != 0 || id[15] != 0 {
		t.Fatalf("%x", id)
	}
}

func TestAufrufBytes(t *testing.T) {
	got, err := protocol.AufrufBytes(7, "V-1", []string{"Ada"}, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("aufruf"), be64(7)...)
	want = append(want, text("V-1")...)
	want = append(want, be32(1)...)
	want = append(want, text("Ada")...)
	want = append(want, be32(2)...)
	want = append(want, 'h', 'i')
	if !bytes.Equal(got, want) {
		t.Fatalf("aufruf\n got %x\nwant %x", got, want)
	}
	if _, err := protocol.AufrufBytes(0, "", []string{"Ada", "Ada"}, nil); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("doppelt %v", err)
	}
	if _, err := protocol.AufrufBytes(0, "", []string{""}, nil); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("leer %v", err)
	}
	if _, err := protocol.AufrufBytes(0, "\xff", nil, nil); !errors.Is(err, protocol.ErrUTF8) {
		t.Fatalf("utf8 %v", err)
	}
	mandant, event := fillID(0x11), fillID(0x22)
	hash, err := protocol.AufrufHash(mandant, event, got)
	if err != nil {
		t.Fatal(err)
	}
	wieder, err := protocol.EventHash(mandant, event, got)
	if err != nil || hash != wieder {
		t.Fatalf("hash %x %x %v", hash, wieder, err)
	}
}

func TestAussageBytes(t *testing.T) {
	a := protocol.Aussage{
		Mandant: fillID(0x11),
		Person:  "Ada",
		Rolle:   protocol.RollePerson,
		Von:     10,
		Bis:     20,
	}
	got, err := protocol.AussageBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("aussage"), bytes.Repeat([]byte{0x11}, 16)...)
	want = append(want, text("Ada")...)
	want = append(want, byte(protocol.RollePerson))
	want = append(want, be64(10)...)
	want = append(want, be64(20)...)
	want = append(want, make([]byte, 32)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("aussage\n got %x\nwant %x", got, want)
	}
	back, err := protocol.ParseAussage(got)
	if err != nil || back != a {
		t.Fatalf("parse %+v %v", back, err)
	}
	if !a.Deckt(10) || !a.Deckt(20) || a.Deckt(9) || a.Deckt(21) {
		t.Fatal("gültigkeit")
	}
	a.Rolle = protocol.RolleDatenschuetzer
	if _, err := protocol.AussageBytes(a); !errors.Is(err, protocol.ErrRolle) {
		t.Fatalf("finger %v", err)
	}
	a.Finger[0] = 1
	if _, err := protocol.AussageBytes(a); err != nil {
		t.Fatal(err)
	}
	a.Rolle = protocol.RollePerson
	if _, err := protocol.AussageBytes(a); !errors.Is(err, protocol.ErrRolle) {
		t.Fatalf("person finger %v", err)
	}
	a.Finger = protocol.Hash{}
	a.Bis = 9
	if _, err := protocol.AussageBytes(a); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("zeit %v", err)
	}
}

func TestLogUndAuffangBytes(t *testing.T) {
	teil := protocol.AussageTeil{
		Nutzlast: protocol.Aussage{
			Mandant: fillID(0x11),
			Person:  "Ada",
			Rolle:   protocol.RollePerson,
			Von:     1,
			Bis:     2,
		},
		Signatur: []byte{0xab, 0xcd},
	}
	log, err := protocol.LogBytes(protocol.LogInhalt{
		Text:     []byte("hi"),
		Vorgang:  "V-1",
		Aussagen: []protocol.AussageTeil{teil},
		Bezuege:  []string{"Ada", "Bea"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseLog(log)
	if err != nil || string(got.Text) != "hi" || got.Vorgang != "V-1" || len(got.Aussagen) != 1 || len(got.Bezuege) != 2 {
		t.Fatalf("parse %+v %v", got, err)
	}
	if !bytes.Equal(got.Aussagen[0].Signatur, teil.Signatur) || got.Bezuege[1] != "Bea" {
		t.Fatalf("teil %+v", got)
	}
	fremd := teil
	fremd.Nutzlast.Person = "Cleo"
	if _, err := protocol.LogBytes(protocol.LogInhalt{
		Aussagen: []protocol.AussageTeil{fremd},
		Bezuege:  []string{"Ada"},
	}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("fremd %v", err)
	}
	auffang, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:    protocol.GrundZielFehlt,
		Text:     []byte("hi"),
		Personen: []string{"Ada"},
		Aussagen: []protocol.AussageTeil{teil},
	})
	if err != nil {
		t.Fatal(err)
	}
	back, err := protocol.ParseAuffang(auffang)
	if err != nil || back.Grund != protocol.GrundZielFehlt || len(back.Aussagen) != 1 {
		t.Fatalf("auffang %+v %v", back, err)
	}
	if _, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:    protocol.GrundUnbekannt,
		Personen: []string{"Ada"},
		Aussagen: []protocol.AussageTeil{teil},
	}); !errors.Is(err, protocol.ErrGrund) {
		t.Fatalf("aussage bei unbekannt %v", err)
	}
	if _, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:  protocol.GrundOhneBezug,
		Angabe: "fremd",
	}); !errors.Is(err, protocol.ErrGrund) {
		t.Fatalf("angabe %v", err)
	}
	offen, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:  protocol.GrundMandantUnbekannt,
		Angabe: "Niemand",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParseAuffang(append(offen, 0)); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("rest %v", err)
	}
}

func TestVerweisUndIndex(t *testing.T) {
	v := protocol.Verweis{
		Art:        protocol.VerweisPerson,
		Schluessel: "Ada",
		Mandant:    fillID(0x11),
		Bind:       fillID(0x22),
		Seq:        4,
	}
	raw, err := protocol.VerweisBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("verweis"), byte(protocol.VerweisPerson))
	want = append(want, text("Ada")...)
	want = append(want, bytes.Repeat([]byte{0x11}, 16)...)
	want = append(want, bytes.Repeat([]byte{0x22}, 16)...)
	want = append(want, make([]byte, protocol.EpochLen)...)
	want = append(want, be64(4)...)
	if !bytes.Equal(raw, want) {
		t.Fatalf("verweis\n got %x\nwant %x", raw, want)
	}
	if _, err := protocol.ParseVerweis(raw); err != nil {
		t.Fatal(err)
	}
	idx := protocol.IndexEintrag{
		Nummer:    "V-1",
		Person:    "Ada",
		Rolle:     protocol.RolleGruppe,
		Kohorte:   "Nord",
		Seq:       4,
		Zeitpunkt: 9,
	}
	raw, err = protocol.IndexBytes(idx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseIndex(raw)
	if err != nil || got != idx {
		t.Fatalf("index %+v %v", got, err)
	}
	idx.Kohorte = ""
	if _, err := protocol.IndexBytes(idx); !errors.Is(err, protocol.ErrRolle) {
		t.Fatalf("kohorte %v", err)
	}
	idx.Rolle = protocol.RolleEinzel
	if _, err := protocol.IndexBytes(idx); err != nil {
		t.Fatal(err)
	}
}

func TestKatalogBytes(t *testing.T) {
	gruppe := protocol.Kennung{
		Rolle:   protocol.RolleGruppe,
		Ablage:  fillID(0x22),
		Bind:    fillID(0x22),
		Kohorte: "Nord",
		Aktiv:   protocol.KennungAn,
	}
	einzel := protocol.Kennung{
		Rolle:  protocol.RolleEinzel,
		Ablage: fillID(0x33),
		Bind:   fillID(0x44),
		Aktiv:  protocol.KennungAus,
	}
	raw, err := protocol.KatalogBytes(protocol.Stand{Name: "Mandant", Kennungen: []protocol.Kennung{gruppe, einzel}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseKatalog(raw)
	if err != nil || got.Name != "Mandant" || len(got.Kennungen) != 2 || got.Kennungen[1].Aktiv != protocol.KennungAus {
		t.Fatalf("katalog %+v %v", got, err)
	}
	if _, err := protocol.KatalogBytes(protocol.Stand{Name: "Mandant", Kennungen: []protocol.Kennung{gruppe, gruppe}}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("doppelt %v", err)
	}
	einzel.Kohorte = "Nord"
	if _, err := protocol.KatalogBytes(protocol.Stand{Name: "Mandant", Kennungen: []protocol.Kennung{einzel}}); !errors.Is(err, protocol.ErrRolle) {
		t.Fatalf("einzel kohorte %v", err)
	}
}

func TestSummeUndAnfrage(t *testing.T) {
	var epoch protocol.EpochID
	copy(epoch[:], "20261101T000000Z")
	beleg := protocol.Beleg{Epoch: epoch, Hash: protocol.Hash{7}}
	raw, err := protocol.BelegBytes(beleg)
	if err != nil {
		t.Fatal(err)
	}
	gotBeleg, err := protocol.ParseBeleg(raw)
	if err != nil || gotBeleg != beleg {
		t.Fatalf("beleg %+v %v", gotBeleg, err)
	}
	ada := protocol.Bezug{Name: "Ada", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Erster: 5, Letzter: 9}
	bea := protocol.Bezug{Name: "Bea", Rolle: protocol.RolleEinzel, Erster: 7, Letzter: 7}
	summe := protocol.VorgangSumme{Nummer: "V-1", Personen: []protocol.Bezug{ada, bea}}
	raw, err = protocol.VorgangSummeBytes(summe)
	if err != nil {
		t.Fatal(err)
	}
	gotSumme, err := protocol.ParseVorgangSumme(raw)
	if err != nil || gotSumme.Nummer != "V-1" || len(gotSumme.Personen) != 2 || gotSumme.Personen[1].Name != "Bea" {
		t.Fatalf("summe %+v %v", gotSumme, err)
	}
	summe.Personen = []protocol.Bezug{bea, ada}
	if _, err := protocol.VorgangSummeBytes(summe); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("ordnung %v", err)
	}
	person := protocol.PersonSumme{Person: "Ada", Nummern: []protocol.Bezug{
		{Name: "V-1", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Erster: 5, Letzter: 9},
	}}
	raw, err = protocol.PersonSummeBytes(person)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParsePersonSumme(raw); err != nil {
		t.Fatal(err)
	}
	anfrage := protocol.Indexanfrage{
		Mandant: fillID(0x11), Zone: fillID(0x61), Person: "Dora", Art: protocol.AnfrageVorgang,
		Schluessel: "V-1", Von: 1, Bis: 2, Zeitpunkt: 3,
	}
	raw, err = protocol.IndexanfrageBytes(anfrage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseIndexanfrage(raw)
	if err != nil || got != anfrage {
		t.Fatalf("anfrage %+v %v", got, err)
	}
	anfrage.Bis = anfrage.Von
	if _, err := protocol.IndexanfrageBytes(anfrage); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("fenster %v", err)
	}
}
