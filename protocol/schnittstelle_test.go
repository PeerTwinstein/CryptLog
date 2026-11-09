package protocol_test

import (
	"bytes"
	"testing"

	"cryptlog/protocol"
)

func TestEreignisUndBestaetigt(t *testing.T) {
	a := protocol.EreignisAufruf{
		ID: fillID(0x42), Mandant: fillID(0x11), Zeit: 1500,
		Vorgang: "V-1", Personen: []string{"Ada"}, Text: []byte("text"),
	}
	raw, err := protocol.EreignisBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseEreignis(raw)
	if err != nil || got.ID != a.ID || got.Mandant != a.Mandant || got.Vorgang != a.Vorgang || string(got.Text) != "text" || len(got.Personen) != 1 || got.Personen[0] != "Ada" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := protocol.ParseEreignis(append(raw, 0)); err == nil {
		t.Fatal("zusatz")
	}
	a.Angabe = "fremd"
	a.Mandant = protocol.ID{}
	raw, err = protocol.EreignisBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err = protocol.ParseEreignis(raw)
	if err != nil || got.Angabe != "fremd" || got.Mandant != (protocol.ID{}) {
		t.Fatalf("ohne mandant %v %+v", err, got)
	}
	a.Mandant = fillID(0x11)
	if _, err := protocol.EreignisBytes(a); err == nil {
		t.Fatal("angabe und mandant")
	}

	best := protocol.Bestaetigt{Event: a.ID, Hash: protocol.Hash{7}, Seq: 3, Schluessel: "annahme/aa/3"}
	roh, err := protocol.BestaetigtBytes(best)
	if err != nil {
		t.Fatal(err)
	}
	zurueck, err := protocol.ParseBestaetigt(roh)
	if err != nil || zurueck != best {
		t.Fatalf("%v %+v", err, zurueck)
	}
	if _, err := protocol.ParseBestaetigt(bytes.TrimSuffix(roh, []byte("3"))); err == nil {
		t.Fatal("kurz")
	}
}
