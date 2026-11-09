package protocol_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"cryptlog/protocol"
)

func TestBelegungBytes(t *testing.T) {
	b := protocol.Belegung{
		Event:      fillID(0x11),
		Instanz:    fillID(0x22),
		Batch:      fillID(0x33),
		Generation: 1,
		Lage:       protocol.LageOffen,
		Hash:       protocol.Hash{0x44},
	}
	got, err := protocol.BelegungBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("belegung"), b.Event[:]...)
	want = append(want, b.Instanz[:]...)
	want = append(want, b.Batch[:]...)
	want = append(want, be64(1)...)
	want = append(want, byte(protocol.LageOffen))
	want = append(want, b.Hash[:]...)
	if !bytes.Equal(got, want) || len(got) != protocol.BelegungLen {
		t.Fatalf("belegung %d\n%x", len(got), got)
	}
	back, err := protocol.ParseBelegung(got)
	if err != nil || back != b {
		t.Fatalf("parse %+v %v", back, err)
	}
	if protocol.BelegungSchluessel(b.Event) != "belegt/"+b.Event.Hex() {
		t.Fatal("schlüssel")
	}
	raw := append([]byte(nil), got...)
	binary.BigEndian.PutUint64(raw[4+8+16+16+16:], 0)
	if _, err := protocol.ParseBelegung(raw); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("generation 0 %v", err)
	}
	if _, err := protocol.BelegungBytes(protocol.Belegung{}); !errors.Is(err, protocol.ErrLength) {
		t.Fatal(err)
	}
}

func TestInstanzBytes(t *testing.T) {
	lauf := protocol.InstanzLauf{Instanz: fillID(0x22), Frist: 0x0102030405060708}
	got := protocol.InstanzBytes(lauf)
	want := append(text("instanz"), lauf.Instanz[:]...)
	want = append(want, be64(lauf.Frist)...)
	if !bytes.Equal(got, want) || len(got) != protocol.InstanzLen {
		t.Fatalf("instanz %x", got)
	}
	back, err := protocol.ParseInstanzLauf(got)
	if err != nil || back != lauf {
		t.Fatalf("parse %+v %v", back, err)
	}
	if protocol.InstanzSchluessel(lauf.Instanz) != "instanz/"+lauf.Instanz.Hex() {
		t.Fatal("schlüssel")
	}
}

func TestEntscheiden(t *testing.T) {
	eigene := fillID(0x22)
	fremd := fillID(0x99)
	hash := protocol.Hash{1}
	anderer := protocol.Hash{2}
	beleg := protocol.Belegung{Event: fillID(1), Instanz: eigene, Batch: fillID(3), Generation: 1, Lage: protocol.LageOffen, Hash: hash}
	lauf := protocol.InstanzLauf{Instanz: eigene, Frist: 100}
	neu, err := protocol.Entscheiden(nil, hash, false, eigene, 50, nil)
	if err != nil || neu != protocol.EntscheidNeu {
		t.Fatalf("neu %v %v", neu, err)
	}
	if _, err := protocol.Entscheiden(nil, hash, true, eigene, 50, nil); !errors.Is(err, protocol.ErrBelegung) {
		t.Fatalf("annahme ohne belegung %v", err)
	}
	ab, err := protocol.Entscheiden(&beleg, anderer, false, eigene, 50, &lauf)
	if err != nil || ab != protocol.EntscheidAbgelehnt {
		t.Fatalf("hash %v", ab)
	}
	offen, err := protocol.Entscheiden(&beleg, hash, true, fremd, 1000, nil)
	if err != nil || offen != protocol.EntscheidUebernahme {
		t.Fatalf("offen trotz annahme %v", offen)
	}
	angenommen := beleg
	angenommen.Lage = protocol.LageAngenommen
	ok, err := protocol.Entscheiden(&angenommen, hash, true, fremd, 1000, nil)
	if err != nil || ok != protocol.EntscheidBestaetigt {
		t.Fatalf("bestätigt %v", ok)
	}
	weiter, err := protocol.Entscheiden(&beleg, hash, false, eigene, 1000, nil)
	if err != nil || weiter != protocol.EntscheidWeiter {
		t.Fatalf("weiter %v", weiter)
	}
	gehalten, err := protocol.Entscheiden(&beleg, hash, false, fremd, 99, &lauf)
	if err != nil || gehalten != protocol.EntscheidGehalten {
		t.Fatalf("gehalten %v", gehalten)
	}
	schiefe, err := protocol.Entscheiden(&beleg, hash, false, fremd, 100, &lauf)
	if err != nil || schiefe != protocol.EntscheidGehalten {
		t.Fatalf("schiefe %v", schiefe)
	}
	ueber, err := protocol.Entscheiden(&beleg, hash, false, fremd, 100+protocol.UhrSchiefe, &lauf)
	if err != nil || ueber != protocol.EntscheidUebernahme {
		t.Fatalf("frist %v", ueber)
	}
	ohne, err := protocol.Entscheiden(&beleg, hash, false, fremd, 1, nil)
	if err != nil || ohne != protocol.EntscheidUebernahme {
		t.Fatalf("ohne instanzobjekt %v", ohne)
	}
	nach, err := beleg.Nachfolger(fremd, fillID(0x44))
	if err != nil || nach.Generation != 2 || nach.Event != beleg.Event || nach.Hash != beleg.Hash || nach.Instanz != fremd || nach.Batch != fillID(0x44) {
		t.Fatalf("nachfolger %+v %v", nach, err)
	}
	beleg.Generation = ^uint64(0)
	if _, err := beleg.Nachfolger(fremd, fillID(1)); !errors.Is(err, protocol.ErrLength) {
		t.Fatal(err)
	}
}

func TestPlaetzeUndSchluessel(t *testing.T) {
	if n, err := protocol.SlotZahl(0); err != nil || n != 8 {
		t.Fatalf("0 %d %v", n, err)
	}
	if n, err := protocol.SlotZahl(9); err != nil || n != 16 {
		t.Fatalf("9 %d %v", n, err)
	}
	instanz := fillID(0x22)
	key, err := protocol.AnnahmeSchluessel(instanz, 10)
	if err != nil || key != "annahme/"+instanz.Hex()+"/10" {
		t.Fatalf("annahme %s %v", key, err)
	}
	if _, err := protocol.VorbereitungSchluessel(instanz, 0); !errors.Is(err, protocol.ErrLength) {
		t.Fatal(err)
	}

	ev := protocol.Slot{Event: fillID(0x11), Hash: protocol.Hash{7}}
	var zufall []byte
	zufall = append(zufall, ev.Event[:]...)
	zufall = append(zufall, bytes.Repeat([]byte{0x01}, 32)...)
	for i := 0; i < 7; i++ {
		zufall = append(zufall, bytes.Repeat([]byte{byte(0x30 + i)}, 16)...)
		zufall = append(zufall, bytes.Repeat([]byte{0x33}, 32)...)
	}
	plaetze, err := protocol.Plaetze([]protocol.Slot{ev}, bytes.NewReader(zufall))
	if err != nil {
		t.Fatal(err)
	}
	if len(plaetze) != 8 || plaetze[0] != ev || plaetze[1].Event != fillID(0x30) {
		t.Fatalf("plätze %+v", plaetze[0:2])
	}
	if _, err := protocol.Plaetze([]protocol.Slot{ev, ev}, bytes.NewReader(nil)); !errors.Is(err, protocol.ErrEvent) {
		t.Fatal(err)
	}
}
