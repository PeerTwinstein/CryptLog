package werkzeug

import (
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestAnnahmePrevious(t *testing.T) {
	var mandant, ablage, instanz, batch protocol.ID
	mandant[0], ablage[0], instanz[0], batch[0] = 0x11, 0x22, 0x44, 0x0b
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC), instanz, protocol.Prefix{3})
	if err != nil {
		t.Fatal(err)
	}
	slots := make([]protocol.Slot, 8)
	for i := range slots {
		slots[i].Event[0] = byte(0x10 + i)
		slots[i].Hash[0] = byte(i + 1)
	}
	erste, err := protocol.AnnahmePayload(batch, instanz, 1, protocol.AnnahmeGenesis(instanz), slots, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocol.AnnahmeHash(erste)
	if err != nil {
		t.Fatal(err)
	}
	var falsch protocol.Hash
	falsch[0] = 9
	zweite, err := protocol.AnnahmePayload(batch, instanz, 2, falsch, slots, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := Auftrag{Mandant: mandant, Ablage: ablage, Epoch: epoch}
	saetze, segs, err := segmenteAusAnnahme(Auftrag{
		Mandant: mandant, Ablage: ablage, Epoch: epoch,
		Annahmen: [][]byte{erste, zweite},
	})
	if err != nil || len(segs) != 0 || len(saetze) != 2 {
		t.Fatalf("leer %d %v", len(segs), err)
	}
	manifest := protocol.Manifest{AnnahmeFirst: 1, AnnahmeLast: 2, AnnahmeHead: hash}
	if _, err := annahmeBereich(a, manifest, saetze); err != ErrAnnahme {
		t.Fatalf("previous %v", err)
	}
	richtig, err := protocol.AnnahmePayload(batch, instanz, 2, hash, slots, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kopf, err := protocol.AnnahmeHash(richtig)
	if err != nil {
		t.Fatal(err)
	}
	saetze, _, err = segmenteAusAnnahme(Auftrag{
		Mandant: mandant, Ablage: ablage, Epoch: epoch,
		Annahmen: [][]byte{erste, richtig},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest.AnnahmeHead = kopf
	bereich, err := annahmeBereich(a, manifest, saetze)
	if err != nil || len(bereich) != 2 || bereich[1].hash != kopf {
		t.Fatalf("kette %+v %v", bereich, err)
	}
}
