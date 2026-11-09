package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"cryptlog/protocol"
)

func TestParseNutzlast(t *testing.T) {
	batch, instanz, mandant := fillID(0x01), fillID(0x02), fillID(0x03)
	var previous protocol.Hash
	previous[0] = 0xab
	slots := make([]protocol.Slot, 8)
	for i := range slots {
		slots[i].Event = fillID(byte(0x10 + i))
		slots[i].Hash[0] = byte(i)
	}
	segs := []protocol.SegmentRef{{ObjectKey: "obj", Hash: protocol.Hash{9}}}
	var nonce protocol.Nonce
	nonce[0] = 1
	blobs := []protocol.Blob{{
		Mandant:    mandant,
		WrappedKey: []byte{0xee},
		Nonce:      nonce,
		Ciphertext: []byte{0x10},
		Tag:        bytes.Repeat([]byte{0x7e}, protocol.TagLen),
	}}
	ann, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, segs, blobs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseAnnahme(ann)
	if err != nil {
		t.Fatal(err)
	}
	if got.Batch != batch || got.Instanz != instanz || got.BatchSeq != 7 || !got.HasPrevious || got.Previous != previous {
		t.Fatalf("kopf %+v", got)
	}
	if len(got.Slots) != 8 || got.Slots[3] != slots[3] || len(got.Segmente) != 1 || got.Segmente[0].ObjectKey != "obj" {
		t.Fatal("plätze")
	}
	if len(got.Bloecke) != 1 || !bytes.Equal(got.Bloecke[0].WrappedKey, blobs[0].WrappedKey) || !bytes.Equal(got.Bloecke[0].Tag, blobs[0].Tag) {
		t.Fatal("blob")
	}
	vor, err := protocol.VorbereitungPayload(batch, instanz, 7, slots, segs, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParseAnnahme(vor); !errors.Is(err, protocol.ErrDomain) {
		t.Fatalf("domäne %v", err)
	}
	zurueck, err := protocol.AnnahmeAusVorbereitung(vor, previous)
	if err != nil || !bytes.Equal(zurueck, ann) {
		t.Fatalf("aus vorbereitung %v", err)
	}
	ann2, err := protocol.AnnahmePayload(batch, instanz, 8, previous, slots, segs, blobs)
	if err != nil {
		t.Fatal(err)
	}
	slots[0].Event = fillID(0x10)
	konflikt, err := protocol.EreignisKonflikt([][]byte{ann, ann2})
	if err != nil || !konflikt {
		t.Fatalf("zwei annahmen %v %v", konflikt, err)
	}
	einer, err := protocol.EreignisKonflikt([][]byte{ann})
	if err != nil || einer {
		t.Fatalf("eine annahme %v", einer)
	}
}
