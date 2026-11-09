package protocol_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestEventHashBytes(t *testing.T) {
	mandant, event := fillID(0x01), fillID(0x02)
	klartext := []byte("hallo")
	got, err := protocol.EventHash(mandant, event, klartext)
	if err != nil {
		t.Fatal(err)
	}
	want := digest(
		[]byte{0x00, 0x00, 0x00, 0x05},
		[]byte("event"),
		mandant[:],
		event[:],
		[]byte{0x00, 0x00, 0x00, 0x05},
		klartext,
	)
	if got != want {
		t.Fatalf("event_hash = %x", got)
	}
	other, err := protocol.EventHash(mandant, event, []byte("hallo!"))
	if err != nil {
		t.Fatal(err)
	}
	if other == got {
		t.Fatal("anderer Klartext ergibt denselben Hash")
	}
}

func TestBindungBytes(t *testing.T) {
	batch := fillID(0x0b)
	event := fillID(0x44)
	got, err := protocol.Bindung(batch, []protocol.SeqEintrag{
		{Seq: 1, Art: protocol.ArtEreignis, Event: event},
		{Seq: 2, Art: protocol.ArtFuellung},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("bindung"), batch[:]...)
	want = append(want, be64(2)...)
	want = append(want, be64(1)...)
	want = append(want, byte(protocol.ArtEreignis))
	want = append(want, event[:]...)
	want = append(want, be64(2)...)
	want = append(want, byte(protocol.ArtFuellung))
	want = append(want, make([]byte, protocol.IDLen)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Bindung:\n%x\n%x", got, want)
	}

	if _, err := protocol.Bindung(batch, []protocol.SeqEintrag{{Art: 9}}); !errors.Is(err, protocol.ErrArt) {
		t.Fatalf("Art: %v", err)
	}
	if _, err := protocol.Bindung(batch, []protocol.SeqEintrag{{Seq: 3, Art: protocol.ArtFortsetzung, Event: event}}); !errors.Is(err, protocol.ErrEvent) {
		t.Fatalf("Fortsetzung mit event_id: %v", err)
	}
	if _, err := protocol.Bindung(batch, []protocol.SeqEintrag{{Art: protocol.ArtEreignis}}); err != nil {
		t.Fatalf("Ereignis ohne gesetzte event_id: %v", err)
	}
	gotBatch, gotEntries, err := protocol.ParseBindung(got)
	if err != nil || gotBatch != batch || len(gotEntries) != 2 || gotEntries[0].Event != event || gotEntries[1].Art != protocol.ArtFuellung {
		t.Fatalf("ParseBindung %+v %v", gotEntries, err)
	}
	if _, _, err := protocol.ParseBindung(append(got, 0)); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("Rest: %v", err)
	}
}

func TestAnnahmeBytes(t *testing.T) {
	batch, instanz, mandant := fillID(0x01), fillID(0x02), fillID(0x03)
	var previous protocol.Hash
	for i := range previous {
		previous[i] = 0xab
	}
	slots := make([]protocol.Slot, 8)
	for i := range slots {
		slots[i].Event = fillID(byte(0x10 + i))
		slots[i].Hash[0] = byte(i)
	}
	segs := []protocol.SegmentRef{{ObjectKey: "obj", Hash: protocol.Hash{9}}}
	var nonce protocol.Nonce
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	tag := bytes.Repeat([]byte{0x7e}, protocol.TagLen)
	blobs := []protocol.Blob{{
		Mandant:    mandant,
		WrappedKey: []byte{0xee, 0xff},
		Nonce:      nonce,
		Ciphertext: []byte{0x10, 0x20},
		Tag:        tag,
	}}

	got, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, segs, blobs)
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("annahme"), batch[:]...)
	want = append(want, instanz[:]...)
	want = append(want, be64(7)...)
	want = append(want, previous[:]...)
	want = append(want, be64(8)...)
	for _, slot := range slots {
		want = append(want, slot.Event[:]...)
		want = append(want, slot.Hash[:]...)
	}
	want = append(want, be64(1)...)
	want = append(want, 0, 0, 0, 3)
	want = append(want, "obj"...)
	want = append(want, segs[0].Hash[:]...)
	want = append(want, be64(1)...)
	want = append(want, mandant[:]...)
	want = append(want, 0, 0, 0, 2, 0xee, 0xff)
	want = append(want, nonce[:]...)
	want = append(want, 0, 0, 0, 2, 0x10, 0x20)
	want = append(want, tag...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Annahme:\n%x\n%x", got, want)
	}

	sum, err := protocol.AnnahmeHash(got)
	if err != nil {
		t.Fatal(err)
	}
	if sum != digest(text("annahme-hash"), got) {
		t.Fatalf("annahme_hash = %x", sum)
	}

	vor, err := protocol.VorbereitungPayload(batch, instanz, 7, slots, segs, blobs)
	if err != nil {
		t.Fatal(err)
	}
	wantVor := append(text("vorbereitung"), batch[:]...)
	wantVor = append(wantVor, instanz[:]...)
	wantVor = append(wantVor, be64(7)...)
	wantVor = append(wantVor, be64(8)...)
	for _, slot := range slots {
		wantVor = append(wantVor, slot.Event[:]...)
		wantVor = append(wantVor, slot.Hash[:]...)
	}
	wantVor = append(wantVor, be64(1)...)
	wantVor = append(wantVor, 0, 0, 0, 3)
	wantVor = append(wantVor, "obj"...)
	wantVor = append(wantVor, segs[0].Hash[:]...)
	wantVor = append(wantVor, be64(1)...)
	wantVor = append(wantVor, mandant[:]...)
	wantVor = append(wantVor, 0, 0, 0, 2, 0xee, 0xff)
	wantVor = append(wantVor, nonce[:]...)
	wantVor = append(wantVor, 0, 0, 0, 2, 0x10, 0x20)
	wantVor = append(wantVor, tag...)
	if !bytes.Equal(vor, wantVor) {
		t.Fatalf("Vorbereitung:\n%x\n%x", vor, wantVor)
	}
	if _, err := protocol.AnnahmeHash(vor); !errors.Is(err, protocol.ErrDomain) {
		t.Fatalf("AnnahmeHash über Vorbereitung: %v", err)
	}

	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots[:7], segs, blobs); !errors.Is(err, protocol.ErrSlotCount) {
		t.Fatalf("7 Plätze: %v", err)
	}
	slots16 := make([]protocol.Slot, 16)
	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots16, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, []protocol.SegmentRef{{Hash: protocol.Hash{}}}, blobs); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("leerer Schlüssel: %v", err)
	}
	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, []protocol.SegmentRef{{ObjectKey: "\xff"}}, blobs); !errors.Is(err, protocol.ErrUTF8) {
		t.Fatalf("UTF-8: %v", err)
	}
	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, nil, []protocol.Blob{{Mandant: mandant}}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("leerer Blob: %v", err)
	}
	short := blobs[0]
	short.Tag = short.Tag[:15]
	if _, err := protocol.AnnahmePayload(batch, instanz, 7, previous, slots, nil, []protocol.Blob{short}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("kurzes Tag: %v", err)
	}
}

func TestAnnahmeGenesisUndKontext(t *testing.T) {
	instanz := fillID(0x22)
	want := digest([]byte{0x00, 0x00, 0x00, 15}, []byte("annahme-genesis"), instanz[:])
	if got := protocol.AnnahmeGenesis(instanz); got != want {
		t.Fatalf("annahme_genesis = %x", got)
	}

	mandant, ablage, batch := fillID(1), fillID(2), fillID(3)
	var kek protocol.Hash
	kek[0] = 9
	epoch, err := protocol.NewEpochID(
		time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC),
		instanz,
		protocol.Prefix{1, 2, 3, 4},
	)
	if err != nil {
		t.Fatal(err)
	}
	wrapCtx := protocol.WrapContext(mandant, ablage, epoch, kek)
	if len(wrapCtx) != 112 || !bytes.HasPrefix(wrapCtx, text("dek-wrap")) {
		t.Fatalf("wrap_ctx len=%d prefix=%x", len(wrapCtx), wrapCtx[:12])
	}
	wantWrap := append(text("dek-wrap"), mandant[:]...)
	wantWrap = append(wantWrap, ablage[:]...)
	wantWrap = append(wantWrap, epoch[:]...)
	wantWrap = append(wantWrap, kek[:]...)
	if !bytes.Equal(wrapCtx, wantWrap) {
		t.Fatal("wrap_ctx weicht ab")
	}

	bindungCtx := protocol.BindungContext(mandant, batch, kek)
	wantBindung := append(text("annahme-bindung"), mandant[:]...)
	wantBindung = append(wantBindung, batch[:]...)
	wantBindung = append(wantBindung, kek[:]...)
	if len(bindungCtx) != 83 || !bytes.Equal(bindungCtx, wantBindung) {
		t.Fatalf("bindung_ctx = %x", bindungCtx)
	}
	aad := protocol.BindungAAD(mandant, batch, kek)
	wantAAD := append(text("bindung-aad"), mandant[:]...)
	wantAAD = append(wantAAD, batch[:]...)
	wantAAD = append(wantAAD, kek[:]...)
	if len(aad) != 79 || !bytes.Equal(aad, wantAAD) {
		t.Fatalf("bindung_aad len=%d %x", len(aad), aad)
	}
}
