package protocol_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestGenesisBytes(t *testing.T) {
	ablage, instanz := fillID(0x11), fillID(0x22)
	want := digest(
		[]byte{0x00, 0x00, 0x00, 0x07},
		[]byte("genesis"),
		ablage[:],
		instanz[:],
	)
	if got := protocol.Genesis(ablage, instanz); got != want {
		t.Fatalf("Genesis = %x, erwartet %x", got, want)
	}
	if protocol.Genesis(instanz, ablage) == want {
		t.Fatal("vertauschte Kennungen ergeben denselben Genesis-Hash")
	}
}

func TestEpochHeadUndEintrag(t *testing.T) {
	ablage := fillID(0x11)
	dek := fillID(0x44)
	var kek protocol.Hash
	for i := range kek {
		kek[i] = 0x55
	}
	var prefix protocol.Prefix
	copy(prefix[:], []byte{0x10, 0x20, 0x30, 0x40})
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC), fillID(0x22), prefix)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := []byte{0xaa, 0xbb, 0xcc}

	head, err := protocol.EpochHead(ablage, kek, epoch, dek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	wantHead := digest(
		[]byte{0x00, 0x00, 0x00, 0x0a},
		[]byte("epoch-head"),
		ablage[:],
		kek[:],
		epoch[:],
		dek[:],
		[]byte{0x00, 0x00, 0x00, 0x03},
		wrapped,
	)
	if head != wantHead {
		t.Fatalf("head_0 = %x, erwartet %x", head, wantHead)
	}
	if _, err := protocol.EpochHead(ablage, kek, epoch, dek, nil); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("leerer Wrap: %v", err)
	}

	nonce := protocol.MakeNonce(prefix, 1)
	ct := []byte{0x01, 0x02}
	tag := bytes.Repeat([]byte{0x7e}, protocol.TagLen)
	mandant := fillID(0x01)
	aad := protocol.AAD(mandant, ablage, epoch, dek, 1)
	entry, err := protocol.EntryHead(head, dek, 1, nonce, ct, tag, aad)
	if err != nil {
		t.Fatal(err)
	}
	wantEntry := digest(
		[]byte{0x00, 0x00, 0x00, 0x05},
		[]byte("entry"),
		head[:],
		dek[:],
		be64(1),
		nonce[:],
		[]byte{0x00, 0x00, 0x00, 0x02},
		ct,
		tag,
		[]byte{0x00, 0x00, 0x00, 92},
		aad,
	)
	if entry != wantEntry {
		t.Fatalf("head_1 = %x, erwartet %x", entry, wantEntry)
	}
	if _, err := protocol.EntryHead(head, dek, 1, nonce, ct, tag[:15], aad); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("kurzes Tag: %v", err)
	}
}

func TestChain(t *testing.T) {
	mandant, ablage, dek := fillID(0x01), fillID(0x11), fillID(0x44)
	instanz := fillID(0x22)
	var kek protocol.Hash
	for i := range kek {
		kek[i] = 0x55
	}
	var prefix protocol.Prefix
	copy(prefix[:], []byte{0x10, 0x20, 0x30, 0x40})
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := []byte{0xaa, 0xbb}

	chain, err := protocol.NewChain(mandant, ablage, epoch, dek, kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	head, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	want, err := protocol.EpochHead(ablage, kek, epoch, dek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if head != want {
		t.Fatal("offene Kette beginnt nicht bei head_0")
	}
	if n, err := chain.Count(); err != nil || n != 0 {
		t.Fatalf("Count = %d, %v", n, err)
	}

	ct := []byte{0x01}
	tag := bytes.Repeat([]byte{0x7e}, protocol.TagLen)
	if err := chain.Append(1, protocol.MakeNonce(prefix, 1), ct, tag); err != nil {
		t.Fatal(err)
	}
	if err := chain.Append(2, protocol.MakeNonce(prefix, 2), ct, tag); err != nil {
		t.Fatal(err)
	}
	head, err = chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := chain.Manifest(protocol.Genesis(ablage, instanz), 1, 1, protocol.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, protocol.ManifestPayload(epoch, protocol.Genesis(ablage, instanz), head, 2, 1, 1, protocol.Hash{})) {
		t.Fatal("Manifest verwendet nicht Kettenkopf und entry_count")
	}
	if n, err := chain.Count(); err != nil || n != 2 {
		t.Fatalf("Count = %d, %v", n, err)
	}
	if err := chain.Append(2, protocol.MakeNonce(prefix, 2), ct, tag); !errors.Is(err, protocol.ErrSeq) {
		t.Fatalf("wiederholte Sequenz: %v", err)
	}
	if err := chain.Append(4, protocol.MakeNonce(prefix, 4), ct, tag); !errors.Is(err, protocol.ErrSeq) {
		t.Fatalf("Lücke: %v", err)
	}

	var other protocol.Prefix
	other[0] = 0xff
	if err := chain.Append(3, protocol.MakeNonce(other, 3), ct, tag); !errors.Is(err, protocol.ErrNonce) {
		t.Fatalf("fremder Präfix: %v", err)
	}
	bad := protocol.MakeNonce(prefix, 3)
	bad[11] = 9
	if err := chain.Append(3, bad, ct, tag); !errors.Is(err, protocol.ErrNonce) {
		t.Fatalf("Nonce-Sequenz: %v", err)
	}

	var zero protocol.Chain
	if _, err := zero.Head(); !errors.Is(err, protocol.ErrChain) {
		t.Fatalf("leere Kette: %v", err)
	}
	if err := zero.Append(1, protocol.MakeNonce(prefix, 1), ct, tag); !errors.Is(err, protocol.ErrChain) {
		t.Fatalf("Append auf leerer Kette: %v", err)
	}
}

func TestManifestUndBestaetigung(t *testing.T) {
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC), fillID(0x22), protocol.Prefix{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	var previous, chainHead, annahmeHead protocol.Hash
	previous[0] = 1
	chainHead[0] = 2
	annahmeHead[0] = 3
	payload := protocol.ManifestPayload(epoch, previous, chainHead, 4, 8, 9, annahmeHead)
	want := append([]byte{}, text("manifest")...)
	want = append(want, epoch[:]...)
	want = append(want, previous[:]...)
	want = append(want, chainHead[:]...)
	want = append(want, be64(4)...)
	want = append(want, be64(8)...)
	want = append(want, be64(9)...)
	want = append(want, annahmeHead[:]...)
	if !bytes.Equal(payload, want) {
		t.Fatalf("Manifest:\n%x\n%x", payload, want)
	}
	gotManifest, err := protocol.ParseManifest(payload)
	if err != nil || gotManifest.Epoch != epoch || gotManifest.Previous != previous || gotManifest.ChainHead != chainHead || gotManifest.Count != 4 || gotManifest.AnnahmeFirst != 8 || gotManifest.AnnahmeLast != 9 || gotManifest.AnnahmeHead != annahmeHead {
		t.Fatalf("parse %+v %v", gotManifest, err)
	}
	if _, err := protocol.ParseManifest(payload[:len(payload)-1]); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("kurz %v", err)
	}

	var sig protocol.Signature
	for i := range sig {
		sig[i] = 0x5a
	}
	got, err := protocol.EpochHash(payload, sig)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := digest(text("epoch-hash"), payload, be32(protocol.SignatureLen), sig[:])
	if got != wantHash {
		t.Fatalf("epoch_hash = %x", got)
	}
	if _, err := protocol.EpochHash(text("vorbereitung"), sig); !errors.Is(err, protocol.ErrDomain) {
		t.Fatalf("falsche Domäne: %v", err)
	}

	confirm := protocol.ConfirmationPayload(got)
	if !bytes.Equal(confirm, append(text("confirm"), got[:]...)) {
		t.Fatalf("Bestätigung = %x", confirm)
	}
}
