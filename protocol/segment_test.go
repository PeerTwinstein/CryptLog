package protocol_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestSegmentklasse(t *testing.T) {
	if _, err := protocol.KleinsteKlasse(0); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("0 %v", err)
	}
	got, err := protocol.KleinsteKlasse(1)
	if err != nil || got != protocol.Segment256KiB {
		t.Fatalf("1 %d %v", got, err)
	}
	got, err = protocol.KleinsteKlasse(protocol.Segment256KiB)
	if err != nil || got != protocol.Segment256KiB {
		t.Fatalf("voll %d %v", got, err)
	}
	got, err = protocol.KleinsteKlasse(protocol.Segment256KiB + 1)
	if err != nil || got != protocol.Segment1MiB {
		t.Fatalf("darüber %d %v", got, err)
	}
	got, err = protocol.KleinsteKlasse(protocol.Segment32MiB)
	if err != nil || got != protocol.Segment32MiB {
		t.Fatalf("32 %d %v", got, err)
	}
	if _, err := protocol.KleinsteKlasse(protocol.Segment32MiB + 1); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("zu groß %v", err)
	}
	if protocol.Segmentklasse(protocol.Segment4MiB) != true || protocol.Segmentklasse(3) {
		t.Fatal("klasse")
	}
}

func TestObjektSchluessel(t *testing.T) {
	mandant := fillID(0x11)
	ablage := fillID(0x22)
	instanz := fillID(0x44)
	var prefix protocol.Prefix
	prefix[0] = 0xab
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 6, 16, 0, 0, 0, time.UTC), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ObjektSchluessel(mandant, ablage, epoch, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := mandant.Hex() + "/" + ablage.Hex() + "/" + epoch.String() + "/10"
	if got != want {
		t.Fatalf("schlüssel %s", got)
	}
	if _, err := protocol.ObjektSchluessel(mandant, ablage, epoch, 0); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("nr 0 %v", err)
	}
}

func TestZerlegen(t *testing.T) {
	var kek protocol.Hash
	for i := range kek {
		kek[i] = 0xAB
	}
	dek := fillID(0xCD)
	wrapped := bytes.Repeat([]byte{0x7E}, 64)
	kopf, err := protocol.KopfBereich(kek, dek, wrapped, 8192, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	var epoch protocol.EpochID
	copy(epoch[:], "20261106T160000Z")
	payload := protocol.ManifestPayload(epoch, protocol.Hash{}, protocol.Hash{1}, 3, 1, 2, protocol.Hash{})
	var sig protocol.Signature
	sig[0] = 0x5A
	manifest, err := protocol.ManifestRahmen(payload, sig, 8192, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	seg := make([]byte, protocol.Segment256KiB)
	copy(seg, kopf)
	copy(seg[len(seg)-len(manifest):], manifest)
	gotKopf, kette, gotManifest, err := protocol.Zerlegen(seg, 8192, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotKopf) != 8192 || len(kette) != 30 || len(gotManifest) != 8192 {
		t.Fatalf("kopf %d kette %d manifest %d", len(gotKopf), len(kette), len(gotManifest))
	}
	_, _, gotWrapped, n, err := protocol.ParseKopf(gotKopf)
	if err != nil || n != 32+16+4+64 || !bytes.Equal(gotWrapped, wrapped) {
		t.Fatalf("parse kopf n %d %v", n, err)
	}
	if _, kette, manifest, err := protocol.Zerlegen(seg, 8192, true, false); err != nil || manifest != nil || len(kette) != 31 {
		t.Fatalf("ohne manifest %d %v", len(kette), err)
	}
	if _, _, _, err := protocol.Zerlegen(seg[:1000], 8192, false, false); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("länge %v", err)
	}

	gross := bytes.Repeat([]byte{0x7E}, 253901)
	voll, err := protocol.KopfBereich(kek, dek, gross, 8192, padReader{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(voll) != protocol.Segment256KiB {
		t.Fatalf("voll %d", len(voll))
	}
	if _, _, _, err := protocol.Zerlegen(voll, 8192, true, true); !errors.Is(err, protocol.ErrRahmen) {
		t.Fatalf("überlappung %v", err)
	}
}

func TestObjektSchluesselUndKette(t *testing.T) {
	mandant, ablage := fillID(0x11), fillID(0x22)
	var prefix protocol.Prefix
	prefix[0] = 0xab
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 6, 16, 0, 0, 0, time.UTC), fillID(0x44), prefix)
	if err != nil {
		t.Fatal(err)
	}
	key, err := protocol.ObjektSchluessel(mandant, ablage, epoch, 10)
	if err != nil {
		t.Fatal(err)
	}
	gotM, gotA, gotE, nr, err := protocol.ParseObjektSchluessel(key)
	if err != nil || gotM != mandant || gotA != ablage || gotE != epoch || nr != 10 {
		t.Fatalf("parse %s %v", key, err)
	}
	if _, _, _, _, err := protocol.ParseObjektSchluessel(mandant.Hex() + "/" + ablage.Hex() + "/" + epoch.String() + "/01"); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("führende null %v", err)
	}

	var kek protocol.Hash
	kek[0] = 0xcd
	dek := fillID(0xee)
	wrapped := bytes.Repeat([]byte{0x7e}, 64)
	kopf, err := protocol.KopfBereich(kek, dek, wrapped, 8192, padReader{1})
	if err != nil {
		t.Fatal(err)
	}
	seg := make([]byte, protocol.Segment256KiB)
	copy(seg, kopf)
	chain, err := protocol.NewChain(mandant, ablage, epoch, dek, kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 31; seq++ {
		frame := make([]byte, 8192)
		nonce := protocol.MakeNonce(prefix, seq)
		copy(frame, nonce[:])
		frame[20] = byte(seq)
		copy(seg[seq*8192:], frame)
		if err := chain.Append(seq, nonce, frame[protocol.NonceLen:8192-protocol.TagLen], frame[8192-protocol.TagLen:]); err != nil {
			t.Fatal(err)
		}
	}
	want, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	count, err := chain.Count()
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := protocol.KetteAusSegmenten(mandant, ablage, epoch, 8192, [][]byte{seg})
	if err != nil {
		t.Fatal(err)
	}
	if got != want || n != count || n != 31 {
		t.Fatalf("kette %d/%d", n, count)
	}
}
