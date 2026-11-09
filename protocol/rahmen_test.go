package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"cryptlog/protocol"
)

type padReader struct{ b byte }

func (p padReader) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = p.b
	}
	return len(dst), nil
}

func TestEreignisKlartextBytes(t *testing.T) {
	event := fillID(0x11)
	bind := fillID(0x22)
	got, err := protocol.EreignisKlartext(event, 0x0000000100000002, bind, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append(append(
		bytes.Repeat([]byte{0x11}, 16),
		be64(0x0000000100000002)...),
		bytes.Repeat([]byte{0x22}, 16)...),
		be32(2)...),
		'h', 'i')
	if !bytes.Equal(got, want) {
		t.Fatalf("klartext\n got %x\nwant %x", got, want)
	}
	if len(got) != 46 {
		t.Fatalf("länge %d", len(got))
	}
	ev, zeit, bi, inhalt, err := protocol.ParseEreignisKlartext(got)
	if err != nil {
		t.Fatal(err)
	}
	if ev != event || zeit != 0x0000000100000002 || bi != bind || string(inhalt) != "hi" {
		t.Fatalf("parse %x %d %x %q", ev, zeit, bi, inhalt)
	}
}

func TestEreignisKlartextLeer(t *testing.T) {
	got, err := protocol.EreignisKlartext(fillID(1), 0, fillID(2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 44 {
		t.Fatalf("länge %d", len(got))
	}
	_, _, _, inhalt, err := protocol.ParseEreignisKlartext(got)
	if err != nil || len(inhalt) != 0 {
		t.Fatalf("inhalt %x err %v", inhalt, err)
	}
	if _, _, _, _, err := protocol.ParseEreignisKlartext(got[:len(got)-1]); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("err %v", err)
	}
}

func TestSplitEinRahmen(t *testing.T) {
	klar, err := protocol.EreignisKlartext(fillID(0x11), 1, fillID(0x22), []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	frames, err := protocol.SplitEreignis(klar, 256, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || len(frames[0]) != 256-28 {
		t.Fatalf("rahmen %d len %d", len(frames), len(frames[0]))
	}
	f := frames[0]
	if f[0] != byte(protocol.ArtEreignis) {
		t.Fatalf("art %d", f[0])
	}
	if !bytes.Equal(f[1:9], be64(uint64(len(klar)))) {
		t.Fatalf("gesamt %x", f[1:9])
	}
	if !bytes.Equal(f[9:9+len(klar)], klar) {
		t.Fatalf("stück %x", f[9:9+len(klar)])
	}
	for _, b := range f[9+len(klar):] {
		if b != 0xA5 {
			t.Fatalf("zufall %x", f[9+len(klar):])
		}
	}
	back, err := protocol.JoinEreignis(frames)
	if err != nil || !bytes.Equal(back, klar) {
		t.Fatalf("join %v", err)
	}
}

func TestSplitMehrereRahmen(t *testing.T) {
	inhalt := bytes.Repeat([]byte{0x33}, 400)
	klar, err := protocol.EreignisKlartext(fillID(0x11), 7, fillID(0x22), inhalt)
	if err != nil {
		t.Fatal(err)
	}
	if len(klar) != 444 {
		t.Fatalf("klartext %d", len(klar))
	}
	frames, err := protocol.SplitEreignis(klar, 256, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("rahmen %d", len(frames))
	}
	nutz := 256 - 28
	if len(frames[0]) != nutz || frames[0][0] != 1 {
		t.Fatalf("erster rahmen")
	}
	// Erster Rahmen ist nach dem Kopf voll: 219 Datenbytes, kein Zufall.
	if !bytes.Equal(frames[0][9:], klar[:nutz-9]) {
		t.Fatal("erstes stück")
	}
	if frames[1][0] != byte(protocol.ArtFortsetzung) {
		t.Fatalf("art %d", frames[1][0])
	}
	rest := klar[nutz-9:]
	if !bytes.Equal(frames[1][1:1+len(rest)], rest) {
		t.Fatal("fortsetzung")
	}
	if !bytes.Equal(frames[1][1+len(rest):], []byte{0xA5, 0xA5}) {
		t.Fatalf("zufall %x", frames[1][1+len(rest):])
	}
	back, err := protocol.JoinEreignis(frames)
	if err != nil || !bytes.Equal(back, klar) {
		t.Fatalf("join %v", err)
	}
}

func TestLesenMitFuellung(t *testing.T) {
	a, _ := protocol.EreignisKlartext(fillID(1), 1, fillID(2), []byte("a"))
	b, _ := protocol.EreignisKlartext(fillID(3), 2, fillID(4), bytes.Repeat([]byte{9}, 400))
	fa, err := protocol.SplitEreignis(a, 256, padReader{1})
	if err != nil {
		t.Fatal(err)
	}
	fb, err := protocol.SplitEreignis(b, 256, padReader{2})
	if err != nil {
		t.Fatal(err)
	}
	fuell, err := protocol.Fuellrahmen(256, padReader{3})
	if err != nil {
		t.Fatal(err)
	}
	if fuell[0] != byte(protocol.ArtFuellung) {
		t.Fatalf("art %d", fuell[0])
	}
	seq := append(append(append([][]byte{}, fa...), fuell), fb...)
	got, err := protocol.Lesen(seq)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("lesen %d", len(got))
	}
}

func TestRahmenfolgeUngueltig(t *testing.T) {
	klar, err := protocol.EreignisKlartext(fillID(1), 1, fillID(2), bytes.Repeat([]byte{1}, 400))
	if err != nil {
		t.Fatal(err)
	}
	frames, err := protocol.SplitEreignis(klar, 256, padReader{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.JoinEreignis(frames[:1]); !errors.Is(err, protocol.ErrRahmen) {
		t.Fatalf("unvollständig %v", err)
	}
	broken := [][]byte{frames[0], append([]byte(nil), frames[1]...)}
	broken[1][0] = byte(protocol.ArtFuellung)
	if _, err := protocol.Lesen(broken); !errors.Is(err, protocol.ErrRahmen) {
		t.Fatalf("fuellung mitten im ereignis %v", err)
	}
	fort := append([]byte(nil), frames[1]...)
	if _, err := protocol.Lesen([][]byte{fort}); !errors.Is(err, protocol.ErrArt) {
		t.Fatalf("fortsetzung ohne ereignis %v", err)
	}
	short := [][]byte{append([]byte(nil), frames[0][:10]...)}
	if _, err := protocol.JoinEreignis(short); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("kurzer rahmen %v", err)
	}
}

func TestRahmenGroesse(t *testing.T) {
	klar, _ := protocol.EreignisKlartext(fillID(1), 1, fillID(2), nil)
	for _, n := range []int{128, 300, 384, 16384} {
		if _, err := protocol.SplitEreignis(klar, n, padReader{1}); !errors.Is(err, protocol.ErrLength) {
			t.Fatalf("größe %d err %v", n, err)
		}
	}
	if _, err := protocol.RahmenNutz(1024); err != nil {
		t.Fatal(err)
	}
}

func TestKopfBereich(t *testing.T) {
	var kek protocol.Hash
	for i := range kek {
		kek[i] = 0xAB
	}
	dek := fillID(0xCD)
	wrapped := bytes.Repeat([]byte{0x7E}, 300)
	bereich, err := protocol.KopfBereich(kek, dek, wrapped, 256, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	if len(bereich) != 512 {
		t.Fatalf("bereich %d", len(bereich))
	}
	gotKek, gotDek, gotWrapped, n, err := protocol.ParseKopf(bereich)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32+16+4+300 || gotKek != kek || gotDek != dek || !bytes.Equal(gotWrapped, wrapped) {
		t.Fatalf("kopf n %d", n)
	}
	if bereich[n] != 0xA5 || bereich[len(bereich)-1] != 0xA5 {
		t.Fatal("zufall")
	}
	if _, err := protocol.Kopf(kek, dek, nil); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("leer %v", err)
	}
}

func TestManifestRahmen(t *testing.T) {
	var epoch protocol.EpochID
	copy(epoch[:], "20261106T160000Z")
	payload := protocol.ManifestPayload(epoch, protocol.Hash{}, protocol.Hash{1}, 3, 1, 2, protocol.Hash{})
	if len(payload) != protocol.ManifestPayloadLen || protocol.ManifestPayloadLen != 168 {
		t.Fatalf("payload %d konstante %d", len(payload), protocol.ManifestPayloadLen)
	}
	var sig protocol.Signature
	for i := range sig {
		sig[i] = 0x5A
	}
	frame, err := protocol.ManifestRahmen(payload, sig, 256, padReader{0xA5})
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 256 {
		t.Fatalf("len %d", len(frame))
	}
	got, gotSig, err := protocol.ParseManifestRahmen(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) || gotSig != sig {
		t.Fatal("parse")
	}
	if frame[168+64] != 0xA5 {
		t.Fatal("zufall")
	}
	frame[4] ^= 0xFF
	if _, _, err := protocol.ParseManifestRahmen(frame); !errors.Is(err, protocol.ErrDomain) {
		t.Fatalf("domäne %v", err)
	}
}
