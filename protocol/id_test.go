package protocol_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestIDHex(t *testing.T) {
	id := fillID(0xab)
	const want = "abababababababababababababababab"
	if id.Hex() != want {
		t.Fatalf("Hex = %s", id.Hex())
	}
	got, err := protocol.ParseID(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("ParseID = %x", got)
	}
	if _, err := protocol.ParseID("ABABABABABABABABABABABABABABABAB"); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("Großbuchstaben: %v", err)
	}
	if _, err := protocol.ParseID(want[:31]); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("zu kurz: %v", err)
	}
}

func TestEpochID(t *testing.T) {
	raster := time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC)
	instanz := fillID(0x22)
	var prefix protocol.Prefix
	copy(prefix[:], []byte{0xa1, 0xb2, 0xc3, 0xd4})
	epoch, err := protocol.NewEpochID(raster, instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if epoch.Raster() != "20261105T210000Z" {
		t.Fatalf("Raster = %q", epoch.Raster())
	}
	if epoch.Instanz() != instanz || epoch.Prefix() != prefix {
		t.Fatalf("Instanz oder Präfix fehlt: %x", epoch)
	}
	const key = "20261105T210000Z-22222222222222222222222222222222-a1b2c3d4"
	if epoch.String() != key {
		t.Fatalf("String = %s", epoch.String())
	}
	parsed, err := protocol.ParseEpochID(key)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != epoch {
		t.Fatalf("ParseEpochID = %x", parsed)
	}
	if _, err := protocol.ParseEpochID("20261105T210000Z-22222222222222222222222222222222-A1B2C3D4"); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("Präfix in Großbuchstaben: %v", err)
	}

	local := time.Date(2026, 11, 5, 21, 0, 0, 0, time.FixedZone("CET", 3600))
	if _, err := protocol.NewEpochID(local, instanz, prefix); !errors.Is(err, protocol.ErrRaster) {
		t.Fatalf("Ortszeit: %v", err)
	}
	if _, err := protocol.NewEpochID(raster.Add(time.Millisecond), instanz, prefix); !errors.Is(err, protocol.ErrRaster) {
		t.Fatalf("Millisekunde: %v", err)
	}
}

func TestNonceUndAAD(t *testing.T) {
	var prefix protocol.Prefix
	copy(prefix[:], []byte{0x10, 0x20, 0x30, 0x40})
	nonce := protocol.MakeNonce(prefix, 1)
	want := []byte{0x10, 0x20, 0x30, 0x40, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(nonce[:], want) {
		t.Fatalf("Nonce = %x", nonce)
	}

	mandant, ablage, dek := fillID(1), fillID(2), fillID(4)
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC), fillID(3), prefix)
	if err != nil {
		t.Fatal(err)
	}
	aad := protocol.AAD(mandant, ablage, epoch, dek, 1)
	if len(aad) != protocol.AADSize || protocol.AADSize != 92 {
		t.Fatalf("AAD = %d, Konstante %d", len(aad), protocol.AADSize)
	}
	manual := append(append(append(append(append([]byte{}, mandant[:]...), ablage[:]...), epoch[:]...), dek[:]...), be64(1)...)
	if !bytes.Equal(aad, manual) {
		t.Fatalf("AAD weicht ab:\n%x\n%x", aad, manual)
	}
}
