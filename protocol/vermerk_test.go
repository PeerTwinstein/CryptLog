package protocol_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestVermerkBytes(t *testing.T) {
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC), fillID(0x44), protocol.Prefix{9})
	if err != nil {
		t.Fatal(err)
	}
	tag := time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)
	got, err := protocol.VermerkBytes(epoch, tag)
	if err != nil {
		t.Fatal(err)
	}
	id, gelesen, err := protocol.ParseVermerk(got)
	if err != nil || id != epoch || !gelesen.Equal(tag) {
		t.Fatalf("%x %v %v", id, gelesen, err)
	}
	if _, err := protocol.VermerkBytes(epoch, tag.Add(time.Hour)); !errors.Is(err, protocol.ErrRaster) {
		t.Fatalf("Stunde: %v", err)
	}
	if _, _, err := protocol.ParseVermerk(append(got, 0)); !errors.Is(err, protocol.ErrLength) && !errors.Is(err, protocol.ErrDomain) {
		t.Fatalf("Rest: %v", err)
	}
	key := protocol.VermerkSchluessel(fillID(0x11), fillID(0x22), epoch)
	if !bytes.Contains([]byte(key), []byte("vermerk/")) || !bytes.Contains([]byte(key), []byte(epoch.String())) {
		t.Fatal(key)
	}
}
