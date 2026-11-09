package crypt_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestAES256GCMVektor(t *testing.T) {
	// Vektor aus crypto/cipher, Schlüssel 32 Byte, Klartext 16 Byte, leere Zusatzdaten.
	key := mustHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonceRaw := mustHex(t, "54cc7dc2c37ec006bcc6d1da")
	plain := mustHex(t, "007c5e5b3e59df24a7c355584fc1518d")
	result := mustHex(t, "d50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197")

	var dek crypt.DEK
	copy(dek[:], key)
	var nonce protocol.Nonce
	copy(nonce[:], nonceRaw)
	ct, tag, err := crypt.Seal(dek, nonce, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, result[:16]) || !bytes.Equal(tag, result[16:]) {
		t.Fatalf("ct=%x tag=%x", ct, tag)
	}
	got, err := crypt.Open(dek, nonce, ct, tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Klartext = %x", got)
	}

	aad := bytes.Repeat([]byte{0x03}, protocol.AADSize)
	ct, tag, err = crypt.Seal(dek, nonce, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.Open(dek, nonce, ct, tag, aad); err != nil {
		t.Fatal(err)
	}
	aad[0] ^= 1
	if _, err := crypt.Open(dek, nonce, ct, tag, aad); !errors.Is(err, crypt.ErrOpen) {
		t.Fatalf("geänderte Zusatzdaten: %v", err)
	}
	tag[0] ^= 1
	aad[0] ^= 1
	if _, err := crypt.Open(dek, nonce, ct, tag, aad); !errors.Is(err, crypt.ErrOpen) {
		t.Fatalf("geändertes Tag: %v", err)
	}
	if _, err := crypt.Open(dek, nonce, ct, tag[:15], aad); !errors.Is(err, crypt.ErrTag) {
		t.Fatalf("kurzes Tag: %v", err)
	}
}

func TestNewDEK(t *testing.T) {
	a, _, err := crypt.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := crypt.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Fatal("zwei DEKs sind gleich")
	}
	a.Wipe()
	if a != (crypt.DEK{}) {
		t.Fatal("Wipe lässt Bytes stehen")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
