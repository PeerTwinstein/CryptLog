package crypt_test

import (
	"bytes"
	"crypto"
	"errors"
	"testing"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestSealBindung(t *testing.T) {
	mandant := fillID(0x11)
	batch := fillID(0x22)
	var kek protocol.Hash
	kek[0] = 9
	ctx := protocol.BindungContext(mandant, batch, kek)
	aad := protocol.BindungAAD(mandant, batch, kek)
	entries := make([]protocol.SeqEintrag, 40)
	for i := range entries {
		entries[i] = protocol.SeqEintrag{Seq: uint64(i + 1), Art: protocol.ArtFuellung}
	}
	body, err := protocol.Bindung(batch, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 318 {
		t.Fatalf("Bindung hat %d Byte und träfe die alte OAEP-Grenze nicht", len(body))
	}

	t.Run("P-256", func(t *testing.T) {
		key := mustP256(t)
		sealAndOpen(t, key, &key.PublicKey, batch, body, ctx, aad, 65+48+16)
	})
	t.Run("RSA-3072", func(t *testing.T) {
		key := mustRSA(t)
		sealAndOpen(t, key, &key.PublicKey, batch, body, ctx, aad, key.Size())
	})
}

func sealAndOpen(t *testing.T, priv crypto.PrivateKey, pub crypto.PublicKey, batch protocol.ID, body, ctx, aad []byte, wantWrap int) {
	t.Helper()
	wrapped, nonce, ct, tag, err := crypt.SealBindung(nil, pub, batch, body, ctx, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != wantWrap {
		t.Fatalf("Wrap = %d Byte, erwartet %d", len(wrapped), wantWrap)
	}
	if len(ct) != len(body) || len(tag) != protocol.TagLen {
		t.Fatalf("ct=%d tag=%d", len(ct), len(tag))
	}
	got, err := crypt.OpenBindung(priv, batch, wrapped, nonce, ct, tag, ctx, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("Klartext weicht ab")
	}

	opened, gotBatch, err := crypt.UnwrapDEK(priv, wrapped, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	if gotBatch != batch {
		t.Fatal("der Wrap enthält nicht die batch_id")
	}

	badAAD := append([]byte{}, aad...)
	badAAD[len(badAAD)-1] ^= 1
	if _, err := crypt.OpenBindung(priv, batch, wrapped, nonce, ct, tag, ctx, badAAD); !errors.Is(err, crypt.ErrOpen) {
		t.Fatalf("falsche Zusatzdaten: %v", err)
	}
	other := batch
	other[0] ^= 1
	if _, err := crypt.OpenBindung(priv, other, wrapped, nonce, ct, tag, ctx, aad); !errors.Is(err, crypt.ErrOpen) {
		t.Fatalf("fremde batch_id: %v", err)
	}
	ct[0] ^= 1
	if _, err := crypt.OpenBindung(priv, batch, wrapped, nonce, ct, tag, ctx, aad); !errors.Is(err, crypt.ErrOpen) {
		t.Fatalf("veränderter Ciphertext: %v", err)
	}
	if _, _, _, _, err := crypt.SealBindung(nil, pub, batch, nil, ctx, aad); !errors.Is(err, crypt.ErrPlaintext) {
		t.Fatalf("leere Bindung: %v", err)
	}
}

func fillID(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}
