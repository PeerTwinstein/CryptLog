package crypt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync"
	"testing"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestWrapDEK(t *testing.T) {
	ctx := []byte("dek-wrap-test")
	dek := crypt.DEK{}
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	bind := protocol.ID{}
	for i := range bind {
		bind[i] = byte(0xa0 + i)
	}

	t.Run("P-256", func(t *testing.T) {
		key := mustP256(t)
		wrapped, err := crypt.WrapDEK(nil, &key.PublicKey, dek, bind, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(wrapped) != 65+48+16 || wrapped[0] != 0x04 {
			t.Fatalf("HPKE-P-256 = %d Byte, erstes = %x", len(wrapped), wrapped[0])
		}
		gotDEK, gotBind, err := crypt.UnwrapDEK(key, wrapped, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !gotDEK.Equal(dek) || gotBind != bind {
			t.Fatal("DEK oder bind_id kommt verändert zurück")
		}
		bad := append([]byte{}, ctx...)
		bad[0] ^= 1
		if _, _, err := crypt.UnwrapDEK(key, wrapped, bad); !errors.Is(err, crypt.ErrOpen) {
			t.Fatalf("falscher Kontext: %v", err)
		}
		long := bytes.Repeat([]byte{7}, 400)
		out, err := crypt.Wrap(nil, &key.PublicKey, long, ctx)
		if err != nil {
			t.Fatal(err)
		}
		back, err := crypt.Unwrap(key, out, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back, long) {
			t.Fatal("langer HPKE-Klartext weicht ab")
		}
	})

	t.Run("P-384", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypt.WrapDEK(nil, &key.PublicKey, dek, bind, ctx); !errors.Is(err, crypt.ErrAlgorithm) {
			t.Fatalf("P-384 %v", err)
		}
	})

	t.Run("RSA-3072", func(t *testing.T) {
		key := mustRSA(t)
		limit, err := crypt.MaxPlaintext(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if key.Size() != 384 || limit != 318 {
			t.Fatalf("RSA-3072 Size=%d Limit=%d", key.Size(), limit)
		}
		wrapped, err := crypt.WrapDEK(nil, &key.PublicKey, dek, bind, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(wrapped) != key.Size() {
			t.Fatalf("RSA-Chiffrat = %d", len(wrapped))
		}
		again, err := crypt.WrapDEK(nil, &key.PublicKey, dek, bind, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(wrapped, again) {
			t.Fatal("RSA-OAEP ist bei zwei Aufrufen gleich")
		}
		gotDEK, gotBind, err := crypt.UnwrapDEK(key, wrapped, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !gotDEK.Equal(dek) || gotBind != bind {
			t.Fatal("DEK oder bind_id kommt verändert zurück")
		}
		bad := append([]byte{}, ctx...)
		bad[len(bad)-1] ^= 1
		if _, _, err := crypt.UnwrapDEK(key, wrapped, bad); !errors.Is(err, crypt.ErrOpen) {
			t.Fatalf("falsches Label: %v", err)
		}
		exact := bytes.Repeat([]byte{9}, limit)
		out, err := crypt.Wrap(nil, &key.PublicKey, exact, ctx)
		if err != nil {
			t.Fatal(err)
		}
		back, err := crypt.Unwrap(key, out, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back, exact) {
			t.Fatal("Klartext an der OAEP-Grenze weicht ab")
		}
		if _, err := crypt.Wrap(nil, &key.PublicKey, append(exact, 1), ctx); !errors.Is(err, crypt.ErrPlaintext) {
			t.Fatalf("über der OAEP-Grenze: %v", err)
		}
	})
}

func TestWrapLehntAb(t *testing.T) {
	ctx := []byte("ctx")
	small := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	if _, err := crypt.Wrap(nil, small, []byte{1}, ctx); !errors.Is(err, crypt.ErrAlgorithm) {
		t.Fatalf("RSA-2048: %v", err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.Wrap(nil, &p521.PublicKey, []byte{1}, ctx); !errors.Is(err, crypt.ErrAlgorithm) {
		t.Fatalf("P-521: %v", err)
	}
	key := mustP256(t)
	if _, err := crypt.Wrap(nil, &key.PublicKey, nil, ctx); !errors.Is(err, crypt.ErrPlaintext) {
		t.Fatalf("leerer Klartext: %v", err)
	}
	if _, err := crypt.Wrap(nil, &key.PublicKey, []byte{1}, nil); !errors.Is(err, crypt.ErrContext) {
		t.Fatalf("leerer Kontext: %v", err)
	}
}

var (
	p256Once sync.Once
	p256Key  *ecdsa.PrivateKey
	p256Err  error
	rsaOnce  sync.Once
	rsaKey   *rsa.PrivateKey
	rsaErr   error
)

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	p256Once.Do(func() {
		p256Key, p256Err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if p256Err != nil {
		t.Fatal(p256Err)
	}
	return p256Key
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		rsaKey, rsaErr = rsa.GenerateKey(rand.Reader, 3072)
	})
	if rsaErr != nil {
		t.Fatal(rsaErr)
	}
	return rsaKey
}
