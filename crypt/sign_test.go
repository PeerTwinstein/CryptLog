package crypt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"cryptlog/crypt"
)

func TestSignP256(t *testing.T) {
	key := mustP256(t)
	payload := []byte("L(\"manifest\") || manifest")
	sig, err := crypt.SignP256(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !crypt.VerifyP256(&key.PublicKey, payload, sig) {
		t.Fatal("Signatur prüft nicht")
	}
	digest := sha256.Sum256(payload)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("r || s ist kein ECDSA-P256-SHA-256 über die Nutzlast")
	}
	payload[0] ^= 1
	if crypt.VerifyP256(&key.PublicKey, payload, sig) {
		t.Fatal("geänderte Nutzlast prüft")
	}
	payload[0] ^= 1
	sig[63] ^= 1
	if crypt.VerifyP256(&key.PublicKey, payload, sig) {
		t.Fatal("geänderte Signatur prüft")
	}

	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.SignP256(other, payload); !errors.Is(err, crypt.ErrAlgorithm) {
		t.Fatalf("P-384: %v", err)
	}
	if crypt.VerifyP256(&other.PublicKey, payload, sig) {
		t.Fatal("P-384 prüft eine P-256-Signatur")
	}
}

func TestFingerprint(t *testing.T) {
	key := mustP256(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mandant Datenschutzbeauftragter"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(cert.Raw)
	if got != want {
		t.Fatalf("Zertifikat = %x", got)
	}
	spki, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if spki != sha256.Sum256(raw) {
		t.Fatalf("SPKI = %x", spki)
	}
	if spki == got {
		t.Fatal("Zertifikat und SubjectPublicKeyInfo haben denselben Fingerabdruck")
	}
	if _, err := crypt.FingerprintCertificate(&x509.Certificate{}); !errors.Is(err, crypt.ErrKey) {
		t.Fatalf("leeres Zertifikat: %v", err)
	}
}
