package crypt

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"

	"cryptlog/protocol"
)

// FingerprintCertificate ist SHA-256 über die DER-Kodierung des Zertifikats.
// Gültigkeit, Sperrstatus und Key Usage prüft diese Funktion nicht.
func FingerprintCertificate(cert *x509.Certificate) (protocol.Hash, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return protocol.Hash{}, ErrKey
	}
	return sha256.Sum256(cert.Raw), nil
}

// FingerprintSPKI ist SHA-256 über das SubjectPublicKeyInfo in DER.
// So sind der Bestätigungsschlüssel und der Aufrufschlüssel benannt.
func FingerprintSPKI(pub crypto.PublicKey) (protocol.Hash, error) {
	if pub == nil {
		return protocol.Hash{}, ErrKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return protocol.Hash{}, err
	}
	return sha256.Sum256(der), nil
}
