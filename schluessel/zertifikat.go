package schluessel

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

// pruefeBlatt prüft ein Zertifikat gegen den Vertrauensanker.
// name ist der registrierte Datenschutzbeauftragte.
// kek verlangt keyEncipherment oder keyAgreement, sonst digitalSignature.
func pruefeBlatt(der []byte, anker *x509.Certificate, mandant protocol.ID, name string, jetzt time.Time, crl *x509.RevocationList, kek bool) (*x509.Certificate, protocol.Hash, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if kek {
		if err := wrapAlgorithmus(cert.PublicKey); err != nil {
			return nil, protocol.Hash{}, err
		}
	} else if err := signaturAlgorithmus(cert.PublicKey); err != nil {
		return nil, protocol.Hash{}, err
	}
	if kek {
		if err := nutzungKEK(cert); err != nil {
			return nil, protocol.Hash{}, err
		}
	} else if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if !subjektOK(cert, mandant, name) {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if jetzt.Before(cert.NotBefore) || !jetzt.Before(cert.NotAfter) {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if anker == nil {
		return nil, protocol.Hash{}, ErrAnker
	}
	pool := x509.NewCertPool()
	pool.AddCert(anker)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		CurrentTime:   jetzt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Intermediates: x509.NewCertPool(),
	}); err != nil {
		return nil, protocol.Hash{}, ErrZertifikat
	}
	if err := sperre(cert, anker, crl, jetzt); err != nil {
		return nil, protocol.Hash{}, err
	}
	finger, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	return cert, finger, nil
}

func nutzungKEK(cert *x509.Certificate) error {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return ErrZertifikat
		}
	case *ecdsa.PublicKey:
		if cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return ErrZertifikat
		}
	default:
		return ErrZertifikat
	}
	return nil
}

func subjektOK(cert *x509.Certificate, mandant protocol.ID, name string) bool {
	if cert.Subject.CommonName != name {
		return false
	}
	want := mandant.Hex()
	for _, org := range cert.Subject.Organization {
		if org == want {
			return true
		}
	}
	return false
}

func sperre(cert, anker *x509.Certificate, crl *x509.RevocationList, jetzt time.Time) error {
	if crl == nil {
		return nil
	}
	if anker == nil || crl.CheckSignatureFrom(anker) != nil {
		return ErrZertifikat
	}
	if jetzt.Before(crl.ThisUpdate) || (!crl.NextUpdate.IsZero() && !jetzt.Before(crl.NextUpdate)) {
		return ErrZertifikat
	}
	for _, ein := range crl.RevokedCertificateEntries {
		if ein.SerialNumber != nil && ein.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return ErrZertifikat
		}
	}
	return nil
}

func parseCRL(der []byte) (*x509.RevocationList, error) {
	if len(der) == 0 {
		return nil, nil
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, ErrZertifikat
	}
	return list, nil
}

// verschluesseltPKCS8 verlangt eine EncryptedPrivateKeyInfo.
// Ein unverschlüsselter PKCS#8-Schlüssel wird abgelehnt. Die Passphrase bleibt beim Absender.
func verschluesseltPKCS8(b []byte) error {
	der := b
	if len(b) > 10 && b[0] == '-' {
		block, rest := pem.Decode(b)
		if block == nil || len(rest) != 0 || block.Type != "ENCRYPTED PRIVATE KEY" {
			return ErrPrivat
		}
		der = block.Bytes
	}
	if len(der) == 0 {
		return ErrPrivat
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return ErrPrivat
	}
	var info struct {
		Algo asn1.RawValue
		Data []byte
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || len(info.Data) == 0 || !info.Algo.IsCompound || info.Algo.Tag != asn1.TagSequence {
		return ErrPrivat
	}
	return nil
}
