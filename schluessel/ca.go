package schluessel

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

// CA ist die lokale CA des einfachen Modus. Sie bleibt bei der Verwaltung.
// Der Schreibprozess erhält sie nicht.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// NeueCA erzeugt eine P-256-CA. name steht im Subjekt. bis begrenzt die Laufzeit.
func NeueCA(name string, jetzt, bis time.Time) (*CA, error) {
	if name == "" || !bis.After(jetzt) {
		return nil, ErrAnker
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             jetzt.Add(-time.Minute).UTC(),
		NotAfter:              bis.UTC(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, cert: cert}, nil
}

// Zertifikat ist der Vertrauensanker, den der Datenschutzbeauftragte quittiert.
func (c *CA) Zertifikat() *x509.Certificate {
	if c == nil {
		return nil
	}
	return c.cert
}

// Fingerabdruck ist SHA-256 über das CA-Zertifikat.
func (c *CA) Fingerabdruck() (protocol.Hash, error) {
	return crypt.FingerprintCertificate(c.Zertifikat())
}

// Ausstellen stellt ein Blatt aus. kek wählt die Key Usage des KEK, sonst die Signatur.
func (c *CA) Ausstellen(pub crypto.PublicKey, mandant protocol.ID, name string, bis time.Time, jetzt time.Time, kek bool) (*x509.Certificate, error) {
	if c == nil || c.key == nil || c.cert == nil {
		return nil, ErrAnker
	}
	if kek {
		if err := wrapAlgorithmus(pub); err != nil {
			return nil, err
		}
	} else if err := signaturAlgorithmus(pub); err != nil {
		return nil, err
	}
	if name == "" || mandant == (protocol.ID{}) || !bis.After(jetzt) {
		return nil, ErrZertifikat
	}
	usage := x509.KeyUsageDigitalSignature
	if kek {
		switch pub.(type) {
		case *ecdsa.PublicKey:
			usage = x509.KeyUsageKeyAgreement
		default:
			usage = x509.KeyUsageKeyEncipherment
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{mandant.Hex()},
		},
		NotBefore:             jetzt.UTC(),
		NotAfter:              bis.UTC(),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
