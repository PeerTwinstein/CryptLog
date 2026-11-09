package schluessel

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math/big"
)

// Signieren signiert die Veröffentlichung mit dem privaten Schlüssel des Vertrauensankers.
// ECDSA P-256 liefert r || s, jede Koordinate 32 Byte, vorzeichenlos Big-Endian.
// rnd nil liest aus crypto/rand.
func Signieren(rnd io.Reader, priv crypto.PrivateKey, payload []byte) ([]byte, error) {
	if len(payload) == 0 || priv == nil {
		return nil, ErrSignatur
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	digest := sha256.Sum256(payload)
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		if err := signaturAlgorithmus(k.Public()); err != nil {
			return nil, err
		}
		r, s, err := ecdsa.Sign(rnd, k, digest[:])
		if err != nil {
			return nil, err
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*n)
		if err := koord(out[:n], r); err != nil {
			return nil, err
		}
		if err := koord(out[n:], s); err != nil {
			return nil, err
		}
		return out, nil
	case *rsa.PrivateKey:
		return nil, ErrSignatur
	default:
		return nil, ErrSignatur
	}
}

// SignaturOK prüft eine Signatur über SHA-256(payload) gegen den öffentlichen Anker.
func SignaturOK(pub crypto.PublicKey, payload, sig []byte) bool {
	if len(payload) == 0 || len(sig) == 0 || signaturAlgorithmus(pub) != nil {
		return false
	}
	digest := sha256.Sum256(payload)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return false
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		order := k.Curve.Params().N
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
			return false
		}
		return ecdsa.Verify(k, digest[:], r, s)
	default:
		return false
	}
}

func koord(dst []byte, n *big.Int) error {
	if n == nil || n.Sign() <= 0 || n.BitLen() > len(dst)*8 {
		return ErrSignatur
	}
	n.FillBytes(dst)
	return nil
}

// wrapAlgorithmus lässt für einen KEK RSA ab 3072 Bit und P-256 zu.
func wrapAlgorithmus(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.BitLen() < 3072 || k.E < 3 {
			return ErrZertifikat
		}
		return nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.X == nil || k.Y == nil || k.Curve.Params().Name != "P-256" || k.Curve.Params().BitSize != 256 {
			return ErrZertifikat
		}
		return nil
	default:
		return ErrZertifikat
	}
}

// signaturAlgorithmus lässt für eine Signatur nur ECDSA P-256 zu.
func signaturAlgorithmus(pub crypto.PublicKey) error {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve == nil || k.X == nil || k.Y == nil || k.Curve.Params().Name != "P-256" || k.Curve.Params().BitSize != 256 {
		return ErrZertifikat
	}
	return nil
}
