package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"cryptlog/protocol"
)

const (
	rsaMinBits = 3072
	p256Enc    = 65 // unkomprimierter Punkt, Nenc aus RFC 9180
	gcmTag     = 16
	dekPlain   = 48
)

// MaxPlaintext ist die größte Klartextlänge, die Wrap für diesen öffentlichen
// Schlüssel annimmt.
//
// RSA-OAEP mit SHA-256 fasst modulusBytes-66 Byte. Der Bindungsschlüssel
// belegt davon 48 Byte. Der Klartext der Bindung läuft über AES-256-GCM
// und unterliegt dieser Grenze nicht. Bei HPKE hält die Grenze das
// Ergebnis in einem 32-Bit-Längenfeld.
func MaxPlaintext(pub crypto.PublicKey) (int, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := checkRSA(k); err != nil {
			return 0, err
		}
		return k.Size() - 2*sha256.Size - 2, nil
	case *ecdsa.PublicKey:
		_, enc, _, err := suiteFor(k)
		if err != nil {
			return 0, err
		}
		limit := uint64(math.MaxUint32) - uint64(enc) - gcmTag
		if limit > uint64(math.MaxInt) {
			limit = uint64(math.MaxInt)
		}
		return int(limit), nil
	default:
		return 0, ErrAlgorithm
	}
}

// Wrap verschlüsselt plaintext für den öffentlichen Schlüssel.
// Bei RSA ab 3072 Bit ist das RSA-OAEP mit SHA-256, MGF1-SHA-256 und ctx als Label.
// Bei P-256 ist das HPKE im Basismodus nach RFC 9180; info und aad sind ctx.
// Die Ausgabe ist bei RSA das Chiffrat und bei HPKE enc || ct.
// rnd nil verwendet crypto/rand.Reader.
func Wrap(rnd io.Reader, pub crypto.PublicKey, plaintext, ctx []byte) ([]byte, error) {
	if len(ctx) == 0 {
		return nil, ErrContext
	}
	if len(plaintext) == 0 {
		return nil, ErrPlaintext
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return wrapRSA(rnd, k, plaintext, ctx)
	case *ecdsa.PublicKey:
		return wrapHPKE(rnd, k, plaintext, ctx)
	default:
		return nil, ErrAlgorithm
	}
}

// Unwrap öffnet ein Ergebnis von Wrap. Der private Schlüssel bestimmt das Verfahren.
// Der zurückgegebene Klartext gehört dem Aufrufer; Bindung und DEK sind vertraulich.
func Unwrap(priv crypto.PrivateKey, wrapped, ctx []byte) ([]byte, error) {
	if len(ctx) == 0 || len(wrapped) == 0 {
		return nil, ErrOpen
	}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return unwrapRSA(k, wrapped, ctx)
	case *ecdsa.PrivateKey:
		return unwrapHPKE(k, wrapped, ctx)
	default:
		return nil, ErrAlgorithm
	}
}

// WrapDEK wrappt die 48 Byte dek || bind_id.
func WrapDEK(rnd io.Reader, pub crypto.PublicKey, dek DEK, bind protocol.ID, ctx []byte) ([]byte, error) {
	defer dek.Wipe()
	var pt [dekPlain]byte
	copy(pt[:32], dek[:])
	copy(pt[32:], bind[:])
	defer Wipe(pt[:])
	return Wrap(rnd, pub, pt[:], ctx)
}

// UnwrapDEK liefert DEK und bind_id. Der Klartext muss 48 Byte lang sein.
func UnwrapDEK(priv crypto.PrivateKey, wrapped, ctx []byte) (DEK, protocol.ID, error) {
	pt, err := Unwrap(priv, wrapped, ctx)
	if err != nil {
		return DEK{}, protocol.ID{}, err
	}
	defer Wipe(pt)
	if len(pt) != dekPlain {
		return DEK{}, protocol.ID{}, ErrPlaintext
	}
	var dek DEK
	var bind protocol.ID
	copy(dek[:], pt[:32])
	copy(bind[:], pt[32:])
	return dek, bind, nil
}

func wrapRSA(rnd io.Reader, pub *rsa.PublicKey, plaintext, ctx []byte) ([]byte, error) {
	if err := checkRSA(pub); err != nil {
		return nil, err
	}
	if len(plaintext) > pub.Size()-2*sha256.Size-2 {
		return nil, ErrPlaintext
	}
	return rsa.EncryptOAEP(sha256.New(), rnd, pub, plaintext, ctx)
}

func unwrapRSA(priv *rsa.PrivateKey, wrapped, ctx []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrKey
	}
	if err := checkRSA(&priv.PublicKey); err != nil {
		return nil, err
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, ctx)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func wrapHPKE(rnd io.Reader, pub *ecdsa.PublicKey, plaintext, ctx []byte) ([]byte, error) {
	kemID, encSize, suite, err := suiteFor(pub)
	if err != nil {
		return nil, err
	}
	if uint64(len(plaintext)) > uint64(math.MaxUint32)-uint64(encSize)-gcmTag {
		return nil, ErrPlaintext
	}
	pk, err := hpkePublic(kemID, pub)
	if err != nil {
		return nil, err
	}
	sender, err := suite.NewSender(pk, ctx)
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(rnd)
	if err != nil {
		return nil, err
	}
	if len(enc) != encSize {
		return nil, ErrKey
	}
	ct, err := sealer.Seal(plaintext, ctx)
	if err != nil {
		return nil, err
	}
	if len(ct) != len(plaintext)+gcmTag {
		return nil, ErrKey
	}
	out := make([]byte, len(enc)+len(ct))
	copy(out, enc)
	copy(out[len(enc):], ct)
	return out, nil
}

func unwrapHPKE(priv *ecdsa.PrivateKey, wrapped, ctx []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrKey
	}
	kemID, encSize, suite, err := suiteFor(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < encSize+gcmTag {
		return nil, ErrOpen
	}
	sk, err := hpkePrivate(kemID, priv)
	if err != nil {
		return nil, err
	}
	receiver, err := suite.NewReceiver(sk, ctx)
	if err != nil {
		return nil, ErrOpen
	}
	opener, err := receiver.Setup(wrapped[:encSize])
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := opener.Open(wrapped[encSize:], ctx)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func checkRSA(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.E < 3 || pub.E%2 == 0 {
		return ErrKey
	}
	if pub.N.BitLen() < rsaMinBits {
		return ErrAlgorithm
	}
	return nil
}

func suiteFor(pub *ecdsa.PublicKey) (hpke.KEM, int, hpke.Suite, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return 0, 0, hpke.Suite{}, ErrKey
	}
	switch {
	case pub.Curve.Params().Name == "P-256" && pub.Curve.Params().BitSize == 256:
		id := hpke.KEM_P256_HKDF_SHA256
		return id, p256Enc, hpke.NewSuite(id, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM), nil
	default:
		return 0, 0, hpke.Suite{}, ErrAlgorithm
	}
}

func hpkePublic(id hpke.KEM, pub *ecdsa.PublicKey) (kem.PublicKey, error) {
	dh, err := pub.ECDH()
	if err != nil {
		return nil, ErrKey
	}
	pk, err := id.Scheme().UnmarshalBinaryPublicKey(dh.Bytes())
	if err != nil {
		return nil, ErrKey
	}
	return pk, nil
}

func hpkePrivate(id hpke.KEM, priv *ecdsa.PrivateKey) (kem.PrivateKey, error) {
	dh, err := priv.ECDH()
	if err != nil {
		return nil, ErrKey
	}
	sk, err := id.Scheme().UnmarshalBinaryPrivateKey(dh.Bytes())
	if err != nil {
		return nil, ErrKey
	}
	return sk, nil
}
