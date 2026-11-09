package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"cryptlog/protocol"
)

// SignP256 signiert payload mit ECDSA P-256 und SHA-256.
// Die Signatur ist r || s, jede Koordinate 32 Byte vorzeichenlos in Big-Endian.
// Der Zufall der Signatur kommt aus der Laufzeit.
func SignP256(priv *ecdsa.PrivateKey, payload []byte) (protocol.Signature, error) {
	if priv == nil || priv.D == nil || priv.Curve == nil || priv.X == nil || priv.Y == nil {
		return protocol.Signature{}, ErrKey
	}
	if !isP256(&priv.PublicKey) {
		return protocol.Signature{}, ErrAlgorithm
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return protocol.Signature{}, err
	}
	var sig protocol.Signature
	if err := putCoord(sig[:32], r); err != nil {
		return protocol.Signature{}, err
	}
	if err := putCoord(sig[32:], s); err != nil {
		return protocol.Signature{}, err
	}
	return sig, nil
}

// VerifyP256 prüft eine Signatur über SHA-256(payload).
func VerifyP256(pub *ecdsa.PublicKey, payload []byte, sig protocol.Signature) bool {
	if !isP256(pub) {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	digest := sha256.Sum256(payload)
	return ecdsa.Verify(pub, digest[:], r, s)
}

func isP256(pub *ecdsa.PublicKey) bool {
	return pub != nil && pub.Curve != nil && pub.X != nil && pub.Y != nil &&
		pub.Curve.Params().Name == "P-256" && pub.Curve.Params().BitSize == 256
}

func putCoord(dst []byte, n *big.Int) error {
	if n == nil || n.Sign() <= 0 || n.BitLen() > len(dst)*8 {
		return ErrKey
	}
	n.FillBytes(dst)
	return nil
}
