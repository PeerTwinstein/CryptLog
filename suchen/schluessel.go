package suchen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"runtime"

	"cryptlog/crypt"
)

const maxSchluessel = 64 << 10

// schluesselLesen liest die PKCS#8-Datei. Eine verschlüsselte Fassung wird abgelehnt:
// die Passphrase ginge sonst an den Prozess.
func schluesselLesen(pfad string) (crypto.PrivateKey, error) {
	if !dateiLesbar(pfad) {
		return nil, ErrGeheimnis
	}
	der, err := os.ReadFile(pfad)
	if err != nil {
		return nil, ErrGeheimnis
	}
	defer crypt.Wipe(der)
	if len(der) == 0 || len(der) > maxSchluessel {
		return nil, ErrGeheimnis
	}
	der, err = pkcs8(der)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	crypt.Wipe(der)
	if err != nil {
		return nil, ErrGeheimnis
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if !kurve(k) {
			verwerfen(k)
			return nil, ErrGeheimnis
		}
		return k, nil
	case *rsa.PrivateKey:
		if k.N == nil || k.N.BitLen() < 3072 {
			verwerfen(k)
			return nil, ErrGeheimnis
		}
		return k, nil
	default:
		return nil, ErrGeheimnis
	}
}

func pkcs8(b []byte) ([]byte, error) {
	if len(b) == 0 || b[0] != '-' {
		return append([]byte(nil), b...), nil
	}
	block, rest := pem.Decode(b)
	if block == nil || len(trimSpace(rest)) != 0 || block.Type != "PRIVATE KEY" {
		return nil, ErrGeheimnis
	}
	return append([]byte(nil), block.Bytes...), nil
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

func dateiLesbar(pfad string) bool {
	f, err := os.Open(pfad)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func oeffentlich(k crypto.PrivateKey) (crypto.PublicKey, error) {
	s, ok := k.(crypto.Signer)
	if !ok || s.Public() == nil {
		return nil, ErrGeheimnis
	}
	return s.Public(), nil
}

func kurve(k *ecdsa.PrivateKey) bool {
	if k == nil || k.Curve == nil || k.D == nil || k.X == nil || k.Y == nil {
		return false
	}
	return k.Curve.Params().Name == "P-256" && k.Curve.Params().BitSize == 256
}

func p256(pub *ecdsa.PublicKey) bool {
	return pub != nil && pub.Curve != nil && pub.X != nil && pub.Y != nil &&
		pub.Curve.Params().Name == "P-256" && pub.Curve.Params().BitSize == 256
}

func verwerfen(k crypto.PrivateKey) {
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		if key != nil {
			nullen(key.D)
		}
	case *rsa.PrivateKey:
		if key != nil {
			nullen(key.D)
			nullen(key.Precomputed.Dp)
			nullen(key.Precomputed.Dq)
			nullen(key.Precomputed.Qinv)
			for _, prime := range key.Primes {
				nullen(prime)
			}
		}
	}
	runtime.KeepAlive(k)
}

func nullen(n *big.Int) {
	if n == nil {
		return
	}
	w := n.Bits()
	for i := range w {
		w[i] = 0
	}
	runtime.KeepAlive(n)
}
