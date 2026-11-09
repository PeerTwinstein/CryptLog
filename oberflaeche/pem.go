package oberflaeche

import (
	"crypto/ecdsa"
	"encoding/pem"
	"math/big"
	"os"
	"runtime"
	"strings"
)

func pemBlock(pfad string) (*pem.Block, error) {
	roh, err := os.ReadFile(pfad)
	if err != nil || len(roh) == 0 || len(roh) > 1<<16 {
		return nil, ErrAngabe
	}
	block, rest := pemDecode(roh)
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrAngabe
	}
	return block, nil
}

func pemDecode(roh []byte) (*pem.Block, []byte) {
	return pem.Decode(roh)
}

func privatWeg(key *ecdsa.PrivateKey) {
	if key == nil {
		return
	}
	nullen(key.D)
	runtime.KeepAlive(key)
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
