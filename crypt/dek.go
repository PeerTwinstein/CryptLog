// Package crypt erzeugt Datenschlüssel, verschlüsselt Einträge mit AES-256-GCM
// und wrappt Klartext mit RSA-OAEP oder HPKE. Integritätssignaturen sind
// ECDSA P-256 als r || s.
package crypt

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"runtime"

	"cryptlog/protocol"
)

// DEK ist der 32-Byte-Datenschlüssel einer Epoche. Der Klartext bleibt beim Aufrufer.
type DEK [32]byte

// Equal vergleicht in konstanter Zeit.
func (d DEK) Equal(o DEK) bool {
	return subtle.ConstantTimeCompare(d[:], o[:]) == 1
}

// Wipe überschreibt den DEK. Das ist ein bestmögliches Löschen des eigenen Speichers.
func (d *DEK) Wipe() { Wipe(d[:]) }

// Wipe überschreibt b.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// NewDEK zieht DEK und Epochenpräfix unabhängig voneinander aus dem kryptografischen Zufall.
func NewDEK() (DEK, protocol.Prefix, error) {
	var dek DEK
	var prefix protocol.Prefix
	if _, err := io.ReadFull(rand.Reader, dek[:]); err != nil {
		return DEK{}, protocol.Prefix{}, err
	}
	if _, err := io.ReadFull(rand.Reader, prefix[:]); err != nil {
		dek.Wipe()
		return DEK{}, protocol.Prefix{}, err
	}
	return dek, prefix, nil
}
