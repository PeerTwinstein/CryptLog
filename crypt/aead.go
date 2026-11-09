package crypt

import (
	"crypto/aes"
	"crypto/cipher"

	"cryptlog/protocol"
)

// Seal verschlüsselt mit AES-256-GCM. ciphertext und tag sind getrennt,
// weil die Hash-Kette sie getrennt aufnimmt. Dieselbe Nonce darf unter
// diesem DEK nur einmal verwendet werden.
func Seal(dek DEK, nonce protocol.Nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	defer dek.Wipe()
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	out := gcm.Seal(nil, nonce[:], plaintext, aad)
	n := len(out) - gcm.Overhead()
	ciphertext = make([]byte, n)
	tag = make([]byte, gcm.Overhead())
	copy(ciphertext, out[:n])
	copy(tag, out[n:])
	Wipe(out)
	return ciphertext, tag, nil
}

// Open prüft Tag und Zusatzdaten und liefert den Klartext.
// Ein Fehler ist immer ErrOpen oder ErrTag, ohne Unterscheidung der Ursache.
func Open(dek DEK, nonce protocol.Nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	defer dek.Wipe()
	if len(tag) != protocol.TagLen {
		return nil, ErrTag
	}
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(ciphertext)+len(tag))
	copy(buf, ciphertext)
	copy(buf[len(ciphertext):], tag)
	plain, err := gcm.Open(nil, nonce[:], buf, aad)
	Wipe(buf)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}
