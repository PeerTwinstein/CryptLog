package crypt

import (
	"crypto"
	"crypto/rand"
	"io"

	"cryptlog/protocol"
)

// SealBindung erzeugt einen Bindungsschlüssel, verschlüsselt bindung einmal
// mit AES-256-GCM und wrappt die 48 Byte schlüssel || batch.
// Der Schlüssel wird danach verworfen. Ein zweiter Klartext unter ihm
// entsteht nicht. rnd nil verwendet crypto/rand.Reader.
func SealBindung(rnd io.Reader, pub crypto.PublicKey, batch protocol.ID, bindung, ctx, aad []byte) (wrapped []byte, nonce protocol.Nonce, ciphertext, tag []byte, err error) {
	if len(bindung) == 0 {
		return nil, protocol.Nonce{}, nil, nil, ErrPlaintext
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var key DEK
	if _, err = io.ReadFull(rnd, key[:]); err != nil {
		return nil, protocol.Nonce{}, nil, nil, err
	}
	defer key.Wipe()
	if _, err = io.ReadFull(rnd, nonce[:]); err != nil {
		return nil, protocol.Nonce{}, nil, nil, err
	}
	wrapped, err = WrapDEK(rnd, pub, key, batch, ctx)
	if err != nil {
		return nil, protocol.Nonce{}, nil, nil, err
	}
	ciphertext, tag, err = Seal(key, nonce, bindung, aad)
	if err != nil {
		return nil, protocol.Nonce{}, nil, nil, err
	}
	return wrapped, nonce, ciphertext, tag, nil
}

// OpenBindung öffnet den Bindungsschlüssel und danach den Klartext.
// Die 16 Byte hinter dem Schlüssel müssen batch sein.
func OpenBindung(priv crypto.PrivateKey, batch protocol.ID, wrapped []byte, nonce protocol.Nonce, ciphertext, tag, ctx, aad []byte) ([]byte, error) {
	key, got, err := UnwrapDEK(priv, wrapped, ctx)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	if got != batch {
		return nil, ErrOpen
	}
	return Open(key, nonce, ciphertext, tag, aad)
}
