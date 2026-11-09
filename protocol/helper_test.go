package protocol_test

import (
	"crypto/sha256"
	"encoding/binary"

	"cryptlog/protocol"
)

func fillID(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func be32(n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b[:]
}

func be64(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}

func text(s string) []byte {
	return append(be32(uint32(len(s))), []byte(s)...)
}

func digest(parts ...[]byte) protocol.Hash {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var out protocol.Hash
	copy(out[:], h.Sum(nil))
	return out
}
