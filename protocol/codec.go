package protocol

import (
	"encoding/binary"
	"math"
)

// AppendU32 hängt eine vorzeichenlose 32-Bit-Zahl in Big-Endian an.
func AppendU32(dst []byte, n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return append(dst, b[:]...)
}

// AppendU64 hängt eine vorzeichenlose 64-Bit-Zahl in Big-Endian an.
func AppendU64(dst []byte, n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return append(dst, b[:]...)
}

// AppendText hängt L(s) || s an. s ist UTF-8. Die Domänenkennungen sind kurz;
// ein Text über 2^32-1 Byte ist ein Programmierfehler.
func AppendText(dst []byte, s string) []byte {
	if uint64(len(s)) > math.MaxUint32 {
		panic("protocol: Text länger als 2^32-1")
	}
	dst = AppendU32(dst, uint32(len(s)))
	return append(dst, s...)
}

// Domain ist die Domänenkennung L(name) || name.
func Domain(name string) []byte { return AppendText(nil, name) }

func appendLen(dst, data []byte) ([]byte, error) {
	if uint64(len(data)) > math.MaxUint32 {
		return nil, ErrLength
	}
	dst = AppendU32(dst, uint32(len(data)))
	return append(dst, data...), nil
}

// MakeNonce baut epoch_prefix || seq. seq steht wie im Eintrag als
// vorzeichenlose 64-Bit-Zahl in Big-Endian.
func MakeNonce(prefix Prefix, seq uint64) Nonce {
	var n Nonce
	copy(n[:PrefixLen], prefix[:])
	binary.BigEndian.PutUint64(n[PrefixLen:], seq)
	return n
}

// AAD sind die authentisierten Zusatzdaten eines Eintrags.
// Ein Zeitstempel, ein Name, eine Personenkennung, eine Vorgangsnummer
// und eine bind_id stehen hier nicht.
func AAD(mandant, ablage ID, epoch EpochID, dek ID, seq uint64) []byte {
	buf := make([]byte, 0, AADSize)
	buf = append(buf, mandant[:]...)
	buf = append(buf, ablage[:]...)
	buf = append(buf, epoch[:]...)
	buf = append(buf, dek[:]...)
	return AppendU64(buf, seq)
}
