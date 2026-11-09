// Package protocol bildet die festgelegten Bytefolgen des CryptLog-Protokolls.
// Domänenkennung, Hash-Kette, Ereignishash, Manifest, Annahme, Bindung und
// die Inhalte der Ströme folgen dem Konzept in docs/protokoll.md und
// docs/ablage-und-lesen.md.
package protocol

import (
	"crypto/subtle"
	"encoding/hex"
	"time"
)

const (
	// IDLen ist die Länge einer Kennung.
	IDLen = 16
	// HashLen ist die Länge eines SHA-256.
	HashLen = 32
	// EpochLen ist die Länge einer Epochenkennung.
	EpochLen = 36
	// PrefixLen ist die Länge des Epochenpräfixes.
	PrefixLen = 4
	// NonceLen ist die Länge der Eintrags-Nonce.
	NonceLen = 12
	// SignatureLen ist die Länge einer P-256-Signatur als r || s.
	SignatureLen = 64
	// RasterLen ist die Länge des Rasterbeginns in der Epochenkennung.
	RasterLen = 16
	// TagLen ist die Länge des GCM-Tags.
	TagLen = 16
	// AADSize ist die Länge der authentisierten Zusatzdaten:
	// mandant_id || ablage_id || epoch_id || dek_id || seq.
	AADSize = IDLen + IDLen + EpochLen + IDLen + 8
)

// Die Differenz der Längen ist 0. Eine Abweichung lässt sich nicht kompilieren.
var (
	_ [EpochLen - RasterLen - IDLen - PrefixLen]struct{}
	_ [RasterLen + IDLen + PrefixLen - EpochLen]struct{}
)

// ID ist eine 16-Byte-Kennung: Mandant, Ablage, Bindung, DEK, Instanz,
// Ereignis oder Abschluss.
type ID [IDLen]byte

// Hash ist ein SHA-256-Wert ohne Längenfeld.
type Hash [HashLen]byte

// Prefix ist der 4-Byte-Zufall einer DEK-Epoche.
type Prefix [PrefixLen]byte

// Nonce ist epoch_prefix || seq, 12 Byte.
type Nonce [NonceLen]byte

// Signature ist eine ECDSA-P-256-Signatur als r || s, je 32 Byte Big-Endian.
type Signature [SignatureLen]byte

// EpochID ist 16 Byte ASCII des Rasterbeginns, danach die Instanz, danach
// der Epochenpräfix. Im Objektschlüssel steht sie als
// {raster}-{instanz_hex}-{prefix_hex}.
type EpochID [EpochLen]byte

// Equal vergleicht in konstanter Zeit.
func (id ID) Equal(o ID) bool { return subtle.ConstantTimeCompare(id[:], o[:]) == 1 }

// Equal vergleicht in konstanter Zeit.
func (h Hash) Equal(o Hash) bool {
	return subtle.ConstantTimeCompare(h[:], o[:]) == 1
}

// Equal vergleicht in konstanter Zeit.
func (p Prefix) Equal(o Prefix) bool {
	return subtle.ConstantTimeCompare(p[:], o[:]) == 1
}

// Equal vergleicht in konstanter Zeit.
func (n Nonce) Equal(o Nonce) bool {
	return subtle.ConstantTimeCompare(n[:], o[:]) == 1
}

// Equal vergleicht in konstanter Zeit.
func (s Signature) Equal(o Signature) bool {
	return subtle.ConstantTimeCompare(s[:], o[:]) == 1
}

// Equal vergleicht in konstanter Zeit.
func (e EpochID) Equal(o EpochID) bool {
	return subtle.ConstantTimeCompare(e[:], o[:]) == 1
}

// Hex liefert 32 Kleinbuchstaben.
func (id ID) Hex() string { return hex.EncodeToString(id[:]) }

// Hex liefert 8 Kleinbuchstaben.
func (p Prefix) Hex() string { return hex.EncodeToString(p[:]) }

// ParseID liest 32 Kleinbuchstaben Hex.
func ParseID(s string) (ID, error) {
	raw, err := decodeHex(s, IDLen)
	if err != nil {
		return ID{}, err
	}
	var id ID
	copy(id[:], raw)
	return id, nil
}

// NewEpochID baut die Epochenkennung aus dem Rasterbeginn in UTC.
// raster muss in time.UTC liegen und auf die Sekunde genau sein.
func NewEpochID(raster time.Time, instanz ID, prefix Prefix) (EpochID, error) {
	if raster.Location() != time.UTC || raster.Nanosecond() != 0 {
		return EpochID{}, ErrRaster
	}
	text := raster.Format("20060102T150405Z")
	if len(text) != RasterLen {
		return EpochID{}, ErrRaster
	}
	var epoch EpochID
	copy(epoch[:RasterLen], text)
	copy(epoch[RasterLen:], instanz[:])
	copy(epoch[RasterLen+IDLen:], prefix[:])
	return epoch, nil
}

// Raster ist der ASCII-Beginn YYYYMMDDThhmmssZ.
func (e EpochID) Raster() string { return string(e[:RasterLen]) }

// Instanz ist die schreibende Instanz in der Epochenkennung.
func (e EpochID) Instanz() ID {
	var id ID
	copy(id[:], e[RasterLen:RasterLen+IDLen])
	return id
}

// Prefix ist der Epochenpräfix aus der Kennung.
func (e EpochID) Prefix() Prefix {
	var p Prefix
	copy(p[:], e[RasterLen+IDLen:])
	return p
}

// String ist der Epochenanteil des Objektschlüssels.
func (e EpochID) String() string {
	return e.Raster() + "-" + e.Instanz().Hex() + "-" + e.Prefix().Hex()
}

// ParseEpochID liest den Epochenanteil des Objektschlüssels.
func ParseEpochID(s string) (EpochID, error) {
	const want = RasterLen + 1 + IDLen*2 + 1 + PrefixLen*2
	if len(s) != want || s[RasterLen] != '-' || s[RasterLen+1+IDLen*2] != '-' {
		return EpochID{}, ErrLength
	}
	raster := s[:RasterLen]
	if _, err := time.Parse("20060102T150405Z", raster); err != nil {
		return EpochID{}, ErrRaster
	}
	instanz, err := ParseID(s[RasterLen+1 : RasterLen+1+IDLen*2])
	if err != nil {
		return EpochID{}, err
	}
	prefixRaw, err := decodeHex(s[want-PrefixLen*2:], PrefixLen)
	if err != nil {
		return EpochID{}, err
	}
	var epoch EpochID
	copy(epoch[:RasterLen], raster)
	copy(epoch[RasterLen:], instanz[:])
	copy(epoch[RasterLen+IDLen:], prefixRaw)
	return epoch, nil
}

func decodeHex(s string, n int) ([]byte, error) {
	if len(s) != n*2 || !lowerHex(s) {
		return nil, ErrLength
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != n {
		return nil, ErrLength
	}
	return raw, nil
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
