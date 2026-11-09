package protocol

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// Nutzlast ist die gemeinsame Fassung von Vorbereitung und Annahme.
// HasPrevious gilt für die Annahme. Die Vorbereitung führt previous nicht.
type Nutzlast struct {
	Batch       ID
	Instanz     ID
	BatchSeq    uint64
	Previous    Hash
	HasPrevious bool
	Slots       []Slot
	Segmente    []SegmentRef
	Bloecke     []Blob
}

// ParseAnnahme liest annahme_payload.
func ParseAnnahme(b []byte) (Nutzlast, error) {
	return parseNutzlast(b, "annahme", true)
}

// ParseVorbereitung liest die Vorbereitung. previous_annahme_hash fehlt.
func ParseVorbereitung(b []byte) (Nutzlast, error) {
	return parseNutzlast(b, "vorbereitung", false)
}

// AnnahmeAusVorbereitung setzt previous_annahme_hash vor die Plätze.
func AnnahmeAusVorbereitung(vor []byte, previous Hash) ([]byte, error) {
	n, err := ParseVorbereitung(vor)
	if err != nil {
		return nil, err
	}
	return AnnahmePayload(n.Batch, n.Instanz, n.BatchSeq, previous, n.Slots, n.Segmente, n.Bloecke)
}

// EreignisKonflikt gilt, wenn eine event_id in zwei Annahmen steht
// oder unter zwei event_hash.
func EreignisKonflikt(annahmen [][]byte) (bool, error) {
	type fund struct {
		hash   Hash
		quelle int
	}
	gesehen := make(map[ID]fund)
	for i, raw := range annahmen {
		n, err := ParseAnnahme(raw)
		if err != nil {
			return false, err
		}
		inDieser := make(map[ID]Hash)
		for _, slot := range n.Slots {
			if alt, ok := inDieser[slot.Event]; ok && alt != slot.Hash {
				return true, nil
			}
			inDieser[slot.Event] = slot.Hash
			if alt, ok := gesehen[slot.Event]; ok && (alt.quelle != i || alt.hash != slot.Hash) {
				return true, nil
			}
			gesehen[slot.Event] = fund{hash: slot.Hash, quelle: i}
		}
	}
	return false, nil
}

func parseNutzlast(b []byte, domain string, previous bool) (Nutzlast, error) {
	prefix := Domain(domain)
	if !bytes.HasPrefix(b, prefix) {
		return Nutzlast{}, ErrDomain
	}
	c := cursor{b: b, i: len(prefix)}
	var out Nutzlast
	var err error
	if out.Batch, err = c.id(); err != nil {
		return Nutzlast{}, err
	}
	if out.Instanz, err = c.id(); err != nil {
		return Nutzlast{}, err
	}
	if out.BatchSeq, err = c.u64(); err != nil {
		return Nutzlast{}, err
	}
	if out.BatchSeq == 0 {
		return Nutzlast{}, ErrSeq
	}
	out.HasPrevious = previous
	if previous {
		if out.Previous, err = c.hash(); err != nil {
			return Nutzlast{}, err
		}
	}
	slots, err := c.u64()
	if err != nil {
		return Nutzlast{}, err
	}
	if slots > uint64(len(b)) || !validSlotCount(int(slots)) {
		return Nutzlast{}, ErrSlotCount
	}
	out.Slots = make([]Slot, slots)
	for i := range out.Slots {
		if out.Slots[i].Event, err = c.id(); err != nil {
			return Nutzlast{}, err
		}
		if out.Slots[i].Hash, err = c.hash(); err != nil {
			return Nutzlast{}, err
		}
	}
	segs, err := c.u64()
	if err != nil {
		return Nutzlast{}, err
	}
	if segs > uint64(len(b)) {
		return Nutzlast{}, ErrLength
	}
	out.Segmente = make([]SegmentRef, segs)
	for i := range out.Segmente {
		key, err := c.text()
		if err != nil {
			return Nutzlast{}, err
		}
		out.Segmente[i].ObjectKey = key
		if out.Segmente[i].Hash, err = c.hash(); err != nil {
			return Nutzlast{}, err
		}
	}
	blobs, err := c.u64()
	if err != nil {
		return Nutzlast{}, err
	}
	if blobs > uint64(len(b)) {
		return Nutzlast{}, ErrLength
	}
	out.Bloecke = make([]Blob, blobs)
	for i := range out.Bloecke {
		if out.Bloecke[i].Mandant, err = c.id(); err != nil {
			return Nutzlast{}, err
		}
		wrapped, err := c.lp()
		if err != nil {
			return Nutzlast{}, err
		}
		if len(wrapped) == 0 {
			return Nutzlast{}, ErrLength
		}
		out.Bloecke[i].WrappedKey = wrapped
		nonce, err := c.take(NonceLen)
		if err != nil {
			return Nutzlast{}, err
		}
		copy(out.Bloecke[i].Nonce[:], nonce)
		ct, err := c.lp()
		if err != nil {
			return Nutzlast{}, err
		}
		out.Bloecke[i].Ciphertext = ct
		tag, err := c.take(TagLen)
		if err != nil {
			return Nutzlast{}, err
		}
		out.Bloecke[i].Tag = append([]byte(nil), tag...)
	}
	if c.i != len(c.b) {
		return Nutzlast{}, ErrLength
	}
	return out, nil
}

type cursor struct {
	b []byte
	i int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.i > len(c.b)-n {
		return nil, ErrLength
	}
	out := c.b[c.i : c.i+n]
	c.i += n
	return out, nil
}

func (c *cursor) u32() (uint32, error) {
	raw, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw), nil
}

func (c *cursor) u64() (uint64, error) {
	raw, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(raw), nil
}

func (c *cursor) id() (ID, error) {
	raw, err := c.take(IDLen)
	if err != nil {
		return ID{}, err
	}
	var id ID
	copy(id[:], raw)
	return id, nil
}

func (c *cursor) hash() (Hash, error) {
	raw, err := c.take(HashLen)
	if err != nil {
		return Hash{}, err
	}
	var h Hash
	copy(h[:], raw)
	return h, nil
}

func (c *cursor) lp() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	raw, err := c.take(int(n))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

func (c *cursor) text() (string, error) {
	raw, err := c.lp()
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", ErrLength
	}
	if !utf8.Valid(raw) {
		return "", ErrUTF8
	}
	return string(raw), nil
}
