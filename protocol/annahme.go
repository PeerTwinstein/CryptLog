package protocol

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// Art eines Rahmens und eines Sequenzeintrags im Bindungsblob.
type Art byte

const (
	// ArtEreignis ist ein Log-, Verzeichnis- oder Indexeintrag.
	ArtEreignis Art = 1
	// ArtFortsetzung setzt einen Eintrag im nächsten Rahmen fort.
	ArtFortsetzung Art = 2
	// ArtFuellung füllt einen Rahmen oder ein Segment auf.
	ArtFuellung Art = 3
)

// SeqEintrag ist eine Sequenz dieses Abschlusses.
// Bei Fortsetzung und Füllung ist Event 16 Nullbytes.
type SeqEintrag struct {
	Seq   uint64
	Art   Art
	Event ID
}

// Slot ist ein Platz der Annahme: event_id || event_hash.
type Slot struct {
	Event ID
	Hash  Hash
}

// SegmentRef verweist auf ein Segmentobjekt und den SHA-256 seiner Bytes.
type SegmentRef struct {
	ObjectKey string
	Hash      Hash
}

// Blob ist der Bindungsanteil eines Abschlusses unter einem Wrap-Schlüssel.
// WrappedKey ist der Wrap der 48 Byte bindungsschluessel || batch_id.
// Nonce, Ciphertext und Tag sind die eine AES-256-GCM-Verschlüsselung von bindung.
type Blob struct {
	Mandant    ID
	WrappedKey []byte
	Nonce      Nonce
	Ciphertext []byte
	Tag        []byte
}

// Bindung ist der Klartext, den der Bindungsschlüssel einmal verschlüsselt.
func Bindung(batch ID, entries []SeqEintrag) ([]byte, error) {
	for _, e := range entries {
		switch e.Art {
		case ArtEreignis:
		case ArtFortsetzung, ArtFuellung:
			var zero ID
			if e.Event != zero {
				return nil, ErrEvent
			}
		default:
			return nil, ErrArt
		}
	}
	buf := make([]byte, 0, 4+7+IDLen+8+len(entries)*25)
	buf = AppendText(buf, "bindung")
	buf = append(buf, batch[:]...)
	buf = AppendU64(buf, uint64(len(entries)))
	for _, e := range entries {
		buf = AppendU64(buf, e.Seq)
		buf = append(buf, byte(e.Art))
		buf = append(buf, e.Event[:]...)
	}
	return buf, nil
}

// ParseBindung liest den Klartext bindung.
// Die batch_id ist dieselbe wie im Annahmeobjekt.
func ParseBindung(b []byte) (ID, []SeqEintrag, error) {
	c := cursor{b: b}
	if err := c.domain("bindung"); err != nil {
		return ID{}, nil, err
	}
	batch, err := c.id()
	if err != nil {
		return ID{}, nil, err
	}
	n, err := c.u64()
	if err != nil {
		return ID{}, nil, err
	}
	if n > uint64(len(b)) {
		return ID{}, nil, ErrLength
	}
	entries := make([]SeqEintrag, n)
	for i := range entries {
		if entries[i].Seq, err = c.u64(); err != nil {
			return ID{}, nil, err
		}
		art, err := c.one()
		if err != nil {
			return ID{}, nil, err
		}
		entries[i].Art = Art(art)
		if entries[i].Event, err = c.id(); err != nil {
			return ID{}, nil, err
		}
	}
	if err := c.done(); err != nil {
		return ID{}, nil, err
	}
	again, err := Bindung(batch, entries)
	if err != nil || !bytes.Equal(again, b) {
		return ID{}, nil, ErrLength
	}
	return batch, entries, nil
}

// AnnahmeGenesis ist der previous_annahme_hash der ersten Annahme einer Instanz.
func AnnahmeGenesis(instanz ID) Hash {
	buf := make([]byte, 0, 4+15+IDLen)
	buf = AppendText(buf, "annahme-genesis")
	buf = append(buf, instanz[:]...)
	return sha256.Sum256(buf)
}

// AnnahmePayload ist die Nutzlast des Annahmeobjekts.
// slot_count ist die nächste Zweierpotenz der Ereignisse, mindestens 8.
func AnnahmePayload(batch, instanz ID, batchSeq uint64, previous Hash, slots []Slot, segs []SegmentRef, blobs []Blob) ([]byte, error) {
	return closurePayload("annahme", batch, instanz, batchSeq, &previous, slots, segs, blobs)
}

// VorbereitungPayload ist dieselbe Nutzlast unter der Domäne "vorbereitung"
// und ohne previous_annahme_hash.
func VorbereitungPayload(batch, instanz ID, batchSeq uint64, slots []Slot, segs []SegmentRef, blobs []Blob) ([]byte, error) {
	return closurePayload("vorbereitung", batch, instanz, batchSeq, nil, slots, segs, blobs)
}

// AnnahmeHash ist SHA-256 über L("annahme-hash") || "annahme-hash" || annahme_payload.
func AnnahmeHash(payload []byte) (Hash, error) {
	if !bytes.HasPrefix(payload, Domain("annahme")) {
		return Hash{}, ErrDomain
	}
	buf := make([]byte, 0, 4+12+len(payload))
	buf = AppendText(buf, "annahme-hash")
	buf = append(buf, payload...)
	return sha256.Sum256(buf), nil
}

func closurePayload(domain string, batch, instanz ID, batchSeq uint64, previous *Hash, slots []Slot, segs []SegmentRef, blobs []Blob) ([]byte, error) {
	if !validSlotCount(len(slots)) {
		return nil, ErrSlotCount
	}
	for _, seg := range segs {
		if seg.ObjectKey == "" {
			return nil, ErrLength
		}
		if !utf8.ValidString(seg.ObjectKey) {
			return nil, ErrUTF8
		}
		if uint64(len(seg.ObjectKey)) > 0xffffffff {
			return nil, ErrLength
		}
	}
	for _, blob := range blobs {
		if len(blob.WrappedKey) == 0 || uint64(len(blob.WrappedKey)) > 0xffffffff {
			return nil, ErrLength
		}
		if len(blob.Tag) != TagLen || uint64(len(blob.Ciphertext)) > 0xffffffff {
			return nil, ErrLength
		}
	}

	buf := AppendText(nil, domain)
	buf = append(buf, batch[:]...)
	buf = append(buf, instanz[:]...)
	buf = AppendU64(buf, batchSeq)
	if previous != nil {
		buf = append(buf, previous[:]...)
	}
	buf = AppendU64(buf, uint64(len(slots)))
	for _, slot := range slots {
		buf = append(buf, slot.Event[:]...)
		buf = append(buf, slot.Hash[:]...)
	}
	buf = AppendU64(buf, uint64(len(segs)))
	for _, seg := range segs {
		var err error
		buf, err = appendLen(buf, []byte(seg.ObjectKey))
		if err != nil {
			return nil, err
		}
		buf = append(buf, seg.Hash[:]...)
	}
	buf = AppendU64(buf, uint64(len(blobs)))
	for _, blob := range blobs {
		buf = append(buf, blob.Mandant[:]...)
		var err error
		buf, err = appendLen(buf, blob.WrappedKey)
		if err != nil {
			return nil, err
		}
		buf = append(buf, blob.Nonce[:]...)
		buf, err = appendLen(buf, blob.Ciphertext)
		if err != nil {
			return nil, err
		}
		buf = append(buf, blob.Tag...)
	}
	return buf, nil
}

// SlotZahl ist die nächste Zweierpotenz der Ereignisse, mindestens 8.
// Liegt kein Ereignis vor, ist die Zahl 8.
func SlotZahl(ereignisse int) (int, error) {
	if ereignisse < 0 {
		return 0, ErrLength
	}
	n := 8
	for n < ereignisse {
		if n > math.MaxInt/2 {
			return 0, ErrLength
		}
		n *= 2
	}
	return n, nil
}

// Plaetze stellt die Ereignisse voran und füllt danach mit zufälligen Plätzen
// auf SlotZahl auf. rnd liefert die Zufallsbytes der Füllplätze.
func Plaetze(ereignisse []Slot, rnd io.Reader) ([]Slot, error) {
	n, err := SlotZahl(len(ereignisse))
	if err != nil {
		return nil, err
	}
	belegt := make(map[ID]struct{}, n)
	for _, s := range ereignisse {
		if _, ok := belegt[s.Event]; ok {
			return nil, ErrEvent
		}
		belegt[s.Event] = struct{}{}
	}
	out := append([]Slot(nil), ereignisse...)
	for len(out) < n {
		slot, err := fuellplatz(rnd, belegt)
		if err != nil {
			return nil, err
		}
		out = append(out, slot)
	}
	return out, nil
}

func fuellplatz(rnd io.Reader, belegt map[ID]struct{}) (Slot, error) {
	if rnd == nil {
		return Slot{}, ErrLength
	}
	for versuch := 0; versuch < 8; versuch++ {
		var slot Slot
		if _, err := io.ReadFull(rnd, slot.Event[:]); err != nil {
			return Slot{}, err
		}
		if _, err := io.ReadFull(rnd, slot.Hash[:]); err != nil {
			return Slot{}, err
		}
		if _, ok := belegt[slot.Event]; ok {
			continue
		}
		belegt[slot.Event] = struct{}{}
		return slot, nil
	}
	return Slot{}, ErrLength
}

// VorbereitungSchluessel ist vorbereitung/{instanz_hex}/{batch_seq}.
// batch_seq beginnt bei 1 und steht dezimal ohne führende Nullen.
func VorbereitungSchluessel(instanz ID, batchSeq uint64) (string, error) {
	return abschlussSchluessel("vorbereitung", instanz, batchSeq)
}

// AnnahmeSchluessel ist annahme/{instanz_hex}/{batch_seq}.
func AnnahmeSchluessel(instanz ID, batchSeq uint64) (string, error) {
	return abschlussSchluessel("annahme", instanz, batchSeq)
}

func abschlussSchluessel(name string, instanz ID, batchSeq uint64) (string, error) {
	if batchSeq == 0 {
		return "", ErrLength
	}
	return name + "/" + instanz.Hex() + "/" + strconv.FormatUint(batchSeq, 10), nil
}

func validSlotCount(n int) bool {
	z, err := SlotZahl(n)
	return err == nil && z == n
}
