package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// Genesis ist der Anfang der Manifestkette einer Instanz in einer Ablage.
func Genesis(ablage, instanz ID) Hash {
	buf := make([]byte, 0, 4+7+IDLen+IDLen)
	buf = AppendText(buf, "genesis")
	buf = append(buf, ablage[:]...)
	buf = append(buf, instanz[:]...)
	return sha256.Sum256(buf)
}

// EpochHead ist head_0. Der gewrappte DEK hängt an derselben Kette wie die Einträge.
func EpochHead(ablage ID, kek Hash, epoch EpochID, dek ID, wrapped []byte) (Hash, error) {
	if len(wrapped) == 0 {
		return Hash{}, ErrLength
	}
	buf := make([]byte, 0, 4+10+IDLen+HashLen+EpochLen+IDLen+4+len(wrapped))
	buf = AppendText(buf, "epoch-head")
	buf = append(buf, ablage[:]...)
	buf = append(buf, kek[:]...)
	buf = append(buf, epoch[:]...)
	buf = append(buf, dek[:]...)
	var err error
	buf, err = appendLen(buf, wrapped)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(buf), nil
}

// EntryHead ist head_n. tag ist das GCM-Tag von 16 Byte und trägt kein Längenfeld.
// aad sind die 92 Byte aus AAD.
func EntryHead(prev Hash, dek ID, seq uint64, nonce Nonce, ciphertext, tag, aad []byte) (Hash, error) {
	if len(tag) != TagLen || len(aad) != AADSize {
		return Hash{}, ErrLength
	}
	buf := make([]byte, 0, 4+5+HashLen+IDLen+8+NonceLen+4+len(ciphertext)+TagLen+4+len(aad))
	buf = AppendText(buf, "entry")
	buf = append(buf, prev[:]...)
	buf = append(buf, dek[:]...)
	buf = AppendU64(buf, seq)
	buf = append(buf, nonce[:]...)
	var err error
	buf, err = appendLen(buf, ciphertext)
	if err != nil {
		return Hash{}, err
	}
	buf = append(buf, tag...)
	buf, err = appendLen(buf, aad)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(buf), nil
}

// ManifestPayloadLen ist die feste Länge von manifest_payload.
const ManifestPayloadLen = 4 + 8 + EpochLen + HashLen + HashLen + 8 + 8 + 8 + HashLen

// ManifestPayload ist die signierte Nutzlast eines Epochenmanifests.
// previous ist bei der ersten Epoche einer Instanz der Genesis-Hash.
// Hat die Epoche keine Einträge, sind annahmeFirst und annahmeLast 0 und
// annahmeHead 32 Nullbytes. Das prüft diese Funktion nicht nach: der Prüfer
// muss dieselbe Nutzlast auch aus einer abweichenden Fassung nachrechnen können.
func ManifestPayload(epoch EpochID, previous, chainHead Hash, entryCount, annahmeFirst, annahmeLast uint64, annahmeHead Hash) []byte {
	buf := make([]byte, 0, 4+8+EpochLen+HashLen*3+8*3)
	buf = AppendText(buf, "manifest")
	buf = append(buf, epoch[:]...)
	buf = append(buf, previous[:]...)
	buf = append(buf, chainHead[:]...)
	buf = AppendU64(buf, entryCount)
	buf = AppendU64(buf, annahmeFirst)
	buf = AppendU64(buf, annahmeLast)
	buf = append(buf, annahmeHead[:]...)
	return buf
}

// Manifest ist die geöffnete Nutzlast eines Epochenmanifests.
type Manifest struct {
	Epoch        EpochID
	Previous     Hash
	ChainHead    Hash
	Count        uint64
	AnnahmeFirst uint64
	AnnahmeLast  uint64
	AnnahmeHead  Hash
}

// ParseManifest liest eine vollständige Manifest-Nutzlast.
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) != ManifestPayloadLen {
		return Manifest{}, ErrLength
	}
	if !bytes.HasPrefix(b, Domain("manifest")) {
		return Manifest{}, ErrDomain
	}
	var m Manifest
	off := len(Domain("manifest"))
	copy(m.Epoch[:], b[off:off+EpochLen])
	off += EpochLen
	copy(m.Previous[:], b[off:off+HashLen])
	off += HashLen
	copy(m.ChainHead[:], b[off:off+HashLen])
	off += HashLen
	m.Count = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	m.AnnahmeFirst = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	m.AnnahmeLast = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	copy(m.AnnahmeHead[:], b[off:off+HashLen])
	return m, nil
}

// EpochHash hängt die Signatur an die Manifest-Nutzlast.
// Die Signatur ist r || s und wird längenpräfixiert.
func EpochHash(manifestPayload []byte, signature Signature) (Hash, error) {
	if !bytes.HasPrefix(manifestPayload, Domain("manifest")) {
		return Hash{}, ErrDomain
	}
	buf := make([]byte, 0, 4+10+len(manifestPayload)+4+SignatureLen)
	buf = AppendText(buf, "epoch-hash")
	buf = append(buf, manifestPayload...)
	buf = AppendU32(buf, SignatureLen)
	buf = append(buf, signature[:]...)
	return sha256.Sum256(buf), nil
}

// ConfirmationPayload ist die Nutzlast der Epochenbestätigung.
// Signiert wird sie vom Empfänger, nicht vom Schreibpfad.
func ConfirmationPayload(epochHash Hash) []byte {
	buf := make([]byte, 0, 4+7+HashLen)
	buf = AppendText(buf, "confirm")
	buf = append(buf, epochHash[:]...)
	return buf
}

// Chain ist die Hash-Kette einer offenen Epoche im Speicher des Schreibers.
// Append wird einmal beim Verschlüsseln aufgerufen, nicht bei jedem
// wiederholten Schreiben derselben Bytes. Der Aufrufer hält den gegenseitigen
// Ausschluss der Sequenzvergabe.
type Chain struct {
	ok      bool
	mandant ID
	ablage  ID
	epoch   EpochID
	dek     ID
	head    Hash
	count   uint64
}

// NewChain beginnt die Kette bei head_0.
func NewChain(mandant, ablage ID, epoch EpochID, dek ID, kek Hash, wrapped []byte) (Chain, error) {
	head, err := EpochHead(ablage, kek, epoch, dek, wrapped)
	if err != nil {
		return Chain{}, err
	}
	return Chain{
		ok:      true,
		mandant: mandant,
		ablage:  ablage,
		epoch:   epoch,
		dek:     dek,
		head:    head,
	}, nil
}

// Head ist chain_head. Ohne Einträge ist das head_0.
func (c Chain) Head() (Hash, error) {
	if !c.ok {
		return Hash{}, ErrChain
	}
	return c.head, nil
}

// Count ist entry_count. Kopf und Manifest zählen nicht mit.
func (c Chain) Count() (uint64, error) {
	if !c.ok {
		return 0, ErrChain
	}
	return c.count, nil
}

// Append hängt einen Rahmen an. Die erste Sequenz ist 1, jede weitere der
// um 1 höhere Wert. Die Nonce muss epoch_prefix || seq dieser Epoche sein.
// Passt der nächste Wert nicht mehr in 64 Bit, wird nicht angehängt.
func (c *Chain) Append(seq uint64, nonce Nonce, ciphertext, tag []byte) error {
	if !c.ok {
		return ErrChain
	}
	if c.count == math.MaxUint64 || seq != c.count+1 {
		return ErrSeq
	}
	var prefix Prefix
	copy(prefix[:], nonce[:PrefixLen])
	if prefix != c.epoch.Prefix() {
		return ErrNonce
	}
	var seqRaw [8]byte
	binary.BigEndian.PutUint64(seqRaw[:], seq)
	if !bytes.Equal(nonce[PrefixLen:], seqRaw[:]) {
		return ErrNonce
	}
	aad := AAD(c.mandant, c.ablage, c.epoch, c.dek, seq)
	head, err := EntryHead(c.head, c.dek, seq, nonce, ciphertext, tag, aad)
	if err != nil {
		return err
	}
	c.head = head
	c.count++
	return nil
}

// Manifest ist die Nutzlast zum aktuellen Kettenkopf.
func (c Chain) Manifest(previous Hash, annahmeFirst, annahmeLast uint64, annahmeHead Hash) ([]byte, error) {
	if !c.ok {
		return nil, ErrChain
	}
	return ManifestPayload(c.epoch, previous, c.head, c.count, annahmeFirst, annahmeLast, annahmeHead), nil
}
