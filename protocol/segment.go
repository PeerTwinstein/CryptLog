package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"strings"
)

const (
	// Segment256KiB ist die kleinste Segmentklasse.
	Segment256KiB = 256 << 10
	// Segment1MiB ist die Segmentklasse von 1 MiB.
	Segment1MiB = 1 << 20
	// Segment4MiB ist die Segmentklasse von 4 MiB und der Ausgangswert des Schreibprozesses.
	Segment4MiB = 4 << 20
	// Segment16MiB ist die Segmentklasse von 16 MiB.
	Segment16MiB = 16 << 20
	// Segment32MiB ist die größte Segmentklasse.
	Segment32MiB = 32 << 20
)

// Segmentklasse gilt für 256 KiB, 1 MiB, 4 MiB, 16 MiB und 32 MiB.
func Segmentklasse(n int) bool {
	switch n {
	case Segment256KiB, Segment1MiB, Segment4MiB, Segment16MiB, Segment32MiB:
		return true
	default:
		return false
	}
}

// KleinsteKlasse ist die kleinste Segmentklasse, die n Byte fasst.
func KleinsteKlasse(n int) (int, error) {
	switch {
	case n <= 0:
		return 0, ErrLength
	case n <= Segment256KiB:
		return Segment256KiB, nil
	case n <= Segment1MiB:
		return Segment1MiB, nil
	case n <= Segment4MiB:
		return Segment4MiB, nil
	case n <= Segment16MiB:
		return Segment16MiB, nil
	case n <= Segment32MiB:
		return Segment32MiB, nil
	default:
		return 0, ErrLength
	}
}

// ObjektSchluessel ist {mandant}/{ablage}/{epoch}/{segment_nr}.
// segment_nr beginnt bei 1 und steht dezimal ohne führende Nullen.
func ObjektSchluessel(mandant, ablage ID, epoch EpochID, nr uint64) (string, error) {
	if nr == 0 {
		return "", ErrLength
	}
	return mandant.Hex() + "/" + ablage.Hex() + "/" + epoch.String() + "/" + strconv.FormatUint(nr, 10), nil
}

// SegmentHash ist SHA-256 über die Bytes des Segmentobjekts.
func SegmentHash(b []byte) Hash {
	return sha256.Sum256(b)
}

// Zerlegen teilt ein Segmentobjekt in Kopf, Rahmen der Kette und Manifest.
// mitKopf gilt für das erste Segment, mitManifest für das letzte.
// Die zurückgegebenen Scheiben verweisen auf seg.
func Zerlegen(seg []byte, rahmen int, mitKopf, mitManifest bool) (kopf []byte, kette [][]byte, manifest []byte, err error) {
	if !Segmentklasse(len(seg)) || !gueltigerRahmen(rahmen) || len(seg)%rahmen != 0 {
		return nil, nil, nil, ErrLength
	}
	start, end := 0, len(seg)
	if mitKopf {
		_, _, _, n, perr := ParseKopf(seg)
		if perr != nil {
			return nil, nil, nil, perr
		}
		kopfEnde := ((n + rahmen - 1) / rahmen) * rahmen
		if kopfEnde <= 0 || kopfEnde > len(seg) {
			return nil, nil, nil, ErrRahmen
		}
		kopf = seg[:kopfEnde]
		start = kopfEnde
	}
	if mitManifest {
		if end-start < rahmen {
			return nil, nil, nil, ErrRahmen
		}
		manifest = seg[end-rahmen : end]
		if _, _, perr := ParseManifestRahmen(manifest); perr != nil {
			return nil, nil, nil, perr
		}
		end -= rahmen
	}
	if start > end {
		return nil, nil, nil, ErrRahmen
	}
	for off := start; off < end; off += rahmen {
		kette = append(kette, seg[off:off+rahmen])
	}
	return kopf, kette, manifest, nil
}

// ParseObjektSchluessel liest {mandant}/{ablage}/{epoch}/{segment_nr}.
// segment_nr steht dezimal ohne führende Nullen.
func ParseObjektSchluessel(s string) (mandant, ablage ID, epoch EpochID, nr uint64, err error) {
	teile := strings.Split(s, "/")
	if len(teile) != 4 {
		return ID{}, ID{}, EpochID{}, 0, ErrLength
	}
	mandant, err = ParseID(teile[0])
	if err != nil {
		return ID{}, ID{}, EpochID{}, 0, err
	}
	ablage, err = ParseID(teile[1])
	if err != nil {
		return ID{}, ID{}, EpochID{}, 0, err
	}
	epoch, err = ParseEpochID(teile[2])
	if err != nil {
		return ID{}, ID{}, EpochID{}, 0, err
	}
	nr, err = strconv.ParseUint(teile[3], 10, 64)
	if err != nil || strconv.FormatUint(nr, 10) != teile[3] {
		return ID{}, ID{}, EpochID{}, 0, ErrLength
	}
	return mandant, ablage, epoch, nr, nil
}

// KetteAusSegmenten setzt die Hash-Kette über die Rahmen der Segmente neu.
// Das erste Segment trägt den Epochenkopf. Ein Manifestrahmen gehört nicht dazu.
// Der Klartext-DEK wird nicht gebraucht.
func KetteAusSegmenten(mandant, ablage ID, epoch EpochID, rahmen int, segmente [][]byte) (Hash, uint64, error) {
	if len(segmente) == 0 {
		return Hash{}, 0, ErrLength
	}
	if _, err := RahmenNutz(rahmen); err != nil {
		return Hash{}, 0, err
	}
	kek, dek, wrapped, _, err := ParseKopf(segmente[0])
	if err != nil {
		return Hash{}, 0, err
	}
	chain, err := NewChain(mandant, ablage, epoch, dek, kek, wrapped)
	if err != nil {
		return Hash{}, 0, err
	}
	for i, seg := range segmente {
		_, kette, _, err := Zerlegen(seg, rahmen, i == 0, false)
		if err != nil {
			return Hash{}, 0, err
		}
		for _, frame := range kette {
			if len(frame) != rahmen {
				return Hash{}, 0, ErrRahmen
			}
			var nonce Nonce
			copy(nonce[:], frame[:NonceLen])
			seq := binary.BigEndian.Uint64(nonce[PrefixLen:])
			ct := frame[NonceLen : rahmen-TagLen]
			tag := frame[rahmen-TagLen:]
			if err := chain.Append(seq, nonce, ct, tag); err != nil {
				return Hash{}, 0, err
			}
		}
	}
	head, err := chain.Head()
	if err != nil {
		return Hash{}, 0, err
	}
	count, err := chain.Count()
	if err != nil {
		return Hash{}, 0, err
	}
	return head, count, nil
}
