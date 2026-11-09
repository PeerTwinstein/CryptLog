package protocol

import (
	"encoding/binary"
	"io"
)

const (
	// RahmenMin ist der kleinste Rahmen, 256 Byte.
	RahmenMin = 256
	// RahmenMax ist der größte Rahmen, 8192 Byte.
	RahmenMax = 8192
	// RahmenHuelle ist Nonce plus GCM-Tag. Die Nutzlänge ist die Rahmengröße abzüglich dieser Hülle.
	RahmenHuelle = NonceLen + TagLen
	// EreignisKopf ist Art plus die Gesamtlänge des Klartexts.
	EreignisKopf = 1 + 8
)

// RahmenNutz ist die Bytezahl des Klartexts in einem verschlüsselten Rahmen.
func RahmenNutz(rahmen int) (int, error) {
	if !gueltigerRahmen(rahmen) {
		return 0, ErrLength
	}
	return rahmen - RahmenHuelle, nil
}

func gueltigerRahmen(n int) bool {
	return n >= RahmenMin && n <= RahmenMax && n&(n-1) == 0
}

// EreignisKlartext ist event_id || zeitstempel || bind_id || L(inhalt) || inhalt.
func EreignisKlartext(event ID, zeitpunkt uint64, bind ID, inhalt []byte) ([]byte, error) {
	buf := make([]byte, 0, IDLen+8+IDLen+4+len(inhalt))
	buf = append(buf, event[:]...)
	buf = AppendU64(buf, zeitpunkt)
	buf = append(buf, bind[:]...)
	return appendLen(buf, inhalt)
}

// ParseEreignisKlartext liest einen vollständigen Ereignis-Klartext.
func ParseEreignisKlartext(b []byte) (event ID, zeitpunkt uint64, bind ID, inhalt []byte, err error) {
	if len(b) < IDLen+8+IDLen+4 {
		return ID{}, 0, ID{}, nil, ErrLength
	}
	copy(event[:], b[:IDLen])
	zeitpunkt = binary.BigEndian.Uint64(b[IDLen : IDLen+8])
	copy(bind[:], b[IDLen+8:IDLen+8+IDLen])
	n := binary.BigEndian.Uint32(b[IDLen+8+IDLen : IDLen+8+IDLen+4])
	rest := b[IDLen+8+IDLen+4:]
	if uint32(len(rest)) != n {
		return ID{}, 0, ID{}, nil, ErrLength
	}
	inhalt = append([]byte(nil), rest...)
	return event, zeitpunkt, bind, inhalt, nil
}

// SplitEreignis teilt den Klartext auf Rahmen der Nutzlänge.
// Der erste Rahmen ist ein Ereignis, jeder weitere eine Fortsetzung.
func SplitEreignis(klartext []byte, rahmen int, rnd io.Reader) ([][]byte, error) {
	nutz, err := RahmenNutz(rahmen)
	if err != nil {
		return nil, err
	}
	if len(klartext) == 0 || nutz <= EreignisKopf {
		return nil, ErrLength
	}
	var out [][]byte
	off := 0
	first := true
	for off < len(klartext) {
		frame := make([]byte, nutz)
		header, capDaten := 1, nutz-1
		if first {
			frame[0] = byte(ArtEreignis)
			binary.BigEndian.PutUint64(frame[1:9], uint64(len(klartext)))
			header, capDaten = EreignisKopf, nutz-EreignisKopf
			first = false
		} else {
			frame[0] = byte(ArtFortsetzung)
		}
		n := len(klartext) - off
		if n > capDaten {
			n = capDaten
		}
		copy(frame[header:header+n], klartext[off:off+n])
		if err := fuellen(frame[header+n:], rnd); err != nil {
			return nil, err
		}
		off += n
		out = append(out, frame)
	}
	return out, nil
}

// JoinEreignis setzt die Rahmen eines Ereignisses zum Klartext zusammen.
func JoinEreignis(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 {
		return nil, ErrLength
	}
	nutz := len(frames[0])
	if _, err := nutzZuRahmen(nutz); err != nil {
		return nil, err
	}
	gesamt, stueck, err := ereignisStueck(frames[0], nutz)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, gesamt)
	out = append(out, stueck...)
	for _, frame := range frames[1:] {
		if len(frame) != nutz || Art(frame[0]) != ArtFortsetzung {
			return nil, ErrRahmen
		}
		n := int(gesamt) - len(out)
		if n <= 0 {
			return nil, ErrRahmen
		}
		capDaten := nutz - 1
		if n > capDaten {
			n = capDaten
		}
		out = append(out, frame[1:1+n]...)
	}
	if uint64(len(out)) != gesamt {
		return nil, ErrRahmen
	}
	return out, nil
}

// Lesen liest eine Folge von Rahmen-Klartexten. Füllung wird übersprungen.
// Zurück kommen die Klartexte der Ereignisse in der Reihenfolge der Rahmen.
func Lesen(frames [][]byte) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < len(frames); {
		if len(frames[i]) == 0 {
			return nil, ErrLength
		}
		switch Art(frames[i][0]) {
		case ArtFuellung:
			if _, err := nutzZuRahmen(len(frames[i])); err != nil {
				return nil, err
			}
			i++
		case ArtEreignis:
			j := i + 1
			for j < len(frames) && len(frames[j]) > 0 && Art(frames[j][0]) == ArtFortsetzung {
				j++
			}
			klar, err := JoinEreignis(frames[i:j])
			if err != nil {
				return nil, err
			}
			out = append(out, klar)
			i = j
		default:
			return nil, ErrArt
		}
	}
	return out, nil
}

// Fuellrahmen ist ein Rahmen ohne Ereignisinhalt.
func Fuellrahmen(rahmen int, rnd io.Reader) ([]byte, error) {
	nutz, err := RahmenNutz(rahmen)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, nutz)
	frame[0] = byte(ArtFuellung)
	if err := fuellen(frame[1:], rnd); err != nil {
		return nil, err
	}
	return frame, nil
}

// Kopf ist kek_fingerabdruck || dek_id || L(wrapped_dek) || wrapped_dek.
func Kopf(kek Hash, dek ID, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, ErrLength
	}
	buf := make([]byte, 0, HashLen+IDLen+4+len(wrapped))
	buf = append(buf, kek[:]...)
	buf = append(buf, dek[:]...)
	return appendLen(buf, wrapped)
}

// KopfBereich legt den Kopf auf ganze Rahmen und füllt den angebrochenen Rahmen mit Zufall.
func KopfBereich(kek Hash, dek ID, wrapped []byte, rahmen int, rnd io.Reader) ([]byte, error) {
	if !gueltigerRahmen(rahmen) {
		return nil, ErrLength
	}
	logical, err := Kopf(kek, dek, wrapped)
	if err != nil {
		return nil, err
	}
	size := ((len(logical) + rahmen - 1) / rahmen) * rahmen
	out := make([]byte, size)
	copy(out, logical)
	if err := fuellen(out[len(logical):], rnd); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseKopf liest den Kopf am Anfang von b und liefert die Zahl der belegten Bytes.
func ParseKopf(b []byte) (kek Hash, dek ID, wrapped []byte, n int, err error) {
	if len(b) < HashLen+IDLen+4 {
		return Hash{}, ID{}, nil, 0, ErrLength
	}
	copy(kek[:], b[:HashLen])
	copy(dek[:], b[HashLen:HashLen+IDLen])
	wn := binary.BigEndian.Uint32(b[HashLen+IDLen : HashLen+IDLen+4])
	if wn == 0 || uint64(HashLen+IDLen+4)+uint64(wn) > uint64(len(b)) {
		return Hash{}, ID{}, nil, 0, ErrLength
	}
	end := HashLen + IDLen + 4 + int(wn)
	wrapped = append([]byte(nil), b[HashLen+IDLen+4:end]...)
	return kek, dek, wrapped, end, nil
}

// ManifestRahmen ist manifest_payload || signature || Zufall, ein Rahmen lang.
func ManifestRahmen(payload []byte, signature Signature, rahmen int, rnd io.Reader) ([]byte, error) {
	if !gueltigerRahmen(rahmen) {
		return nil, ErrLength
	}
	if len(payload) != ManifestPayloadLen {
		return nil, ErrLength
	}
	if rahmen < ManifestPayloadLen+SignatureLen {
		return nil, ErrLength
	}
	out := make([]byte, rahmen)
	copy(out, payload)
	copy(out[ManifestPayloadLen:], signature[:])
	if err := fuellen(out[ManifestPayloadLen+SignatureLen:], rnd); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseManifestRahmen liest Nutzlast und Signatur aus dem Manifest-Rahmen.
func ParseManifestRahmen(frame []byte) ([]byte, Signature, error) {
	if len(frame) < ManifestPayloadLen+SignatureLen || !gueltigerRahmen(len(frame)) {
		return nil, Signature{}, ErrLength
	}
	payload := append([]byte(nil), frame[:ManifestPayloadLen]...)
	prefix := Domain("manifest")
	if len(payload) < len(prefix) || string(payload[:len(prefix)]) != string(prefix) {
		return nil, Signature{}, ErrDomain
	}
	var sig Signature
	copy(sig[:], frame[ManifestPayloadLen:ManifestPayloadLen+SignatureLen])
	return payload, sig, nil
}

func ereignisStueck(frame []byte, nutz int) (uint64, []byte, error) {
	if len(frame) != nutz || nutz <= EreignisKopf || Art(frame[0]) != ArtEreignis {
		return 0, nil, ErrRahmen
	}
	gesamt := binary.BigEndian.Uint64(frame[1:9])
	if gesamt == 0 {
		return 0, nil, ErrLength
	}
	capDaten := nutz - EreignisKopf
	n := capDaten
	if uint64(n) > gesamt {
		n = int(gesamt)
	}
	return gesamt, append([]byte(nil), frame[EreignisKopf:EreignisKopf+n]...), nil
}

func nutzZuRahmen(nutz int) (int, error) {
	rahmen := nutz + RahmenHuelle
	if !gueltigerRahmen(rahmen) {
		return 0, ErrLength
	}
	return rahmen, nil
}

func fuellen(dst []byte, rnd io.Reader) error {
	if len(dst) == 0 {
		return nil
	}
	if rnd == nil {
		return ErrLength
	}
	_, err := io.ReadFull(rnd, dst)
	return err
}
