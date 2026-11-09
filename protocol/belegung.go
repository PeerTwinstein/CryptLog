package protocol

import (
	"bytes"
	"encoding/binary"
	"math"
)

const (
	// BelegungLen ist die feste Länge des Belegungsobjekts.
	BelegungLen = 4 + 8 + IDLen*3 + 8 + 1 + HashLen
	// InstanzLen ist die feste Länge des Instanzobjekts.
	InstanzLen = 4 + 7 + IDLen + 8
	// UhrSchiefe ist die Uhrabweichung, die eine Übernahme zusätzlich zur Frist abwartet.
	// Fünf Sekunden, die Uhren laufen über NTP.
	UhrSchiefe uint64 = 5000
)

// Lage ist der Zustand einer Generation. Offen kann getauscht werden.
// Angenommen ist die Annahme dieser Generation.
type Lage uint8

const (
	// LageOffen kann auf die angenommene Fassung dieser Generation getauscht werden.
	LageOffen Lage = 1
	// LageAngenommen ist die Annahme dieser Generation.
	LageAngenommen Lage = 2
)

// Belegung ist das Objekt belegt/{event_id}.
// Die Generation beginnt bei 1.
type Belegung struct {
	Event      ID
	Instanz    ID
	Batch      ID
	Generation uint64
	Lage       Lage
	Hash       Hash
}

// InstanzLauf ist das Objekt instanz/{instanz_hex}.
// Frist ist die Unix-Zeit in Millisekunden, zu der die Frist endet.
type InstanzLauf struct {
	Instanz ID
	Frist   uint64
}

// Entscheid ist das Ergebnis eines erneuten Sendens gegenüber einer Belegung.
type Entscheid int

const (
	EntscheidNeu        Entscheid = iota + 1 // noch keine Belegung
	EntscheidWeiter                          // dieselbe Instanz führt den Abschluss weiter
	EntscheidBestaetigt                      // die Annahme liegt vor
	EntscheidAbgelehnt                       // anderer event_hash
	EntscheidGehalten                        // eine andere Instanz hält die Frist
	EntscheidUebernahme                      // die Frist ist abgelaufen, die Generation steigt
)

// BelegungSchluessel ist belegt/{event_hex}.
func BelegungSchluessel(event ID) string { return "belegt/" + event.Hex() }

// InstanzSchluessel ist instanz/{instanz_hex}.
func InstanzSchluessel(instanz ID) string { return "instanz/" + instanz.Hex() }

// BelegungBytes ist L("belegung") || "belegung" || event_id || instanz_id || batch_id || generation || lage || event_hash.
func BelegungBytes(b Belegung) ([]byte, error) {
	if b.Generation == 0 || (b.Lage != LageOffen && b.Lage != LageAngenommen) {
		return nil, ErrLength
	}
	buf := make([]byte, 0, BelegungLen)
	buf = AppendText(buf, "belegung")
	buf = append(buf, b.Event[:]...)
	buf = append(buf, b.Instanz[:]...)
	buf = append(buf, b.Batch[:]...)
	buf = AppendU64(buf, b.Generation)
	buf = append(buf, byte(b.Lage))
	buf = append(buf, b.Hash[:]...)
	return buf, nil
}

// ParseBelegung liest ein vollständiges Belegungsobjekt.
func ParseBelegung(b []byte) (Belegung, error) {
	if len(b) != BelegungLen || !bytes.HasPrefix(b, Domain("belegung")) {
		return Belegung{}, ErrLength
	}
	var out Belegung
	off := 4 + 8
	copy(out.Event[:], b[off:off+IDLen])
	off += IDLen
	copy(out.Instanz[:], b[off:off+IDLen])
	off += IDLen
	copy(out.Batch[:], b[off:off+IDLen])
	off += IDLen
	out.Generation = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	out.Lage = Lage(b[off])
	off++
	copy(out.Hash[:], b[off:off+HashLen])
	if out.Generation == 0 || (out.Lage != LageOffen && out.Lage != LageAngenommen) {
		return Belegung{}, ErrLength
	}
	return out, nil
}

// Nachfolger ist die offene Belegung der übernehmenden Instanz.
// event_id und event_hash bleiben, die Generation steigt um 1.
// Eine angenommene Generation hat keinen Nachfolger.
func (b Belegung) Nachfolger(instanz, batch ID) (Belegung, error) {
	if b.Lage != LageOffen || b.Generation == 0 || b.Generation == math.MaxUint64 {
		return Belegung{}, ErrLength
	}
	b.Instanz = instanz
	b.Batch = batch
	b.Generation++
	b.Lage = LageOffen
	return b, nil
}

// Annehmen setzt die offene Generation auf angenommen.
func (b Belegung) Annehmen() (Belegung, error) {
	if b.Lage != LageOffen || b.Generation == 0 {
		return Belegung{}, ErrLength
	}
	b.Lage = LageAngenommen
	return b, nil
}

// InstanzBytes ist L("instanz") || "instanz" || instanz_id || frist.
func InstanzBytes(lauf InstanzLauf) []byte {
	buf := make([]byte, 0, InstanzLen)
	buf = AppendText(buf, "instanz")
	buf = append(buf, lauf.Instanz[:]...)
	return AppendU64(buf, lauf.Frist)
}

// ParseInstanzLauf liest ein vollständiges Instanzobjekt.
func ParseInstanzLauf(b []byte) (InstanzLauf, error) {
	if len(b) != InstanzLen || !bytes.HasPrefix(b, Domain("instanz")) {
		return InstanzLauf{}, ErrLength
	}
	var out InstanzLauf
	copy(out.Instanz[:], b[4+7:4+7+IDLen])
	out.Frist = binary.BigEndian.Uint64(b[4+7+IDLen:])
	return out, nil
}

// Entscheiden vergleicht ein erneutes Senden mit der vorliegenden Belegung.
// vorhanden nil heißt, es liegt keine Belegung vor. annahme heißt, die Annahme
// dieser Generation liegt vor. Bestätigt ist nur eine angenommene Lage mit
// dieser Annahme. lauf nil heißt, das Instanzobjekt des Inhabers fehlt; die
// offene Generation kann dann übernommen werden. jetzt und Frist sind
// Unix-Millisekunden. Eine vorliegende Frist hält bis Frist plus UhrSchiefe.
// Dieselbe Instanz führt ihre offene Generation weiter.
func Entscheiden(vorhanden *Belegung, hash Hash, annahme bool, eigene ID, jetzt uint64, lauf *InstanzLauf) (Entscheid, error) {
	if vorhanden == nil {
		if annahme {
			return 0, ErrBelegung
		}
		return EntscheidNeu, nil
	}
	if vorhanden.Generation == 0 || (vorhanden.Lage != LageOffen && vorhanden.Lage != LageAngenommen) {
		return 0, ErrLength
	}
	if vorhanden.Hash != hash {
		return EntscheidAbgelehnt, nil
	}
	if vorhanden.Lage == LageAngenommen {
		if annahme {
			return EntscheidBestaetigt, nil
		}
		if vorhanden.Instanz == eigene {
			return EntscheidWeiter, nil
		}
		return EntscheidGehalten, nil
	}
	if vorhanden.Instanz == eigene {
		return EntscheidWeiter, nil
	}
	if gehalten(*vorhanden, jetzt, lauf) {
		return EntscheidGehalten, nil
	}
	return EntscheidUebernahme, nil
}

func gehalten(b Belegung, jetzt uint64, lauf *InstanzLauf) bool {
	if lauf == nil || lauf.Instanz != b.Instanz {
		return false
	}
	if lauf.Frist > math.MaxUint64-UhrSchiefe {
		return jetzt < lauf.Frist
	}
	return jetzt < lauf.Frist+UhrSchiefe
}
