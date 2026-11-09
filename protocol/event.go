package protocol

import "crypto/sha256"

// EventHash bindet die event_id an den Klartext, so wie der Dienst ihn vor
// der Aufteilung auf Rahmen fasst. seq, Nonce und Ciphertext gehören nicht dazu.
func EventHash(mandant, event ID, klartext []byte) (Hash, error) {
	buf := AppendText(nil, "event")
	buf = append(buf, mandant[:]...)
	buf = append(buf, event[:]...)
	var err error
	buf, err = appendLen(buf, klartext)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(buf), nil
}
