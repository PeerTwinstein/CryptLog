package fenster

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// SpeicherAbschluss ist der Bestätigungsspeicher hinter dem Fenster.
// Anhaengen schreibt die Signatur des Empfängers an die eine Fassung.
type SpeicherAbschluss struct {
	Speicher   *bestaetigung.Speicher
	Schluessel *ecdsa.PublicKey
}

// Bestaetigung liest Hash und Signatur der einen Fassung.
func (a SpeicherAbschluss) Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (protocol.Hash, protocol.Signature, bool, error) {
	if a.Speicher == nil {
		return protocol.Hash{}, protocol.Signature{}, false, ErrBestaetigung
	}
	return a.Speicher.Bestaetigung(mandant, ablage, epoch)
}

// Vermerk liest den Löschtag.
func (a SpeicherAbschluss) Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (time.Time, bool, error) {
	if a.Speicher == nil {
		return time.Time{}, false, ErrBestaetigung
	}
	return a.Speicher.Vermerk(mandant, ablage, epoch)
}

// Anhaengen schreibt die Signatur des Empfängers an diese Fassung.
// ok ist falsch, wenn bereits eine andere Fassung der Abschluss ist.
func (a SpeicherAbschluss) Anhaengen(b Bestaetigung) (bool, error) {
	if a.Speicher == nil || a.Schluessel == nil {
		return false, ErrBestaetigung
	}
	finger, err := crypt.FingerprintSPKI(a.Schluessel)
	if err != nil || b.Finger != finger {
		return false, ErrBestaetigung
	}
	err = a.Speicher.Signieren(b.Mandant, b.Ablage, b.Epoch, b.Previous, b.Hash, b.Signatur, a.Schluessel)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bestaetigung.ErrFassung) {
		return false, nil
	}
	return false, err
}

// Zweige liefert die weiteren gültig signierten Fassungen.
func (a SpeicherAbschluss) Zweige(mandant, ablage protocol.ID, epoch protocol.EpochID) ([]werkzeug.Zweig, error) {
	if a.Speicher == nil {
		return nil, ErrBestaetigung
	}
	liste, err := a.Speicher.Zweige(mandant, ablage, epoch)
	if err != nil {
		return nil, err
	}
	out := make([]werkzeug.Zweig, len(liste))
	for i, z := range liste {
		out[i] = werkzeug.Zweig{Nutzlast: z.Nutzlast, Signatur: z.Signatur}
	}
	return out, nil
}
