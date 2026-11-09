package fenster

import (
	"crypto/ecdsa"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Bestaetigt ist die eigene Signatur einer Epoche.
type Bestaetigt struct {
	Epoch    protocol.EpochID
	Signatur protocol.Signature
}

// Bestaetigen signiert die genannten Epochen, nachdem Kette und HSM-Signatur halten.
// Eine Lücke, eine Verzweigung und ein Bruch zum Vorgänger werden nicht bestätigt.
// Die Passphrase des Bestätigungsschlüssels wird nicht abgelegt.
// Genau einer von Passphrase und Träger öffnet die Signatur.
func (f *Fenster) Bestaetigen(passphrase []byte, traeger Traeger, ablage protocol.ID, rolle protocol.StromRolle, epochen []protocol.EpochID) ([]Bestaetigt, error) {
	defer crypt.Wipe(passphrase)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.entsperrt() {
		return nil, ErrFenster
	}
	if traeger != nil && len(passphrase) != 0 {
		return nil, ErrModus
	}
	if traeger == nil && len(passphrase) == 0 {
		return nil, ErrPassphrase
	}
	var key *ecdsa.PrivateKey
	if traeger == nil {
		if f.verb.Bestaetigung == "" {
			return nil, ErrPassphrase
		}
		roh, err := datei(f.verb.Bestaetigung)
		if err != nil {
			return nil, err
		}
		defer crypt.Wipe(roh)
		priv, err := Entschluesseln(roh, passphrase)
		if err != nil {
			return nil, err
		}
		defer verwerfen(priv)
		pub, err := oeffentlich(priv)
		if err != nil || !gleich(pub, f.bestPub) {
			return nil, ErrBestaetigung
		}
		var ok bool
		key, ok = priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrBestaetigung
		}
	} else {
		pub, err := traeger.Oeffentlich()
		if err != nil || !gleich(pub, f.bestPub) {
			return nil, ErrBestaetigung
		}
	}
	return f.bestaetigen(key, traeger, ablage, rolle, epochen)
}

func (f *Fenster) bestaetigen(key *ecdsa.PrivateKey, traeger Traeger, ablage protocol.ID, rolle protocol.StromRolle, epochen []protocol.EpochID) ([]Bestaetigt, error) {
	switch rolle {
	case protocol.RolleGruppe, protocol.RolleEinzel, protocol.RolleAuffang,
		protocol.RolleVerzeichnis, protocol.RolleKatalog, protocol.RolleVerzeichnisSumme:
	default:
		return nil, ErrArt
	}
	if len(epochen) == 0 || ablage == (protocol.ID{}) {
		return nil, ErrBestaetigung
	}
	ids, nach, err := f.gruppieren(f.verb.Mandant, ablage)
	if err != nil {
		return nil, err
	}
	wollen := make(map[protocol.EpochID]struct{}, len(epochen))
	for _, id := range epochen {
		wollen[id] = struct{}{}
	}
	finger, err := crypt.FingerprintSPKI(f.bestPub)
	if err != nil {
		return nil, err
	}
	vorher := map[protocol.ID]protocol.Hash{}
	gebrochen := map[protocol.ID]bool{}
	gesehen := map[protocol.EpochID]struct{}{}
	var out []Bestaetigt
	abgelehnt := false
	for _, id := range ids {
		gesehen[id] = struct{}{}
		instanz := id.Instanz()
		_, gewollt := wollen[id]
		if gebrochen[instanz] {
			if gewollt {
				abgelehnt = true
			}
			continue
		}
		if _, ok := vorher[instanz]; !ok {
			vorher[instanz] = protocol.Genesis(ablage, instanz)
		}
		refs := nach[id]
		if !lueckenlos(refs) {
			gebrochen[instanz] = true
			if gewollt {
				abgelehnt = true
			}
			continue
		}
		bericht, err := f.kette(ablage, rolle, id, refs, vorher[instanz])
		if err != nil || bericht.Verzweigung || bericht.VorgaengerBruch {
			gebrochen[instanz] = true
			if gewollt {
				abgelehnt = true
			}
			continue
		}
		gespeichert, _, ok, err := f.abschluss.Bestaetigung(f.verb.Mandant, ablage, id)
		if err != nil {
			return nil, err
		}
		if ok {
			if gespeichert != bericht.EpochHash {
				gebrochen[instanz] = true
				if gewollt {
					abgelehnt = true
				}
				continue
			}
			vorher[instanz] = gespeichert
			continue
		}
		if !gewollt {
			gebrochen[instanz] = true
			continue
		}
		sig, err := bestaetigungsSignatur(key, traeger, f.bestPub, bericht.EpochHash)
		if err != nil {
			return nil, err
		}
		geschrieben, err := f.abschluss.Anhaengen(Bestaetigung{
			Mandant: f.verb.Mandant, Ablage: ablage, Epoch: id,
			Previous: bericht.Previous, Hash: bericht.EpochHash,
			Signatur: sig, Finger: finger,
		})
		if err != nil {
			return nil, err
		}
		if !geschrieben {
			abgelehnt = true
			gebrochen[instanz] = true
			continue
		}
		vorher[instanz] = bericht.EpochHash
		out = append(out, Bestaetigt{Epoch: id, Signatur: sig})
	}
	for _, id := range epochen {
		if _, ok := gesehen[id]; !ok {
			abgelehnt = true
		}
	}
	if abgelehnt {
		return out, ErrBestaetigung
	}
	return out, nil
}

func (f *Fenster) kette(ablage protocol.ID, rolle protocol.StromRolle, id protocol.EpochID, refs []segRef, vorher protocol.Hash) (werkzeug.Bericht, error) {
	segs := make([]werkzeug.Segment, len(refs))
	for i, ref := range refs {
		roh, err := f.lesen(ref.key)
		if err != nil {
			return werkzeug.Bericht{}, err
		}
		segs[i] = werkzeug.Segment{Schluessel: ref.key, Bytes: roh}
	}
	zweige, err := f.abschluss.Zweige(f.verb.Mandant, ablage, id)
	if err != nil {
		return werkzeug.Bericht{}, err
	}
	return werkzeug.Pruefen(werkzeug.Auftrag{
		Mandant: f.verb.Mandant, Ablage: ablage, Epoch: id, Rahmen: f.rahmen,
		Rolle: rolle, Segmente: segs, HSM: f.hsm, Zertifikat: f.cert,
		Status: f.lageStatus(), Vorgaenger: vorher, Zweige: zweige,
	})
}

func bestaetigungsSignatur(key *ecdsa.PrivateKey, traeger Traeger, pub *ecdsa.PublicKey, hash protocol.Hash) (protocol.Signature, error) {
	payload := protocol.ConfirmationPayload(hash)
	var (
		sig protocol.Signature
		err error
	)
	if traeger != nil {
		sig, err = traeger.Signieren(payload)
	} else {
		sig, err = crypt.SignP256(key, payload)
	}
	if err != nil || !crypt.VerifyP256(pub, payload, sig) {
		return protocol.Signature{}, ErrBestaetigung
	}
	return sig, nil
}
