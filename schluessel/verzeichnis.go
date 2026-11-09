package schluessel

import "cryptlog/protocol"

// Verzeichnis ist der Schlüsselspeicher des einfachen Modus.
// Der Schreibpfad bindet es nur lesend ein. Diese Methoden schreiben.
type Verzeichnis struct{ *ordner }

// OeffnenVerzeichnis legt die Wurzel an.
func OeffnenVerzeichnis(wurzel string) (*Verzeichnis, error) {
	o, err := oeffnenOrdner(wurzel)
	if err != nil {
		return nil, err
	}
	return &Verzeichnis{ordner: o}, nil
}

// Lesen liefert die aktuelle Veröffentlichung.
func (v *Verzeichnis) Lesen(id protocol.ID) ([]byte, []byte, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lesen(id)
}

// Stand ist die laufende Nummer und die aktuelle Veröffentlichung.
func (v *Verzeichnis) Stand(id protocol.ID) (Stand, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.stand(id)
}

// Fest hängt die Fassung an. Eine vorhandene Nummer wird nicht ersetzt.
func (v *Verzeichnis) Fest(id protocol.ID, pub, sig, eintrag []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fest(id, pub, sig, eintrag, nil)
}

// Privat legt den verschlüsselten privaten Schlüssel ab.
func (v *Verzeichnis) Privat(id protocol.ID, finger protocol.Hash, pkcs8 []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.privat(id, finger, pkcs8)
}

// Mandanten listet die Kennungen unter der Wurzel.
func (v *Verzeichnis) Mandanten() ([]protocol.ID, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.mandanten()
}

// Meta liest die Metadaten des Mandanten.
func (v *Verzeichnis) Meta(id protocol.ID) ([]byte, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.meta(id)
}

// MetaSetzen schreibt die Metadaten des Mandanten.
func (v *Verzeichnis) MetaSetzen(id protocol.ID, meta []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.metaSetzen(id, meta)
}
