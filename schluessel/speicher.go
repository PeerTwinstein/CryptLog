package schluessel

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cryptlog/protocol"
)

// Stand ist die zuletzt angefügte Nummer und die aktuelle Veröffentlichung.
// Liegt keine Veröffentlichung, ist Da falsch. Die Nummer bleibt die des Protokolls.
type Stand struct {
	Nummer uint64
	Pub    []byte
	Sig    []byte
	Da     bool
}

// Quelle liest die Veröffentlichung. Der Schreibprozess schreibt sie nicht.
type Quelle interface {
	Lesen(id protocol.ID) (pub, sig []byte, da bool, err error)
}

// Speicher ist die Ablage der Verwaltung.
type Speicher interface {
	Quelle
	Stand(id protocol.ID) (Stand, error)
	Fest(id protocol.ID, pub, sig, eintrag []byte) error
	Privat(id protocol.ID, finger protocol.Hash, pkcs8 []byte) error
	Mandanten() ([]protocol.ID, error)
	Meta(id protocol.ID) ([]byte, bool, error)
	MetaSetzen(id protocol.ID, meta []byte) error
}

// AnkerRegistrierung merkt den Vertrauensanker des sicheren Modus.
type AnkerRegistrierung interface {
	Anker(id protocol.ID, certDER []byte) error
}

type ordner struct {
	mu     sync.Mutex
	wurzel string
}

func oeffnenOrdner(wurzel string) (*ordner, error) {
	abs, err := filepath.Abs(wurzel)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &ordner{wurzel: abs}, nil
}

func (o *ordner) mandantDir(id protocol.ID) (string, error) {
	if id == (protocol.ID{}) {
		return "", ErrMandant
	}
	dir := filepath.Join(o.wurzel, id.Hex())
	rel, err := filepath.Rel(o.wurzel, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel != id.Hex() {
		return "", ErrMandant
	}
	return dir, nil
}

func (o *ordner) stand(id protocol.ID) (Stand, error) {
	dir, err := o.mandantDir(id)
	if err != nil {
		return Stand{}, err
	}
	eintraege, err := leseProtokoll(dir)
	if err != nil {
		return Stand{}, err
	}
	if err := kette(id, eintraege); err != nil {
		return Stand{}, err
	}
	var nummer uint64
	if len(eintraege) > 0 {
		nummer = eintraege[len(eintraege)-1].Nummer
	}
	pub, da, err := lesenDatei(filepath.Join(dir, "veroeffentlichung"))
	if err != nil || !da {
		return Stand{Nummer: nummer}, err
	}
	gefasst, err := ParseVeroeffentlichung(pub)
	if err != nil || gefasst.Mandant != id || gefasst.Nummer > nummer {
		return Stand{}, ErrFormat
	}
	sig, _, err := lesenDatei(filepath.Join(dir, "signatur"))
	if err != nil {
		return Stand{}, err
	}
	return Stand{Nummer: nummer, Pub: pub, Sig: sig, Da: true}, nil
}

func (o *ordner) fest(id protocol.ID, pub, sig, eintrag []byte, signatur func([]byte, []byte) error) error {
	if signatur != nil {
		if err := signatur(pub, sig); err != nil {
			return err
		}
	} else if len(sig) != 0 {
		return ErrModus
	}
	gefasst, err := ParseVeroeffentlichung(pub)
	if err != nil || gefasst.Mandant != id {
		return ErrFormat
	}
	ein, err := ParseEintrag(eintrag)
	if err != nil || ein.Mandant != id || ein.Nummer != gefasst.Nummer {
		return ErrFormat
	}
	st, err := o.stand(id)
	if err != nil {
		return err
	}
	if ein.Nummer != st.Nummer+1 {
		return ErrNummer
	}
	dir, err := o.mandantDir(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := anhaengen(filepath.Join(dir, "protokoll"), eintrag); err != nil {
		return err
	}
	if err := ersetzen(filepath.Join(dir, "veroeffentlichung"), pub); err != nil {
		return err
	}
	sigPfad := filepath.Join(dir, "signatur")
	if len(sig) == 0 {
		if err := os.Remove(sigPfad); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return ersetzen(sigPfad, sig)
}

func (o *ordner) lesen(id protocol.ID) ([]byte, []byte, bool, error) {
	dir, err := o.mandantDir(id)
	if err != nil {
		return nil, nil, false, err
	}
	pub, da, err := lesenDatei(filepath.Join(dir, "veroeffentlichung"))
	if err != nil {
		return nil, nil, false, ErrQuelle
	}
	if !da {
		return nil, nil, false, nil
	}
	sig, _, err := lesenDatei(filepath.Join(dir, "signatur"))
	if err != nil {
		return nil, nil, false, ErrQuelle
	}
	return pub, sig, true, nil
}

func (o *ordner) privat(id protocol.ID, finger protocol.Hash, pkcs8 []byte) error {
	if finger == (protocol.Hash{}) || len(pkcs8) == 0 {
		return ErrPrivat
	}
	if err := verschluesseltPKCS8(pkcs8); err != nil {
		return err
	}
	dir, err := o.mandantDir(id)
	if err != nil {
		return err
	}
	return ersetzen(filepath.Join(dir, "privat", hex.EncodeToString(finger[:])), pkcs8)
}

func (o *ordner) mandanten() ([]protocol.ID, error) {
	eintraege, err := os.ReadDir(o.wurzel)
	if err != nil {
		return nil, err
	}
	var ids []protocol.ID
	for _, e := range eintraege {
		if !e.IsDir() {
			continue
		}
		id, err := protocol.ParseID(e.Name())
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (o *ordner) meta(id protocol.ID) ([]byte, bool, error) {
	dir, err := o.mandantDir(id)
	if err != nil {
		return nil, false, err
	}
	return lesenDatei(filepath.Join(dir, "mandant"))
}

func (o *ordner) metaSetzen(id protocol.ID, meta []byte) error {
	dir, err := o.mandantDir(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return ersetzen(filepath.Join(dir, "mandant"), meta)
}

func kette(id protocol.ID, eintraege []Eintrag) error {
	for i, e := range eintraege {
		if e.Mandant != id || e.Nummer != uint64(i)+1 {
			return ErrFormat
		}
	}
	return nil
}

func leseProtokoll(dir string) ([]Eintrag, error) {
	b, err := os.ReadFile(filepath.Join(dir, "protokoll"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Eintrag
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, ErrFormat
		}
		n := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if n == 0 || uint32(len(b)) < n || n > maxFassung {
			return nil, ErrFormat
		}
		ein, err := ParseEintrag(b[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, ein)
		b = b[n:]
	}
	return out, nil
}

func lesenDatei(pfad string) ([]byte, bool, error) {
	b, err := os.ReadFile(pfad)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return append([]byte(nil), b...), true, nil
}

func anhaengen(pfad string, eintrag []byte) error {
	if len(eintrag) == 0 || len(eintrag) > maxFassung {
		return ErrFormat
	}
	f, err := os.OpenFile(pfad, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(eintrag)))
	if _, err := f.Write(n[:]); err != nil {
		return err
	}
	if _, err := f.Write(eintrag); err != nil {
		return err
	}
	return f.Sync()
}

func ersetzen(datei string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(datei), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(datei), ".schluessel-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, datei); err != nil {
		if rem := os.Remove(datei); rem != nil && !errors.Is(rem, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(name, datei); err != nil {
			return err
		}
	}
	ok = true
	return nil
}
