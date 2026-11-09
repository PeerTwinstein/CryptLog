package suchen

import (
	"crypto/ecdsa"
	"sort"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Ziel liest die Ablage und nimmt nur die Summenepoche entgegen, die die Zone selbst schreibt.
type Ziel interface {
	Lesen(schluessel string) ([]byte, bool, error)
	Liste(prefix string) ([]string, error)
	Schreiben(schluessel string, inhalt []byte) error
}

// Abschluss ist die Epochenbestätigung und der Löschvermerk, außerhalb des Log-Buckets.
type Abschluss interface {
	Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (hash protocol.Hash, sig protocol.Signature, ok bool, err error)
	Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (tag time.Time, ok bool, err error)
}

// Stroeme sind die Indexströme eines Mandanten. Der Aufrufer einer Suche legt sie nicht vor.
type Stroeme struct {
	Vorgang      protocol.ID
	Summe        protocol.ID
	Bind         protocol.ID
	Rahmen       int
	Intervall    time.Duration
	Frist        time.Duration
	HSM          *ecdsa.PublicKey
	Bestaetigung *ecdsa.PublicKey
	Status       werkzeug.Status
}

// Bestand nennt die Indexströme. Er nennt keinen privaten Schlüssel.
type Bestand interface {
	Index(mandant protocol.ID) (Stroeme, bool, error)
}

func (s Stroeme) gueltig() error {
	var leer protocol.ID
	if s.Vorgang == leer || !p256(s.HSM) || !p256(s.Bestaetigung) {
		return ErrBestand
	}
	if s.Summe == s.Vorgang {
		return ErrBestand
	}
	if _, err := protocol.RahmenNutz(s.Rahmen); err != nil {
		return ErrBestand
	}
	if !intervallOK(s.Intervall) || !fristOK(s.Frist) {
		return ErrBestand
	}
	switch s.Status {
	case werkzeug.StatusAktuell, werkzeug.StatusAbgeloest, werkzeug.StatusAbgelaufen,
		werkzeug.StatusKompromittiert, werkzeug.StatusVerloren:
	default:
		return ErrBestand
	}
	return nil
}

func intervallOK(d time.Duration) bool {
	if d < 15*time.Minute || d > 8*time.Hour {
		return false
	}
	return (24*time.Hour)%d == 0
}

func fristOK(d time.Duration) bool {
	return d > 0 && d%(24*time.Hour) == 0
}

func (p *Prozess) laden(mandant protocol.ID, st Stroeme) (werkzeug.Strom, werkzeug.Strom, error) {
	index, err := p.strom(mandant, st.Vorgang, protocol.RolleVorgang, st.Intervall, st)
	if err != nil {
		return werkzeug.Strom{}, werkzeug.Strom{}, err
	}
	var summe werkzeug.Strom
	if st.Summe != (protocol.ID{}) {
		summe, err = p.strom(mandant, st.Summe, protocol.RolleVorgangSumme, 0, st)
		if err != nil {
			return werkzeug.Strom{}, werkzeug.Strom{}, err
		}
	}
	return index, summe, nil
}

func (p *Prozess) strom(mandant, ablage protocol.ID, rolle protocol.StromRolle, intervall time.Duration, st Stroeme) (werkzeug.Strom, error) {
	if rolle != protocol.RolleVorgang && rolle != protocol.RolleVorgangSumme {
		return werkzeug.Strom{}, ErrZiel
	}
	prefix := mandant.Hex() + "/" + ablage.Hex() + "/"
	keys, err := p.ziel.Liste(prefix)
	if err != nil {
		return werkzeug.Strom{}, err
	}
	ids, nach, err := gruppieren(keys, mandant, ablage)
	if err != nil {
		return werkzeug.Strom{}, err
	}
	var lagen []werkzeug.Lage
	for _, id := range ids {
		lage, err := p.lage(mandant, ablage, id, rolle, st, nach[id])
		if err != nil {
			return werkzeug.Strom{}, err
		}
		lagen = append(lagen, lage)
	}
	return werkzeug.Strom{Ablage: ablage, Rolle: rolle, Intervall: intervall, Epochen: lagen}, nil
}

type segmentRef struct {
	nr  uint64
	key string
}

func gruppieren(keys []string, mandant, ablage protocol.ID) ([]protocol.EpochID, map[protocol.EpochID][]segmentRef, error) {
	nach := map[protocol.EpochID][]segmentRef{}
	var ids []protocol.EpochID
	gesehen := map[protocol.EpochID]struct{}{}
	for _, key := range keys {
		gotMandant, gotAblage, epoch, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil || gotMandant != mandant || gotAblage != ablage || nr == 0 {
			return nil, nil, ErrZiel
		}
		if _, ok := gesehen[epoch]; !ok {
			gesehen[epoch] = struct{}{}
			ids = append(ids, epoch)
		}
		nach[epoch] = append(nach[epoch], segmentRef{nr: nr, key: key})
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for id, refs := range nach {
		sort.Slice(refs, func(i, j int) bool { return refs[i].nr < refs[j].nr })
		for i := 1; i < len(refs); i++ {
			if refs[i].nr == refs[i-1].nr {
				return nil, nil, ErrZiel
			}
		}
		nach[id] = refs
	}
	return ids, nach, nil
}

func (p *Prozess) lage(mandant, ablage protocol.ID, epoch protocol.EpochID, rolle protocol.StromRolle, st Stroeme, refs []segmentRef) (werkzeug.Lage, error) {
	segs := make([]werkzeug.Segment, 0, len(refs))
	for _, ref := range refs {
		roh, ok, err := p.ziel.Lesen(ref.key)
		if err != nil {
			return werkzeug.Lage{}, err
		}
		if !ok {
			return werkzeug.Lage{}, ErrZiel
		}
		segs = append(segs, werkzeug.Segment{Schluessel: ref.key, Bytes: roh})
	}
	auftrag := werkzeug.Auftrag{
		Mandant:  mandant,
		Ablage:   ablage,
		Epoch:    epoch,
		Rahmen:   st.Rahmen,
		Rolle:    rolle,
		Segmente: segs,
		HSM:      st.HSM,
		Status:   st.Status,
		Priv:     p.priv,
	}
	hash, sig, ok, err := p.abschluss.Bestaetigung(mandant, ablage, epoch)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	if ok {
		auftrag.Bestaetigung = st.Bestaetigung
		auftrag.BestaetigungsSignatur = sig
		auftrag.AbschlussHash = hash
	}
	tag, vermerkt, err := p.abschluss.Vermerk(mandant, ablage, epoch)
	if err != nil {
		return werkzeug.Lage{}, err
	}
	var lage werkzeug.Lage
	lage.Auftrag = auftrag
	if vermerkt {
		if tag.Location() != time.UTC || tag.Hour() != 0 || tag.Minute() != 0 || tag.Second() != 0 || tag.Nanosecond() != 0 {
			return werkzeug.Lage{}, ErrZiel
		}
		merk := tag
		lage.Vermerk = &merk
	}
	return lage, nil
}
