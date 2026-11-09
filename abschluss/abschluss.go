// Package abschluss baut Belegung, Vorbereitung und Annahme eines Gruppenabschlusses
// und legt sie in der festgelegten Reihenfolge ab.
package abschluss

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

var (
	// ErrObjekt heißt, unter dem Schlüssel liegt ein anderer Inhalt.
	ErrObjekt = errors.New("abschluss: Objekt liegt mit anderem Inhalt vor")
	// ErrSegment heißt, ein Segment fehlt oder sein Hash weicht von der Annahme ab.
	ErrSegment = errors.New("abschluss: Segment fehlt oder der Hash weicht ab")
	// ErrBelegung heißt, die Belegung gehört diesem Abschluss nicht mehr.
	ErrBelegung = errors.New("abschluss: Belegung gehört diesem Abschluss nicht mehr")
)

// Anteil ist der Bindungsblob unter einem Wrap-Schlüssel.
type Anteil struct {
	Mandant   protocol.ID
	KEK       protocol.Hash
	Pub       crypto.PublicKey
	Eintraege []protocol.SeqEintrag
}

// Auftrag ist ein Gruppenabschluss vor dem Schreiben.
// Previous ist der previous_annahme_hash. Die Vorbereitung führt ihn nicht.
// Rand nil zieht den Zufall aus crypto/rand.
type Auftrag struct {
	Batch      protocol.ID
	Instanz    protocol.ID
	BatchSeq   uint64
	Previous   protocol.Hash
	Ereignisse []protocol.Slot
	Segmente   []protocol.SegmentRef
	Anteile    []Anteil
	Rand       io.Reader
}

// Objekt ist ein Schlüssel und seine Bytes.
type Objekt struct {
	Schluessel string
	Bytes      []byte
}

// Segmentobjekt ist ein Segment, dessen Bytes zum Hash in der Annahme passen.
type Segmentobjekt struct {
	Schluessel string
	Bytes      []byte
}

// Gebaut sind die Objekte eines Abschlusses. Vorbereitung und Annahme nennen
// dieselben Plätze, Segmente und Blobs.
type Gebaut struct {
	Belegungen   []Objekt
	Vorbereitung Objekt
	Annahme      Objekt
	Hash         protocol.Hash
	Plaetze      []protocol.Slot
	Bloecke      []protocol.Blob
	Segmente     []protocol.SegmentRef
}

// Ziel ist das Speicherziel. Schreiben lässt denselben Inhalt zu und ersetzt
// einen anderen Inhalt nicht. Ersetzen tauscht die Bytes nur, wenn bisher
// noch vorliegt.
type Ziel interface {
	Lesen(schluessel string) ([]byte, bool, error)
	Schreiben(schluessel string, inhalt []byte) error
	Ersetzen(schluessel string, bisher, neu []byte) error
}

// Speicher hält Objekte im Speicher und wendet die Schreibregel an.
type Speicher struct {
	mu  sync.Mutex
	obj map[string][]byte
}

// Lesen liefert eine Kopie.
func (s *Speicher) Lesen(schluessel string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.obj[schluessel]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

// Schreiben legt inhalt ab. Dieselben Bytes sind ein wiederholtes Schreiben.
func (s *Speicher) Schreiben(schluessel string, inhalt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.schreiben(schluessel, inhalt)
}

// Ersetzen schreibt neu nur über den noch vorliegenden Inhalt bisher.
func (s *Speicher) Ersetzen(schluessel string, bisher, neu []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	alt, ok := s.obj[schluessel]
	if !ok || !bytes.Equal(alt, bisher) {
		return ErrObjekt
	}
	s.obj[schluessel] = append([]byte(nil), neu...)
	return nil
}

func (s *Speicher) schreiben(schluessel string, inhalt []byte) error {
	if schluessel == "" {
		return protocol.ErrLength
	}
	if s.obj == nil {
		s.obj = make(map[string][]byte)
	}
	if alt, ok := s.obj[schluessel]; ok {
		if bytes.Equal(alt, inhalt) {
			return nil
		}
		return ErrObjekt
	}
	s.obj[schluessel] = append([]byte(nil), inhalt...)
	return nil
}

// Bauen bildet Belegungen, Vorbereitung und Annahme. Die Bindungsschlüssel
// werden nach dem Wrap verworfen.
func Bauen(a Auftrag) (Gebaut, error) {
	if a.BatchSeq == 0 || len(a.Segmente) == 0 || len(a.Anteile) == 0 {
		return Gebaut{}, protocol.ErrLength
	}
	real := make(map[protocol.ID]struct{}, len(a.Ereignisse))
	for _, ev := range a.Ereignisse {
		if _, ok := real[ev.Event]; ok {
			return Gebaut{}, protocol.ErrEvent
		}
		real[ev.Event] = struct{}{}
	}
	gesehen := make(map[protocol.ID]struct{})
	for _, anteil := range a.Anteile {
		if len(anteil.Eintraege) == 0 || anteil.Pub == nil {
			return Gebaut{}, protocol.ErrLength
		}
		for _, e := range anteil.Eintraege {
			if e.Art != protocol.ArtEreignis {
				continue
			}
			if _, ok := real[e.Event]; !ok {
				return Gebaut{}, protocol.ErrEvent
			}
			gesehen[e.Event] = struct{}{}
		}
	}
	if len(gesehen) != len(real) {
		return Gebaut{}, protocol.ErrEvent
	}
	rnd := a.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	plaetze, err := protocol.Plaetze(a.Ereignisse, rnd)
	if err != nil {
		return Gebaut{}, err
	}
	blobs := make([]protocol.Blob, 0, len(a.Anteile))
	for _, anteil := range a.Anteile {
		bindung, err := protocol.Bindung(a.Batch, anteil.Eintraege)
		if err != nil {
			return Gebaut{}, err
		}
		ctx := protocol.BindungContext(anteil.Mandant, a.Batch, anteil.KEK)
		aad := protocol.BindungAAD(anteil.Mandant, a.Batch, anteil.KEK)
		wrapped, nonce, ct, tag, err := crypt.SealBindung(rnd, anteil.Pub, a.Batch, bindung, ctx, aad)
		if err != nil {
			return Gebaut{}, err
		}
		blobs = append(blobs, protocol.Blob{
			Mandant:    anteil.Mandant,
			WrappedKey: wrapped,
			Nonce:      nonce,
			Ciphertext: ct,
			Tag:        tag,
		})
	}
	vorKey, err := protocol.VorbereitungSchluessel(a.Instanz, a.BatchSeq)
	if err != nil {
		return Gebaut{}, err
	}
	annKey, err := protocol.AnnahmeSchluessel(a.Instanz, a.BatchSeq)
	if err != nil {
		return Gebaut{}, err
	}
	vor, err := protocol.VorbereitungPayload(a.Batch, a.Instanz, a.BatchSeq, plaetze, a.Segmente, blobs)
	if err != nil {
		return Gebaut{}, err
	}
	ann, err := protocol.AnnahmePayload(a.Batch, a.Instanz, a.BatchSeq, a.Previous, plaetze, a.Segmente, blobs)
	if err != nil {
		return Gebaut{}, err
	}
	sum, err := protocol.AnnahmeHash(ann)
	if err != nil {
		return Gebaut{}, err
	}
	belegungen := make([]Objekt, 0, len(a.Ereignisse))
	for _, ev := range a.Ereignisse {
		b := protocol.Belegung{
			Event:      ev.Event,
			Instanz:    a.Instanz,
			Batch:      a.Batch,
			Generation: 1,
			Lage:       protocol.LageOffen,
			Hash:       ev.Hash,
		}
		raw, err := protocol.BelegungBytes(b)
		if err != nil {
			return Gebaut{}, err
		}
		belegungen = append(belegungen, Objekt{
			Schluessel: protocol.BelegungSchluessel(ev.Event),
			Bytes:      raw,
		})
	}
	segs := append([]protocol.SegmentRef(nil), a.Segmente...)
	return Gebaut{
		Belegungen:   belegungen,
		Vorbereitung: Objekt{Schluessel: vorKey, Bytes: vor},
		Annahme:      Objekt{Schluessel: annKey, Bytes: ann},
		Hash:         sum,
		Plaetze:      plaetze,
		Bloecke:      blobs,
		Segmente:     segs,
	}, nil
}

// Ablegen schreibt Belegungen, Vorbereitung, Segmente und die Annahme.
// Danach tauscht es jede offene Belegung bedingt auf angenommen.
// Dieser Tausch ist die Annahme. Ein Segment mit anderem Hash wird nicht ersetzt.
// Fehlt ein Segment oder weicht der Hash ab, entsteht keine Annahme.
func Ablegen(z Ziel, g Gebaut, segmente []Segmentobjekt) error {
	for _, b := range g.Belegungen {
		if err := belegungSchreiben(z, b.Bytes); err != nil {
			return err
		}
	}
	if err := z.Schreiben(g.Vorbereitung.Schluessel, g.Vorbereitung.Bytes); err != nil {
		return err
	}
	vorhanden := make(map[string][]byte, len(segmente))
	for _, seg := range segmente {
		if seg.Schluessel == "" {
			return ErrSegment
		}
		if _, ok := vorhanden[seg.Schluessel]; ok {
			return ErrSegment
		}
		vorhanden[seg.Schluessel] = seg.Bytes
	}
	genannt := make(map[string]protocol.Hash, len(g.Segmente))
	for _, ref := range g.Segmente {
		if _, ok := genannt[ref.ObjectKey]; ok {
			return ErrSegment
		}
		inhalt, ok := vorhanden[ref.ObjectKey]
		if !ok || protocol.SegmentHash(inhalt) != ref.Hash {
			return ErrSegment
		}
		genannt[ref.ObjectKey] = ref.Hash
	}
	if len(genannt) != len(vorhanden) {
		return ErrSegment
	}
	for _, ref := range g.Segmente {
		if err := z.Schreiben(ref.ObjectKey, vorhanden[ref.ObjectKey]); err != nil {
			return err
		}
	}
	for key, hash := range genannt {
		inhalt, ok, err := z.Lesen(key)
		if err != nil {
			return err
		}
		if !ok || protocol.SegmentHash(inhalt) != hash {
			return ErrSegment
		}
	}
	for _, b := range g.Belegungen {
		if err := belegungOffen(z, b.Bytes); err != nil {
			return err
		}
	}
	if err := z.Schreiben(g.Annahme.Schluessel, g.Annahme.Bytes); err != nil {
		return err
	}
	return siegeln(z, belegungRoh(g.Belegungen))
}

func belegungRoh(objekte []Objekt) [][]byte {
	roh := make([][]byte, len(objekte))
	for i, b := range objekte {
		roh[i] = b.Bytes
	}
	return roh
}

// belegungSchreiben legt die offenen Bytes an. Dieselben Bytes und die schon
// angenommene Fassung dieser Generation gelten als geschrieben.
func belegungSchreiben(z Ziel, raw []byte) error {
	offen, err := protocol.ParseBelegung(raw)
	if err != nil || offen.Lage != protocol.LageOffen {
		return ErrBelegung
	}
	key := protocol.BelegungSchluessel(offen.Event)
	if err := z.Schreiben(key, raw); err == nil {
		return nil
	} else if !errors.Is(err, ErrObjekt) {
		return err
	}
	liegen, ok, err := z.Lesen(key)
	if err != nil || !ok {
		return ErrBelegung
	}
	if bytes.Equal(liegen, raw) {
		return nil
	}
	if angenommen, err := belegtAngenommen(offen, liegen); err != nil || !angenommen {
		return ErrObjekt
	}
	return nil
}

// belegungOffen verlangt die offenen Bytes dieser Generation oder ihre
// schon angenommene Fassung. Ein anderer Inhalt bricht ab.
func belegungOffen(z Ziel, raw []byte) error {
	offen, err := protocol.ParseBelegung(raw)
	if err != nil || offen.Lage != protocol.LageOffen {
		return ErrBelegung
	}
	liegen, ok, err := z.Lesen(protocol.BelegungSchluessel(offen.Event))
	if err != nil {
		return err
	}
	if !ok {
		return ErrBelegung
	}
	if bytes.Equal(liegen, raw) {
		return nil
	}
	passt, err := belegtAngenommen(offen, liegen)
	if err != nil || !passt {
		return ErrBelegung
	}
	return nil
}

// siegeln tauscht jede offene Generation bedingt auf angenommen.
// Die angenommene Fassung bleibt stehen. Ein anderer Inhalt bricht ab.
func siegeln(z Ziel, offen [][]byte) error {
	for _, raw := range offen {
		ist, err := protocol.ParseBelegung(raw)
		if err != nil || ist.Lage != protocol.LageOffen {
			return ErrBelegung
		}
		key := protocol.BelegungSchluessel(ist.Event)
		liegen, ok, err := z.Lesen(key)
		if err != nil {
			return err
		}
		if !ok {
			return ErrBelegung
		}
		if bytes.Equal(liegen, raw) {
			angenommen, err := ist.Annehmen()
			if err != nil {
				return err
			}
			nach, err := protocol.BelegungBytes(angenommen)
			if err != nil {
				return err
			}
			if err := z.Ersetzen(key, raw, nach); err != nil {
				return err
			}
			continue
		}
		passt, err := belegtAngenommen(ist, liegen)
		if err != nil {
			return err
		}
		if !passt {
			return ErrBelegung
		}
	}
	return nil
}

func belegtAngenommen(offen protocol.Belegung, liegen []byte) (bool, error) {
	ist, err := protocol.ParseBelegung(liegen)
	if err != nil {
		return false, err
	}
	angenommen, err := offen.Annehmen()
	if err != nil {
		return false, err
	}
	return ist == angenommen, nil
}

// Uebernehmen ersetzt die offene Belegung durch die nächste offene Generation.
// event_id und event_hash bleiben. Der Tausch gelingt nur über die bisherigen Bytes.
func Uebernehmen(z Ziel, alt, neu protocol.Belegung) error {
	if alt.Lage != protocol.LageOffen || neu.Lage != protocol.LageOffen || neu.Event != alt.Event || neu.Hash != alt.Hash || neu.Generation != alt.Generation+1 {
		return protocol.ErrBelegung
	}
	bisher, err := protocol.BelegungBytes(alt)
	if err != nil {
		return err
	}
	nach, err := protocol.BelegungBytes(neu)
	if err != nil {
		return err
	}
	return z.Ersetzen(protocol.BelegungSchluessel(alt.Event), bisher, nach)
}
