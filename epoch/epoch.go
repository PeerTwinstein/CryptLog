// Package epoch baut eine Epoche als Folge von Segmentobjekten.
// Volle Segmente haben die konfigurierte Klasse. Das letzte Segment hat die
// kleinste Klasse, die Kopf, Ereignisrahmen und Manifest fasst. Was an einer
// Klasse fehlt, sind Füllrahmen. Sie stehen in der Hash-Kette und vor dem Manifest.
package epoch

import (
	"crypto/rand"
	"errors"
	"io"
	"math"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

var (
	// ErrZustand heißt, die Epoche ist abgeschlossen und nimmt nichts mehr auf.
	ErrZustand = errors.New("epoch: Epoche ist abgeschlossen")
	// ErrSchnitt heißt, es gibt kein offenes Segment zum Abschließen.
	ErrSchnitt = errors.New("epoch: kein offenes Segment")
	// ErrSignatur heißt, der Abschluss der Epoche hat keine Integritätssignatur.
	ErrSignatur = errors.New("epoch: Signatur fehlt")
)

// Glied ist ein Rahmen der Kette. Bei Fortsetzung und Füllung ist Event 16 Nullbytes.
type Glied struct {
	Seq   uint64
	Art   protocol.Art
	Event protocol.ID
}

// Segment ist ein geschriebenes Segmentobjekt.
type Segment struct {
	Nr         uint64
	Schluessel string
	Bytes      []byte
	Hash       protocol.Hash
}

// Ergebnis ist der Abschluss einer Epoche.
// Segmente enthält auch die zuvor mit Ereignis oder Schnitt geschlossenen Objekte.
type Ergebnis struct {
	Segmente   []Segment
	Nutzlast   []byte
	Signatur   protocol.Signature
	EpochHash  protocol.Hash
	Eintraege  uint64
	Kettenkopf protocol.Hash
	Glieder    []Glied
}

// Config ist die offene Epoche. Rand nil zieht den Zufall aus crypto/rand.
// Der DEK in der Epoche wird beim Abschluss gelöscht. Die Kopie des Aufrufers bleibt.
type Config struct {
	Mandant protocol.ID
	Ablage  protocol.ID
	DekID   protocol.ID
	Epoch   protocol.EpochID
	KEK     protocol.Hash
	Wrapped []byte
	DEK     crypt.DEK
	Rahmen  int
	Klasse  int
	Rand    io.Reader
}

// Epoche verschlüsselt Ereignisse und legt sie in Segmente.
type Epoche struct {
	rahmen  int
	klasse  int
	rnd     io.Reader
	mandant protocol.ID
	ablage  protocol.ID
	dekID   protocol.ID
	epoch   protocol.EpochID
	dek     crypt.DEK
	chain   protocol.Chain
	seq     uint64
	nr      uint64
	seg     []byte
	segs    []Segment
	glieder []Glied
	offen   bool
}

// Oeffnen beginnt die Epoche. Das erste Segment trägt den Epochenkopf.
func Oeffnen(cfg Config) (*Epoche, error) {
	if _, err := protocol.RahmenNutz(cfg.Rahmen); err != nil {
		return nil, err
	}
	if !protocol.Segmentklasse(cfg.Klasse) || cfg.Klasse%cfg.Rahmen != 0 {
		return nil, protocol.ErrLength
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	kopf, err := protocol.KopfBereich(cfg.KEK, cfg.DekID, cfg.Wrapped, cfg.Rahmen, rnd)
	if err != nil {
		return nil, err
	}
	if len(kopf)+cfg.Rahmen > cfg.Klasse {
		return nil, protocol.ErrLength
	}
	chain, err := protocol.NewChain(cfg.Mandant, cfg.Ablage, cfg.Epoch, cfg.DekID, cfg.KEK, append([]byte(nil), cfg.Wrapped...))
	if err != nil {
		return nil, err
	}
	return &Epoche{
		rahmen:  cfg.Rahmen,
		klasse:  cfg.Klasse,
		rnd:     rnd,
		mandant: cfg.Mandant,
		ablage:  cfg.Ablage,
		dekID:   cfg.DekID,
		epoch:   cfg.Epoch,
		dek:     cfg.DEK,
		chain:   chain,
		seq:     1,
		nr:      1,
		seg:     kopf,
		offen:   true,
	}, nil
}

// Offen sagt, ob die Epoche noch Rahmen annimmt.
func (e *Epoche) Offen() bool { return e != nil && e.offen }

// Mandant ist die mandant_id der Zusatzdaten.
func (e *Epoche) Mandant() protocol.ID {
	if e == nil {
		return protocol.ID{}
	}
	return e.mandant
}

// Ablage ist die ablage_id der Zusatzdaten.
func (e *Epoche) Ablage() protocol.ID {
	if e == nil {
		return protocol.ID{}
	}
	return e.ablage
}

// Kennung ist die epoch_id dieser Epoche.
func (e *Epoche) Kennung() protocol.EpochID {
	if e == nil {
		return protocol.EpochID{}
	}
	return e.epoch
}

// Ereignis verschlüsselt den Klartext auf einen oder mehrere Rahmen.
// Die ersten 16 Byte sind die event_id. Segmente enthält die Objekte, die
// dieser Aufruf geschlossen hat.
func (e *Epoche) Ereignis(klartext []byte) (segs []Segment, glieder []Glied, err error) {
	if !e.offen {
		return nil, nil, ErrZustand
	}
	if len(klartext) < protocol.IDLen {
		return nil, nil, protocol.ErrLength
	}
	frames, err := protocol.SplitEreignis(klartext, e.rahmen, e.rnd)
	if err != nil {
		if errors.Is(err, protocol.ErrLength) {
			return nil, nil, err
		}
		e.beenden()
		return nil, nil, err
	}
	var event protocol.ID
	copy(event[:], klartext[:protocol.IDLen])
	arts := make([]protocol.Art, len(frames))
	events := make([]protocol.ID, len(frames))
	arts[0] = protocol.ArtEreignis
	events[0] = event
	for i := 1; i < len(frames); i++ {
		arts[i] = protocol.ArtFortsetzung
	}
	return e.siegeln(frames, arts, events)
}

// Schnitt schließt das offene Segment auf die konfigurierte Klasse.
// Das Manifest liegt in diesem Segment nicht.
func (e *Epoche) Schnitt() (Segment, []Glied, error) {
	if !e.offen {
		return Segment{}, nil, ErrZustand
	}
	if len(e.seg) == 0 || len(e.seg) >= e.klasse || (e.klasse-len(e.seg))%e.rahmen != 0 {
		return Segment{}, nil, ErrSchnitt
	}
	n := (e.klasse - len(e.seg)) / e.rahmen
	frames, arts, events, err := e.fuellung(n)
	if err != nil {
		e.beenden()
		return Segment{}, nil, err
	}
	segs, glieder, err := e.siegeln(frames, arts, events)
	if err != nil {
		return Segment{}, glieder, err
	}
	if len(segs) != 1 {
		e.beenden()
		return Segment{}, glieder, protocol.ErrRahmen
	}
	return segs[0], glieder, nil
}

// Abschluss füllt das letzte Segment, hängt das Manifest an und signiert die Nutzlast.
// sign erhält manifest_payload. Die Epoche nimmt danach keine Rahmen mehr an.
func (e *Epoche) Abschluss(previous protocol.Hash, annahmeFirst, annahmeLast uint64, annahmeHead protocol.Hash, sign func([]byte) (protocol.Signature, error)) (Ergebnis, error) {
	if !e.offen {
		return Ergebnis{}, ErrZustand
	}
	if sign == nil {
		return Ergebnis{}, ErrSignatur
	}
	inhalt := len(e.seg) + e.rahmen
	klasse, err := protocol.KleinsteKlasse(inhalt)
	if err != nil {
		return Ergebnis{}, err
	}
	if klasse > e.klasse || (klasse-len(e.seg))%e.rahmen != 0 {
		e.beenden()
		return Ergebnis{}, protocol.ErrLength
	}
	n := (klasse-len(e.seg))/e.rahmen - 1
	if n > 0 {
		frames, arts, events, ferr := e.fuellung(n)
		if ferr != nil {
			e.beenden()
			return Ergebnis{}, ferr
		}
		if _, _, serr := e.siegeln(frames, arts, events); serr != nil {
			return Ergebnis{}, serr
		}
	}
	if len(e.seg)+e.rahmen != klasse {
		e.beenden()
		return Ergebnis{}, protocol.ErrRahmen
	}
	nutzlast, err := e.chain.Manifest(previous, annahmeFirst, annahmeLast, annahmeHead)
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	sig, err := sign(nutzlast)
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	manifest, err := protocol.ManifestRahmen(nutzlast, sig, e.rahmen, e.rnd)
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	e.seg = append(e.seg, manifest...)
	letztes, err := e.abschliessen()
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	_ = letztes
	kopf, err := e.chain.Head()
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	anzahl, err := e.chain.Count()
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	hash, err := protocol.EpochHash(nutzlast, sig)
	if err != nil {
		e.beenden()
		return Ergebnis{}, err
	}
	ergebnis := Ergebnis{
		Segmente:   append([]Segment(nil), e.segs...),
		Nutzlast:   nutzlast,
		Signatur:   sig,
		EpochHash:  hash,
		Eintraege:  anzahl,
		Kettenkopf: kopf,
		Glieder:    append([]Glied(nil), e.glieder...),
	}
	e.beenden()
	return ergebnis, nil
}

func (e *Epoche) fuellung(n int) ([][]byte, []protocol.Art, []protocol.ID, error) {
	frames := make([][]byte, n)
	arts := make([]protocol.Art, n)
	events := make([]protocol.ID, n)
	for i := 0; i < n; i++ {
		frame, err := protocol.Fuellrahmen(e.rahmen, e.rnd)
		if err != nil {
			return nil, nil, nil, err
		}
		frames[i] = frame
		arts[i] = protocol.ArtFuellung
	}
	return frames, arts, events, nil
}

func (e *Epoche) siegeln(frames [][]byte, arts []protocol.Art, events []protocol.ID) ([]Segment, []Glied, error) {
	if !e.offen {
		return nil, nil, ErrZustand
	}
	if len(frames) == 0 || len(frames) != len(arts) || len(frames) != len(events) {
		return nil, nil, protocol.ErrLength
	}
	if uint64(len(frames)) > math.MaxUint64-e.seq+1 {
		e.beenden()
		return nil, nil, protocol.ErrSeq
	}
	seq := e.seq
	type roh struct {
		glied Glied
		frame []byte
	}
	rohlinge := make([]roh, len(frames))
	for i, plain := range frames {
		nonce := protocol.MakeNonce(e.epoch.Prefix(), seq)
		aad := protocol.AAD(e.mandant, e.ablage, e.epoch, e.dekID, seq)
		ct, tag, err := crypt.Seal(e.dek, nonce, plain, aad)
		if err != nil {
			e.beenden()
			return nil, nil, err
		}
		if len(ct) != e.rahmen-protocol.RahmenHuelle || len(tag) != protocol.TagLen {
			e.beenden()
			return nil, nil, protocol.ErrLength
		}
		frame := make([]byte, e.rahmen)
		copy(frame, nonce[:])
		copy(frame[protocol.NonceLen:], ct)
		copy(frame[e.rahmen-protocol.TagLen:], tag)
		rohlinge[i] = roh{
			glied: Glied{Seq: seq, Art: arts[i], Event: events[i]},
			frame: frame,
		}
		seq++
	}
	var segs []Segment
	glieder := make([]Glied, 0, len(rohlinge))
	for _, r := range rohlinge {
		e.seg = append(e.seg, r.frame...)
		if err := e.chain.Append(r.glied.Seq, protocol.MakeNonce(e.epoch.Prefix(), r.glied.Seq), r.frame[protocol.NonceLen:e.rahmen-protocol.TagLen], r.frame[e.rahmen-protocol.TagLen:]); err != nil {
			e.beenden()
			return segs, glieder, err
		}
		e.seq = r.glied.Seq + 1
		e.glieder = append(e.glieder, r.glied)
		glieder = append(glieder, r.glied)
		if len(e.seg) == e.klasse {
			seg, err := e.abschliessen()
			if err != nil {
				e.beenden()
				return segs, glieder, err
			}
			segs = append(segs, seg)
		} else if len(e.seg) > e.klasse {
			e.beenden()
			return segs, glieder, protocol.ErrRahmen
		}
	}
	return segs, glieder, nil
}

func (e *Epoche) abschliessen() (Segment, error) {
	if !protocol.Segmentklasse(len(e.seg)) {
		return Segment{}, protocol.ErrLength
	}
	key, err := protocol.ObjektSchluessel(e.mandant, e.ablage, e.epoch, e.nr)
	if err != nil {
		return Segment{}, err
	}
	seg := Segment{
		Nr:         e.nr,
		Schluessel: key,
		Bytes:      e.seg,
		Hash:       protocol.SegmentHash(e.seg),
	}
	e.seg = nil
	e.nr++
	e.segs = append(e.segs, seg)
	return seg, nil
}

// Verwerfen löscht den Klartext-DEK und nimmt keine weiteren Rahmen an.
// Geschlossene Segmente bleiben liegen. Ein Abschluss ist danach nicht möglich,
// weil Füllung und Manifest den DEK brauchen. Der Abschluss bereits angenommener
// Ciphertexte braucht ihn nicht.
func (e *Epoche) Verwerfen() {
	if e == nil {
		return
	}
	e.beenden()
}

func (e *Epoche) beenden() {
	e.dek.Wipe()
	e.offen = false
}
