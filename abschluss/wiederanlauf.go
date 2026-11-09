package abschluss

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"cryptlog/protocol"
)

var (
	// ErrLuecke heißt, in der Annahmekette der Instanz fehlt ein Glied.
	ErrLuecke = errors.New("abschluss: Lücke in der Annahmekette")
	// ErrGrenze heißt, der Spool nimmt keine weitere Folge auf.
	ErrGrenze = errors.New("abschluss: Spool hat die Obergrenze erreicht")
)

// Befund ist das Ergebnis der Prüfung eines Abschlusses.
type Befund int

const (
	// BefundLeer heißt, an dieser Stelle liegt keine Annahme.
	BefundLeer Befund = iota
	// BefundAngenommen heißt, Annahme und Segmente passen.
	BefundAngenommen
	// BefundUnvollstaendig heißt, Vorbereitung oder Segmente reichen für eine Annahme nicht.
	BefundUnvollstaendig
	// BefundOffen ist für eine noch offene Belegung vorgesehen. Der Wiederanlauf setzt den Wert nicht.
	BefundOffen
	// BefundBeschaedigt heißt, die Annahme liegt vor und ein Segmenthash weicht ab.
	BefundBeschaedigt
	// BefundKonflikt heißt, dieselbe Kennung trägt einen anderen event_hash.
	BefundKonflikt
	// BefundVerfallen heißt, die Belegung gehört einer anderen Instanz oder einem anderen Abschluss.
	BefundVerfallen
)

// Eintrag ist ein Abschluss im Spool.
type Eintrag struct {
	Instanz      protocol.ID
	BatchSeq     uint64
	Annahme      []byte
	Vorbereitung []byte
	Belegungen   [][]byte
	Segmente     []Segmentobjekt
}

// Spool hält die lokalen Folgen und die gemerkten Annahme-Hashes.
// Die Obergrenze zählt die Folgen, nicht die gemerkten Hashes.
type Spool struct {
	grenze  int
	groesse int
	rec     map[string][]byte
	merk    map[string]protocol.Hash
}

// NeuSpool verlangt eine Obergrenze über 0.
func NeuSpool(grenze int) (*Spool, error) {
	if grenze <= 0 {
		return nil, protocol.ErrLength
	}
	return &Spool{
		grenze: grenze,
		rec:    make(map[string][]byte),
		merk:   make(map[string]protocol.Hash),
	}, nil
}

// Encode ist die Bytefolge, die der Knoten per Fsync festhält.
func Encode(e Eintrag) ([]byte, error) {
	if e.BatchSeq == 0 || len(e.Annahme) == 0 || len(e.Vorbereitung) == 0 || len(e.Segmente) == 0 {
		return nil, protocol.ErrLength
	}
	buf := protocol.AppendText(nil, "spool")
	buf = append(buf, e.Instanz[:]...)
	buf = protocol.AppendU64(buf, e.BatchSeq)
	var err error
	if buf, err = anhaengen(buf, e.Annahme); err != nil {
		return nil, err
	}
	if buf, err = anhaengen(buf, e.Vorbereitung); err != nil {
		return nil, err
	}
	buf = protocol.AppendU64(buf, uint64(len(e.Belegungen)))
	for _, b := range e.Belegungen {
		if buf, err = anhaengen(buf, b); err != nil {
			return nil, err
		}
	}
	buf = protocol.AppendU64(buf, uint64(len(e.Segmente)))
	for _, seg := range e.Segmente {
		if seg.Schluessel == "" || len(seg.Bytes) == 0 {
			return nil, protocol.ErrLength
		}
		if buf, err = anhaengen(buf, []byte(seg.Schluessel)); err != nil {
			return nil, err
		}
		if buf, err = anhaengen(buf, seg.Bytes); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// Decode liest eine Spool-Folge.
func Decode(b []byte) (Eintrag, error) {
	prefix := protocol.Domain("spool")
	if !bytes.HasPrefix(b, prefix) {
		return Eintrag{}, protocol.ErrDomain
	}
	c := &leser{b: b, i: len(prefix)}
	var e Eintrag
	raw, err := c.n(protocol.IDLen)
	if err != nil {
		return Eintrag{}, err
	}
	copy(e.Instanz[:], raw)
	if e.BatchSeq, err = c.u64(); err != nil {
		return Eintrag{}, err
	}
	if e.BatchSeq == 0 {
		return Eintrag{}, protocol.ErrSeq
	}
	if e.Annahme, err = c.lp(); err != nil || len(e.Annahme) == 0 {
		return Eintrag{}, protocol.ErrLength
	}
	if e.Vorbereitung, err = c.lp(); err != nil || len(e.Vorbereitung) == 0 {
		return Eintrag{}, protocol.ErrLength
	}
	nb, err := c.u64()
	if err != nil || nb > uint64(len(b)) {
		return Eintrag{}, protocol.ErrLength
	}
	e.Belegungen = make([][]byte, nb)
	for i := range e.Belegungen {
		if e.Belegungen[i], err = c.lp(); err != nil || len(e.Belegungen[i]) == 0 {
			return Eintrag{}, protocol.ErrLength
		}
	}
	ns, err := c.u64()
	if err != nil || ns == 0 || ns > uint64(len(b)) {
		return Eintrag{}, protocol.ErrLength
	}
	e.Segmente = make([]Segmentobjekt, ns)
	for i := range e.Segmente {
		key, err := c.lp()
		if err != nil || len(key) == 0 {
			return Eintrag{}, protocol.ErrLength
		}
		inhalt, err := c.lp()
		if err != nil || len(inhalt) == 0 {
			return Eintrag{}, protocol.ErrLength
		}
		e.Segmente[i] = Segmentobjekt{Schluessel: string(key), Bytes: inhalt}
	}
	if c.i != len(c.b) {
		return Eintrag{}, protocol.ErrLength
	}
	return e, nil
}

// Festhalten nimmt eine Folge auf. Dieselben Bytes sind ein wiederholtes Schreiben.
func (s *Spool) Festhalten(e Eintrag) error {
	raw, err := Encode(e)
	if err != nil {
		return err
	}
	back, err := Decode(raw)
	if err != nil {
		return err
	}
	if back.Instanz != e.Instanz || back.BatchSeq != e.BatchSeq {
		return protocol.ErrLength
	}
	key := spoolKey(e.Instanz, e.BatchSeq)
	if alt, ok := s.rec[key]; ok {
		if bytes.Equal(alt, raw) {
			return nil
		}
		return ErrObjekt
	}
	if s.groesse > s.grenze-len(raw) {
		return ErrGrenze
	}
	s.rec[key] = raw
	s.groesse += len(raw)
	return nil
}

// Hash ist ein gemerkter annahme_hash.
func (s *Spool) Hash(instanz protocol.ID, seq uint64) (protocol.Hash, bool) {
	h, ok := s.merk[spoolKey(instanz, seq)]
	return h, ok
}

// Abdecken löscht gemerkte Hashes, die das Manifest einschließt.
// annahme_first und annahme_last 0 lassen die Hashes stehen.
func (s *Spool) Abdecken(instanz protocol.ID, first, last uint64) error {
	if first == 0 && last == 0 {
		return nil
	}
	if first == 0 || last < first {
		return protocol.ErrLength
	}
	prefix := instanz.Hex() + "/"
	for key := range s.merk {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		seq, err := strconv.ParseUint(key[len(prefix):], 10, 64)
		if err != nil || strconv.FormatUint(seq, 10) != key[len(prefix):] {
			continue
		}
		if seq >= first && seq <= last {
			delete(s.merk, key)
		}
	}
	return nil
}

// Fortsetzen schreibt einen eigenen Abschluss aus dem Spool mit denselben Bytes.
// Passt die Annahme am Ziel, löscht es die Folge und merkt den Hash.
func (s *Spool) Fortsetzen(z Ziel, instanz protocol.ID, seq uint64) (Befund, error) {
	raw, ok := s.rec[spoolKey(instanz, seq)]
	if !ok {
		return BefundLeer, nil
	}
	ein, nutz, err := oeffnen(raw)
	if err != nil {
		return 0, err
	}
	if ein.Instanz != instanz || ein.BatchSeq != seq || nutz.Instanz != instanz || nutz.BatchSeq != seq {
		return 0, protocol.ErrLength
	}
	annKey, err := protocol.AnnahmeSchluessel(instanz, seq)
	if err != nil {
		return 0, err
	}
	liegen, ok, err := z.Lesen(annKey)
	if err != nil {
		return 0, err
	}
	if ok {
		if !bytes.Equal(liegen, ein.Annahme) {
			return BefundKonflikt, nil
		}
		passen, err := alleSegmente(z, nutz.Segmente)
		if err != nil {
			return 0, err
		}
		if !passen {
			return BefundBeschaedigt, nil
		}
		if err := siegeln(z, ein.Belegungen); err != nil {
			return 0, err
		}
		if err := s.abschliessen(instanz, seq, ein.Annahme); err != nil {
			return 0, err
		}
		return BefundAngenommen, nil
	}
	befund, err := spoolBelegungen(z, nutz, ein.Belegungen)
	if err != nil || befund != BefundLeer {
		return befund, err
	}
	if err := segmenteDesEintrags(nutz, ein.Segmente); err != nil {
		return 0, err
	}
	g := Gebaut{
		Belegungen:   belegungObjekte(ein.Belegungen),
		Vorbereitung: Objekt{Schluessel: vorbereitungKey(instanz, seq), Bytes: ein.Vorbereitung},
		Annahme:      Objekt{Schluessel: annKey, Bytes: ein.Annahme},
		Segmente:     nutz.Segmente,
	}
	if err := Ablegen(z, g, ein.Segmente); err != nil {
		return 0, err
	}
	if err := s.abschliessen(instanz, seq, ein.Annahme); err != nil {
		return 0, err
	}
	return BefundAngenommen, nil
}

// Erkennen prüft Annahme, Vorbereitung und die genannten Segmente am Ziel.
func Erkennen(z Ziel, instanz protocol.ID, seq uint64) (Befund, error) {
	key, err := protocol.AnnahmeSchluessel(instanz, seq)
	if err != nil {
		return 0, err
	}
	ann, ok, err := z.Lesen(key)
	if err != nil {
		return 0, err
	}
	if ok {
		nutz, err := protocol.ParseAnnahme(ann)
		if err != nil {
			return 0, err
		}
		if nutz.Instanz != instanz || nutz.BatchSeq != seq {
			return 0, protocol.ErrLength
		}
		passen, err := alleSegmente(z, nutz.Segmente)
		if err != nil {
			return 0, err
		}
		if !passen {
			return BefundBeschaedigt, nil
		}
		return BefundAngenommen, nil
	}
	vorKey := vorbereitungKey(instanz, seq)
	if _, ok, err := z.Lesen(vorKey); err != nil {
		return 0, err
	} else if ok {
		return BefundUnvollstaendig, nil
	}
	return BefundLeer, nil
}

// FremdeAnnahme schreibt die fehlende Annahme, wenn Vorbereitung und Segmente passen
// und die Frist der Instanz abgelaufen ist. Eine beschädigte Annahme wird nicht ersetzt.
func FremdeAnnahme(z Ziel, instanz protocol.ID, seq uint64, jetzt uint64) (Befund, error) {
	befund, err := Erkennen(z, instanz, seq)
	if err != nil {
		return 0, err
	}
	switch befund {
	case BefundAngenommen, BefundBeschaedigt:
		return befund, nil
	case BefundLeer:
		return BefundUnvollstaendig, nil
	}
	vorKey := vorbereitungKey(instanz, seq)
	vor, ok, err := z.Lesen(vorKey)
	if err != nil {
		return 0, err
	}
	if !ok {
		return BefundUnvollstaendig, nil
	}
	nutz, err := protocol.ParseVorbereitung(vor)
	if err != nil {
		return 0, err
	}
	if nutz.Instanz != instanz || nutz.BatchSeq != seq {
		return 0, protocol.ErrLength
	}
	abgelaufen, err := fristAbgelaufen(z, instanz, jetzt)
	if err != nil {
		return 0, err
	}
	if !abgelaufen {
		return BefundUnvollstaendig, nil
	}
	if befund, err = platzBelegungen(z, nutz); err != nil || befund != BefundLeer {
		return befund, err
	}
	passen, err := alleSegmente(z, nutz.Segmente)
	if err != nil {
		return 0, err
	}
	if !passen {
		return BefundUnvollstaendig, nil
	}
	previous, err := previousAnnahme(z, instanz, seq)
	if err != nil {
		return 0, err
	}
	ann, err := protocol.AnnahmeAusVorbereitung(vor, previous)
	if err != nil {
		return 0, err
	}
	annKey, err := protocol.AnnahmeSchluessel(instanz, seq)
	if err != nil {
		return 0, err
	}
	if befund, err = platzBelegungen(z, nutz); err != nil || befund != BefundLeer {
		return befund, err
	}
	if err := z.Schreiben(annKey, ann); err != nil {
		return 0, err
	}
	return BefundAngenommen, nil
}

// FristSetzen erneuert das Instanzobjekt. Die Generation einer Belegung ändert das nicht.
func FristSetzen(z Ziel, instanz protocol.ID, frist uint64) error {
	neu := protocol.InstanzBytes(protocol.InstanzLauf{Instanz: instanz, Frist: frist})
	key := protocol.InstanzSchluessel(instanz)
	alt, ok, err := z.Lesen(key)
	if err != nil {
		return err
	}
	if !ok {
		return z.Schreiben(key, neu)
	}
	return z.Ersetzen(key, alt, neu)
}

// AngenommenesPraefix ist die lückenlose Folge angenommener Segmente ab Nummer 1.
// Ein nicht genanntes Segment beendet die Folge. Ein späteres genanntes Segment ist eine Lücke.
func AngenommenesPraefix(schluessel []string, genannt map[string]bool) ([]string, error) {
	if len(schluessel) == 0 {
		return nil, nil
	}
	haben := make(map[uint64]string, len(schluessel))
	var mandant, ablage protocol.ID
	var epoch protocol.EpochID
	var maxGenannt uint64
	irgend := false
	for i, key := range schluessel {
		m, a, e, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			mandant, ablage, epoch = m, a, e
		} else if m != mandant || a != ablage || e != epoch {
			return nil, protocol.ErrLength
		}
		if _, ok := haben[nr]; ok {
			return nil, protocol.ErrLength
		}
		haben[nr] = key
		if genannt[key] && nr > maxGenannt {
			maxGenannt = nr
			irgend = true
		}
	}
	if !irgend {
		return nil, nil
	}
	out := make([]string, 0, maxGenannt)
	for nr := uint64(1); nr <= maxGenannt; nr++ {
		key, ok := haben[nr]
		if !ok || !genannt[key] {
			return nil, ErrLuecke
		}
		out = append(out, key)
	}
	return out, nil
}

func (s *Spool) abschliessen(instanz protocol.ID, seq uint64, annahme []byte) error {
	sum, err := protocol.AnnahmeHash(annahme)
	if err != nil {
		return err
	}
	key := spoolKey(instanz, seq)
	if raw, ok := s.rec[key]; ok {
		s.groesse -= len(raw)
		delete(s.rec, key)
	}
	s.merk[key] = sum
	return nil
}

func oeffnen(raw []byte) (Eintrag, protocol.Nutzlast, error) {
	ein, err := Decode(raw)
	if err != nil {
		return Eintrag{}, protocol.Nutzlast{}, err
	}
	nutz, err := protocol.ParseAnnahme(ein.Annahme)
	if err != nil {
		return Eintrag{}, protocol.Nutzlast{}, err
	}
	vor, err := protocol.VorbereitungPayload(nutz.Batch, nutz.Instanz, nutz.BatchSeq, nutz.Slots, nutz.Segmente, nutz.Bloecke)
	if err != nil {
		return Eintrag{}, protocol.Nutzlast{}, err
	}
	if !bytes.Equal(vor, ein.Vorbereitung) {
		return Eintrag{}, protocol.Nutzlast{}, protocol.ErrLength
	}
	return ein, nutz, nil
}

func spoolBelegungen(z Ziel, nutz protocol.Nutzlast, belegungen [][]byte) (Befund, error) {
	plaetze := make(map[protocol.ID]protocol.Hash, len(nutz.Slots))
	for _, slot := range nutz.Slots {
		plaetze[slot.Event] = slot.Hash
	}
	gesehen := make(map[protocol.ID]struct{}, len(belegungen))
	for _, raw := range belegungen {
		b, err := protocol.ParseBelegung(raw)
		if err != nil {
			return 0, err
		}
		if _, ok := gesehen[b.Event]; ok {
			return 0, protocol.ErrEvent
		}
		gesehen[b.Event] = struct{}{}
		hash, ok := plaetze[b.Event]
		if !ok || hash != b.Hash || b.Instanz != nutz.Instanz || b.Batch != nutz.Batch {
			return 0, protocol.ErrBelegung
		}
		liegen, ok, err := z.Lesen(protocol.BelegungSchluessel(b.Event))
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		if bytes.Equal(liegen, raw) {
			continue
		}
		ist, err := protocol.ParseBelegung(liegen)
		if err != nil {
			return 0, err
		}
		if ist.Hash != b.Hash {
			return BefundKonflikt, nil
		}
		return BefundVerfallen, nil
	}
	return BefundLeer, nil
}

func platzBelegungen(z Ziel, nutz protocol.Nutzlast) (Befund, error) {
	for _, slot := range nutz.Slots {
		liegen, ok, err := z.Lesen(protocol.BelegungSchluessel(slot.Event))
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		b, err := protocol.ParseBelegung(liegen)
		if err != nil {
			return 0, err
		}
		if b.Hash != slot.Hash {
			return BefundKonflikt, nil
		}
		if b.Instanz != nutz.Instanz || b.Batch != nutz.Batch {
			return BefundVerfallen, nil
		}
	}
	return BefundLeer, nil
}

func alleSegmente(z Ziel, refs []protocol.SegmentRef) (bool, error) {
	for _, ref := range refs {
		liegen, ok, err := z.Lesen(ref.ObjectKey)
		if err != nil {
			return false, err
		}
		if !ok || protocol.SegmentHash(liegen) != ref.Hash {
			return false, nil
		}
	}
	return true, nil
}

func segmenteDesEintrags(nutz protocol.Nutzlast, segmente []Segmentobjekt) error {
	if len(segmente) != len(nutz.Segmente) {
		return ErrSegment
	}
	for i, ref := range nutz.Segmente {
		if segmente[i].Schluessel != ref.ObjectKey || protocol.SegmentHash(segmente[i].Bytes) != ref.Hash {
			return ErrSegment
		}
	}
	return nil
}

func belegungObjekte(raws [][]byte) []Objekt {
	out := make([]Objekt, len(raws))
	for i, raw := range raws {
		b, _ := protocol.ParseBelegung(raw)
		out[i] = Objekt{Schluessel: protocol.BelegungSchluessel(b.Event), Bytes: raw}
	}
	return out
}

func previousAnnahme(z Ziel, instanz protocol.ID, seq uint64) (protocol.Hash, error) {
	if seq == 1 {
		return protocol.AnnahmeGenesis(instanz), nil
	}
	key, err := protocol.AnnahmeSchluessel(instanz, seq-1)
	if err != nil {
		return protocol.Hash{}, err
	}
	liegen, ok, err := z.Lesen(key)
	if err != nil {
		return protocol.Hash{}, err
	}
	if !ok {
		return protocol.Hash{}, ErrLuecke
	}
	if _, err := protocol.ParseAnnahme(liegen); err != nil {
		return protocol.Hash{}, err
	}
	return protocol.AnnahmeHash(liegen)
}

func fristAbgelaufen(z Ziel, instanz protocol.ID, jetzt uint64) (bool, error) {
	liegen, ok, err := z.Lesen(protocol.InstanzSchluessel(instanz))
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	lauf, err := protocol.ParseInstanzLauf(liegen)
	if err != nil {
		return false, err
	}
	if lauf.Instanz != instanz {
		return true, nil
	}
	return jetzt >= lauf.Frist, nil
}

func vorbereitungKey(instanz protocol.ID, seq uint64) string {
	key, _ := protocol.VorbereitungSchluessel(instanz, seq)
	return key
}

func spoolKey(instanz protocol.ID, seq uint64) string {
	return instanz.Hex() + "/" + strconv.FormatUint(seq, 10)
}

func anhaengen(dst, data []byte) ([]byte, error) {
	if uint64(len(data)) > uint64(^uint32(0)) {
		return nil, protocol.ErrLength
	}
	dst = protocol.AppendU32(dst, uint32(len(data)))
	return append(dst, data...), nil
}

type leser struct {
	b []byte
	i int
}

func (c *leser) n(k int) ([]byte, error) {
	if k < 0 || c.i > len(c.b)-k {
		return nil, protocol.ErrLength
	}
	out := c.b[c.i : c.i+k]
	c.i += k
	return out, nil
}

func (c *leser) u64() (uint64, error) {
	raw, err := c.n(8)
	if err != nil {
		return 0, err
	}
	return protocolU64(raw), nil
}

func (c *leser) lp() ([]byte, error) {
	raw, err := c.n(4)
	if err != nil {
		return nil, err
	}
	k := int(protocolU32(raw))
	inhalt, err := c.n(k)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), inhalt...), nil
}

func protocolU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func protocolU64(b []byte) uint64 {
	return uint64(protocolU32(b[:4]))<<32 | uint64(protocolU32(b[4:]))
}
