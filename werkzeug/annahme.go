package werkzeug

import (
	"errors"
	"sort"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

// errObjektFehlt heißt, dass eine Annahme ein Segment nennt, das nicht vorliegt.
// Der Zeitraum wertet das als Lücke oder Löschung. Ein abweichender Hash bleibt ErrKette.
var errObjektFehlt = errors.New("werkzeug: genanntes Segment fehlt")

// annahmeSatz ist eine geöffnete Annahme dieser Instanz.
type annahmeSatz struct {
	nutz protocol.Nutzlast
	hash protocol.Hash
}

// segmenteAusAnnahme liest die Segmente, die eine Annahme dieser Epoche nennt,
// in der Reihenfolge der Segmentnummer. Ein Objekt ohne Annahme bleibt draußen.
func segmenteAusAnnahme(a Auftrag) ([]annahmeSatz, []Segment, error) {
	saetze := make([]annahmeSatz, 0, len(a.Annahmen))
	genannt := make(map[uint64]protocol.SegmentRef)
	for _, raw := range a.Annahmen {
		nutz, err := protocol.ParseAnnahme(raw)
		if err != nil {
			return nil, nil, err
		}
		if nutz.Instanz != a.Epoch.Instanz() {
			return nil, nil, ErrAnnahme
		}
		summe, err := protocol.AnnahmeHash(raw)
		if err != nil {
			return nil, nil, err
		}
		refs, err := refsDerEpoche(a, nutz)
		if err != nil {
			return nil, nil, err
		}
		for nr, ref := range refs {
			alt, ok := genannt[nr]
			if ok && (alt.Hash != ref.Hash || alt.ObjectKey != ref.ObjectKey) {
				return nil, nil, ErrAnnahme
			}
			genannt[nr] = ref
		}
		saetze = append(saetze, annahmeSatz{nutz: nutz, hash: summe})
	}
	if len(genannt) == 0 {
		return saetze, nil, nil
	}
	nummern := make([]uint64, 0, len(genannt))
	for nr := range genannt {
		nummern = append(nummern, nr)
	}
	sort.Slice(nummern, func(i, j int) bool { return nummern[i] < nummern[j] })
	segs := make([]Segment, 0, len(nummern))
	for i, nr := range nummern {
		if nr != uint64(i+1) {
			return nil, nil, ErrKette
		}
		ref := genannt[nr]
		inhalt, ok := a.Objekte[ref.ObjectKey]
		if !ok {
			return saetze, nil, errObjektFehlt
		}
		if protocol.SegmentHash(inhalt) != ref.Hash {
			return nil, nil, ErrKette
		}
		segs = append(segs, Segment{Schluessel: ref.ObjectKey, Bytes: inhalt})
	}
	return saetze, segs, nil
}

// annahmeBereich prüft die Annahmen von annahme_first bis annahme_last
// und die Previous-Kette. annahme_head vergleicht der Aufrufer.
func annahmeBereich(a Auftrag, m protocol.Manifest, saetze []annahmeSatz) ([]annahmeSatz, error) {
	if m.AnnahmeFirst == 0 || m.AnnahmeLast == 0 || m.AnnahmeLast < m.AnnahmeFirst {
		return nil, ErrAnnahme
	}
	if m.AnnahmeLast-m.AnnahmeFirst > uint64(len(saetze)) {
		return nil, ErrAnnahme
	}
	index := make(map[uint64]annahmeSatz, len(saetze))
	for _, s := range saetze {
		if s.nutz.Instanz != a.Epoch.Instanz() {
			return nil, ErrAnnahme
		}
		if _, ok := index[s.nutz.BatchSeq]; ok {
			return nil, ErrAnnahme
		}
		index[s.nutz.BatchSeq] = s
	}
	bereich := make([]annahmeSatz, 0, m.AnnahmeLast-m.AnnahmeFirst+1)
	genannt := make(map[uint64]protocol.SegmentRef)
	for seq := m.AnnahmeFirst; ; seq++ {
		s, ok := index[seq]
		if !ok {
			return nil, ErrAnnahme
		}
		if seq == m.AnnahmeFirst {
			if seq == 1 && s.nutz.Previous != protocol.AnnahmeGenesis(s.nutz.Instanz) {
				return nil, ErrAnnahme
			}
		} else if s.nutz.Previous != index[seq-1].hash {
			return nil, ErrAnnahme
		}
		refs, err := refsDerEpoche(a, s.nutz)
		if err != nil {
			return nil, err
		}
		for nr, ref := range refs {
			alt, da := genannt[nr]
			if da && (alt.Hash != ref.Hash || alt.ObjectKey != ref.ObjectKey) {
				return nil, ErrAnnahme
			}
			genannt[nr] = ref
		}
		bereich = append(bereich, s)
		if seq == m.AnnahmeLast {
			break
		}
	}
	for seq, s := range index {
		if seq >= m.AnnahmeFirst && seq <= m.AnnahmeLast {
			continue
		}
		refs, err := refsDerEpoche(a, s.nutz)
		if err != nil {
			return nil, err
		}
		if len(refs) > 0 {
			return nil, ErrAnnahme
		}
	}
	if len(genannt) != len(a.Segmente) {
		return nil, ErrAnnahme
	}
	for i, seg := range a.Segmente {
		ref, ok := genannt[uint64(i+1)]
		if !ok || ref.ObjectKey != seg.Schluessel || ref.Hash != protocol.SegmentHash(seg.Bytes) {
			return nil, ErrAnnahme
		}
	}
	return bereich, nil
}

// bindungPruefen öffnet den Bindungsblob und prüft die batch_id.
// Jede Sequenz der Epoche kommt darin genau einmal vor.
func bindungPruefen(a Auftrag, finger protocol.Hash, frames []rahmen, bereich []annahmeSatz) error {
	erwartet := make(map[uint64]int, len(frames))
	for _, fr := range frames {
		erwartet[fr.seq]++
	}
	if len(erwartet) != len(frames) {
		return ErrBindung
	}
	gefunden := make(map[uint64]int)
	for _, s := range bereich {
		refs, err := refsDerEpoche(a, s.nutz)
		if err != nil {
			return err
		}
		braucht := len(refs) > 0
		geoeffnet := 0
		for _, blob := range s.nutz.Bloecke {
			if blob.Mandant != a.Mandant {
				continue
			}
			klar, err := bindungKlar(a, s.nutz.Batch, blob, finger)
			if err != nil {
				if braucht {
					return ErrBindung
				}
				continue
			}
			batch, eintraege, err := protocol.ParseBindung(klar)
			if err != nil || batch != s.nutz.Batch {
				return ErrBindung
			}
			for _, e := range eintraege {
				gefunden[e.Seq]++
			}
			geoeffnet++
		}
		if braucht && geoeffnet == 0 {
			return ErrBindung
		}
	}
	for seq, n := range erwartet {
		if gefunden[seq] != n {
			return ErrBindung
		}
	}
	return nil
}

func bindungKlar(a Auftrag, batch protocol.ID, blob protocol.Blob, finger protocol.Hash) ([]byte, error) {
	pt, err := wrapOeffnen(a, blob.WrappedKey, protocol.BindungContext(a.Mandant, batch, finger))
	if err != nil {
		return nil, err
	}
	defer crypt.Wipe(pt)
	if len(pt) != wrapKlar {
		return nil, crypt.ErrOpen
	}
	var key crypt.DEK
	copy(key[:], pt[:32])
	defer key.Wipe()
	var got protocol.ID
	copy(got[:], pt[32:])
	if got != batch {
		return nil, crypt.ErrOpen
	}
	return crypt.Open(key, blob.Nonce, blob.Ciphertext, blob.Tag, protocol.BindungAAD(a.Mandant, batch, finger))
}

func refsDerEpoche(a Auftrag, n protocol.Nutzlast) (map[uint64]protocol.SegmentRef, error) {
	out := make(map[uint64]protocol.SegmentRef)
	for _, ref := range n.Segmente {
		mandant, ablage, epoch, nr, err := protocol.ParseObjektSchluessel(ref.ObjectKey)
		if err != nil {
			return nil, err
		}
		if mandant != a.Mandant || ablage != a.Ablage || epoch != a.Epoch {
			continue
		}
		if nr == 0 {
			return nil, ErrAnnahme
		}
		alt, ok := out[nr]
		if ok && (alt.Hash != ref.Hash || alt.ObjectKey != ref.ObjectKey) {
			return nil, ErrAnnahme
		}
		out[nr] = ref
	}
	return out, nil
}
