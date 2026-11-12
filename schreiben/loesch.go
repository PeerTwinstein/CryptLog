package schreiben

import (
	"strconv"
	"strings"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// Vermerke ist der Bestätigungsspeicher, neben dem der Löschvermerk liegt.
type Vermerke interface {
	Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (time.Time, bool, error)
	Vermerken(mandant, ablage protocol.ID, epoch protocol.EpochID, tag time.Time) error
}

// Entfernen nimmt ein Objekt aus dem Ziel. Ein fehlendes Objekt ist bereits entfernt.
type Entfernen interface {
	Entfernen(schluessel string) error
}

func (p *Prozess) loeschenFaellig() bool {
	if p.loeschzeit <= 0 || p.vermerke == nil {
		return false
	}
	return !p.jetzt().Before(p.naechsteLoesch)
}

func (p *Prozess) loeschlauf() {
	p.naechsteLoesch = p.jetzt().Add(p.loeschzeit)
	weg, ok := p.ziel.(Entfernen)
	if !ok {
		p.zielFehl(nil)
		return
	}
	epochen, abschluesse, err := p.loeschBild()
	if err != nil {
		p.zielFehl(err)
		return
	}
	lager := loeschLager{ziel: p.ziel, weg: weg, vermerke: p.vermerke}
	if _, err := werkzeug.Loeschen(p.jetzt(), p.aufbewahrung, epochen, abschluesse, lager); err != nil {
		p.zielFehl(err)
	}
}

func (p *Prozess) loeschBild() ([]werkzeug.LoeschEpoche, []werkzeug.LoeschAbschluss, error) {
	keys, err := p.ziel.Liste("")
	if err != nil {
		return nil, nil, err
	}
	gruppen := map[string][]string{}
	var annahmen []werkzeug.LoeschAbschluss
	for _, key := range keys {
		if instanz, seq, ok := annahmeAusSchluessel(key); ok {
			annahmen = append(annahmen, werkzeug.LoeschAbschluss{Instanz: instanz, BatchSeq: seq})
			continue
		}
		mandant, ablage, epoch, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil || nr == 0 {
			continue
		}
		gruppen[mandant.Hex()+"/"+ablage.Hex()+"/"+epoch.String()] = append(gruppen[mandant.Hex()+"/"+ablage.Hex()+"/"+epoch.String()], key)
	}
	var epochen []werkzeug.LoeschEpoche
	for _, liste := range gruppen {
		ep, ok, err := p.epocheAusSegmenten(liste)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			epochen = append(epochen, ep)
		}
	}
	return epochen, annahmen, nil
}

func (p *Prozess) epocheAusSegmenten(keys []string) (werkzeug.LoeschEpoche, bool, error) {
	var ep werkzeug.LoeschEpoche
	nr := map[uint64]string{}
	var max uint64
	for _, key := range keys {
		mandant, ablage, epoch, n, err := protocol.ParseObjektSchluessel(key)
		if err != nil {
			return werkzeug.LoeschEpoche{}, false, err
		}
		if ep.Mandant == (protocol.ID{}) {
			ep.Mandant, ep.Ablage, ep.Epoch = mandant, ablage, epoch
		}
		if mandant != ep.Mandant || ablage != ep.Ablage || epoch != ep.Epoch {
			return werkzeug.LoeschEpoche{}, false, protocol.ErrLength
		}
		if _, doppelt := nr[n]; doppelt {
			return werkzeug.LoeschEpoche{}, false, protocol.ErrLength
		}
		nr[n] = key
		if n > max {
			max = n
		}
	}
	if uint64(len(nr)) != max || max == 0 {
		ep.Segmente = schluesselInReihenfolge(nr, max)
		return ep, true, nil
	}
	roh, ok, err := p.ziel.Lesen(nr[max])
	if err != nil {
		return werkzeug.LoeschEpoche{}, false, err
	}
	if !ok {
		return werkzeug.LoeschEpoche{}, false, nil
	}
	manifest, ok := manifestAusSegment(roh, ep.Epoch)
	ep.Segmente = schluesselInReihenfolge(nr, max)
	ep.Vollstaendig = ok
	if ok {
		ep.AnnahmeFirst = manifest.AnnahmeFirst
		ep.AnnahmeLast = manifest.AnnahmeLast
	}
	return ep, true, nil
}

func schluesselInReihenfolge(nr map[uint64]string, max uint64) []string {
	out := make([]string, 0, len(nr))
	for n := uint64(1); n <= max; n++ {
		if key, ok := nr[n]; ok {
			out = append(out, key)
		}
	}
	return out
}

func manifestAusSegment(seg []byte, epoch protocol.EpochID) (protocol.Manifest, bool) {
	nutz, _, ok := manifestNutz(seg)
	if !ok {
		return protocol.Manifest{}, false
	}
	m, err := protocol.ParseManifest(nutz)
	if err != nil || m.Epoch != epoch {
		return protocol.Manifest{}, false
	}
	return m, true
}

func manifestNutz(seg []byte) ([]byte, protocol.Signature, bool) {
	if !protocol.Segmentklasse(len(seg)) {
		return nil, protocol.Signature{}, false
	}
	for rahmen := protocol.RahmenMin; rahmen <= protocol.RahmenMax; rahmen <<= 1 {
		if len(seg)%rahmen != 0 {
			continue
		}
		nutz, sig, err := protocol.ParseManifestRahmen(seg[len(seg)-rahmen:])
		if err != nil {
			continue
		}
		return nutz, sig, true
	}
	return nil, protocol.Signature{}, false
}

// manifestEinreichen reicht jedes Manifest dieser Annahme beim Empfänger ein.
// Der Löschvermerk setzt diesen Abschluss voraus.
func (p *Prozess) manifestEinreichen(g *gespult) error {
	if p.einreichen == nil {
		return nil
	}
	for _, seg := range g.ein.Segmente {
		mandant, ablage, epoch, _, err := protocol.ParseObjektSchluessel(seg.Schluessel)
		if err != nil {
			continue
		}
		nutz, sig, ok := manifestNutz(seg.Bytes)
		if !ok {
			continue
		}
		m, err := protocol.ParseManifest(nutz)
		if err != nil || m.Epoch != epoch {
			continue
		}
		if err := p.einreichen(mandant, ablage, nutz, sig); err != nil {
			return err
		}
	}
	return nil
}

func annahmeAusSchluessel(key string) (protocol.ID, uint64, bool) {
	teile := strings.Split(key, "/")
	if len(teile) != 3 || teile[0] != "annahme" {
		return protocol.ID{}, 0, false
	}
	id, err := protocol.ParseID(teile[1])
	if err != nil {
		return protocol.ID{}, 0, false
	}
	seq, err := strconv.ParseUint(teile[2], 10, 64)
	if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != teile[2] {
		return protocol.ID{}, 0, false
	}
	return id, seq, true
}

// loeschLager legt Vermerke neben die Bestätigung und entfernt Segmente im Ziel.
type loeschLager struct {
	ziel     Ziel
	weg      Entfernen
	vermerke Vermerke
}

func (l loeschLager) Lesen(schluessel string) ([]byte, bool, error) {
	if mandant, ablage, epoch, ok := vermerkAusSchluessel(schluessel); ok {
		tag, da, err := l.vermerke.Vermerk(mandant, ablage, epoch)
		if err != nil || !da {
			return nil, false, err
		}
		body, err := protocol.VermerkBytes(epoch, tag)
		if err != nil {
			return nil, false, err
		}
		return body, true, nil
	}
	return l.ziel.Lesen(schluessel)
}

func (l loeschLager) Schreiben(schluessel string, inhalt []byte) error {
	mandant, ablage, epoch, ok := vermerkAusSchluessel(schluessel)
	if !ok {
		return l.ziel.Schreiben(schluessel, inhalt)
	}
	id, tag, err := protocol.ParseVermerk(inhalt)
	if err != nil || id != epoch {
		return werkzeug.ErrLoeschen
	}
	return l.vermerke.Vermerken(mandant, ablage, epoch, tag)
}

func (l loeschLager) Entfernen(schluessel string) error {
	if _, _, _, ok := vermerkAusSchluessel(schluessel); ok {
		return werkzeug.ErrLoeschen
	}
	return l.weg.Entfernen(schluessel)
}

func vermerkAusSchluessel(key string) (protocol.ID, protocol.ID, protocol.EpochID, bool) {
	teile := strings.Split(key, "/")
	if len(teile) != 4 || teile[0] != "vermerk" {
		return protocol.ID{}, protocol.ID{}, protocol.EpochID{}, false
	}
	mandant, err := protocol.ParseID(teile[1])
	if err != nil {
		return protocol.ID{}, protocol.ID{}, protocol.EpochID{}, false
	}
	ablage, err := protocol.ParseID(teile[2])
	if err != nil {
		return protocol.ID{}, protocol.ID{}, protocol.EpochID{}, false
	}
	epoch, err := protocol.ParseEpochID(teile[3])
	if err != nil {
		return protocol.ID{}, protocol.ID{}, protocol.EpochID{}, false
	}
	return mandant, ablage, epoch, true
}
