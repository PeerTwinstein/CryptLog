package schreiben

import (
	"crypto"
	"errors"
	"io"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/strom"
)

// lauf ist eine offene Epoche eines logischen Stroms.
type lauf struct {
	key          stromSchluss
	ep           *epoch.Epoche
	rolle        protocol.StromRolle
	rahmen       int
	pub          crypto.PublicKey
	raster       time.Time
	next         uint64
	lastSeq      uint64
	geschrieben  bool
	segmente     []epoch.Segment
	eintraege    []protocol.SeqEintrag
	ausgegeben   uint64
	annahmeFirst uint64
	annahmeLast  uint64
	annahmeHead  protocol.Hash
	rest         *epoch.Ergebnis
	schon        uint64
	lastVor      uint64
}

func (l *lauf) frames(event protocol.ID, n int) {
	for i := 0; i < n; i++ {
		eintrag := protocol.SeqEintrag{Seq: l.next, Art: protocol.ArtFortsetzung}
		if i == 0 {
			eintrag.Art = protocol.ArtEreignis
			eintrag.Event = event
		}
		l.eintraege = append(l.eintraege, eintrag)
		l.lastSeq = l.next
		l.next++
	}
	l.geschrieben = true
}

func (l *lauf) segment(seg epoch.Segment) {
	l.segmente = append(l.segmente, seg)
	if seg.Nr > l.ausgegeben {
		l.ausgegeben = seg.Nr
	}
}

func (l *lauf) fuellung(glieder []epoch.Glied) {
	for _, g := range glieder {
		l.eintraege = append(l.eintraege, protocol.SeqEintrag{Seq: g.Seq, Art: g.Art, Event: g.Event})
		if g.Seq+1 > l.next {
			l.next = g.Seq + 1
		}
		l.lastSeq = g.Seq
	}
}

func (l *lauf) merken(seq uint64, hash protocol.Hash) {
	if l.annahmeFirst == 0 {
		l.annahmeFirst = seq
	}
	l.annahmeLast = seq
	l.annahmeHead = hash
}

func (p *Prozess) bahn(mandant, ablage, bind protocol.ID, rolle protocol.StromRolle, schl Schluessel, lage Lage, jetzt time.Time) (strom.Bahn, error) {
	rahmen := lage.Rahmen
	if weiter, ok, err := p.fortsetzen(mandant, ablage, bind, lage, jetzt); err != nil {
		return strom.Bahn{}, err
	} else if ok {
		return strom.Bahn{Bind: bind, Epoche: weiter.ep}, nil
	}
	key := stromSchluss{mandant: mandant, ablage: ablage, bind: bind, finger: schl.Finger}
	l := p.laeufe[key]
	if l != nil && l.ep != nil {
		weiter, err := p.vorSchreiben(l, jetzt)
		if err != nil {
			return strom.Bahn{}, err
		}
		l = weiter
	}
	if l == nil || l.ep == nil {
		var err error
		l, err = p.oeffnen(key, rolle, schl, rahmen, jetzt)
		if err != nil {
			return strom.Bahn{}, err
		}
	}
	return strom.Bahn{Bind: bind, Epoche: l.ep}, nil
}

// fortsetzen führt eine offene Epoche weiter, deren Schlüssel abgelöst ist,
// bis ihr Raster endet. Verloren und kompromittiert fallen nicht darunter.
func (p *Prozess) fortsetzen(mandant, ablage, bind protocol.ID, lage Lage, jetzt time.Time) (*lauf, bool, error) {
	var alt *lauf
	for _, l := range p.laeufe {
		if l == nil || l.key.mandant != mandant || l.key.ablage != ablage || l.key.bind != bind {
			continue
		}
		if l.ep == nil || !l.ep.Offen() || lage.Status[l.key.finger] != SchluesselAbgeloest {
			continue
		}
		alt = l
		break
	}
	if alt == nil {
		return nil, false, nil
	}
	weiter, err := p.vorSchreiben(alt, jetzt)
	if err != nil {
		return nil, false, err
	}
	if weiter == nil {
		return nil, false, nil
	}
	return weiter, true, nil
}

// abloesen schließt abgelöste Epochen, deren Raster vorbei ist.
func (p *Prozess) abloesen(mandant protocol.ID, lage Lage) error {
	jetzt := p.jetzt()
	for _, l := range p.laeufe {
		if l == nil || l.key.mandant != mandant || l.ep == nil || !l.ep.Offen() {
			continue
		}
		if lage.Status[l.key.finger] != SchluesselAbgeloest {
			continue
		}
		if _, err := p.vorSchreiben(l, jetzt); err != nil {
			return err
		}
	}
	return nil
}

// sperren verwirft den Klartext-DEK, sobald verloren oder kompromittiert lesbar ist.
// Noch nicht angenommene Einträge im Puffer bleiben beim Aufrufer.
func (p *Prozess) sperren(mandant protocol.ID, lage Lage) {
	hart := false
	for key, l := range p.laeufe {
		if l == nil || key.mandant != mandant || l.ep == nil || !l.ep.Offen() {
			continue
		}
		st := lage.Status[key.finger]
		if st != SchluesselVerloren && st != SchluesselKompromittiert {
			continue
		}
		if l.geschrieben || len(l.segmente) > 0 || len(l.eintraege) > 0 {
			hart = true
		}
		l.ep.Verwerfen()
		l.geschrieben = false
		l.eintraege = nil
		l.segmente = nil
		p.entfernen(l)
	}
	if hart {
		p.pufferScheitern(ErrSchluessel)
	}
}

func (p *Prozess) vorSchreiben(l *lauf, jetzt time.Time) (*lauf, error) {
	if rasterBeginn(jetzt, p.schwellen.intervall(l.rolle)) == l.raster {
		return l, nil
	}
	if err := p.rotieren(l); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *Prozess) rotieren(l *lauf) error {
	if len(p.puffer) > 0 {
		if err := p.pufferAbschluss(); err != nil {
			return err
		}
	}
	if err := p.hochladen(true); err != nil {
		return err
	}
	if err := p.manifest(l); err != nil {
		return err
	}
	return p.hochladen(true)
}

func (p *Prozess) oeffnen(key stromSchluss, rolle protocol.StromRolle, schl Schluessel, rahmen int, jetzt time.Time) (*lauf, error) {
	return p.oeffnenRaster(key, rolle, schl, rahmen, rasterBeginn(jetzt, p.schwellen.intervall(rolle)))
}

func (p *Prozess) oeffnenRaster(key stromSchluss, rolle protocol.StromRolle, schl Schluessel, rahmen int, raster time.Time) (*lauf, error) {
	if schl.Pub == nil || rahmen == 0 || p.schwellen.Klasse%rahmen != 0 {
		return nil, protocol.ErrLength
	}
	dek, prefix, err := crypt.NewDEK()
	if err != nil {
		return nil, err
	}
	defer dek.Wipe()
	var dekID protocol.ID
	if _, err := io.ReadFull(p.rand, dekID[:]); err != nil {
		return nil, err
	}
	kennung, err := protocol.NewEpochID(raster, p.instanz, prefix)
	if err != nil {
		return nil, err
	}
	wrapped, err := crypt.WrapDEK(p.rand, schl.Pub, dek, key.bind, protocol.WrapContext(key.mandant, key.ablage, kennung, schl.Finger))
	if err != nil {
		return nil, err
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: key.mandant,
		Ablage:  key.ablage,
		DekID:   dekID,
		Epoch:   kennung,
		KEK:     schl.Finger,
		Wrapped: wrapped,
		DEK:     dek,
		Rahmen:  rahmen,
		Klasse:  p.schwellen.Klasse,
		Rand:    p.rand,
	})
	if err != nil {
		return nil, err
	}
	l := &lauf{
		key:    key,
		ep:     ep,
		rolle:  rolle,
		rahmen: rahmen,
		pub:    schl.Pub,
		raster: raster,
		next:   1,
	}
	if p.laeufe == nil {
		p.laeufe = make(map[stromSchluss]*lauf)
	}
	p.laeufe[key] = l
	p.reihe = append(p.reihe, l)
	return l, nil
}

func (p *Prozess) schnittEiner(l *lauf) error {
	if l == nil || l.ep == nil {
		return nil
	}
	if !l.ep.Offen() {
		if l.geschrieben {
			return epoch.ErrZustand
		}
		return nil
	}
	if !l.geschrieben {
		return nil
	}
	seg, glieder, err := l.ep.Schnitt()
	l.geschrieben = false
	if errors.Is(err, epoch.ErrSchnitt) {
		return nil
	}
	if err != nil {
		return err
	}
	l.segment(seg)
	l.fuellung(glieder)
	return nil
}

// manifest schließt die Epoche. Die Annahme der Einträge ist zu diesem
// Zeitpunkt schon gebildet. Das Segment, das das Manifest trägt, hängt an
// der folgenden Annahme: der Hash dieser Annahme kann nicht im Manifest
// stehen, weil das Manifest in den Segmentbytes liegt, über die der Hash geht.
func (p *Prozess) manifest(l *lauf) error {
	if l == nil || l.ep == nil {
		return nil
	}
	if l.rest == nil {
		kette := ablageSchluss{l.key.mandant, l.key.ablage}
		prev, ok := p.kette[kette]
		if !ok {
			prev = protocol.Genesis(l.key.ablage, p.instanz)
		}
		l.schon = l.ausgegeben
		l.lastVor = l.lastSeq
		erg, err := l.ep.Abschluss(prev, l.annahmeFirst, l.annahmeLast, l.annahmeHead, p.sign)
		if err != nil {
			if l.ep == nil || !l.ep.Offen() {
				p.entfernen(l)
			}
			return err
		}
		l.rest = &erg
	}
	st, err := manifestStueck(l)
	if err != nil {
		return err
	}
	if err := p.spulen(nil, []stueck{st}); err != nil {
		return err
	}
	p.queue[len(p.queue)-1].abdeckenFirst = l.annahmeFirst
	p.queue[len(p.queue)-1].abdeckenLast = l.annahmeLast
	p.kette[ablageSchluss{l.key.mandant, l.key.ablage}] = l.rest.EpochHash
	p.entfernen(l)
	return nil
}

func manifestStueck(l *lauf) (stueck, error) {
	var segs []epoch.Segment
	for _, seg := range l.rest.Segmente {
		if seg.Nr > l.schon {
			segs = append(segs, seg)
		}
	}
	var eintraege []protocol.SeqEintrag
	for _, g := range l.rest.Glieder {
		if g.Seq > l.lastVor {
			eintraege = append(eintraege, protocol.SeqEintrag{Seq: g.Seq, Art: g.Art, Event: g.Event})
		}
	}
	if len(segs) == 0 || len(eintraege) == 0 {
		return stueck{}, protocol.ErrLength
	}
	return stueck{
		lauf:      l,
		mandant:   l.key.mandant,
		finger:    l.key.finger,
		pub:       l.pub,
		eintraege: eintraege,
		segmente:  segs,
		manifest:  true,
	}, nil
}

func (p *Prozess) entfernen(l *lauf) {
	if l == nil {
		return
	}
	delete(p.laeufe, l.key)
	l.ep = nil
}

func (p *Prozess) laufVonEpoche(ep *epoch.Epoche) *lauf {
	for _, l := range p.reihe {
		if l.ep == ep {
			return l
		}
	}
	return nil
}

func (p *Prozess) laufZuSegment(seg epoch.Segment) (*lauf, error) {
	_, _, kennung, _, err := protocol.ParseObjektSchluessel(seg.Schluessel)
	if err != nil {
		return nil, err
	}
	for _, l := range p.reihe {
		if l.ep != nil && l.ep.Kennung() == kennung {
			return l, nil
		}
	}
	return nil, protocol.ErrLength
}
