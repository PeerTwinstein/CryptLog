package schreiben

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"cryptlog/protocol"
	"cryptlog/strom"
)

func (p *Prozess) katalogNachziehen(mandant protocol.ID, lage Lage) error {
	if lage.Katalog == (protocol.ID{}) || lage.Stand.Name == "" || !lage.KEKVorhanden || lage.KEK.Pub == nil {
		return nil
	}
	raw, err := protocol.KatalogBytes(lage.Stand)
	if err != nil {
		return err
	}
	if bytesEqual(p.katalog[mandant], raw) {
		return nil
	}
	bahn, err := p.bahn(mandant, lage.Katalog, lage.Katalog, protocol.RolleKatalog, lage.KEK, lage, p.jetzt())
	if err != nil {
		return err
	}
	var id protocol.ID
	if _, err := io.ReadFull(p.rand, id[:]); err != nil {
		return err
	}
	if id == (protocol.ID{}) {
		return protocol.ErrLength
	}
	zeit := uint64(p.jetzt().UnixMilli())
	segs, eintraege, err := strom.KatalogSchreiben(bahn, id, zeit, lage.Stand)
	if err != nil {
		return err
	}
	lauf := p.laufVonEpoche(bahn.Epoche)
	if lauf == nil {
		return strom.ErrBahn
	}
	for _, seg := range segs {
		lauf.segment(seg)
	}
	for _, e := range eintraege {
		lauf.eintraege = append(lauf.eintraege, e)
		lauf.lastSeq = e.Seq
		if e.Seq+1 > lauf.next {
			lauf.next = e.Seq + 1
		}
	}
	lauf.geschrieben = true
	aufruf, err := protocol.AufrufBytes(zeit, "", nil, raw)
	if err != nil {
		return err
	}
	hash, err := protocol.AufrufHash(mandant, id, aufruf)
	if err != nil {
		return err
	}
	w := &warten{
		id: id, hash: hash, seit: time.Now(), bytes: len(eintraege) * lauf.rahmen,
		katalogMandant: mandant, katalogRoh: append([]byte(nil), raw...), mandant: mandant,
		rollen: []protocol.StromRolle{protocol.RolleKatalog}, zaehlen: !p.deck[mandant],
	}
	p.katalog[mandant] = w.katalogRoh
	p.nachID[id] = w
	if len(p.puffer) == 0 {
		p.pufferSeit = time.Now()
	}
	p.puffer = append(p.puffer, w)
	p.pufferBytes += w.bytes
	return nil
}

func (p *Prozess) katalogSichern(w *warten) {
	if w == nil || len(w.katalogRoh) == 0 {
		return
	}
	datei := filepath.Join(p.spoolDir, "katalog-"+w.katalogMandant.Hex())
	_ = schreibeFest(datei, w.katalogRoh)
}

func (p *Prozess) katalogVergessen(w *warten) {
	if w == nil || len(w.katalogRoh) == 0 {
		return
	}
	if bytesEqual(p.katalog[w.katalogMandant], w.katalogRoh) {
		delete(p.katalog, w.katalogMandant)
	}
	_ = os.Remove(filepath.Join(p.spoolDir, "katalog-"+w.katalogMandant.Hex()))
}

func (p *Prozess) katalogLaden() error {
	eintraege, err := os.ReadDir(p.spoolDir)
	if err != nil {
		return err
	}
	if p.katalog == nil {
		p.katalog = map[protocol.ID][]byte{}
	}
	for _, eintrag := range eintraege {
		name := eintrag.Name()
		if len(name) != len("katalog-")+protocol.IDLen*2 || name[:len("katalog-")] != "katalog-" {
			continue
		}
		id, err := protocol.ParseID(name[len("katalog-"):])
		if err != nil {
			continue
		}
		roh, err := os.ReadFile(filepath.Join(p.spoolDir, name))
		if err != nil {
			return err
		}
		if _, err := protocol.ParseKatalog(roh); err != nil {
			continue
		}
		p.katalog[id] = roh
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
