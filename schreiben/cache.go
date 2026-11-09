package schreiben

import (
	"cryptlog/protocol"
	schl "cryptlog/schluessel"
)

// AusCache legt KEK, Prüfschlüssel und Status aus dem Cache über die übrige Lage.
// Register, Stromkennungen und Rahmen bleiben bei grund.
func AusCache(c *schl.Cache, grund Bestand) Bestand {
	return cacheBestand{cache: c, grund: grund}
}

type cacheBestand struct {
	cache *schl.Cache
	grund Bestand
}

func (b cacheBestand) Mandanten() ([]protocol.ID, error) {
	if b.grund == nil {
		return nil, nil
	}
	return b.grund.Mandanten()
}

func (b cacheBestand) Mandant(id protocol.ID) (Lage, error) {
	var basis Lage
	var err error
	if b.grund != nil {
		basis, err = b.grund.Mandant(id)
		if err != nil {
			return Lage{}, err
		}
	}
	if b.cache == nil {
		return basis, nil
	}
	sicht, err := b.cache.Oeffentlich(id)
	if err != nil {
		return Lage{}, err
	}
	basis.KEKVorhanden = sicht.Vorhanden
	basis.KEK = Schluessel{}
	if sicht.Vorhanden {
		basis.KEK = Schluessel{Pub: sicht.Pub, Finger: sicht.Finger}
	}
	basis.Pruef = sicht.Pruef
	basis.Status = map[protocol.Hash]SchluesselStatus{}
	for finger, st := range sicht.Status {
		if lage, ok := lageStatus(st); ok {
			basis.Status[finger] = lage
		}
	}
	return basis, nil
}

func lageStatus(st schl.Status) (SchluesselStatus, bool) {
	switch st {
	case schl.StatusAbgeloest:
		return SchluesselAbgeloest, true
	case schl.StatusVerloren:
		return SchluesselVerloren, true
	case schl.StatusKompromittiert:
		return SchluesselKompromittiert, true
	default:
		return 0, false
	}
}
