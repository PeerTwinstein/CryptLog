package oberflaeche

import (
	"cryptlog/protocol"
	"cryptlog/schreiben"
)

type plattenZiel struct{ p *schreiben.Platte }

func (z plattenZiel) Lesen(schluessel string) ([]byte, bool, error) {
	return z.p.Lesen(schluessel)
}

func (z plattenZiel) Liste(prefix string) ([]string, error) { return z.p.Liste(prefix) }

func (z plattenZiel) Schreiben(schluessel string, inhalt []byte) error {
	return z.p.Schreiben(schluessel, inhalt)
}

func (z plattenZiel) Mandanten() ([]protocol.ID, error) { return mandanten(z) }

type s3Ziel struct{ s *schreiben.S3 }

func (z s3Ziel) Lesen(schluessel string) ([]byte, bool, error) { return z.s.Lesen(schluessel) }

func (z s3Ziel) Liste(prefix string) ([]string, error) { return z.s.Liste(prefix) }

func (z s3Ziel) Schreiben(schluessel string, inhalt []byte) error {
	return z.s.Schreiben(schluessel, inhalt)
}

func (z s3Ziel) Mandanten() ([]protocol.ID, error) { return mandanten(z) }

type listenZiel interface {
	Liste(prefix string) ([]string, error)
}

func mandanten(z listenZiel) ([]protocol.ID, error) {
	keys, err := z.Liste("")
	if err != nil {
		return nil, err
	}
	gesehen := map[protocol.ID]struct{}{}
	var out []protocol.ID
	for _, key := range keys {
		mandant, _, _, _, err := protocol.ParseObjektSchluessel(key)
		if err != nil {
			continue
		}
		if _, ok := gesehen[mandant]; ok {
			continue
		}
		gesehen[mandant] = struct{}{}
		out = append(out, mandant)
	}
	return out, nil
}
