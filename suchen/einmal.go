package suchen

import (
	"sync"
	"time"

	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

// menge merkt angenommene Anfragesignaturen für das Zeitfenster der Zone.
// Die dauerhafte Fassung ist das Suchprotokoll dieser Replica. Ein Neustart lädt es.
// Ein neuer Pod hat es nicht.
type menge struct {
	mu    sync.Mutex
	jetzt func() time.Time
	zeit  int64
	merk  map[protocol.Signature]int64
}

func neueMenge(jetzt func() time.Time) *menge {
	return &menge{jetzt: jetzt, merk: map[protocol.Signature]int64{}}
}

func (m *menge) zeitSetzen(ms int64) {
	m.mu.Lock()
	m.zeit = ms
	m.mu.Unlock()
}

func (m *menge) hat(sig protocol.Signature) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streichen()
	_, ok := m.merk[sig]
	return ok
}

// Merken erfüllt werkzeug.Einmal. Dieselbe Signatur gilt im Fenster nur einmal.
func (m *menge) Merken(sig protocol.Signature) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streichen()
	if _, ok := m.merk[sig]; ok {
		return false
	}
	m.merk[sig] = m.zeit
	return true
}

func (m *menge) setzen(sig protocol.Signature, zeit int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.imFenster(zeit) {
		return
	}
	if _, ok := m.merk[sig]; ok {
		return
	}
	m.merk[sig] = zeit
}

func (m *menge) streichen() {
	for sig, zeit := range m.merk {
		if !m.imFenster(zeit) {
			delete(m.merk, sig)
		}
	}
}

func (m *menge) imFenster(zeit int64) bool {
	delta := m.jetzt().UTC().UnixMilli() - zeit
	if delta < 0 {
		delta = -delta
	}
	return delta <= werkzeug.Abweichung.Milliseconds()
}
