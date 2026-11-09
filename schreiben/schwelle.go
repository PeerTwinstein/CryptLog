package schreiben

import (
	"errors"
	"time"

	"cryptlog/protocol"
)

const (
	pufferMin     = 64 << 10
	pufferVorgabe = 1 << 20
	pufferMax     = 8 << 20

	warteMin     = 10 * time.Millisecond
	warteVorgabe = 100 * time.Millisecond
	warteMax     = time.Second

	segmentMin     = 256 << 10
	segmentVorgabe = 4 << 20
	segmentMax     = 32 << 20

	segmentWarteMin     = 10 * time.Second
	segmentWarteVorgabe = 60 * time.Second
	segmentWarteMax     = 5 * time.Minute

	epocheMin     = 15 * time.Minute
	epocheMax     = 8 * time.Hour
	epocheGruppe  = time.Hour
	epocheEinzel  = 8 * time.Hour
	epocheSonstig = time.Hour
)

// ErrSchwelle heißt, ein Wert liegt außerhalb der festgelegten Grenzen.
var ErrSchwelle = errors.New("schreiben: Schwelle liegt außerhalb der Grenzen")

// Schwellen sind Puffer, Segment und Epochenintervall.
// SpoolGrenze und Frist haben keine Vorgabe; beide müssen gesetzt sein.
type Schwellen struct {
	Puffer       int
	PufferWarte  time.Duration
	Segment      int
	SegmentWarte time.Duration
	Klasse       int
	Gruppe       time.Duration
	Einzel       time.Duration
	Sonstige     time.Duration
	SpoolGrenze  int
	Frist        time.Duration
}

// Voreinstellung setzt die festgelegten Ausgangswerte.
// SpoolGrenze und Frist bleiben 0 und sind vom Aufrufer zu setzen.
func Voreinstellung() Schwellen {
	return Schwellen{
		Puffer:       pufferVorgabe,
		PufferWarte:  warteVorgabe,
		Segment:      segmentVorgabe,
		SegmentWarte: segmentWarteVorgabe,
		Klasse:       protocol.Segment4MiB,
		Gruppe:       epocheGruppe,
		Einzel:       epocheEinzel,
		Sonstige:     epocheSonstig,
	}
}

// Pruefen lehnt Werte außerhalb der Grenzen ab.
// Ein Epochenintervall muss 24 Stunden teilen.
func (s Schwellen) Pruefen() error {
	if s.Puffer < pufferMin || s.Puffer > pufferMax {
		return ErrSchwelle
	}
	if s.PufferWarte < warteMin || s.PufferWarte > warteMax {
		return ErrSchwelle
	}
	if s.Segment < segmentMin || s.Segment > segmentMax {
		return ErrSchwelle
	}
	if s.SegmentWarte < segmentWarteMin || s.SegmentWarte > segmentWarteMax {
		return ErrSchwelle
	}
	if !protocol.Segmentklasse(s.Klasse) || s.SpoolGrenze < s.Klasse || s.Frist <= s.SegmentWarte {
		return ErrSchwelle
	}
	if !epocheTeilt(s.Gruppe) || !epocheTeilt(s.Einzel) || !epocheTeilt(s.Sonstige) {
		return ErrSchwelle
	}
	return nil
}

func epocheTeilt(d time.Duration) bool {
	if d < epocheMin || d > epocheMax {
		return false
	}
	return int64(24*time.Hour)%int64(d) == 0
}

func (s Schwellen) intervall(rolle protocol.StromRolle) time.Duration {
	switch rolle {
	case protocol.RolleEinzel:
		return s.Einzel
	case protocol.RolleGruppe:
		return s.Gruppe
	default:
		return s.Sonstige
	}
}
