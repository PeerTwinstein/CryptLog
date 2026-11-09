package schreiben

import (
	"testing"
	"time"

	"cryptlog/protocol"
)

func TestSchwellenGrenzen(t *testing.T) {
	gut := Voreinstellung()
	gut.SpoolGrenze = 8 << 20
	gut.Frist = 2 * time.Minute
	if err := gut.Pruefen(); err != nil {
		t.Fatal(err)
	}
	faelle := []Schwellen{gut, gut, gut, gut, gut, gut}
	faelle[0].Puffer = 63 << 10
	faelle[1].PufferWarte = 9 * time.Millisecond
	faelle[2].Segment = 255 << 10
	faelle[3].SegmentWarte = 9 * time.Second
	faelle[4].Gruppe = 7 * time.Hour
	faelle[5].Klasse = protocol.Segment4MiB + 1
	for i, s := range faelle {
		s.SpoolGrenze = 8 << 20
		s.Frist = time.Minute
		if i == 5 {
			s.Klasse = 12345
		}
		if err := s.Pruefen(); err != ErrSchwelle {
			t.Fatalf("fall %d: %v", i, err)
		}
	}
	halb := gut
	halb.Gruppe = 45 * time.Minute
	halb.Einzel = 8 * time.Hour
	halb.Sonstige = 15 * time.Minute
	if err := halb.Pruefen(); err != nil {
		t.Fatal(err)
	}
}
