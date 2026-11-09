package protocol

import (
	"bytes"
	"math"
	"time"
)

// VermerkBytes ist der Löschvermerk neben der Epochenbestätigung.
// tag ist der Löschtag, Mitternacht in UTC. Er steht als Unix-Zeit in Millisekunden.
//
//	L("loeschvermerk") || "loeschvermerk" || epoch_id || loeschtag
func VermerkBytes(epoch EpochID, tag time.Time) ([]byte, error) {
	if !loeschMitternacht(tag) {
		return nil, ErrRaster
	}
	ms := tag.UnixMilli()
	if ms < 0 {
		return nil, ErrRaster
	}
	buf := AppendText(nil, "loeschvermerk")
	buf = append(buf, epoch[:]...)
	buf = AppendU64(buf, uint64(ms))
	return buf, nil
}

// ParseVermerk liest einen Löschvermerk.
func ParseVermerk(b []byte) (EpochID, time.Time, error) {
	c := cursor{b: b}
	if err := c.domain("loeschvermerk"); err != nil {
		return EpochID{}, time.Time{}, err
	}
	epoch, err := c.epoch()
	if err != nil {
		return EpochID{}, time.Time{}, err
	}
	ms, err := c.u64()
	if err != nil {
		return EpochID{}, time.Time{}, err
	}
	if err := c.done(); err != nil {
		return EpochID{}, time.Time{}, err
	}
	if ms > uint64(math.MaxInt64) {
		return EpochID{}, time.Time{}, ErrRaster
	}
	tag := time.UnixMilli(int64(ms)).UTC()
	if !loeschMitternacht(tag) {
		return EpochID{}, time.Time{}, ErrRaster
	}
	again, err := VermerkBytes(epoch, tag)
	if err != nil || !bytes.Equal(again, b) {
		return EpochID{}, time.Time{}, ErrLength
	}
	return epoch, tag, nil
}

// VermerkSchluessel liegt neben der Epochenbestätigung, außerhalb des Log-Buckets.
func VermerkSchluessel(mandant, ablage ID, epoch EpochID) string {
	return "vermerk/" + mandant.Hex() + "/" + ablage.Hex() + "/" + epoch.String()
}

func loeschMitternacht(t time.Time) bool {
	return t.Location() == time.UTC && !t.IsZero() &&
		t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}
