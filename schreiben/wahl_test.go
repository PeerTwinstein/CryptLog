package schreiben

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cryptlog/abschluss"
	"cryptlog/protocol"
)

func TestWahlVerteilt(t *testing.T) {
	dir := t.TempDir()
	gemeinsam, err := OeffnenPlatte(filepath.Join(dir, "gemeinsam"))
	if err != nil {
		t.Fatal(err)
	}
	eigen, err := OeffnenPlatte(filepath.Join(dir, "eigen"))
	if err != nil {
		t.Fatal(err)
	}
	mandant := fill(0x11)
	anderer := fill(0x22)
	wahl, err := NeueWahl(gemeinsam, "platte", map[protocol.ID]Ziel{mandant: eigen}, map[protocol.ID]string{mandant: "platte"})
	if err != nil {
		t.Fatal(err)
	}
	seg := segKey(t, mandant)
	fremd := segKey(t, anderer)
	inhalt := []byte("segment")

	if err := wahl.Schreiben(seg, inhalt); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := gemeinsam.Lesen(seg); err != nil || ok {
		t.Fatalf("Segment im gemeinsamen Ziel: ok=%v err=%v", ok, err)
	}
	got, ok, err := eigen.Lesen(seg)
	if err != nil || !ok || !bytes.Equal(got, inhalt) {
		t.Fatalf("Segment im Mandantenziel: ok=%v err=%v", ok, err)
	}
	if err := wahl.Schreiben(seg, inhalt); err != nil {
		t.Fatal(err)
	}
	if err := wahl.Schreiben(seg, []byte("anders")); !errors.Is(err, abschluss.ErrObjekt) {
		t.Fatal(err)
	}

	if err := wahl.Schreiben(fremd, inhalt); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := eigen.Lesen(fremd); err != nil || ok {
		t.Fatalf("fremdes Segment im Mandantenziel: ok=%v err=%v", ok, err)
	}
	if _, ok, err := gemeinsam.Lesen(fremd); err != nil || !ok {
		t.Fatalf("fremdes Segment fehlt im gemeinsamen Ziel: ok=%v err=%v", ok, err)
	}

	belegt := protocol.BelegungSchluessel(fill(0x33))
	if err := wahl.Schreiben(belegt, []byte("offen")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := eigen.Lesen(belegt); err != nil || ok {
		t.Fatalf("Belegung im Mandantenziel: ok=%v err=%v", ok, err)
	}
	alt := segKeyNr(t, mandant, 2)
	if err := gemeinsam.Schreiben(alt, inhalt); err != nil {
		t.Fatal(err)
	}
	if err := wahl.Schreiben(alt, inhalt); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := eigen.Lesen(alt); err != nil || ok {
		t.Fatalf("alte Fassung wurde kopiert: ok=%v err=%v", ok, err)
	}
	if err := wahl.Schreiben(alt, []byte("anders")); !errors.Is(err, abschluss.ErrObjekt) {
		t.Fatal(err)
	}
	gelesen, ok, err := wahl.Lesen(alt)
	if err != nil || !ok || !bytes.Equal(gelesen, inhalt) {
		t.Fatalf("Lesen alt=%q ok=%v err=%v", gelesen, ok, err)
	}

	ann, err := protocol.AnnahmeSchluessel(fill(0x44), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := wahl.Schreiben(ann, []byte("annahme")); err != nil {
		t.Fatal(err)
	}
	liste, err := wahl.Liste("annahme/")
	if err != nil || len(liste) != 1 || liste[0] != ann {
		t.Fatalf("Annahmen %v %v", liste, err)
	}
	alle, err := wahl.Liste("")
	if err != nil {
		t.Fatal(err)
	}
	if !enthaelt(alle, seg) || !enthaelt(alle, fremd) || !enthaelt(alle, belegt) || !enthaelt(alle, ann) {
		t.Fatalf("Liste %v", alle)
	}
	if err := wahl.Entfernen(seg); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := eigen.Lesen(seg); err != nil || ok {
		t.Fatalf("Segment nach Entfernen im Mandantenziel: ok=%v err=%v", ok, err)
	}
	if err := wahl.Entfernen(alt); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := gemeinsam.Lesen(alt); err != nil || ok {
		t.Fatalf("alte Fassung nach Entfernen: ok=%v err=%v", ok, err)
	}
}

func TestZieleAus(t *testing.T) {
	dir := t.TempDir()
	gemeinsam, err := OeffnenPlatte(filepath.Join(dir, "gemeinsam"))
	if err != nil {
		t.Fatal(err)
	}
	mandant := fill(0x11)
	wurzel := filepath.Join(dir, "mandanten")
	mdir := filepath.Join(wurzel, mandant.Hex())
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		t.Fatal(err)
	}
	ziel, err := zieleAus(wurzel, gemeinsam, "platte")
	if err != nil || ziel != Ziel(gemeinsam) {
		t.Fatalf("ohne Datei: %v %T", err, ziel)
	}

	schreib(t, filepath.Join(mdir, "ziel"), "ziel = platte\nwurzel = "+gemeinsam.wurzel+"\n")
	if _, err := zieleAus(wurzel, gemeinsam, "platte"); !errors.Is(err, ErrKonfig) {
		t.Fatal(err)
	}

	eigen := filepath.Join(dir, "eigen")
	schreib(t, filepath.Join(mdir, "ziel"), "ziel = platte\nwurzel = "+eigen+"\n")
	ziel, err = zieleAus(wurzel, gemeinsam, "platte")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ziel.(*Wahl); !ok {
		t.Fatalf("%T", ziel)
	}

	s3gemeinsam, err := OeffnenS3(S3Konfig{
		Endpunkt: "http://127.0.0.1:9", Bucket: "cryptlog", Region: "eu-central-1",
		Zugang: "a", Geheimnis: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	zugang := filepath.Join(mdir, "zugang")
	geheim := filepath.Join(mdir, "geheimnis")
	schreib(t, zugang, "a\n")
	schreib(t, geheim, "b\n")
	schreib(t, filepath.Join(mdir, "ziel"), ""+
		"ziel = s3\n"+
		"endpunkt = http://127.0.0.1:9\n"+
		"bucket = cryptlog\n"+
		"region = andere\n"+
		"zugang = zugang\n"+
		"geheimnis = geheimnis\n")
	if _, err := zieleAus(wurzel, s3gemeinsam, "s3"); !errors.Is(err, ErrKonfig) {
		t.Fatal(err)
	}
	schreib(t, filepath.Join(mdir, "ziel"), ""+
		"ziel = s3\n"+
		"endpunkt = http://127.0.0.1:9\n"+
		"bucket = plattform\n"+
		"region = eu-central-1\n"+
		"zugang = zugang\n"+
		"geheimnis = geheimnis\n")
	if _, err := zieleAus(wurzel, s3gemeinsam, "s3"); !errors.Is(err, ErrKonfig) {
		t.Fatal(err)
	}
}

func TestZielFehlArt(t *testing.T) {
	p := &Prozess{zielArt: "s3", zielFehler: map[string]uint64{}}
	p.zielFehl(artFehler{art: "platte", err: errors.New("platte")})
	p.zielFehl(errors.New("gemeinsam"))
	if p.zielFehler["platte"] != 1 || p.zielFehler["s3"] != 1 {
		t.Fatalf("%v", p.zielFehler)
	}
}

func segKey(t *testing.T, mandant protocol.ID) string {
	t.Helper()
	return segKeyNr(t, mandant, 1)
}

func segKeyNr(t *testing.T, mandant protocol.ID, nr uint64) string {
	t.Helper()
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC), mandant, protocol.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := protocol.ObjektSchluessel(mandant, mandant, epoch, nr)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func enthaelt(keys []string, want string) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}
