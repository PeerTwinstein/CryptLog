package schreiben

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/strom"
)

func TestAntwortNachAnnahme(t *testing.T) {
	tor := neuesTor(t)
	p := starten(t, tor, testSchwellen(20*time.Millisecond), time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC))
	fertig := make(chan error, 1)
	go func() {
		_, err := p.Ereignis(context.Background(), ereignis(fill(0x42), false))
		fertig <- err
	}()
	select {
	case <-tor.rein:
	case <-time.After(5 * time.Second):
		t.Fatal("kein schreiben am ziel")
	}
	if !spoolHatFolge(t, p.spoolDir) {
		t.Fatal("spool vor dem ziel leer")
	}
	if _, ok, _ := tor.Platte.Lesen(annahmePfad(p)); ok {
		t.Fatal("annahme liegt vor der freigabe")
	}
	select {
	case err := <-fertig:
		t.Fatalf("antwort vor der annahme: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(tor.los)
	select {
	case err := <-fertig:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keine antwort")
	}
	if spoolHatFolge(t, p.spoolDir) {
		t.Fatal("spool nach der annahme")
	}
	if !reihenfolge(tor.schritte()) {
		t.Fatalf("reihenfolge %v", tor.schritte())
	}
}

func TestZweiEreignisseEinAbschluss(t *testing.T) {
	p := starten(t, platte(t), testSchwellen(time.Second), time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC))
	a := make(chan Bestaetigung, 1)
	b := make(chan Bestaetigung, 1)
	go func() {
		best, err := p.Ereignis(context.Background(), ereignis(fill(0x51), false))
		if err != nil {
			t.Errorf("erstes %v", err)
		}
		a <- best
	}()
	go func() {
		best, err := p.Ereignis(context.Background(), ereignis(fill(0x52), false))
		if err != nil {
			t.Errorf("zweites %v", err)
		}
		b <- best
	}()
	var erste, zweite Bestaetigung
	select {
	case erste = <-a:
	case <-time.After(5 * time.Second):
		t.Fatal("erstes")
	}
	select {
	case zweite = <-b:
	case <-time.After(5 * time.Second):
		t.Fatal("zweites")
	}
	if erste.Seq == 0 || erste.Seq != zweite.Seq || erste.Schluessel != zweite.Schluessel {
		t.Fatalf("abschluss %d %d %s %s", erste.Seq, zweite.Seq, erste.Schluessel, zweite.Schluessel)
	}
	noch, err := p.Ereignis(context.Background(), ereignis(fill(0x51), false))
	if err != nil || noch != erste {
		t.Fatalf("erneut %+v %v", noch, err)
	}
}

func TestBelegungGehaltenUndAbgelehnt(t *testing.T) {
	ziel := platte(t)
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	p := starten(t, ziel, testSchwellen(20*time.Millisecond), jetzt)
	ev := ereignis(fill(0x61), false)
	lage := testLage(t)
	zu, err := strom.Zuordnen(ev, strom.Eingang{KEKVorhanden: true, Register: lage.Register, Pruef: lage.Pruef})
	if err != nil {
		t.Fatal(err)
	}
	fremd := fill(0x99)
	raw, err := protocol.BelegungBytes(protocol.Belegung{
		Event: ev.ID, Instanz: fremd, Batch: fill(0x01), Generation: 1, Lage: protocol.LageOffen, Hash: zu.Hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben(protocol.BelegungSchluessel(ev.ID), raw); err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben(protocol.InstanzSchluessel(fremd), protocol.InstanzBytes(protocol.InstanzLauf{
		Instanz: fremd, Frist: uint64(jetzt.Add(time.Hour).UnixMilli()),
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ereignis(context.Background(), ev); err != ErrGehalten {
		t.Fatalf("gehalten %v", err)
	}
	ev2 := ereignis(fill(0x62), false)
	falsch, err := protocol.BelegungBytes(protocol.Belegung{
		Event: ev2.ID, Instanz: fremd, Batch: fill(0x01), Generation: 1, Lage: protocol.LageOffen, Hash: protocol.Hash{9},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben(protocol.BelegungSchluessel(ev2.ID), falsch); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ereignis(context.Background(), ev2); err != ErrBelegung {
		t.Fatalf("abgelehnt %v", err)
	}
}

func TestEpocheRotiert(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	uhr := jetzt
	ziel := platte(t)
	schwellen := testSchwellen(30 * time.Millisecond)
	p := startenUhr(t, ziel, schwellen, func() time.Time { return uhr })
	erste, err := p.Ereignis(context.Background(), ereignis(fill(0x71), false))
	if err != nil {
		t.Fatal(err)
	}
	uhr = uhr.Add(15 * time.Minute)
	zweite, err := p.Ereignis(context.Background(), ereignis(fill(0x72), false))
	if err != nil {
		t.Fatal(err)
	}
	if rasterVon(t, ziel, erste) == rasterVon(t, ziel, zweite) {
		t.Fatalf("raster %s", rasterVon(t, ziel, erste))
	}
}

func TestKetteUeberNeustart(t *testing.T) {
	ziel := platte(t)
	spool := t.TempDir()
	schwellen := testSchwellen(20 * time.Millisecond)
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	p := startenMit(t, ziel, spool, schwellen, func() time.Time { return jetzt })
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x81), false)); err != nil {
		t.Fatal(err)
	}
	if err := p.Beenden(context.Background()); err != nil {
		t.Fatal(err)
	}
	seq, hash := annahmeKette(t, ziel, fill(0x77))
	p = startenMit(t, ziel, spool, schwellen, func() time.Time { return jetzt })
	zweite, err := p.Ereignis(context.Background(), ereignis(fill(0x82), false))
	if err != nil {
		t.Fatal(err)
	}
	nutz, err := annahme(ziel, zweite.Schluessel)
	if err != nil {
		t.Fatal(err)
	}
	if nutz.Previous != hash || nutz.BatchSeq != seq+1 {
		t.Fatalf("previous %x seq %d", nutz.Previous, nutz.BatchSeq)
	}
	annahmeKette(t, ziel, fill(0x77))
}

func TestInstanzfristWirdErneuert(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	uhr := jetzt
	ziel := platte(t)
	schwellen := testSchwellen(20 * time.Millisecond)
	schwellen.Frist = time.Hour
	p := startenUhr(t, ziel, schwellen, func() time.Time { return uhr })
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x91), false)); err != nil {
		t.Fatal(err)
	}
	erste, ok, err := ziel.Lesen(protocol.InstanzSchluessel(p.instanz))
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	lauf, err := protocol.ParseInstanzLauf(erste)
	if err != nil {
		t.Fatal(err)
	}
	uhr = uhr.Add(31 * time.Minute)
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x92), false)); err != nil {
		t.Fatal(err)
	}
	zweite, _, err := ziel.Lesen(protocol.InstanzSchluessel(p.instanz))
	if err != nil {
		t.Fatal(err)
	}
	neu, err := protocol.ParseInstanzLauf(zweite)
	if err != nil {
		t.Fatal(err)
	}
	if neu.Frist <= lauf.Frist {
		t.Fatalf("frist %d dann %d", lauf.Frist, neu.Frist)
	}
}

func TestPufferGroesse(t *testing.T) {
	p := starten(t, platte(t), testSchwellen(time.Second), time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC))
	anfang := time.Now()
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0xa1), true)); err != nil {
		t.Fatal(err)
	}
	if time.Since(anfang) >= 900*time.Millisecond {
		t.Fatal("größe hat nicht vor der wartezeit geschrieben")
	}
}

func TestUebernahme(t *testing.T) {
	ziel := platte(t)
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	p := starten(t, ziel, testSchwellen(20*time.Millisecond), jetzt)
	ev := ereignis(fill(0xb1), false)
	lage := testLage(t)
	zu, err := strom.Zuordnen(ev, strom.Eingang{KEKVorhanden: true, Register: lage.Register, Pruef: lage.Pruef})
	if err != nil {
		t.Fatal(err)
	}
	fremd := fill(0x99)
	raw, err := protocol.BelegungBytes(protocol.Belegung{
		Event: ev.ID, Instanz: fremd, Batch: fill(0x01), Generation: 1, Lage: protocol.LageOffen, Hash: zu.Hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben(protocol.BelegungSchluessel(ev.ID), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ereignis(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	liegen, ok, err := ziel.Lesen(protocol.BelegungSchluessel(ev.ID))
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	beleg, err := protocol.ParseBelegung(liegen)
	if err != nil {
		t.Fatal(err)
	}
	if beleg.Generation != 2 || beleg.Instanz != fill(0x77) || beleg.Hash != zu.Hash {
		t.Fatalf("generation %d instanz %x", beleg.Generation, beleg.Instanz)
	}
}

type torZiel struct {
	*Platte
	mu   sync.Mutex
	ops  []string
	once sync.Once
	rein chan struct{}
	los  chan struct{}
}

func neuesTor(t *testing.T) *torZiel {
	t.Helper()
	p := platte(t)
	return &torZiel{Platte: p, rein: make(chan struct{}), los: make(chan struct{})}
}

func (z *torZiel) Schreiben(schluessel string, inhalt []byte) error {
	if !strings.HasPrefix(schluessel, "instanz/") {
		z.once.Do(func() {
			close(z.rein)
			<-z.los
		})
	}
	z.mu.Lock()
	z.ops = append(z.ops, schluessel)
	z.mu.Unlock()
	return z.Platte.Schreiben(schluessel, inhalt)
}

func (z *torZiel) schritte() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.ops...)
}

func starten(t *testing.T, ziel Ziel, s Schwellen, jetzt time.Time) *Prozess {
	t.Helper()
	return startenUhr(t, ziel, s, func() time.Time { return jetzt })
}

func startenUhr(t *testing.T, ziel Ziel, s Schwellen, jetzt func() time.Time) *Prozess {
	t.Helper()
	return startenMit(t, ziel, t.TempDir(), s, jetzt)
}

func startenMit(t *testing.T, ziel Ziel, spool string, s Schwellen, jetzt func() time.Time) *Prozess {
	t.Helper()
	key := schluessel(t)
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	schl := Schluessel{Pub: &key.PublicKey, Finger: finger}
	p, err := Start(Konfig{
		Instanz:   fill(0x77),
		Schwellen: s,
		Spool:     spool,
		Ziel:      ziel,
		Plattform: schl,
		Index:     schl,
		Bestand:   festBestand{lage: testLage(t)},
		Signatur: func(payload []byte) (protocol.Signature, error) {
			return crypt.SignP256(key, payload)
		},
		Jetzt: jetzt,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.Beenden(ctx)
	})
	return p
}

func testSchwellen(warte time.Duration) Schwellen {
	s := Voreinstellung()
	s.Puffer = 64 << 10
	s.PufferWarte = warte
	s.Segment = protocol.Segment256KiB
	s.SegmentWarte = 10 * time.Second
	s.Klasse = protocol.Segment256KiB
	s.Gruppe = 15 * time.Minute
	s.Einzel = 8 * time.Hour
	s.Sonstige = 15 * time.Minute
	s.SpoolGrenze = 16 << 20
	s.Frist = 2 * time.Minute
	return s
}

func platte(t *testing.T) *Platte {
	t.Helper()
	p, err := OeffnenPlatte(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type festBestand struct{ lage Lage }

func (f festBestand) Mandant(protocol.ID) (Lage, error) { return f.lage, nil }

func (f festBestand) Mandanten() ([]protocol.ID, error) { return nil, nil }

func testLage(t *testing.T) Lage {
	t.Helper()
	key := schluessel(t)
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mandant := fill(0x11)
	return Lage{
		KEKVorhanden: true,
		KEK:          Schluessel{Pub: &key.PublicKey, Finger: finger},
		Register: memReg{
			"Ada": person(t, key, mandant, "Ada"),
		},
		Pruef:       &key.PublicKey,
		Verzeichnis: fill(0x33),
		Vorgang:     fill(0x44),
		Auffang:     fill(0x55),
		Einzel:      fill(0x66),
		Rahmen:      256,
	}
}

func ereignis(id protocol.ID, gross bool) strom.Ereignis {
	text := []byte("text")
	if gross {
		text = bytes.Repeat([]byte("a"), 80_000)
	}
	return strom.Ereignis{
		ID: id, Zeit: 1_500, Mandant: fill(0x11),
		Personen: []string{"Ada"}, Vorgang: "V-1", Text: text,
	}
}

func person(t *testing.T, key *ecdsa.PrivateKey, mandant protocol.ID, name string) strom.Eintrag {
	t.Helper()
	a := protocol.Aussage{Mandant: mandant, Person: name, Rolle: protocol.RollePerson, Von: 1_000, Bis: 2_000}
	raw, err := protocol.AussageBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	return strom.Eintrag{
		Merkmal: protocol.MerkmalGruppe, Ablage: fill(0x22), Bind: fill(0x22), Kohorte: "Nord",
		Rolle: protocol.RollePerson, Von: 1_000, Bis: 2_000, Signatur: sig[:],
	}
}

type memReg map[string]strom.Eintrag

func (m memReg) Person(name string) (strom.Eintrag, bool, error) {
	e, ok := m[name]
	return e, ok, nil
}

func schluessel(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fill(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func spoolHatFolge(t *testing.T, dir string) bool {
	t.Helper()
	eintraege, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range eintraege {
		if _, ok := seqName(e.Name()); ok {
			return true
		}
	}
	return false
}

func annahmePfad(p *Prozess) string {
	return "annahme/" + p.instanz.Hex() + "/1"
}

func reihenfolge(keys []string) bool {
	phase := 0
	gesehen := false
	for _, key := range keys {
		if strings.HasPrefix(key, "instanz/") {
			continue
		}
		gesehen = true
		switch {
		case strings.HasPrefix(key, "belegt/"):
			if phase > 0 {
				return false
			}
		case strings.HasPrefix(key, "vorbereitung/"):
			if phase > 1 {
				return false
			}
			phase = 1
		case strings.HasPrefix(key, "annahme/"):
			phase = 3
		default:
			if phase > 2 {
				return false
			}
			phase = 2
		}
	}
	return gesehen && phase == 3
}

func rasterVon(t *testing.T, ziel *Platte, best Bestaetigung) string {
	t.Helper()
	nutz, err := annahme(ziel, best.Schluessel)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range nutz.Segmente {
		_, _, epoch, _, err := protocol.ParseObjektSchluessel(seg.ObjectKey)
		if err != nil {
			t.Fatal(err)
		}
		return epoch.Raster()
	}
	t.Fatal("kein segment")
	return ""
}

func annahmeKette(t *testing.T, ziel *Platte, instanz protocol.ID) (uint64, protocol.Hash) {
	t.Helper()
	keys, err := ziel.Liste("annahme/" + instanz.Hex() + "/")
	if err != nil || len(keys) == 0 {
		t.Fatalf("annahmen %v %v", keys, err)
	}
	type glied struct {
		seq      uint64
		hash     protocol.Hash
		previous protocol.Hash
	}
	alle := make([]glied, 0, len(keys))
	for _, key := range keys {
		raw, ok, err := ziel.Lesen(key)
		if err != nil || !ok {
			t.Fatalf("%s %v", key, err)
		}
		nutz, err := protocol.ParseAnnahme(raw)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := protocol.AnnahmeHash(raw)
		if err != nil {
			t.Fatal(err)
		}
		alle = append(alle, glied{seq: nutz.BatchSeq, hash: sum, previous: nutz.Previous})
	}
	sort.Slice(alle, func(i, j int) bool { return alle[i].seq < alle[j].seq })
	prev := protocol.AnnahmeGenesis(instanz)
	for i, g := range alle {
		if g.seq != uint64(i+1) || g.previous != prev {
			t.Fatalf("kette seq %d", g.seq)
		}
		prev = g.hash
	}
	return alle[len(alle)-1].seq, prev
}

func TestAbgeloestBleibtImRaster(t *testing.T) {
	ziel := platte(t)
	alt := schluessel(t)
	neu := schluessel(t)
	altF, err := crypt.FingerprintSPKI(&alt.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	neuF, err := crypt.FingerprintSPKI(&neu.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	w := &wechsel{lage: lageMit(t, alt)}
	p := startenBestand(t, ziel, w, alt)
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x71), false)); err != nil {
		t.Fatal(err)
	}
	w.setzen(Schluessel{Pub: &neu.PublicKey, Finger: neuF}, true, map[protocol.Hash]SchluesselStatus{
		altF: SchluesselAbgeloest,
	})
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x72), false)); err != nil {
		t.Fatal(err)
	}
	finger := segmentFinger(t, ziel)
	if len(finger) == 0 {
		t.Fatal("keine segmente")
	}
	altGesehen := false
	for _, f := range finger {
		if f == neuF {
			t.Fatal("nachfolger wickelt vor dem raster")
		}
		if f == altF {
			altGesehen = true
		}
	}
	if !altGesehen {
		t.Fatal("abgelöster schlüssel fehlt")
	}
}

func TestVerlorenNimmtKeineWeiterenEintraege(t *testing.T) {
	ziel := platte(t)
	alt := schluessel(t)
	altF, err := crypt.FingerprintSPKI(&alt.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	w := &wechsel{lage: lageMit(t, alt)}
	p := startenBestand(t, ziel, w, alt)
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x73), false)); err != nil {
		t.Fatal(err)
	}
	w.setzen(Schluessel{}, false, map[protocol.Hash]SchluesselStatus{altF: SchluesselVerloren})
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x74), false)); err != nil {
		t.Fatal(err)
	}
}

func TestAusCacheLeer(t *testing.T) {
	grund := festBestand{lage: testLage(t)}
	lage, err := AusCache(nil, grund).Mandant(fill(0x11))
	if err != nil || !lage.KEKVorhanden || lage.Register == nil {
		t.Fatalf("%+v %v", lage.KEKVorhanden, err)
	}
}

type wechsel struct {
	mu   sync.Mutex
	lage Lage
}

func (w *wechsel) Mandanten() ([]protocol.ID, error) { return nil, nil }

func (w *wechsel) Mandant(protocol.ID) (Lage, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	lage := w.lage
	if w.lage.Status != nil {
		lage.Status = map[protocol.Hash]SchluesselStatus{}
		for k, v := range w.lage.Status {
			lage.Status[k] = v
		}
	}
	return lage, nil
}

func (w *wechsel) setzen(kek Schluessel, vorhanden bool, status map[protocol.Hash]SchluesselStatus) {
	w.mu.Lock()
	w.lage.KEK = kek
	w.lage.KEKVorhanden = vorhanden
	w.lage.Status = status
	w.mu.Unlock()
}

func lageMit(t *testing.T, key *ecdsa.PrivateKey) Lage {
	t.Helper()
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mandant := fill(0x11)
	return Lage{
		KEKVorhanden: true,
		KEK:          Schluessel{Pub: &key.PublicKey, Finger: finger},
		Register:     memReg{"Ada": person(t, key, mandant, "Ada")},
		Pruef:        &key.PublicKey,
		Verzeichnis:  fill(0x33),
		Vorgang:      fill(0x44),
		Auffang:      fill(0x55),
		Einzel:       fill(0x66),
		Rahmen:       256,
	}
}

func startenBestand(t *testing.T, ziel Ziel, bestand Bestand, signKey *ecdsa.PrivateKey) *Prozess {
	t.Helper()
	finger, err := crypt.FingerprintSPKI(&signKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	schl := Schluessel{Pub: &signKey.PublicKey, Finger: finger}
	p, err := Start(Konfig{
		Instanz: fill(0x77), Schwellen: testSchwellen(20 * time.Millisecond), Spool: t.TempDir(),
		Ziel: ziel, Plattform: schl, Index: schl, Bestand: bestand,
		Signatur: func(payload []byte) (protocol.Signature, error) {
			return crypt.SignP256(signKey, payload)
		},
		Jetzt: func() time.Time { return time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.Beenden(ctx)
	})
	return p
}

func segmentFinger(t *testing.T, ziel *Platte) []protocol.Hash {
	t.Helper()
	keys, err := ziel.Liste("")
	if err != nil {
		t.Fatal(err)
	}
	var out []protocol.Hash
	for _, key := range keys {
		_, _, _, nr, err := protocol.ParseObjektSchluessel(key)
		if err != nil || nr != 1 {
			continue
		}
		raw, ok, err := ziel.Lesen(key)
		if err != nil || !ok {
			t.Fatal(err)
		}
		kek, _, _, _, err := protocol.ParseKopf(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, kek)
	}
	return out
}

func annahme(ziel interface {
	Lesen(string) ([]byte, bool, error)
}, key string) (protocol.Nutzlast, error) {
	raw, ok, err := ziel.Lesen(key)
	if err != nil || !ok {
		return protocol.Nutzlast{}, os.ErrNotExist
	}
	return protocol.ParseAnnahme(raw)
}
