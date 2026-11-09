package schreiben

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestDeckFuelltLeereRaster(t *testing.T) {
	uhr := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	key := schluessel(t)
	ziel := platte(t)
	lage := deckLage(t, key, uhr)
	p := startenDeck(t, ziel, lage, key, func() time.Time { return uhr })
	uhr = uhr.Add(15 * time.Minute)
	if err := p.Beenden(context.Background()); err != nil {
		t.Fatal(err)
	}
	raster := []string{"20261108T140000Z", "20261108T141500Z"}
	for _, ablage := range []protocol.ID{fill(0x22), fill(0x55), fill(0x66)} {
		if got := epochenJeRaster(t, ziel, ablage); !gleicheRaster(got, raster) {
			t.Fatalf("ablage %s raster %v", ablage.Hex(), rasterNamen(got))
		}
	}
	if belegt := schluesselMit(t, ziel, "belegt/"); len(belegt) != 0 {
		t.Fatalf("belegungen %v", belegt)
	}
	for _, nutz := range annahmen(t, ziel, p.instanz) {
		if len(nutz.Slots) != 8 {
			t.Fatalf("plätze %d", len(nutz.Slots))
		}
		eintraege := bindungEintraege(t, key, nutz)
		if len(eintraege) == 0 {
			t.Fatal("blob leer")
		}
		for _, e := range eintraege {
			if e.Art != protocol.ArtFuellung {
				t.Fatalf("art %d", e.Art)
			}
		}
	}
	for _, seg := range segmenteVon(t, ziel) {
		if art := ersteArt(t, key, seg.key, seg.bytes); art != protocol.ArtFuellung {
			t.Fatalf("rahmen %d", art)
		}
	}
	text := p.metrikText()
	hex := fill(0x11).Hex()
	if strings.Contains(text, `cryptlog_events_accepted_total{mandant_id="`+hex) {
		t.Fatalf("mengenmetrik\n%s", text)
	}
	if strings.Contains(text, `cryptlog_epochs_open{mandant_id="`+hex) {
		t.Fatalf("offene epochen\n%s", text)
	}
	if !strings.Contains(text, `cryptlog_cache_age_seconds{mandant_id="`+hex+`"} 900`) {
		t.Fatalf("cache\n%s", text)
	}
}

func TestDeckErsetztKeineEreignisepoche(t *testing.T) {
	uhr := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	key := schluessel(t)
	ziel := platte(t)
	lage := deckLage(t, key, uhr)
	lage.Register = memReg{"Ada": person(t, key, fill(0x11), "Ada")}
	p := startenDeck(t, ziel, lage, key, func() time.Time { return uhr })
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x42), false)); err != nil {
		t.Fatal(err)
	}
	if err := p.Beenden(context.Background()); err != nil {
		t.Fatal(err)
	}
	gruppe := epochenJeRaster(t, ziel, fill(0x22))
	if len(gruppe) != 1 || gruppe["20261108T140000Z"] != 2 {
		t.Fatalf("gruppe %v", rasterNamen(gruppe))
	}
	for _, ablage := range []protocol.ID{fill(0x55), fill(0x66)} {
		got := epochenJeRaster(t, ziel, ablage)
		if len(got) != 1 || got["20261108T140000Z"] != 1 {
			t.Fatalf("ablage %s %v", ablage.Hex(), rasterNamen(got))
		}
	}
	var ereignisGesehen bool
	for _, nutz := range annahmen(t, ziel, p.instanz) {
		if !annahmeTrifft(nutz, fill(0x22)) {
			continue
		}
		for _, e := range bindungEintraege(t, key, nutz) {
			if e.Art == protocol.ArtEreignis {
				ereignisGesehen = true
			}
		}
	}
	if !ereignisGesehen {
		t.Fatal("ereignis fehlt im blob")
	}
	text := p.metrikText()
	if strings.Contains(text, `cryptlog_events_accepted_total{mandant_id="`+fill(0x11).Hex()) {
		t.Fatalf("mengenmetrik\n%s", text)
	}
}

func TestDeckEinzelStehtDaneben(t *testing.T) {
	uhr := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	key := schluessel(t)
	ziel := platte(t)
	lage := deckLage(t, key, uhr)
	eintrag := person(t, key, fill(0x11), "Ada")
	eintrag.Merkmal = protocol.MerkmalEinzeln
	eintrag.Ablage = fill(0x66)
	eintrag.Bind = fill(0x67)
	eintrag.Kohorte = ""
	lage.Register = memReg{"Ada": eintrag}
	p := startenDeck(t, ziel, lage, key, func() time.Time { return uhr })
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x43), false)); err != nil {
		t.Fatal(err)
	}
	if err := p.Beenden(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(epochKennungen(t, ziel, fill(0x66))); n != 2 {
		t.Fatalf("epochen am präfix %d", n)
	}
}

func TestDeckAusSchreibtKeineFuellung(t *testing.T) {
	uhr := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	key := schluessel(t)
	ziel := platte(t)
	lage := deckLage(t, key, uhr)
	lage.Deck = false
	p := startenDeck(t, ziel, lage, key, func() time.Time { return uhr })
	if err := p.Beenden(context.Background()); err != nil {
		t.Fatal(err)
	}
	if segs := segmenteVon(t, ziel); len(segs) != 0 {
		t.Fatalf("segmente %d", len(segs))
	}
}

type deckBestand struct {
	id   protocol.ID
	lage Lage
}

func (b deckBestand) Mandant(id protocol.ID) (Lage, error) {
	if id != b.id {
		return Lage{}, ErrKonfig
	}
	return b.lage, nil
}

func (b deckBestand) Mandanten() ([]protocol.ID, error) { return []protocol.ID{b.id}, nil }

func deckLage(t *testing.T, key *ecdsa.PrivateKey, seit time.Time) Lage {
	t.Helper()
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Lage{
		KEKVorhanden: true,
		KEK:          Schluessel{Pub: &key.PublicKey, Finger: finger},
		Pruef:        &key.PublicKey,
		Verzeichnis:  fill(0x33),
		Vorgang:      fill(0x44),
		Auffang:      fill(0x55),
		Einzel:       fill(0x66),
		Rahmen:       256,
		Deck:         true,
		CacheSeit:    seit,
		Stand: protocol.Stand{Kennungen: []protocol.Kennung{{
			Rolle: protocol.RolleGruppe, Ablage: fill(0x22), Bind: fill(0x22), Kohorte: "Nord", Aktiv: protocol.KennungAn,
		}}},
	}
}

func startenDeck(t *testing.T, ziel *Platte, lage Lage, key *ecdsa.PrivateKey, jetzt func() time.Time) *Prozess {
	t.Helper()
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	schl := Schluessel{Pub: &key.PublicKey, Finger: finger}
	schwellen := testSchwellen(20 * time.Millisecond)
	schwellen.Einzel = 15 * time.Minute
	p, err := Start(Konfig{
		Instanz: fill(0x77), Schwellen: schwellen, Spool: t.TempDir(),
		Ziel: ziel, Plattform: schl, Index: schl,
		Bestand: deckBestand{id: fill(0x11), lage: lage},
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

type segmentObjekt struct {
	key   string
	bytes []byte
}

func segmenteVon(t *testing.T, ziel *Platte) []segmentObjekt {
	t.Helper()
	keys, err := ziel.Liste("")
	if err != nil {
		t.Fatal(err)
	}
	var out []segmentObjekt
	for _, key := range keys {
		if _, _, _, _, err := protocol.ParseObjektSchluessel(key); err != nil {
			continue
		}
		raw, ok, err := ziel.Lesen(key)
		if err != nil || !ok {
			t.Fatal(err)
		}
		if len(raw) != protocol.Segment256KiB {
			t.Fatalf("klasse %d %s", len(raw), key)
		}
		out = append(out, segmentObjekt{key: key, bytes: raw})
	}
	return out
}

func epochKennungen(t *testing.T, ziel *Platte, ablage protocol.ID) map[protocol.EpochID]struct{} {
	t.Helper()
	out := map[protocol.EpochID]struct{}{}
	for _, seg := range segmenteVon(t, ziel) {
		_, got, epoch, _, err := protocol.ParseObjektSchluessel(seg.key)
		if err != nil || got != ablage {
			continue
		}
		out[epoch] = struct{}{}
	}
	return out
}

func epochenJeRaster(t *testing.T, ziel *Platte, ablage protocol.ID) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, seg := range segmenteVon(t, ziel) {
		_, got, epoch, _, err := protocol.ParseObjektSchluessel(seg.key)
		if err != nil || got != ablage {
			continue
		}
		out[epoch.Raster()]++
	}
	return out
}

func gleicheRaster(got map[string]int, raster []string) bool {
	if len(got) != len(raster) {
		return false
	}
	for _, name := range raster {
		if got[name] != 1 {
			return false
		}
	}
	return true
}

func rasterNamen(got map[string]int) []string {
	out := make([]string, 0, len(got))
	for name, n := range got {
		out = append(out, name+"="+strconv.Itoa(n))
	}
	return out
}

func schluesselMit(t *testing.T, ziel *Platte, prefix string) []string {
	t.Helper()
	keys, err := ziel.Liste(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func annahmen(t *testing.T, ziel *Platte, instanz protocol.ID) []protocol.Nutzlast {
	t.Helper()
	var out []protocol.Nutzlast
	for seq := uint64(1); ; seq++ {
		key, err := protocol.AnnahmeSchluessel(instanz, seq)
		if err != nil {
			t.Fatal(err)
		}
		nutz, err := annahme(ziel, key)
		if err != nil {
			break
		}
		out = append(out, nutz)
	}
	if len(out) == 0 {
		t.Fatal("keine annahme")
	}
	return out
}

func annahmeTrifft(nutz protocol.Nutzlast, ablage protocol.ID) bool {
	for _, seg := range nutz.Segmente {
		_, got, _, _, err := protocol.ParseObjektSchluessel(seg.ObjectKey)
		if err == nil && got == ablage {
			return true
		}
	}
	return false
}

func bindungEintraege(t *testing.T, key *ecdsa.PrivateKey, nutz protocol.Nutzlast) []protocol.SeqEintrag {
	t.Helper()
	var out []protocol.SeqEintrag
	for _, blob := range nutz.Bloecke {
		klar, err := crypt.OpenBindung(key, nutz.Batch, blob.WrappedKey, blob.Nonce, blob.Ciphertext, blob.Tag,
			protocol.BindungContext(blob.Mandant, nutz.Batch, fingerVon(t, key)),
			protocol.BindungAAD(blob.Mandant, nutz.Batch, fingerVon(t, key)))
		if err != nil {
			t.Fatal(err)
		}
		_, eintraege, err := protocol.ParseBindung(klar)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, eintraege...)
	}
	return out
}

func fingerVon(t *testing.T, key *ecdsa.PrivateKey) protocol.Hash {
	t.Helper()
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return finger
}

func ersteArt(t *testing.T, key *ecdsa.PrivateKey, schluessel string, seg []byte) protocol.Art {
	t.Helper()
	mandant, ablage, epoch, _, err := protocol.ParseObjektSchluessel(schluessel)
	if err != nil {
		t.Fatal(err)
	}
	kek, dekID, wrapped, _, err := protocol.ParseKopf(seg)
	if err != nil {
		t.Fatal(err)
	}
	dek, _, err := crypt.UnwrapDEK(key, wrapped, protocol.WrapContext(mandant, ablage, epoch, kek))
	if err != nil {
		t.Fatal(err)
	}
	defer dek.Wipe()
	_, kette, _, err := protocol.Zerlegen(seg, 256, true, true)
	if err != nil || len(kette) == 0 {
		t.Fatalf("zerlegen %v", err)
	}
	fr := kette[0]
	var nonce protocol.Nonce
	copy(nonce[:], fr[:protocol.NonceLen])
	seq := binary.BigEndian.Uint64(nonce[protocol.PrefixLen:])
	plain, err := crypt.Open(dek, nonce, fr[protocol.NonceLen:len(fr)-protocol.TagLen], fr[len(fr)-protocol.TagLen:], protocol.AAD(mandant, ablage, epoch, dekID, seq))
	if err != nil || len(plain) == 0 {
		t.Fatalf("offen %v", err)
	}
	return protocol.Art(plain[0])
}
