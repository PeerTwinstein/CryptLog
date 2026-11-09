package abschluss_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"cryptlog/abschluss"
	"cryptlog/protocol"
)

func testAbschluss(t *testing.T) (abschluss.Eintrag, []byte) {
	t.Helper()
	instanz, batch := fill(0x22), fill(0x0b)
	ev := protocol.Slot{Event: fill(0x11), Hash: protocol.Hash{0x44}}
	slots := make([]protocol.Slot, 8)
	slots[0] = ev
	for i := 1; i < 8; i++ {
		slots[i].Event = fill(byte(0x30 + i))
		slots[i].Hash[0] = byte(i)
	}
	seg := []byte("segment-bytes")
	ref := protocol.SegmentRef{ObjectKey: "strom/1", Hash: protocol.SegmentHash(seg)}
	var nonce protocol.Nonce
	nonce[0] = 3
	blobs := []protocol.Blob{{
		Mandant:    fill(0x01),
		WrappedKey: []byte{0xee},
		Nonce:      nonce,
		Tag:        bytes.Repeat([]byte{0x7e}, protocol.TagLen),
	}}
	previous := protocol.AnnahmeGenesis(instanz)
	ann, err := protocol.AnnahmePayload(batch, instanz, 1, previous, slots, []protocol.SegmentRef{ref}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	vor, err := protocol.VorbereitungPayload(batch, instanz, 1, slots, []protocol.SegmentRef{ref}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	beleg, err := protocol.BelegungBytes(protocol.Belegung{
		Event: ev.Event, Instanz: instanz, Batch: batch, Generation: 1, Lage: protocol.LageOffen, Hash: ev.Hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return abschluss.Eintrag{
		Instanz:      instanz,
		BatchSeq:     1,
		Annahme:      ann,
		Vorbereitung: vor,
		Belegungen:   [][]byte{beleg},
		Segmente:     []abschluss.Segmentobjekt{{Schluessel: ref.ObjectKey, Bytes: seg}},
	}, seg
}

func TestSpoolBytes(t *testing.T) {
	ein, _ := testAbschluss(t)
	raw, err := abschluss.Encode(ein)
	if err != nil {
		t.Fatal(err)
	}
	want := append(text("spool"), ein.Instanz[:]...)
	want = append(want, be64(1)...)
	if !bytes.HasPrefix(raw, want) {
		t.Fatalf("anfang %x", raw[:len(want)])
	}
	back, err := abschluss.Decode(raw)
	if err != nil || back.Instanz != ein.Instanz || back.BatchSeq != 1 || !bytes.Equal(back.Annahme, ein.Annahme) || !bytes.Equal(back.Segmente[0].Bytes, ein.Segmente[0].Bytes) {
		t.Fatalf("decode %v", err)
	}
	spool, err := abschluss.NeuSpool(len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Festhalten(ein); err != nil {
		t.Fatal(err)
	}
	if err := spool.Festhalten(ein); err != nil {
		t.Fatalf("dieselben bytes %v", err)
	}
	klein, err := abschluss.NeuSpool(len(raw) - 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := klein.Festhalten(ein); !errors.Is(err, abschluss.ErrGrenze) {
		t.Fatalf("grenze %v", err)
	}
	ein2 := ein
	ein2.BatchSeq = 2
	ann, err := protocol.ParseAnnahme(ein.Annahme)
	if err != nil {
		t.Fatal(err)
	}
	ein2.Annahme, err = protocol.AnnahmePayload(ann.Batch, ann.Instanz, 2, protocol.Hash{1}, ann.Slots, ann.Segmente, ann.Bloecke)
	if err != nil {
		t.Fatal(err)
	}
	ein2.Vorbereitung, err = protocol.VorbereitungPayload(ann.Batch, ann.Instanz, 2, ann.Slots, ann.Segmente, ann.Bloecke)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Festhalten(ein2); !errors.Is(err, abschluss.ErrGrenze) {
		t.Fatalf("zweiter %v", err)
	}
}

func TestFortsetzen(t *testing.T) {
	ein, seg := testAbschluss(t)
	raw, err := abschluss.Encode(ein)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := abschluss.NeuSpool(len(raw) * 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Festhalten(ein); err != nil {
		t.Fatal(err)
	}
	ziel := &abschluss.Speicher{}
	befund, err := spool.Fortsetzen(ziel, ein.Instanz, 1)
	if err != nil || befund != abschluss.BefundAngenommen {
		t.Fatalf("fortsetzen %v %v", befund, err)
	}
	if _, ok := spool.Hash(ein.Instanz, 1); !ok {
		t.Fatal("hash fehlt")
	}
	noch, err := spool.Fortsetzen(ziel, ein.Instanz, 1)
	if err != nil || noch != abschluss.BefundLeer {
		t.Fatalf("spool leer %v %v", noch, err)
	}
	if liegen, ok, _ := ziel.Lesen(ein.Segmente[0].Schluessel); !ok || !bytes.Equal(liegen, seg) {
		t.Fatal("segment")
	}
	if err := spool.Abdecken(ein.Instanz, 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := spool.Hash(ein.Instanz, 1); ok {
		t.Fatal("hash bleibt")
	}
	if err := spool.Abdecken(ein.Instanz, 0, 0); err != nil {
		t.Fatal(err)
	}

	spool, _ = abschluss.NeuSpool(len(raw) * 2)
	_ = spool.Festhalten(ein)
	fremd := &abschluss.Speicher{}
	_ = fremd.Schreiben(annahmeKey(t, ein.Instanz, 1), []byte("andere-annahme"))
	befund, err = spool.Fortsetzen(fremd, ein.Instanz, 1)
	if err != nil || befund != abschluss.BefundKonflikt {
		t.Fatalf("fremde annahme %v %v", befund, err)
	}
	liegen, _, _ := fremd.Lesen(annahmeKey(t, ein.Instanz, 1))
	if string(liegen) != "andere-annahme" {
		t.Fatal("ersetzt")
	}

	kaputt := &abschluss.Speicher{}
	_ = kaputt.Schreiben(annahmeKey(t, ein.Instanz, 1), ein.Annahme)
	_ = kaputt.Schreiben(ein.Segmente[0].Schluessel, []byte("falsch"))
	befund, err = spool.Fortsetzen(kaputt, ein.Instanz, 1)
	if err != nil || befund != abschluss.BefundBeschaedigt {
		t.Fatalf("beschädigt %v %v", befund, err)
	}
	liegen, _, _ = kaputt.Lesen(ein.Segmente[0].Schluessel)
	if string(liegen) != "falsch" {
		t.Fatal("segment ersetzt")
	}

	verfallen := &abschluss.Speicher{}
	alt, _ := protocol.ParseBelegung(ein.Belegungen[0])
	neu, err := alt.Nachfolger(fill(0x99), fill(0x77))
	if err != nil {
		t.Fatal(err)
	}
	rawNeu, err := protocol.BelegungBytes(neu)
	if err != nil {
		t.Fatal(err)
	}
	_ = verfallen.Schreiben(protocol.BelegungSchluessel(alt.Event), rawNeu)
	befund, err = spool.Fortsetzen(verfallen, ein.Instanz, 1)
	if err != nil || befund != abschluss.BefundVerfallen {
		t.Fatalf("verfallen %v %v", befund, err)
	}
	if _, ok, _ := verfallen.Lesen(annahmeKey(t, ein.Instanz, 1)); ok {
		t.Fatal("annahme trotz generation")
	}
}

func TestFremdeAnnahme(t *testing.T) {
	ein, seg := testAbschluss(t)
	ziel := &abschluss.Speicher{}
	b, err := protocol.ParseBelegung(ein.Belegungen[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = ziel.Schreiben(protocol.BelegungSchluessel(b.Event), ein.Belegungen[0])
	vorKey, err := protocol.VorbereitungSchluessel(ein.Instanz, 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = ziel.Schreiben(vorKey, ein.Vorbereitung)
	_ = ziel.Schreiben(ein.Segmente[0].Schluessel, seg)
	if err := abschluss.FristSetzen(ziel, ein.Instanz, 100); err != nil {
		t.Fatal(err)
	}
	befund, err := abschluss.FremdeAnnahme(ziel, ein.Instanz, 1, 50)
	if err != nil || befund != abschluss.BefundUnvollstaendig {
		t.Fatalf("frist läuft %v %v", befund, err)
	}
	if _, ok, _ := ziel.Lesen(annahmeKey(t, ein.Instanz, 1)); ok {
		t.Fatal("annahme zu früh")
	}
	befund, err = abschluss.FremdeAnnahme(ziel, ein.Instanz, 1, 100)
	if err != nil || befund != abschluss.BefundAngenommen {
		t.Fatalf("übernahme %v %v", befund, err)
	}
	liegen, ok, err := ziel.Lesen(annahmeKey(t, ein.Instanz, 1))
	if err != nil || !ok || !bytes.Equal(liegen, ein.Annahme) {
		t.Fatal("annahme bytes")
	}
	befund, err = abschluss.Erkennen(ziel, ein.Instanz, 1)
	if err != nil || befund != abschluss.BefundAngenommen {
		t.Fatalf("erkennen %v %v", befund, err)
	}

	luecke := &abschluss.Speicher{}
	ann, err := protocol.ParseAnnahme(ein.Annahme)
	if err != nil {
		t.Fatal(err)
	}
	vor2, err := protocol.VorbereitungPayload(ann.Batch, ann.Instanz, 2, ann.Slots, ann.Segmente, ann.Bloecke)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := protocol.VorbereitungSchluessel(ein.Instanz, 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = luecke.Schreiben(key2, vor2)
	_ = luecke.Schreiben(ein.Segmente[0].Schluessel, seg)
	if _, err := abschluss.FremdeAnnahme(luecke, ein.Instanz, 2, 1); !errors.Is(err, abschluss.ErrLuecke) {
		t.Fatalf("lücke %v", err)
	}
}

func TestPraefix(t *testing.T) {
	mandant, ablage := fill(0x11), fill(0x22)
	var prefix protocol.Prefix
	prefix[0] = 0xab
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 6, 16, 0, 0, 0, time.UTC), fill(0x44), prefix)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for nr := uint64(1); nr <= 3; nr++ {
		key, err := protocol.ObjektSchluessel(mandant, ablage, epoch, nr)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	got, err := abschluss.AngenommenesPraefix(keys, map[string]bool{keys[0]: true, keys[1]: true})
	if err != nil || len(got) != 2 || got[0] != keys[0] || got[1] != keys[1] {
		t.Fatalf("präfix %v %v", got, err)
	}
	if _, err := abschluss.AngenommenesPraefix(keys, map[string]bool{keys[0]: true, keys[2]: true}); !errors.Is(err, abschluss.ErrLuecke) {
		t.Fatalf("lücke %v", err)
	}
	if got, err := abschluss.AngenommenesPraefix(keys, map[string]bool{}); err != nil || got != nil {
		t.Fatalf("leer %v %v", got, err)
	}
}

func annahmeKey(t *testing.T, instanz protocol.ID, seq uint64) string {
	t.Helper()
	key, err := protocol.AnnahmeSchluessel(instanz, seq)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func text(s string) []byte {
	return append(be64u32(uint32(len(s))), []byte(s)...)
}

func be64u32(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func be64(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b[:]
}
