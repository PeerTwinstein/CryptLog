package schreiben

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestEreignisportUndMetrik(t *testing.T) {
	p := starten(t, platte(t), testSchwellen(20*time.Millisecond), time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC))
	ereignisSrv := httptest.NewServer(p.Ereignisport())
	defer ereignisSrv.Close()
	metrikSrv := httptest.NewServer(p.Metrik())
	defer metrikSrv.Close()

	if code := holen(t, metrikSrv.URL+"/ready"); code != http.StatusOK {
		t.Fatalf("ready %d", code)
	}
	if code := holen(t, metrikSrv.URL+"/live"); code != http.StatusOK {
		t.Fatalf("live %d", code)
	}
	if code := holen(t, ereignisSrv.URL+"/metrics"); code != http.StatusNotFound {
		t.Fatalf("ereignisport metrik %d", code)
	}
	if code := senden(t, metrikSrv.URL+"/ereignis", []byte("nein")); code != http.StatusNotFound {
		t.Fatalf("metrikport ereignis %d", code)
	}
	if code := senden(t, ereignisSrv.URL+"/ereignis", []byte("nein")); code != http.StatusBadRequest {
		t.Fatalf("format %d", code)
	}

	ev := ereignis(fill(0x42), false)
	raw, err := protocol.EreignisBytes(protocol.EreignisAufruf{
		ID: ev.ID, Mandant: ev.Mandant, Zeit: ev.Zeit, Vorgang: ev.Vorgang, Personen: ev.Personen, Text: ev.Text,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(ereignisSrv.URL+"/ereignis", "application/octet-stream", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("annahme %d %s", res.StatusCode, body)
	}
	best, err := protocol.ParseBestaetigt(body)
	if err != nil || best.Event != ev.ID || best.Seq == 0 || best.Schluessel == "" {
		t.Fatalf("%v %+v", err, best)
	}
	text := string(holenText(t, metrikSrv.URL+"/metrics"))
	for _, teil := range []string{
		"cryptlog_ready 1\n",
		"cryptlog_events_unaccepted_total{grund=\"belegung\"} 0\n",
		"cryptlog_events_accepted_total{mandant_id=\"" + ev.Mandant.Hex() + "\",rolle=\"gruppe\"} 1\n",
		"cryptlog_epochs_open{mandant_id=\"" + ev.Mandant.Hex() + "\",rolle=\"gruppe\"} ",
		"go_goroutines ",
		"process_start_time_seconds ",
		"# TYPE cryptlog_accept_seconds histogram\n",
	} {
		if !strings.Contains(text, teil) {
			t.Fatalf("fehlt %s\n%s", teil, text)
		}
	}
	if strings.Contains(text, ev.Vorgang) || strings.Contains(text, "Ada") {
		t.Fatal("metrik nennt person oder vorgang")
	}
}

func TestKatalogUndLoeschlauf(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	uhr := jetzt
	ziel := platte(t)
	schwellen := testSchwellen(20 * time.Millisecond)
	vermerk, err := bestaetigung.Oeffnen(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lage := testLage(t)
	katalog := fill(0x88)
	lage.Katalog = katalog
	lage.Stand = protocol.Stand{
		Name: "Mandant",
		Kennungen: []protocol.Kennung{
			{Rolle: protocol.RolleGruppe, Ablage: fill(0x22), Bind: fill(0x22), Kohorte: "Nord", Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleVerzeichnis, Ablage: lage.Verzeichnis, Bind: lage.Verzeichnis, Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleVorgang, Ablage: lage.Vorgang, Bind: lage.Vorgang, Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleAuffang, Ablage: lage.Auffang, Bind: lage.Auffang, Aktiv: protocol.KennungAn},
			{Rolle: protocol.RolleKatalog, Ablage: katalog, Bind: katalog, Aktiv: protocol.KennungAn},
		},
	}
	key := schluessel(t)
	finger, err := crypt.FingerprintSPKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	schl := Schluessel{Pub: &key.PublicKey, Finger: finger}
	spool := t.TempDir()
	p, err := Start(Konfig{
		Instanz: fill(0x77), Schwellen: schwellen, Spool: spool, Ziel: ziel,
		Plattform: schl, Index: schl, Bestand: festBestand{lage: lage},
		Signatur: func(payload []byte) (protocol.Signature, error) {
			return crypt.SignP256(key, payload)
		},
		Jetzt:        func() time.Time { return uhr },
		Loeschzeit:   time.Hour,
		Aufbewahrung: 24 * time.Hour,
		Vermerk:      vermerk,
		Einreichen: func(mandant, ablage protocol.ID, nutzlast []byte, sig protocol.Signature) error {
			_, err := vermerk.Einreichen(mandant, ablage, nutzlast, sig, &key.PublicKey)
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.Beenden(ctx)
	})
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x42), false)); err != nil {
		t.Fatal(err)
	}
	prefix := fill(0x11).Hex() + "/" + katalog.Hex() + "/"
	erste := zaehle(t, ziel, prefix)
	if erste == 0 {
		t.Fatal("katalog fehlt")
	}
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x43), false)); err != nil {
		t.Fatal(err)
	}
	if zaehle(t, ziel, prefix) != erste {
		t.Fatal("katalog ein zweites mal")
	}
	vorher := epochen(t, ziel, fill(0x11), fill(0x22))
	if len(vorher) < 1 {
		t.Fatal("keine gruppenepeoche")
	}
	uhr = uhr.Add(15 * time.Minute)
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x44), false)); err != nil {
		t.Fatal(err)
	}
	geschlossen := epochen(t, ziel, fill(0x11), fill(0x22))
	var alt protocol.EpochID
	var altKeys []string
	for id, keys := range geschlossen {
		if _, noch := vorher[id]; noch && len(keys) > 0 {
			alt, altKeys = id, keys
		}
	}
	if alt == (protocol.EpochID{}) || len(altKeys) == 0 {
		t.Fatalf("erste epoche nicht geschlossen %d", len(geschlossen))
	}
	uhr = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if _, err := p.Ereignis(context.Background(), ereignis(fill(0x45), false)); err != nil {
		t.Fatal(err)
	}
	for _, key := range altKeys {
		if _, ok, err := ziel.Lesen(key); err != nil || ok {
			t.Fatalf("segment %s noch da %v", key, err)
		}
	}
	tag, ok, err := vermerk.Vermerk(fill(0x11), fill(0x22), alt)
	if err != nil || !ok || tag.IsZero() {
		t.Fatalf("vermerk %v %v", ok, err)
	}
}

func holen(t *testing.T, url string) int {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func holenText(t *testing.T, url string) []byte {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("%d %v", res.StatusCode, err)
	}
	return body
}

func senden(t *testing.T, url string, body []byte) int {
	t.Helper()
	res, err := http.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func zaehle(t *testing.T, ziel *Platte, prefix string) int {
	t.Helper()
	keys, err := ziel.Liste(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}

func epochen(t *testing.T, ziel *Platte, mandant, ablage protocol.ID) map[protocol.EpochID][]string {
	t.Helper()
	keys, err := ziel.Liste(mandant.Hex() + "/" + ablage.Hex() + "/")
	if err != nil {
		t.Fatal(err)
	}
	out := map[protocol.EpochID][]string{}
	for _, key := range keys {
		m, a, epoch, _, err := protocol.ParseObjektSchluessel(key)
		if err != nil || m != mandant || a != ablage {
			continue
		}
		out[epoch] = append(out[epoch], key)
	}
	return out
}
