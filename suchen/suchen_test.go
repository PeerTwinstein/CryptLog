package suchen_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/suchen"
	"cryptlog/werkzeug"
)

func TestZone(t *testing.T) {
	fx := neueZone(t)
	if len(fx.ziel.listen) != 0 {
		t.Fatal("start liest den index")
	}

	plattform := fx.anfrage(t, fx.plattform, protocol.AnfrageVorgang, "V-1", fx.jetzt)
	if _, err := fx.p.Anfrage(plattform); !errors.Is(err, suchen.ErrAnfrage) {
		t.Fatalf("plattform %v", err)
	}
	if len(fx.ziel.listen) != 0 {
		t.Fatalf("fremdes register liest den index: %v", fx.ziel.listen)
	}

	rec := rufen(fx.p.Suche(), http.MethodPost, "/suche", fx.vorgang)
	if rec.Code != http.StatusOK {
		t.Fatalf("suche %d %q", rec.Code, rec.Body.Bytes())
	}
	art, treffer, err := suchen.ParseTreffer(rec.Body.Bytes())
	if err != nil || art != protocol.AnfrageVorgang || len(treffer.Personen) != 1 || len(treffer.Vorgaenge) != 0 {
		t.Fatalf("treffer %+v %v", treffer, err)
	}
	if treffer.Personen[0].Person != "Ada" || treffer.Personen[0].Kohorte != "Nord" || treffer.Personen[0].Rolle != protocol.RolleGruppe {
		t.Fatalf("ada %+v", treffer.Personen[0])
	}
	body := rec.Body.Bytes()
	for _, fremd := range []string{"Dora", "Cleo", "V-9", "Logtext-Geheim", "suchprotokoll"} {
		if bytes.Contains(body, feld(fremd)) || bytes.Contains(body, []byte("Logtext-Geheim")) {
			t.Fatalf("antwort enthält %s", fremd)
		}
	}
	proto, err := os.ReadFile(fx.protokoll)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proto, feld("Dora")) || !bytes.Contains(proto, feld("V-1")) {
		t.Fatal("protokoll nennt die anfrage nicht")
	}
	if bytes.Contains(proto, feld("Ada")) || bytes.Contains(proto, feld("Cleo")) || bytes.Contains(proto, feld("V-9")) || bytes.Contains(proto, []byte("Logtext-Geheim")) {
		t.Fatal("protokoll ist ein export des index")
	}

	personen, err := fx.p.Anfrage(fx.anfrage(t, fx.mandant, protocol.AnfragePerson, "Ada", fx.jetzt.Add(time.Second)))
	if err != nil || len(personen.Vorgaenge) != 1 || personen.Vorgaenge[0].Nummer != "V-1" {
		t.Fatalf("person %+v %v", personen.Vorgaenge, err)
	}
	for _, vorgang := range personen.Vorgaenge {
		if vorgang.Nummer == "V-9" {
			t.Fatal("fremder vorgang")
		}
	}

	nachLesen := len(fx.ziel.listen)
	schreiben := fx.ziel.schreiben
	kaputt := append([]byte(nil), fx.vorgang...)
	kaputt[len(kaputt)-1] ^= 0xff
	if _, err := fx.p.Anfrage(kaputt); !errors.Is(err, suchen.ErrAnfrage) {
		t.Fatalf("signatur %v", err)
	}
	if _, err := fx.p.Anfrage(fx.vorgang); !errors.Is(err, suchen.ErrWiederholt) {
		t.Fatalf("wiederholt %v", err)
	}
	if len(fx.ziel.listen) != nachLesen || fx.ziel.schreiben != schreiben {
		t.Fatal("abgelehnte anfrage öffnet den index")
	}
	if ok, grund := fx.p.Ready(); !ok || grund != "" {
		t.Fatalf("bereit nach ablehnung %v %s", ok, grund)
	}

	metrik := rufen(fx.p.Metrik(), http.MethodGet, "/metrics", nil)
	if metrik.Code != http.StatusOK {
		t.Fatal(metrik.Code)
	}
	text := metrik.Body.String()
	for _, zeile := range []string{
		"cryptlog_ready 1\n",
		"cryptlog_search_requests_total{ergebnis=\"autorisiert\"} 2\n",
		"cryptlog_search_requests_total{ergebnis=\"abgelehnt\"} 2\n",
		"cryptlog_search_requests_total{ergebnis=\"wiederholt\"} 1\n",
		"cryptlog_search_seconds_count 2\n",
		"cryptlog_build_info{version=\"test\",digest=\"abc\"} 1\n",
	} {
		if !strings.Contains(text, zeile) {
			t.Fatalf("metrik ohne %s\n%s", zeile, text)
		}
	}
	for _, geheim := range []string{"Dora", "Ada", "Cleo", "V-1", "V-9", "Logtext-Geheim", "Nord"} {
		if strings.Contains(text, geheim) {
			t.Fatalf("metrik nennt %s", geheim)
		}
	}
	if rec := rufen(fx.p.Metrik(), http.MethodPost, "/suche", fx.vorgang); rec.Code != http.StatusNotFound {
		t.Fatalf("metrik nimmt suche an %d", rec.Code)
	}
	if rec := rufen(fx.p.Suche(), http.MethodGet, "/metrics", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("suche gibt metrik %d", rec.Code)
	}
	if strings.Contains(rufen(fx.p.Metrik(), http.MethodGet, "/metrics", nil).Body.String(), "cryptlog_search_requests_total{ergebnis=\"autorisiert\"} 3\n") {
		t.Fatal("metrikport hat die suche ausgeführt")
	}

	fx.p.Beenden()
	if fx.p.Live() {
		t.Fatal("live nach beenden")
	}
	if ok, grund := fx.p.Ready(); ok || grund != "beenden" {
		t.Fatalf("ready %v %s", ok, grund)
	}
	if _, err := fx.p.Anfrage(fx.anfrage(t, fx.mandant, protocol.AnfrageVorgang, "V-1", fx.jetzt.Add(3*time.Second))); !errors.Is(err, suchen.ErrBeenden) {
		t.Fatalf("nach beenden %v", err)
	}

	neu, err := suchen.Start(fx.konfig)
	if err != nil {
		t.Fatal(err)
	}
	fx.p = neu
	vorher := len(fx.ziel.listen)
	if _, err := fx.p.Anfrage(fx.vorgang); !errors.Is(err, suchen.ErrWiederholt) {
		t.Fatalf("neustart %v", err)
	}
	if len(fx.ziel.listen) != vorher {
		t.Fatal("wiederholte signatur öffnet den index")
	}

	if err := fx.p.Fassen(fx.mandant, fx.monat); err != nil {
		t.Fatal(err)
	}
	summen := 0
	var segment []byte
	for key, roh := range fx.ziel.objekte() {
		if strings.Contains(key, fx.summe.Hex()) {
			summen++
			segment = roh
		}
	}
	if summen == 0 || segment == nil {
		t.Fatal("summe fehlt in der ablage")
	}
	if err := fx.p.Fassen(fx.mandant, fx.monat); err != nil {
		t.Fatal(err)
	}
	nochmal := 0
	for key := range fx.ziel.objekte() {
		if strings.Contains(key, fx.summe.Hex()) {
			nochmal++
		}
	}
	if nochmal != summen {
		t.Fatalf("zweite fassung %d %d", nochmal, summen)
	}

	schreiben = fx.ziel.schreiben
	noch, err := fx.p.Anfrage(fx.anfrage(t, fx.mandant, protocol.AnfrageVorgang, "V-1", fx.jetzt.Add(4*time.Second)))
	if err != nil || len(noch.Personen) != 1 || noch.Personen[0].Person != "Ada" {
		t.Fatalf("nach summe %+v %v", noch, err)
	}
	if fx.ziel.schreiben != schreiben {
		t.Fatal("suche schreibt")
	}
	roh, err := suchen.TrefferBytes(protocol.AnfrageVorgang, noch)
	if err != nil || bytes.Equal(roh, segment) || bytes.Contains(roh, []byte("Logtext-Geheim")) || bytes.Contains(roh, feld("Cleo")) {
		t.Fatal("suche gibt die epoche heraus")
	}

	fx.register.brechen(fx.mandant, "Dora")
	if _, err := fx.p.Anfrage(fx.anfrage(t, fx.mandant, protocol.AnfrageVorgang, "V-1", fx.jetzt.Add(5*time.Second))); !errors.Is(err, suchen.ErrAnfrage) {
		t.Fatalf("abschrift %v", err)
	}

	for _, prefix := range fx.ziel.listen {
		if strings.Contains(prefix, fx.decoy.Hex()) {
			t.Fatalf("falsche ablage %s", prefix)
		}
	}
	if err := os.Remove(fx.schluessel); err != nil {
		t.Fatal(err)
	}
	if ok, grund := fx.p.Ready(); ok || grund != "secret" {
		t.Fatalf("secret %v %s", ok, grund)
	}
	if _, err := fx.p.Anfrage(fx.anfrage(t, fx.mandant, protocol.AnfrageVorgang, "V-1", fx.jetzt.Add(6*time.Second))); !errors.Is(err, suchen.ErrGeheimnis) {
		t.Fatalf("ohne datei %v", err)
	}
	fx.p.Beenden()
}

func TestStartOhneSchluessel(t *testing.T) {
	dir := t.TempDir()
	pfad := filepath.Join(dir, "index")
	if _, err := suchen.Start(suchen.Konfig{Schluessel: pfad}); !errors.Is(err, suchen.ErrGeheimnis) {
		t.Fatal(err)
	}
	os.WriteFile(pfad, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"), 0o600)
	if _, err := suchen.Start(suchen.Konfig{Schluessel: pfad}); !errors.Is(err, suchen.ErrGeheimnis) {
		t.Fatal(err)
	}
	klein, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(klein)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pfad, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := suchen.Start(suchen.Konfig{Schluessel: pfad}); !errors.Is(err, suchen.ErrGeheimnis) {
		t.Fatal(err)
	}
	gut, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err = x509.MarshalPKCS8PrivateKey(gut)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pfad, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := suchen.Start(suchen.Konfig{Schluessel: pfad}); !errors.Is(err, suchen.ErrKonfig) {
		t.Fatal(err)
	}
}

func TestGrenze(t *testing.T) {
	typ := reflect.TypeOf(&suchen.Prozess{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := strings.ToLower(typ.Method(i).Name)
		if strings.Contains(name, "export") || strings.Contains(name, "shell") || name == "exec" {
			t.Fatal(typ.Method(i).Name)
		}
	}
	konfig := reflect.TypeOf(suchen.Konfig{})
	for i := 0; i < konfig.NumField(); i++ {
		name := strings.ToLower(konfig.Field(i).Name)
		if strings.Contains(name, "pass") || strings.Contains(name, "shell") || strings.Contains(name, "export") {
			t.Fatal(konfig.Field(i).Name)
		}
	}
}

type zone struct {
	p          *suchen.Prozess
	konfig     suchen.Konfig
	ziel       *speicher
	register   *register
	mandant    protocol.ID
	plattform  protocol.ID
	summe      protocol.ID
	decoy      protocol.ID
	aufruf     *ecdsa.PrivateKey
	jetzt      time.Time
	monat      time.Time
	schluessel string
	protokoll  string
	vorgang    []byte
}

func neueZone(t *testing.T) *zone {
	t.Helper()
	index := paar(t)
	hsm := paar(t)
	best := paar(t)
	pruef := paar(t)
	aufruf := paar(t)
	mandant, vorgang, summe, decoy := kennung(0x11), kennung(0x22), kennung(0x33), kennung(0x77)
	plattform := kennung(0x55)
	writer, sucher := kennung(0x44), kennung(0x99)
	raster := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	jetzt := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	monat := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	zeit := uint64(raster.UnixMilli()) + 1000

	fp, err := crypt.FingerprintSPKI(&index.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dek, prefix, err := crypt.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer dek.Wipe()
	id, err := protocol.NewEpochID(raster, writer, prefix)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypt.WrapDEK(nil, &index.PublicKey, dek, vorgang, protocol.WrapContext(mandant, vorgang, id, fp))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant, Ablage: vorgang, DekID: kennung(0xee), Epoch: id, KEK: fp,
		Wrapped: wrapped, DEK: dek, Rahmen: 256, Klasse: protocol.Segment256KiB,
	})
	if err != nil {
		t.Fatal(err)
	}
	eintraege := []protocol.IndexEintrag{
		{Nummer: "V-1", Person: "Ada", Rolle: protocol.RolleGruppe, Kohorte: "Nord", Epoch: id, Seq: 1, Zeitpunkt: zeit},
		{Nummer: "V-9", Person: "Cleo", Rolle: protocol.RolleEinzel, Epoch: id, Seq: 2, Zeitpunkt: zeit},
	}
	for i, eintrag := range eintraege {
		inhalt, err := protocol.IndexBytes(eintrag)
		if err != nil {
			t.Fatal(err)
		}
		var event protocol.ID
		event[0] = byte(i + 1)
		klar, err := protocol.EreignisKlartext(event, zeit, vorgang, inhalt)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = ep.Ereignis(klar); err != nil {
			t.Fatal(err)
		}
	}
	erg, err := ep.Abschluss(protocol.Genesis(vorgang, writer), 0, 0, protocol.Hash{}, func(p []byte) (protocol.Signature, error) {
		return crypt.SignP256(hsm, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(best, protocol.ConfirmationPayload(erg.EpochHash))
	if err != nil {
		t.Fatal(err)
	}
	ziel := &speicher{obj: map[string][]byte{}}
	for _, seg := range erg.Segmente {
		if err := ziel.Schreiben(seg.Schluessel, seg.Bytes); err != nil {
			t.Fatal(err)
		}
	}
	ziel.schreiben = 0
	ziel.obj[mandant.Hex()+"/"+decoy.Hex()+"/log"] = []byte("Logtext-Geheim")
	abschluss := &abschlussSpeicher{best: map[string]bestaetigt{}}
	abschluss.setzen(mandant, vorgang, id, erg.EpochHash, sig)

	reg := &register{ein: map[string]suchen.Eintrag{}}
	reg.ein[mandant.Hex()+"/Dora"] = aussage(t, mandant, "Dora", aufruf, pruef)
	pruefer := pruefSpeicher{mandant.Hex(): &pruef.PublicKey}
	bestand := bestandSpeicher{mandant.Hex(): suchen.Stroeme{
		Vorgang: vorgang, Summe: summe, Bind: summe, Rahmen: 256, Intervall: time.Hour,
		Frist: 400 * 24 * time.Hour, HSM: &hsm.PublicKey, Bestaetigung: &best.PublicKey,
		Status: werkzeug.StatusAktuell,
	}}
	dir := t.TempDir()
	keyPfad := filepath.Join(dir, "index")
	der, err := x509.MarshalPKCS8PrivateKey(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPfad, der, 0o600); err != nil {
		t.Fatal(err)
	}
	protokoll := filepath.Join(dir, "protokoll")
	konfig := suchen.Konfig{
		Schluessel: keyPfad, Protokoll: protokoll, Ziel: ziel, Register: reg, Pruef: pruefer,
		Bestand: bestand, Abschluss: abschluss, Instanz: sucher,
		Signatur: func(p []byte) (protocol.Signature, error) { return crypt.SignP256(hsm, p) },
		Jetzt:    func() time.Time { return jetzt },
		Version:  "test", Digest: "abc",
	}
	p, err := suchen.Start(konfig)
	if err != nil {
		t.Fatal(err)
	}
	z := &zone{
		p: p, konfig: konfig, ziel: ziel, register: reg, mandant: mandant, plattform: plattform,
		summe: summe, decoy: decoy, aufruf: aufruf, jetzt: jetzt, monat: monat,
		schluessel: keyPfad, protokoll: protokoll,
	}
	t.Cleanup(func() { z.p.Beenden() })
	z.vorgang = z.anfrage(t, mandant, protocol.AnfrageVorgang, "V-1", jetzt)
	return z
}

func (z *zone) anfrage(t *testing.T, mandant protocol.ID, art protocol.AnfrageArt, schluessel string, zeit time.Time) []byte {
	t.Helper()
	body := protocol.Indexanfrage{
		Mandant: mandant, Zone: z.konfig.Instanz, Person: "Dora", Art: art, Schluessel: schluessel,
		Von:       uint64(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC).UnixMilli()),
		Bis:       uint64(time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC).UnixMilli()),
		Zeitpunkt: uint64(zeit.UnixMilli()),
	}
	raw, err := protocol.IndexanfrageBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(z.aufruf, raw)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, sig[:]...)
}

func aussage(t *testing.T, mandant protocol.ID, person string, aufruf, pruef *ecdsa.PrivateKey) suchen.Eintrag {
	t.Helper()
	fp, err := crypt.FingerprintSPKI(&aufruf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nutz := protocol.Aussage{
		Mandant: mandant, Person: person, Rolle: protocol.RolleDatenschuetzer,
		Von: 0, Bis: math.MaxUint64, Finger: fp,
	}
	raw, err := protocol.AussageBytes(nutz)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(pruef, raw)
	if err != nil {
		t.Fatal(err)
	}
	return suchen.Eintrag{Aussage: nutz, Sig: sig, Aufruf: &aufruf.PublicKey}
}

func feld(s string) []byte { return protocol.AppendText(nil, s) }

func rufen(h http.Handler, methode, pfad string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(methode, "http://zone"+pfad, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func paar(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func kennung(b byte) protocol.ID {
	var id protocol.ID
	id[0] = b
	return id
}

type register struct {
	mu  sync.Mutex
	ein map[string]suchen.Eintrag
}

func (r *register) Datenschuetzer(mandant protocol.ID, person string) (suchen.Eintrag, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ein, ok := r.ein[mandant.Hex()+"/"+person]
	return ein, ok, nil
}

func (r *register) brechen(mandant protocol.ID, person string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := mandant.Hex() + "/" + person
	ein := r.ein[key]
	ein.Sig[0] ^= 0xff
	r.ein[key] = ein
}

type pruefSpeicher map[string]*ecdsa.PublicKey

func (p pruefSpeicher) Schluessel(mandant protocol.ID) (*ecdsa.PublicKey, bool, error) {
	k, ok := p[mandant.Hex()]
	return k, ok, nil
}

type bestandSpeicher map[string]suchen.Stroeme

func (b bestandSpeicher) Index(mandant protocol.ID) (suchen.Stroeme, bool, error) {
	s, ok := b[mandant.Hex()]
	return s, ok, nil
}

type bestaetigt struct {
	hash protocol.Hash
	sig  protocol.Signature
}

type abschlussSpeicher struct {
	best map[string]bestaetigt
}

func (a *abschlussSpeicher) setzen(mandant, ablage protocol.ID, epoch protocol.EpochID, hash protocol.Hash, sig protocol.Signature) {
	a.best[mandant.Hex()+"/"+ablage.Hex()+"/"+epoch.String()] = bestaetigt{hash: hash, sig: sig}
}

func (a *abschlussSpeicher) Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (protocol.Hash, protocol.Signature, bool, error) {
	ein, ok := a.best[mandant.Hex()+"/"+ablage.Hex()+"/"+epoch.String()]
	if !ok {
		return protocol.Hash{}, protocol.Signature{}, false, nil
	}
	return ein.hash, ein.sig, true, nil
}

func (a *abschlussSpeicher) Vermerk(protocol.ID, protocol.ID, protocol.EpochID) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

type speicher struct {
	mu        sync.Mutex
	obj       map[string][]byte
	listen    []string
	schreiben int
}

func (s *speicher) Lesen(key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	roh, ok := s.obj[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), roh...), true, nil
}

func (s *speicher) Liste(prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listen = append(s.listen, prefix)
	var out []string
	for key := range s.obj {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	return out, nil
}

func (s *speicher) Schreiben(key string, inhalt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obj[key] = append([]byte(nil), inhalt...)
	s.schreiben++
	return nil
}

func (s *speicher) objekte() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.obj))
	for key, roh := range s.obj {
		out[key] = append([]byte(nil), roh...)
	}
	return out
}
