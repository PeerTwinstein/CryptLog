package fenster

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/suchen"
	"cryptlog/werkzeug"
)

var (
	stunde8  = time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	stunde12 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	jetztFix = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	oktober  = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
)

func TestVerbindung(t *testing.T) {
	v := Verbindung{
		Ziel: ZielS3, Endpunkt: "https://s3.example", Bucket: "logs",
		Mandant: id(0x11), Zone: id(0x61), Katalog: id(0x21), Zertifikat: "kek.cer",
		KEK: "kek.pk8", Aufruf: "aufruf.pk8", Bestaetigung: "best.pk8",
	}
	roh, err := Format(v)
	if err != nil || bytes.Contains(roh, []byte("passphrase")) || bytes.Contains(roh, []byte("pin")) {
		t.Fatalf("format %v %s", err, roh)
	}
	got, err := Parsen(roh)
	if err != nil || got.Mandant != v.Mandant || got.KEK != v.KEK || got.Plattform {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Parsen(append(roh, []byte("passphrase=geheim\n")...)); !errors.Is(err, ErrVerbindung) {
		t.Fatalf("passphrase %v", err)
	}
	if _, err := Parsen([]byte("ziel=s3\nendpunkt=https://s3.example\nbucket=logs\nmandant=" + v.Mandant.Hex() + "\nkatalog=" + v.Katalog.Hex() + "\nzertifikat=kek.cer\npin=1234\n")); !errors.Is(err, ErrVerbindung) {
		t.Fatal(err)
	}
	pfad := filepath.Join(t.TempDir(), "verbindung")
	if err := Ablegen(pfad, v); err != nil {
		t.Fatal(err)
	}
	geladen, err := Lesen(pfad)
	if err != nil || geladen.Bucket != "logs" {
		t.Fatal(err)
	}
	v.Plattform = true
	ziel := &memZiel{}
	if _, err := Neu(konfig(v, ziel, &memAbschluss{}, schluessel.ModusEinfach, nil)); !errors.Is(err, ErrVerbindung) {
		t.Fatalf("plattform-mandant %v", err)
	}
	if ziel.liste != 0 || len(ziel.gelesen) != 0 {
		t.Fatal("neu liest die ablage")
	}
}

func TestEntsperrenUndPruefung(t *testing.T) {
	a := neueAnlage(t, false)
	f := a.fenster(t, schluessel.ModusEinfach)
	if f.Sicht().Finger != a.fp || f.Sicht().Status != werkzeug.StatusAktuell {
		t.Fatalf("%+v", f.Sicht())
	}
	if f.Arten() != nil {
		t.Fatal("arten vor dem entsperren")
	}
	if _, err := f.Pruefung(Auswahl{Art: ArtGruppe, Kohorte: "Nord", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)}); !errors.Is(err, ErrFenster) {
		t.Fatalf("ohne schlüssel %v", err)
	}
	pass := []byte("kek-geheimnis")
	if err := f.Einfach(pass); err != nil {
		t.Fatal(err)
	}
	for _, b := range pass {
		if b != 0 {
			t.Fatal("passphrase bleibt")
		}
	}
	if f.priv == nil {
		t.Fatal("schlüssel fehlt")
	}
	arten := f.Arten()
	if len(arten) != 3 || arten[2] != ArtAuffang {
		t.Fatalf("%v", arten)
	}
	if _, err := f.Pruefung(Auswahl{Art: ArtPlattform, Von: stunde8, Bis: stunde8.Add(time.Hour)}); !errors.Is(err, ErrArt) {
		t.Fatalf("plattform %v", err)
	}

	ziel := f.ziel.(*memZiel)
	ziel.gelesen = nil
	ziel.geschrieben = 0
	n, err := f.Zaehlen(Auswahl{Art: ArtGruppe, Kohorte: "Nord", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil || n != 1 {
		t.Fatalf("zählen %d %v", n, err)
	}
	for _, key := range ziel.gelesen {
		if strings.Contains(key, a.gruppe.Hex()) || strings.Contains(key, a.weg.String()) {
			t.Fatalf("zählen liest %s", key)
		}
	}
	if ziel.geschrieben != 0 {
		t.Fatal("zählen schreibt")
	}

	erg, err := f.Pruefung(Auswahl{Art: ArtGruppe, Kohorte: "Nord", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if erg.Epochen != 1 || erg.Art != ArtGruppe {
		t.Fatalf("%+v", erg)
	}
	var offen, geloest *Befund
	for i := range erg.Befunde {
		b := &erg.Befunde[i]
		if b.Ablage != a.gruppe || b.Name == b.Ablage.Hex() {
			t.Fatalf("beschriftung %+v", b)
		}
		if b.Epoch == a.weg {
			geloest = b
		}
		if len(b.Eintraege) > 0 {
			offen = b
		}
		if b.Epoch == a.spaeter {
			t.Fatal("epoche außerhalb")
		}
	}
	if offen == nil || offen.Name != "Nord" || !offen.Vertraulich || offen.Luecke {
		t.Fatalf("offen %+v", offen)
	}
	if geloest == nil || !geloest.Geloescht || len(geloest.Eintraege) != 0 {
		t.Fatalf("gelöscht %+v", geloest)
	}
	for _, key := range f.ziel.(*memZiel).gelesen {
		if strings.Contains(key, a.weg.String()) {
			t.Fatal("gelöschte epoche geladen")
		}
	}
	text := map[string]Zeile{}
	for _, z := range offen.Eintraege {
		text[string(z.Text)] = z
	}
	if !text["eins"].Gueltig || string(text["eins"].Personen[0]) != "Ada" {
		t.Fatalf("eins %+v", text["eins"])
	}
	if text["zwei"].Gueltig {
		t.Fatal("ungültige zugehörigkeit")
	}
	if !text["drei"].NachRaster || !text["drei"].Gueltig {
		t.Fatalf("raster %+v", text["drei"])
	}
	if ziel.geschrieben != 0 {
		t.Fatal("prüfung schreibt")
	}
	eins := text["eins"].Text
	f.Ende()
	for _, b := range eins {
		if b != 0 {
			t.Fatal("klartext bleibt im fenster")
		}
	}
	if f.sitzung != nil {
		t.Fatal("sitzung bleibt")
	}

	auffang, err := f.Pruefung(Auswahl{Art: ArtAuffang, Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil || auffang.Epochen != 1 || len(auffang.Befunde) != 1 {
		t.Fatalf("%v %+v", err, auffang)
	}
	zeile := auffang.Befunde[0].Eintraege[0]
	if !zeile.Unzugeordnet || zeile.Grund != protocol.GrundOhneBezug || string(zeile.Text) != "tot" {
		t.Fatalf("%+v", zeile)
	}
	f.Ende()

	n, err = f.Zaehlen(Auswahl{Art: ArtGezielt, Person: "Ada", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil || n != 1 {
		t.Fatalf("verzeichnis %d %v", n, err)
	}
	gezielt, err := f.Pruefung(Auswahl{Art: ArtGezielt, Person: "Ada", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(gezielt.Befunde) != 1 || len(gezielt.Befunde[0].Eintraege) != 1 || string(gezielt.Befunde[0].Eintraege[0].Text) != "eins" {
		t.Fatalf("%+v", gezielt.Befunde)
	}
	f.Ende()

	key := f.priv.(*ecdsa.PrivateKey)
	if err := f.AufrufEinfach([]byte("aufruf-passphrase-sichtbar")); err != nil {
		t.Fatal(err)
	}
	f.Schliessen()
	if f.priv != nil || f.aufruf != nil {
		t.Fatal("schlüssel bleibt")
	}
	for _, w := range key.D.Bits() {
		if w != 0 {
			t.Fatal("schlüssel bleibt")
		}
	}
}

func TestSicherUndBestaetigung(t *testing.T) {
	a := neueAnlage(t, false)
	f := a.fenster(t, schluessel.ModusSicher)
	kek := &traeger{key: a.kek}
	if err := f.Sicher(kek); err != nil {
		t.Fatal(err)
	}
	if f.priv != nil {
		t.Fatal("träger gibt den schlüssel heraus")
	}
	if _, err := f.Pruefung(Auswahl{Art: ArtGruppe, Kohorte: "Nord", Von: stunde8, Bis: stunde8.Add(2 * time.Hour)}); err != nil || kek.unwraps == 0 {
		t.Fatalf("%v unwraps %d", err, kek.unwraps)
	}
	f.Ende()
	davor := kek.unwraps

	erste, zweite := a.ungeprueft(t)
	pass := []byte("best-geheimnis")
	kopie := append([]byte(nil), pass...)
	best, err := f.Bestaetigen(pass, nil, a.gruppe, protocol.RolleGruppe, []protocol.EpochID{erste.id, zweite.id})
	if err != nil || len(best) != 2 || best[0].Signatur == best[1].Signatur {
		t.Fatalf("%v %+v", err, best)
	}
	for _, b := range pass {
		if b != 0 {
			t.Fatal("bestätigungspassphrase bleibt")
		}
	}
	if _, err := f.Bestaetigen(nil, nil, a.gruppe, protocol.RolleGruppe, []protocol.EpochID{erste.id}); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("zweite passphrase %v", err)
	}
	nochmal, err := f.Bestaetigen(kopie, nil, a.gruppe, protocol.RolleGruppe, []protocol.EpochID{erste.id, zweite.id})
	if err != nil || len(nochmal) != 0 {
		t.Fatalf("schon bestätigt %v %+v", err, nochmal)
	}
	if kek.unwraps != davor {
		t.Fatal("bestätigung öffnet einen dek")
	}
	if _, err := f.Bestaetigen([]byte("best-geheimnis"), nil, a.gruppe, protocol.RolleGruppe, []protocol.EpochID{a.bruch}); !errors.Is(err, ErrBestaetigung) {
		t.Fatalf("bruch %v", err)
	}
	if _, ok := a.abschluss.best[schlussel(a.mandant, a.gruppe, a.bruch)]; ok {
		t.Fatal("bruch wurde bestätigt")
	}

	alt := a.abschluss.best[schlussel(a.mandant, a.auffang, a.ohne)]
	neu := a.ablegen(t, a.auffang, a.auffang, stunde8.Add(time.Hour), id(0x44), alt.Hash, []teil{{a.auffangInhalt(t, "danach", protocol.GrundOhneBezug), stunde8.Add(time.Hour + time.Minute)}}, false, false)
	traegerBest := &traeger{key: a.best}
	signiert, err := f.Bestaetigen(nil, traegerBest, a.auffang, protocol.RolleAuffang, []protocol.EpochID{neu.id})
	if err != nil || len(signiert) != 1 || traegerBest.signaturen != 1 || f.priv != nil {
		t.Fatalf("%v %+v signaturen %d", err, signiert, traegerBest.signaturen)
	}
}

func TestSumme(t *testing.T) {
	a := neueAnlage(t, false)
	f := a.fenster(t, schluessel.ModusEinfach)
	if err := f.Einfach([]byte("kek-geheimnis")); err != nil {
		t.Fatal(err)
	}
	if err := f.VerzeichnisSumme(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrSumme) {
		t.Fatalf("offener monat %v", err)
	}
	monat := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := f.VerzeichnisSumme(monat); err != nil {
		t.Fatal(err)
	}
	if f.sitzung != nil {
		t.Fatal("summe behält klartext")
	}
	var summen, vorgang int
	for key := range a.ziel.obj {
		if strings.Contains(key, a.summe.Hex()) {
			summen++
		}
		if strings.Contains(key, a.vorgangSumme.Hex()) {
			vorgang++
		}
	}
	if summen == 0 || vorgang != 0 {
		t.Fatalf("summen %d vorgang %d", summen, vorgang)
	}
	bericht := a.summeLesen(t, f)
	if len(bericht.Eintraege) < 2 || bericht.Eintraege[0].Beleg == nil || bericht.Eintraege[1].Verweis == nil || bericht.Eintraege[1].Verweis.Schluessel != "Ada" {
		t.Fatalf("%+v", bericht.Eintraege)
	}
}

func TestFrage(t *testing.T) {
	a := neueAnlage(t, false)
	f := a.fenster(t, schluessel.ModusEinfach)
	if err := f.Einfach([]byte("kek-geheimnis")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Frage(protocol.AnfrageVorgang, "V-1", stunde8, stunde8.Add(time.Hour)); !errors.Is(err, ErrAufruf) {
		t.Fatalf("ohne aufruf %v", err)
	}
	pass := []byte("aufruf-passphrase-sichtbar")
	if err := f.AufrufEinfach(pass); err != nil {
		t.Fatal(err)
	}
	for _, b := range pass {
		if b != 0 {
			t.Fatal("aufrufpassphrase bleibt")
		}
	}
	p := a.suchprozess(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.anfrage = append([]byte(nil), body...)
		r.Body = io.NopCloser(bytes.NewReader(body))
		p.Suche().ServeHTTP(w, r)
	}))
	defer srv.Close()
	defer p.Beenden()
	f.suche = srv.URL + "/suche"
	treffer, err := f.Frage(protocol.AnfrageVorgang, "V-1", stunde8, stunde8.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(treffer.Personen) != 0 || len(treffer.Vorgaenge) != 0 {
		t.Fatalf("%+v", treffer)
	}
	if bytes.Contains(a.anfrage, []byte("aufruf-passphrase-sichtbar")) || bytes.Contains(a.anfrage, []byte("kek-geheimnis")) {
		t.Fatal("passphrase geht an den suchprozess")
	}
	if _, err := protocol.ParseIndexanfrage(a.anfrage[:len(a.anfrage)-protocol.SignatureLen]); err != nil {
		t.Fatal(err)
	}
}

func TestPlattform(t *testing.T) {
	a := neueAnlage(t, true)
	f := a.fenster(t, schluessel.ModusEinfach)
	if err := f.Einfach([]byte("kek-geheimnis")); err != nil {
		t.Fatal(err)
	}
	arten := f.Arten()
	if len(arten) != 4 || arten[3] != ArtPlattform {
		t.Fatalf("%v", arten)
	}
	n, err := f.Zaehlen(Auswahl{Art: ArtPlattform, Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil || n != 2 {
		t.Fatalf("zählen %d %v", n, err)
	}
	erg, err := f.Pruefung(Auswahl{Art: ArtPlattform, Von: stunde8, Bis: stunde8.Add(2 * time.Hour)})
	if err != nil || erg.Epochen != 2 {
		t.Fatalf("%v %+v", err, erg)
	}
	var texte []string
	for _, b := range erg.Befunde {
		for _, z := range b.Eintraege {
			texte = append(texte, string(z.Text))
			if !z.Unzugeordnet || z.Grund != protocol.GrundKEKFehlt {
				t.Fatalf("%+v", z)
			}
		}
	}
	if strings.Join(texte, " ") != "plattform mandant" && strings.Join(texte, " ") != "mandant plattform" {
		if len(texte) != 2 {
			t.Fatalf("%v", texte)
		}
	}
	haben := map[string]bool{}
	for _, s := range texte {
		haben[s] = true
	}
	if !haben["plattform"] || !haben["mandant"] || haben["fremd"] {
		t.Fatalf("%v", texte)
	}
	f.Ende()
}

type traeger struct {
	key        *ecdsa.PrivateKey
	unwraps    int
	signaturen int
}

func (t *traeger) Oeffentlich() (crypto.PublicKey, error) { return &t.key.PublicKey, nil }

func (t *traeger) Unwrap(wrapped, ctx []byte) ([]byte, error) {
	t.unwraps++
	return crypt.Unwrap(t.key, wrapped, ctx)
}

func (t *traeger) Signieren(payload []byte) (protocol.Signature, error) {
	t.signaturen++
	return crypt.SignP256(t.key, payload)
}

type memZiel struct {
	obj         map[string][]byte
	mandanten   []protocol.ID
	gelesen     []string
	liste       int
	geschrieben int
}

func (m *memZiel) Lesen(key string) ([]byte, bool, error) {
	m.gelesen = append(m.gelesen, key)
	b, ok := m.obj[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func (m *memZiel) Liste(prefix string) ([]string, error) {
	m.liste++
	var out []string
	for key := range m.obj {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	return out, nil
}

func (m *memZiel) Schreiben(key string, inhalt []byte) error {
	if alt, ok := m.obj[key]; ok && !bytes.Equal(alt, inhalt) {
		return ErrZiel
	}
	m.obj[key] = append([]byte(nil), inhalt...)
	m.geschrieben++
	return nil
}

func (m *memZiel) Mandanten() ([]protocol.ID, error) {
	return append([]protocol.ID(nil), m.mandanten...), nil
}

type memAbschluss struct {
	best    map[string]Bestaetigung
	vermerk map[string]time.Time
	zweige  map[string][]werkzeug.Zweig
}

func (m *memAbschluss) Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (protocol.Hash, protocol.Signature, bool, error) {
	ein, ok := m.best[schlussel(mandant, ablage, epoch)]
	if !ok {
		return protocol.Hash{}, protocol.Signature{}, false, nil
	}
	return ein.Hash, ein.Signatur, true, nil
}

func (m *memAbschluss) Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (time.Time, bool, error) {
	tag, ok := m.vermerk[schlussel(mandant, ablage, epoch)]
	return tag, ok, nil
}

func (m *memAbschluss) Anhaengen(b Bestaetigung) (bool, error) {
	key := schlussel(b.Mandant, b.Ablage, b.Epoch)
	if _, ok := m.best[key]; ok {
		return false, nil
	}
	m.best[key] = b
	return true, nil
}

func (m *memAbschluss) Zweige(mandant, ablage protocol.ID, epoch protocol.EpochID) ([]werkzeug.Zweig, error) {
	return m.zweige[schlussel(mandant, ablage, epoch)], nil
}

func schlussel(m, a protocol.ID, e protocol.EpochID) string {
	return m.Hex() + "/" + a.Hex() + "/" + e.String()
}

type gebaut struct {
	id   protocol.EpochID
	hash protocol.Hash
	seqs [][]uint64
}

type anlage struct {
	t                                     *testing.T
	mandant, katalog, gruppe, verzeichnis protocol.ID
	auffang, summe, vorgangSumme, tenant  protocol.ID
	tenantAblage                          protocol.ID
	kek, hsm, best, pruef, aufruf         *ecdsa.PrivateKey
	cert                                  *x509.Certificate
	fp                                    protocol.Hash
	ziel                                  *memZiel
	abschluss                             *memAbschluss
	dir                                   string
	weg, spaeter, bruch, ohne             protocol.EpochID
	anfrage                               []byte
	oktober                               gebaut
}

func neueAnlage(t *testing.T, plattform bool) *anlage {
	t.Helper()
	a := &anlage{
		t: t, kek: paar(t), hsm: paar(t), best: paar(t), pruef: paar(t), aufruf: paar(t),
		ziel: &memZiel{obj: map[string][]byte{}}, abschluss: &memAbschluss{
			best: map[string]Bestaetigung{}, vermerk: map[string]time.Time{},
		},
		dir: t.TempDir(),
	}
	a.cert, a.fp = zertifikat(t, a.kek)
	if plattform {
		a.mandant = protocol.PlattformMandant()
		a.tenant = id(0x12)
		a.tenantAblage = id(0x27)
		a.ziel.mandanten = []protocol.ID{a.tenant}
	} else {
		a.mandant = id(0x11)
	}
	a.katalog = id(0x21)
	a.gruppe = id(0x22)
	a.auffang = id(0x23)
	a.verzeichnis = id(0x24)
	a.summe = id(0x25)
	a.vorgangSumme = id(0x26)
	a.schreibenSchluessel(t)
	if plattform {
		a.plattformEpochen(t)
	} else {
		a.mandantenEpochen(t)
	}
	return a
}

func (a *anlage) fenster(t *testing.T, modus schluessel.Modus) *Fenster {
	t.Helper()
	v := Verbindung{
		Ziel: ZielPlatte, Pfad: a.dir, Mandant: a.mandant, Zone: id(0x61), Katalog: a.katalog,
		Zertifikat: "kek.cer", Aufruf: filepath.Join(a.dir, "aufruf.pk8"),
		Bestaetigung: filepath.Join(a.dir, "best.pk8"),
		Plattform:    a.mandant == protocol.PlattformMandant(),
	}
	if modus == schluessel.ModusEinfach {
		v.KEK = filepath.Join(a.dir, "kek.pk8")
	}
	f, err := Neu(Konfig{
		Verbindung: v, Ziel: a.ziel, Abschluss: a.abschluss, Zertifikat: a.cert,
		Status: werkzeug.StatusAktuell, Modus: modus, Pruef: &a.pruef.PublicKey,
		HSM: &a.hsm.PublicKey, Bestaetigung: &a.best.PublicKey, Rahmen: 256,
		Intervall: time.Hour, Frist: 30 * 24 * time.Hour, Instanz: id(0x55),
		Signatur: func(p []byte) (protocol.Signature, error) { return crypt.SignP256(a.hsm, p) },
		Person:   "Dora",
		Jetzt:    func() time.Time { return jetztFix },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func konfig(v Verbindung, ziel Ziel, abschluss Abschluss, modus schluessel.Modus, kek *ecdsa.PrivateKey) Konfig {
	cert, _ := zertifikat(nil, paar(nil))
	if kek != nil {
		cert, _ = zertifikat(nil, kek)
	}
	hsm, best, pruef := paar(nil), paar(nil), paar(nil)
	return Konfig{
		Verbindung: v, Ziel: ziel, Abschluss: abschluss, Zertifikat: cert,
		Status: werkzeug.StatusAktuell, Modus: modus, Pruef: &pruef.PublicKey,
		HSM: &hsm.PublicKey, Bestaetigung: &best.PublicKey, Rahmen: 256,
		Intervall: time.Hour, Frist: 24 * time.Hour, Jetzt: func() time.Time { return jetztFix },
	}
}

func (a *anlage) schreibenSchluessel(t *testing.T) {
	t.Helper()
	kosten := Kosten{Passes: 1, Memory: 8, Threads: 1}
	for _, paar := range []struct {
		name string
		key  *ecdsa.PrivateKey
		pass string
	}{
		{"kek.pk8", a.kek, "kek-geheimnis"},
		{"aufruf.pk8", a.aufruf, "aufruf-passphrase-sichtbar"},
		{"best.pk8", a.best, "best-geheimnis"},
	} {
		roh, err := Verschluesseln(nil, paar.key, []byte(paar.pass), kosten)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(a.dir, paar.name), roh, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	klar, err := x509.MarshalPKCS8PrivateKey(a.kek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Entschluesseln(klar, []byte("kek-geheimnis")); !errors.Is(err, ErrPassphrase) {
		t.Fatal(err)
	}
}

func (a *anlage) mandantenEpochen(t *testing.T) {
	t.Helper()
	stand := protocol.Stand{Name: "Mandant", Kennungen: []protocol.Kennung{
		{Rolle: protocol.RolleGruppe, Ablage: a.gruppe, Bind: a.gruppe, Kohorte: "Nord", Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleEinzel, Ablage: id(0x33), Bind: id(0x34), Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleAuffang, Ablage: a.auffang, Bind: a.auffang, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleVerzeichnis, Ablage: a.verzeichnis, Bind: a.verzeichnis, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleVerzeichnisSumme, Ablage: a.summe, Bind: a.summe, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleVorgangSumme, Ablage: a.vorgangSumme, Bind: a.vorgangSumme, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleKatalog, Ablage: a.katalog, Bind: a.katalog, Aktiv: protocol.KennungAn},
	}}
	katalog, err := protocol.KatalogBytes(stand)
	if err != nil {
		t.Fatal(err)
	}
	a.ablegen(t, a.katalog, a.katalog, stunde8, id(0x44), protocol.Genesis(a.katalog, id(0x44)), []teil{{katalog, stunde8.Add(time.Minute)}}, true, false)

	gruppe := a.beginnen(t, a.gruppe, a.gruppe, stunde8, id(0x44), protocol.Genesis(a.gruppe, id(0x44)))
	gebaut := a.beenden(t, gruppe, []teil{
		{a.log(t, "eins", true), stunde8.Add(time.Minute)},
		{a.log(t, "zwei", false), stunde8.Add(2 * time.Minute)},
		{a.log(t, "drei", true), stunde8.Add(2*time.Hour + 30*time.Minute)},
	}, true, false)
	spaeter := a.ablegen(t, a.gruppe, a.gruppe, stunde12, id(0x44), gebaut.hash, []teil{{a.log(t, "spaeter", true), stunde12.Add(time.Minute)}}, true, false)
	a.spaeter = spaeter.id
	weg := a.ablegen(t, a.gruppe, a.gruppe, stunde8, id(0x45), protocol.Genesis(a.gruppe, id(0x45)), []teil{{a.log(t, "weg", true), stunde8.Add(time.Minute)}}, true, true)
	a.weg = weg.id
	auf := a.ablegen(t, a.auffang, a.auffang, stunde8, id(0x44), protocol.Genesis(a.auffang, id(0x44)), []teil{{a.auffangInhalt(t, "tot", protocol.GrundOhneBezug), stunde8.Add(time.Minute)}}, true, false)
	a.ohne = auf.id
	verweis := protocol.Verweis{
		Art: protocol.VerweisPerson, Schluessel: "Ada", Mandant: a.mandant,
		Bind: a.gruppe, Epoch: gebaut.id, Seq: gebaut.seqs[0][0],
	}
	roh, err := protocol.VerweisBytes(verweis)
	if err != nil {
		t.Fatal(err)
	}
	a.oktober = a.ablegen(t, a.verzeichnis, a.verzeichnis, oktober, id(0x46), protocol.Genesis(a.verzeichnis, id(0x46)), []teil{{roh, oktober.Add(time.Minute)}}, true, false)
	a.ablegen(t, a.verzeichnis, a.verzeichnis, stunde8, id(0x44), protocol.Genesis(a.verzeichnis, id(0x44)), []teil{{roh, stunde8.Add(time.Minute)}}, true, false)
}

func (a *anlage) plattformEpochen(t *testing.T) {
	t.Helper()
	stand := protocol.Stand{Name: "Plattform", Kennungen: []protocol.Kennung{
		{Rolle: protocol.RolleAuffang, Ablage: a.auffang, Bind: a.auffang, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleKatalog, Ablage: a.katalog, Bind: a.katalog, Aktiv: protocol.KennungAn},
		{Rolle: protocol.RolleVerzeichnis, Ablage: a.verzeichnis, Bind: a.verzeichnis, Aktiv: protocol.KennungAn},
	}}
	katalog, err := protocol.KatalogBytes(stand)
	if err != nil {
		t.Fatal(err)
	}
	a.ablegen(t, a.katalog, a.katalog, stunde8, id(0x44), protocol.Genesis(a.katalog, id(0x44)), []teil{{katalog, stunde8.Add(time.Minute)}}, true, false)
	a.ablegen(t, a.auffang, a.auffang, stunde8, id(0x44), protocol.Genesis(a.auffang, id(0x44)), []teil{{a.auffangInhalt(t, "plattform", protocol.GrundKEKFehlt), stunde8.Add(time.Minute)}}, true, false)
	plattform := a.mandant
	a.mandant = a.tenant
	a.ablegen(t, a.tenantAblage, a.tenantAblage, stunde8, id(0x44), protocol.Genesis(a.tenantAblage, id(0x44)), []teil{{a.auffangInhalt(t, "mandant", protocol.GrundKEKFehlt), stunde8.Add(time.Minute)}}, true, false)
	fremd := paar(t)
	_, fp := zertifikat(t, fremd)
	alt, altFP := a.kek, a.fp
	a.kek, a.fp = fremd, fp
	a.ablegen(t, a.tenantAblage, a.tenantAblage, stunde8, id(0x45), protocol.Genesis(a.tenantAblage, id(0x45)), []teil{{a.auffangInhalt(t, "fremd", protocol.GrundKEKFehlt), stunde8.Add(time.Minute)}}, true, false)
	a.kek, a.fp, a.mandant = alt, altFP, plattform
}

func (a *anlage) ungeprueft(t *testing.T) (gebaut, gebaut) {
	t.Helper()
	ablage := id(0x28)
	erste := a.ablegen(t, ablage, ablage, stunde8, id(0x47), protocol.Genesis(ablage, id(0x47)), []teil{{a.log(t, "neu", true), stunde8.Add(time.Minute)}}, false, false)
	zweite := a.ablegen(t, ablage, ablage, stunde8.Add(time.Hour), id(0x47), erste.hash, []teil{{a.log(t, "danach", true), stunde8.Add(time.Hour + time.Minute)}}, false, false)
	a.gruppe = ablage
	bruch := a.ablegen(t, ablage, ablage, stunde12, id(0x47), protocol.Hash{9}, []teil{{a.log(t, "bruch", true), stunde12.Add(time.Minute)}}, false, false)
	a.bruch = bruch.id
	return erste, zweite
}

type teil struct {
	inhalt []byte
	zeit   time.Time
}

func (a *anlage) ablegen(t *testing.T, ablage, bind protocol.ID, raster time.Time, instanz protocol.ID, previous protocol.Hash, teile []teil, bestaetigen, vermerk bool) gebaut {
	t.Helper()
	ep := a.beginnen(t, ablage, bind, raster, instanz, previous)
	return a.beenden(t, ep, teile, bestaetigen, vermerk)
}

func (a *anlage) beginnen(t *testing.T, ablage, bind protocol.ID, raster time.Time, instanz protocol.ID, previous protocol.Hash) *offen {
	t.Helper()
	var prefix protocol.Prefix
	if _, err := rand.Read(prefix[:]); err != nil {
		t.Fatal(err)
	}
	eid, err := protocol.NewEpochID(raster, instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var dek crypt.DEK
	if _, err := rand.Read(dek[:]); err != nil {
		t.Fatal(err)
	}
	var dekID protocol.ID
	if _, err := rand.Read(dekID[:]); err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypt.WrapDEK(nil, &a.kek.PublicKey, dek, bind, protocol.WrapContext(a.mandant, ablage, eid, a.fp))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: a.mandant, Ablage: ablage, DekID: dekID, Epoch: eid, KEK: a.fp,
		Wrapped: wrapped, DEK: dek, Rahmen: 256, Klasse: protocol.Segment256KiB,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &offen{ep: ep, id: eid, previous: previous, ablage: ablage}
}

type offen struct {
	ep       *epoch.Epoche
	id       protocol.EpochID
	previous protocol.Hash
	ablage   protocol.ID
}

func (a *anlage) beenden(t *testing.T, o *offen, teile []teil, bestaetigen, vermerk bool) gebaut {
	t.Helper()
	var seqs [][]uint64
	for i, teil := range teile {
		var event protocol.ID
		event[0] = byte(0x10 + i)
		klar, err := protocol.EreignisKlartext(event, uint64(teil.zeit.UnixMilli()), o.ablage, teil.inhalt)
		if err != nil {
			t.Fatal(err)
		}
		_, glieder, err := o.ep.Ereignis(klar)
		if err != nil {
			t.Fatal(err)
		}
		var s []uint64
		for _, g := range glieder {
			s = append(s, g.Seq)
		}
		seqs = append(seqs, s)
	}
	hsm := a.hsm
	erg, err := o.ep.Abschluss(o.previous, 1, 1, protocol.Hash{7}, func(p []byte) (protocol.Signature, error) {
		return crypt.SignP256(hsm, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range erg.Segmente {
		if err := a.ziel.Schreiben(seg.Schluessel, seg.Bytes); err != nil {
			t.Fatal(err)
		}
	}
	if bestaetigen {
		sig, err := crypt.SignP256(a.best, protocol.ConfirmationPayload(erg.EpochHash))
		if err != nil {
			t.Fatal(err)
		}
		a.abschluss.best[schlussel(a.mandant, o.ablage, o.id)] = Bestaetigung{
			Mandant: a.mandant, Ablage: o.ablage, Epoch: o.id, Hash: erg.EpochHash, Signatur: sig,
		}
	}
	if vermerk {
		a.abschluss.vermerk[schlussel(a.mandant, o.ablage, o.id)] = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	}
	return gebaut{id: o.id, hash: erg.EpochHash, seqs: seqs}
}

func (a *anlage) log(t *testing.T, text string, ok bool) []byte {
	t.Helper()
	nutz := protocol.Aussage{Mandant: a.mandant, Person: "Ada", Rolle: protocol.RollePerson, Von: 0, Bis: math.MaxUint64}
	raw, err := protocol.AussageBytes(nutz)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(a.pruef, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		sig[0] ^= 0xff
	}
	inhalt, err := protocol.LogBytes(protocol.LogInhalt{
		Text: []byte(text), Vorgang: "V-1", Bezuege: []string{"Ada"},
		Aussagen: []protocol.AussageTeil{{Nutzlast: nutz, Signatur: append([]byte(nil), sig[:]...)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return inhalt
}

func (a *anlage) auffangInhalt(t *testing.T, text string, grund protocol.Grund) []byte {
	t.Helper()
	inhalt, err := protocol.AuffangBytes(protocol.AuffangInhalt{Grund: grund, Text: []byte(text)})
	if err != nil {
		t.Fatal(err)
	}
	return inhalt
}

func (a *anlage) summeLesen(t *testing.T, f *Fenster) werkzeug.Bericht {
	t.Helper()
	ids, nach, err := f.gruppieren(a.mandant, a.summe)
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	var segs []werkzeug.Segment
	for _, ref := range nach[ids[0]] {
		roh, ok := a.ziel.obj[ref.key]
		if !ok {
			t.Fatal(ref.key)
		}
		segs = append(segs, werkzeug.Segment{Schluessel: ref.key, Bytes: roh})
	}
	sig, err := crypt.SignP256(a.best, protocol.ConfirmationPayload(a.summenHash(t, segs)))
	if err != nil {
		t.Fatal(err)
	}
	hash := a.summenHash(t, segs)
	bericht, err := werkzeug.Pruefen(werkzeug.Auftrag{
		Mandant: a.mandant, Ablage: a.summe, Epoch: ids[0], Rahmen: 256,
		Rolle: protocol.RolleVerzeichnisSumme, Segmente: segs, HSM: &a.hsm.PublicKey,
		Bestaetigung: &a.best.PublicKey, BestaetigungsSignatur: sig, AbschlussHash: hash,
		Vorgaenger: protocol.Genesis(a.summe, id(0x55)), Zertifikat: a.cert,
		Priv: a.kek, Pruef: &a.pruef.PublicKey, Status: werkzeug.StatusAktuell, Alles: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bericht
}

func (a *anlage) summenHash(t *testing.T, segs []werkzeug.Segment) protocol.Hash {
	t.Helper()
	_, _, manifest, err := protocol.Zerlegen(segs[len(segs)-1].Bytes, 256, len(segs) == 1, true)
	if err != nil {
		t.Fatal(err)
	}
	nutz, sig, err := protocol.ParseManifestRahmen(manifest)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocol.EpochHash(nutz, sig)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func (a *anlage) suchprozess(t *testing.T) *suchen.Prozess {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(paar(t))
	if err != nil {
		t.Fatal(err)
	}
	pfad := filepath.Join(a.dir, "index.pk8")
	if err := os.WriteFile(pfad, der, 0o600); err != nil {
		t.Fatal(err)
	}
	fp, err := crypt.FingerprintSPKI(&a.aufruf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nutz := protocol.Aussage{
		Mandant: a.mandant, Person: "Dora", Rolle: protocol.RolleDatenschuetzer,
		Von: 0, Bis: math.MaxUint64, Finger: fp,
	}
	raw, err := protocol.AussageBytes(nutz)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(a.pruef, raw)
	if err != nil {
		t.Fatal(err)
	}
	ein := suchen.Eintrag{Aussage: nutz, Sig: sig, Aufruf: &a.aufruf.PublicKey}
	p, err := suchen.Start(suchen.Konfig{
		Schluessel: pfad, Protokoll: filepath.Join(a.dir, "protokoll"),
		Ziel: &suchZiel{}, Register: suchRegister{ein: ein}, Pruef: suchPruef{key: &a.pruef.PublicKey},
		Bestand: suchBestand{}, Abschluss: suchAbschluss{}, Instanz: id(0x61),
		Signatur: func(b []byte) (protocol.Signature, error) { return crypt.SignP256(a.hsm, b) },
		Jetzt:    func() time.Time { return jetztFix },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type suchZiel struct{}

func (suchZiel) Lesen(string) ([]byte, bool, error) { return nil, false, nil }
func (suchZiel) Liste(string) ([]string, error)     { return nil, nil }
func (suchZiel) Schreiben(string, []byte) error     { return nil }

type suchRegister struct{ ein suchen.Eintrag }

func (r suchRegister) Datenschuetzer(protocol.ID, string) (suchen.Eintrag, bool, error) {
	return r.ein, true, nil
}

type suchPruef struct{ key *ecdsa.PublicKey }

func (p suchPruef) Schluessel(protocol.ID) (*ecdsa.PublicKey, bool, error) {
	return p.key, true, nil
}

type suchBestand struct{}

func (suchBestand) Index(protocol.ID) (suchen.Stroeme, bool, error) {
	return suchen.Stroeme{
		Vorgang: id(0x71), Rahmen: 256, Intervall: time.Hour, Frist: 30 * 24 * time.Hour,
		HSM: paar(nil).Public().(*ecdsa.PublicKey), Bestaetigung: paar(nil).Public().(*ecdsa.PublicKey),
		Status: werkzeug.StatusAktuell,
	}, true, nil
}

type suchAbschluss struct{}

func (suchAbschluss) Bestaetigung(protocol.ID, protocol.ID, protocol.EpochID) (protocol.Hash, protocol.Signature, bool, error) {
	return protocol.Hash{}, protocol.Signature{}, false, nil
}

func (suchAbschluss) Vermerk(protocol.ID, protocol.ID, protocol.EpochID) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

func paar(t *testing.T) *ecdsa.PrivateKey {
	if t != nil {
		t.Helper()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return key
}

func zertifikat(t *testing.T, key *ecdsa.PrivateKey) (*x509.Certificate, protocol.Hash) {
	if t != nil {
		t.Helper()
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kek"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	fp, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return cert, fp
}

func id(b byte) protocol.ID {
	var out protocol.ID
	for i := range out {
		out[i] = b
	}
	return out
}
