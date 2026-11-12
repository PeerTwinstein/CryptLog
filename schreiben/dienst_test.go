package schreiben

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	schl "cryptlog/schluessel"
)

func TestOeffnenDienst(t *testing.T) {
	dir := umgebung(t)
	dienst := dienstAus(t, dir)
	ev := ereignis(fill(0x42), false)
	roh, err := protocol.EreignisBytes(protocol.EreignisAufruf{
		ID: ev.ID, Mandant: ev.Mandant, Zeit: ev.Zeit, Vorgang: ev.Vorgang, Personen: ev.Personen, Text: ev.Text,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(dienst.Prozess.Ereignisport())
	defer srv.Close()
	res, err := http.Post(srv.URL+"/ereignis", "application/octet-stream", bytes.NewReader(roh))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ereignis %d %q", res.StatusCode, body)
	}
	best, err := protocol.ParseBestaetigt(body)
	if err != nil || best.Event != ev.ID || best.Seq == 0 || best.Schluessel == "" {
		t.Fatalf("%v %+v", err, best)
	}
	metrik := httptest.NewServer(dienst.Prozess.Metrik())
	defer metrik.Close()
	if code := holen(t, metrik.URL+"/ready"); code != http.StatusOK {
		t.Fatalf("ready %d", code)
	}
	if code := holen(t, srv.URL+"/ready"); code != http.StatusNotFound {
		t.Fatalf("ereignisport ready %d", code)
	}
}

func TestDienstEigenesZiel(t *testing.T) {
	dir := umgebung(t)
	eigen := filepath.Join(dir, "eigen")
	schreib(t, filepath.Join(dir, "mandanten", fill(0x11).Hex(), "ziel"), "ziel = platte\nwurzel = "+eigen+"\n")
	dienst := dienstAus(t, dir)
	if _, ok := dienst.Prozess.ziel.(*Wahl); !ok {
		t.Fatalf("%T", dienst.Prozess.ziel)
	}
	ev := ereignis(fill(0x43), false)
	roh, err := protocol.EreignisBytes(protocol.EreignisAufruf{
		ID: ev.ID, Mandant: ev.Mandant, Zeit: ev.Zeit, Vorgang: ev.Vorgang, Personen: ev.Personen, Text: ev.Text,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(dienst.Prozess.Ereignisport())
	defer srv.Close()
	res, err := http.Post(srv.URL+"/ereignis", "application/octet-stream", bytes.NewReader(roh))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ereignis %d %q", res.StatusCode, body)
	}
	eigenPlatte, err := OeffnenPlatte(eigen)
	if err != nil {
		t.Fatal(err)
	}
	gemeinsam, err := OeffnenPlatte(filepath.Join(dir, "ziel"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := fill(0x11).Hex() + "/"
	segEigen := zaehle(t, eigenPlatte, prefix)
	segGemeinsam := zaehle(t, gemeinsam, prefix)
	annahme := zaehle(t, gemeinsam, "annahme/")
	if segEigen == 0 || segGemeinsam != 0 || annahme == 0 {
		t.Fatalf("eigen=%d gemeinsam=%d annahme=%d", segEigen, segGemeinsam, annahme)
	}
}

func umgebung(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	jetzt := time.Now().UTC()
	bis := jetzt.Add(48 * time.Hour)
	ca, err := schl.NeueCA("ca", jetzt, bis)
	if err != nil {
		t.Fatal(err)
	}
	mandant := fill(0x11)
	plattform := schluessel(t)
	index := schluessel(t)
	kek := schluessel(t)
	pruef := schluessel(t)
	signier := schluessel(t)
	platCert, err := ca.Ausstellen(&plattform.PublicKey, mandant, "plattform", bis, jetzt, true)
	if err != nil {
		t.Fatal(err)
	}
	indexCert, err := ca.Ausstellen(&index.PublicKey, mandant, "index", bis, jetzt, false)
	if err != nil {
		t.Fatal(err)
	}
	kekCert, err := ca.Ausstellen(&kek.PublicKey, mandant, "Mandant", bis, jetzt, true)
	if err != nil {
		t.Fatal(err)
	}
	pruefCert, err := ca.Ausstellen(&pruef.PublicKey, mandant, "pruef", bis, jetzt, false)
	if err != nil {
		t.Fatal(err)
	}
	schreib(t, filepath.Join(dir, "plattform.pem"), pemZertifikat(platCert))
	schreib(t, filepath.Join(dir, "index.pem"), pemZertifikat(indexCert))
	schreib(t, filepath.Join(dir, "signatur.pem"), pemSchluessel(t, signier))

	mdir := filepath.Join(dir, "mandanten", mandant.Hex())
	if err := os.MkdirAll(filepath.Join(mdir, "personen"), 0o700); err != nil {
		t.Fatal(err)
	}
	schreib(t, filepath.Join(mdir, "kek.pem"), pemZertifikat(kekCert))
	schreib(t, filepath.Join(mdir, "pruef.pem"), pemZertifikat(pruefCert))
	gruppe, verzeichnis, vorgang, auffang, einzel, katalog := fill(0x22), fill(0x33), fill(0x44), fill(0x55), fill(0x66), fill(0x88)
	schreib(t, filepath.Join(mdir, "lage"), ""+
		"name = Mandant\n"+
		"rahmen = 256\n"+
		"verzeichnis = "+verzeichnis.Hex()+"\n"+
		"vorgang = "+vorgang.Hex()+"\n"+
		"auffang = "+auffang.Hex()+"\n"+
		"einzel = "+einzel.Hex()+"\n"+
		"katalog = "+katalog.Hex()+"\n"+
		"kek = kek.pem\n"+
		"pruef = pruef.pem\n"+
		"deck = aus\n")
	schreib(t, filepath.Join(mdir, "katalog"),
		"gruppe "+gruppe.Hex()+" "+gruppe.Hex()+" Nord an\n"+
			"verzeichnis "+verzeichnis.Hex()+" "+verzeichnis.Hex()+" - an\n"+
			"vorgang "+vorgang.Hex()+" "+vorgang.Hex()+" - an\n"+
			"auffang "+auffang.Hex()+" "+auffang.Hex()+" - an\n"+
			"katalog "+katalog.Hex()+" "+katalog.Hex()+" - an\n")
	aussage := protocol.Aussage{Mandant: mandant, Person: "Ada", Rolle: protocol.RollePerson, Von: 1_000, Bis: 2_000}
	nutz, err := protocol.AussageBytes(aussage)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(pruef, nutz)
	if err != nil {
		t.Fatal(err)
	}
	schreib(t, filepath.Join(mdir, "personen", "Ada"), ""+
		"merkmal = gruppe\n"+
		"ablage = "+gruppe.Hex()+"\n"+
		"bind = "+gruppe.Hex()+"\n"+
		"kohorte = Nord\n"+
		"von = 1000\n"+
		"bis = 2000\n"+
		"signatur = "+hex.EncodeToString(sig[:])+"\n")

	konfig := filepath.Join(dir, "konfig")
	schreib(t, konfig, ""+
		"instanz = "+fill(0x77).Hex()+"\n"+
		"spool = "+filepath.Join(dir, "spool")+"\n"+
		"ereignis = 127.0.0.1:1\n"+
		"metrik = 127.0.0.1:2\n"+
		"ziel = platte\n"+
		"wurzel = "+filepath.Join(dir, "ziel")+"\n"+
		"plattform = plattform.pem\n"+
		"index = index.pem\n"+
		"signatur = signatur.pem\n"+
		"mandanten = mandanten\n"+
		"spool_grenze = 16777216\n"+
		"frist = 2m\n"+
		"puffer_warte = 20ms\n"+
		"segment = 262144\n"+
		"segment_warte = 10s\n"+
		"klasse = 262144\n"+
		"gruppe = 15m\n"+
		"sonstige = 15m\n")
	return dir
}

func dienstAus(t *testing.T, dir string) *Dienst {
	t.Helper()
	dienst, err := OeffnenDienst(filepath.Join(dir, "konfig"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = dienst.Prozess.Beenden(ctx)
	})
	return dienst
}

func TestKonfigUnvollstaendig(t *testing.T) {
	pfad := filepath.Join(t.TempDir(), "konfig")
	schreib(t, pfad, "ziel = platte\n")
	_, err := OeffnenDienst(pfad)
	if !errors.Is(err, ErrKonfig) {
		t.Fatal(err)
	}
}

func schreib(t *testing.T, pfad, inhalt string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(pfad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pfad, []byte(inhalt), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pemZertifikat(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func pemSchluessel(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
