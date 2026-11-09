package oberflaeche

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cryptlog/fenster"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/schreiben"
	"cryptlog/werkzeug"
)

func TestOeffnenUndEntsperren(t *testing.T) {
	dir := t.TempDir()
	kek := paar(t)
	pruef := paar(t)
	hsm := paar(t)
	best := paar(t)
	cert := zertifikat(t, kek)
	schreibenPEM(t, filepath.Join(dir, "kek.pem"), "CERTIFICATE", cert.Raw)
	schreibenPEM(t, filepath.Join(dir, "pruef.pem"), "PUBLIC KEY", spki(t, &pruef.PublicKey))
	schreibenPEM(t, filepath.Join(dir, "hsm.pem"), "PUBLIC KEY", spki(t, &hsm.PublicKey))
	schreibenPEM(t, filepath.Join(dir, "best.pem"), "PUBLIC KEY", spki(t, &best.PublicKey))
	roh, err := fenster.Verschluesseln(rand.Reader, kek, []byte("geheim"), fenster.Kosten{Passes: 1, Memory: 8, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "kek.pk8"), roh, 0o600); err != nil {
		t.Fatal(err)
	}
	ziel := filepath.Join(dir, "ziel")
	v := fenster.Verbindung{
		Ziel: fenster.ZielPlatte, Pfad: ziel,
		Mandant: idVon(1), Zone: idVon(2), Katalog: idVon(3),
		KEK: filepath.Join(dir, "kek.pk8"), Zertifikat: filepath.Join(dir, "kek.pem"),
		Bestaetigung: filepath.Join(dir, "best.pk8"),
	}
	pfad := filepath.Join(dir, "verbindung")
	if err = fenster.Ablegen(pfad, v); err != nil {
		t.Fatal(err)
	}
	vorlage, err := LesenVorlage(pfad)
	if err != nil {
		t.Fatal(err)
	}
	if vorlage.Modus != schluessel.ModusEinfach || vorlage.Pruef == "" || vorlage.HSM == "" || vorlage.Bestaetigung == "" {
		t.Fatalf("vorlage %+v", vorlage)
	}
	if vorlage.Speicher != filepath.Join(dir, "bestaetigung") {
		t.Fatal(vorlage.Speicher)
	}
	sitz, err := Oeffnen(Angaben{
		Vorlage: vorlage, Status: werkzeug.StatusAktuell, Rahmen: 256,
		Intervall: time.Hour, Frist: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sitz.Schliessen()
	if err = sitz.Fenster.Einfach([]byte("geheim")); err != nil {
		t.Fatal(err)
	}
	if sitz.Fenster.Sicht().Modus != schluessel.ModusEinfach {
		t.Fatal(sitz.Fenster.Sicht())
	}
	if _, err = PrivaterSchluessel(filepath.Join(dir, "hsm.pem")); err == nil {
		t.Fatal("öffentlicher Schlüssel")
	}
}

func TestMandanten(t *testing.T) {
	dir := t.TempDir()
	platte, err := schreiben.OeffnenPlatte(dir)
	if err != nil {
		t.Fatal(err)
	}
	mandant, ablage := idVon(4), idVon(5)
	var instanz protocol.ID
	instanz[0] = 9
	var prefix protocol.Prefix
	prefix[0] = 3
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 8, 20, 0, 0, 0, time.UTC), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	key, err := protocol.ObjektSchluessel(mandant, ablage, epoch, 1)
	if err != nil {
		t.Fatal(err)
	}
	voll := filepath.Join(dir, filepath.FromSlash(key))
	if err = os.MkdirAll(filepath.Dir(voll), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(voll, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := plattenZiel{platte}.Mandanten()
	if err != nil || len(got) != 1 || got[0] != mandant {
		t.Fatal(got, err)
	}
}

func TestBestaetigenGruppen(t *testing.T) {
	var ablage protocol.ID
	ablage[0] = 7
	erg := &fenster.Ergebnis{Befunde: []fenster.Befund{
		{Ablage: ablage, Rolle: protocol.RolleGruppe, Luecke: true, Epoch: protocol.EpochID{2}},
		{Ablage: ablage, Rolle: protocol.RolleGruppe, Epoch: protocol.EpochID{1}},
		{Ablage: ablage, Rolle: protocol.RolleGruppe, Verzweigung: true, Epoch: protocol.EpochID{3}},
	}}
	gruppen := bestaetigenGruppen(erg)
	if len(gruppen) != 1 || len(gruppen[0].epochen) != 2 {
		t.Fatal(gruppen)
	}
}

func paar(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func zertifikat(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func spki(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func schreibenPEM(t *testing.T, pfad, art string, der []byte) {
	t.Helper()
	if err := os.WriteFile(pfad, pem.EncodeToMemory(&pem.Block{Type: art, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func idVon(b byte) protocol.ID {
	var id protocol.ID
	id[0] = b
	return id
}
