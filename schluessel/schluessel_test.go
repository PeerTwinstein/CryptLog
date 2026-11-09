package schluessel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

func TestEinfacherModus(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	clock := jetzt
	ca, v, mandant := verwaltungEinfach(t, func() time.Time { return clock })
	anker, err := ca.Fingerabdruck()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.AnkerQuittieren(mandant, "Ada", protocol.Hash{1}); !errors.Is(err, ErrQuittung) {
		t.Fatalf("falscher anker %v", err)
	}
	if err := v.AnkerQuittieren(mandant, "Ada", anker); err != nil {
		t.Fatal(err)
	}

	privat := verschluesseltBeispiel(t)
	key := paeckchen(t)
	finger, raw, err := v.Hinterlegen(mandant, "Ada", Material{
		Oeffentlich: spki(t, &key.PublicKey), Privat: privat, Bis: jetzt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Festschreiben(mandant, raw, nil); !errors.Is(err, ErrEntwurf) {
		t.Fatalf("ohne quittung %v", err)
	}
	if err := v.Quittieren(mandant, "Ada", protocol.Hash{9}); !errors.Is(err, ErrQuittung) {
		t.Fatalf("falsche quittung %v", err)
	}
	if err := v.Quittieren(mandant, "Ada", finger); err != nil {
		t.Fatal(err)
	}
	if err := v.Festschreiben(mandant, raw, nil); err != nil {
		t.Fatal(err)
	}
	wurzel := v.sp.(*Verzeichnis).wurzel
	privatPfad := filepath.Join(wurzel, mandant.Hex(), "privat", hex.EncodeToString(finger[:]))
	got, err := os.ReadFile(privatPfad)
	if err != nil || !bytes.Equal(got, privat) {
		t.Fatalf("privat %v", err)
	}
	pub, _, da, err := v.sp.Lesen(mandant)
	if err != nil || !da || bytes.Contains(pub, privat) {
		t.Fatal("veröffentlichung enthält den privaten schlüssel oder fehlt")
	}

	var lesungen int
	quelle := quelleFunc(func(id protocol.ID) ([]byte, []byte, bool, error) {
		lesungen++
		return v.sp.Lesen(id)
	})
	cache := cacheAuf(t, quelle, func() time.Time { return clock }, "", nil, mandant, ca)
	sicht, err := cache.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || sicht.Finger != finger || sicht.Pub == nil {
		t.Fatalf("sicht %+v %v", sicht.Finger, err)
	}
	if _, err := cache.Oeffentlich(mandant); err != nil || lesungen != 1 {
		t.Fatalf("lesungen %d %v", lesungen, err)
	}
	clock = clock.Add(61 * time.Second)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || lesungen != 2 {
		t.Fatalf("erneut %+v %d %v", sicht.Vorhanden, lesungen, err)
	}

	nach := paeckchen(t)
	gezeigt, raw, err := v.StatusSetzen(mandant, "Ada", finger, StatusAbgeloest, &Material{
		Oeffentlich: spki(t, &nach.PublicKey), Privat: privat, Bis: clock.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Quittieren(mandant, "Ada", gezeigt); err != nil || v.Festschreiben(mandant, raw, nil) != nil {
		t.Fatal("nachfolger")
	}
	clock = clock.Add(61 * time.Second)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || sicht.Finger != gezeigt || sicht.Status[finger] != StatusAbgeloest {
		t.Fatalf("abgelöst %+v %v", sicht, err)
	}
	if _, ok := sicht.Status[gezeigt]; ok {
		t.Fatal("aktueller schlüssel steht im status")
	}

	weg, raw, err := v.StatusSetzen(mandant, "Ada", gezeigt, StatusVerloren, nil)
	if err != nil || weg != gezeigt {
		t.Fatal(err)
	}
	if err := v.Quittieren(mandant, "Ada", weg); err != nil || v.Festschreiben(mandant, raw, nil) != nil {
		t.Fatal("verloren")
	}
	clock = clock.Add(61 * time.Second)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden || sicht.Status[gezeigt] != StatusVerloren {
		t.Fatalf("kein kek %+v %v", sicht, err)
	}

	eintraege := protokoll(t, wurzel, mandant)
	if len(eintraege) != 3 || eintraege[0].Person != "Ada" || eintraege[0].Nummer != 1 || eintraege[2].Status != StatusVerloren {
		t.Fatalf("protokoll %+v", eintraege)
	}
	if eintraege[0].Neu != finger || eintraege[1].Bisher != finger || eintraege[1].Neu != gezeigt {
		t.Fatal("fingerabdrücke")
	}
}

func TestSichererModus(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 15, 0, 0, 0, time.UTC)
	clock := jetzt
	ca, server, v, mandant := verwaltungSicher(t, func() time.Time { return clock })
	anker, _ := ca.Fingerabdruck()
	if err := v.AnkerQuittieren(mandant, "Bea", anker); err != nil {
		t.Fatal(err)
	}
	blatt := blatt(t, ca, mandant, "Bea", jetzt, jetzt.Add(2*time.Hour), true)
	finger, err := crypt.FingerprintCertificate(blatt)
	if err != nil {
		t.Fatal(err)
	}
	gezeigt, raw, err := v.Hinterlegen(mandant, "Bea", Material{Zertifikat: blatt.Raw})
	if err != nil || gezeigt != finger {
		t.Fatal(err)
	}
	sig, err := Signieren(nil, ca.key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Quittieren(mandant, "Bea", finger); err != nil {
		t.Fatal(err)
	}
	if err := v.Festschreiben(mandant, raw, nil); !errors.Is(err, ErrSignatur) {
		t.Fatalf("ohne signatur %v", err)
	}
	if err := v.Festschreiben(mandant, raw, sig); err != nil {
		t.Fatal(err)
	}

	altRaw, altSig := append([]byte(nil), raw...), append([]byte(nil), sig...)
	um := &umschalt{innen: server}
	cache := cacheAuf(t, um, func() time.Time { return clock }, "", nil, mandant, ca)
	sicht, err := cache.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || sicht.Finger != finger {
		t.Fatalf("sicher %+v %v", sicht, err)
	}

	clock = clock.Add(61 * time.Second)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("abgelaufen %+v %v", sicht.Vorhanden, err)
	}
	summe, raw, err := v.Auffrischen(mandant, "Bea")
	if err != nil {
		t.Fatal(err)
	}
	sig, err = Signieren(nil, ca.key, raw)
	if err != nil || v.Quittieren(mandant, "Bea", summe) != nil || v.Festschreiben(mandant, raw, sig) != nil {
		t.Fatal("auffrischen")
	}
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || sicht.Finger != finger {
		t.Fatalf("frisch %+v %v", sicht, err)
	}

	fremd, err := NeueCA("fremd", clock, clock.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	falsch, err := Signieren(nil, fremd.key, raw)
	if err != nil {
		t.Fatal(err)
	}
	um.setzen(raw, falsch)
	clock = clock.Add(61 * time.Second)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("fremder anker %+v %v", sicht.Vorhanden, err)
	}
	um.loesen()

	gefasst, err := ParseVeroeffentlichung(raw)
	if err != nil {
		t.Fatal(err)
	}
	gefasst.Zeit = clock
	andere, err := gefasst.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	andereSig, err := Signieren(nil, ca.key, andere)
	if err != nil {
		t.Fatal(err)
	}
	um.setzen(andere, andereSig)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("gleiche nummer %+v %v", sicht.Vorhanden, err)
	}
	um.loesen()

	alt, err := ParseVeroeffentlichung(altRaw)
	if err != nil {
		t.Fatal(err)
	}
	alt.Zeit = clock
	altBytes, err := alt.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	altSig, err = Signieren(nil, ca.key, altBytes)
	if err != nil {
		t.Fatal(err)
	}
	um.setzen(altBytes, altSig)
	sicht, err = cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("kleinere nummer %+v %v", sicht.Vorhanden, err)
	}
}

func TestCacheFassung(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 16, 0, 0, 0, time.UTC)
	clock := jetzt
	ca, v, mandant := verwaltungEinfach(t, func() time.Time { return clock })
	anker, _ := ca.Fingerabdruck()
	if err := v.AnkerQuittieren(mandant, "Ada", anker); err != nil {
		t.Fatal(err)
	}
	key := paeckchen(t)
	finger, raw, err := v.Hinterlegen(mandant, "Ada", Material{
		Oeffentlich: spki(t, &key.PublicKey), Privat: verschluesseltBeispiel(t), Bis: jetzt.Add(2 * time.Hour),
	})
	if err != nil || v.Quittieren(mandant, "Ada", finger) != nil || v.Festschreiben(mandant, raw, nil) != nil {
		t.Fatal(err)
	}
	geheimnis := bytes.Repeat([]byte{7}, 32)
	pfad := filepath.Join(t.TempDir(), "cache")
	quelle := quelleFunc(func(id protocol.ID) ([]byte, []byte, bool, error) {
		return v.sp.Lesen(id)
	})
	cache := cacheAuf(t, quelle, func() time.Time { return clock }, pfad, geheimnis, mandant, ca)
	if _, err := cache.Oeffentlich(mandant); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pfad); err != nil {
		t.Fatal(err)
	}

	tot := quelleFunc(func(protocol.ID) ([]byte, []byte, bool, error) {
		return nil, nil, false, ErrQuelle
	})
	neu := cacheAuf(t, tot, func() time.Time { return clock }, pfad, geheimnis, mandant, ca)
	sicht, err := neu.Oeffentlich(mandant)
	if err != nil || !sicht.Vorhanden || sicht.Finger != finger {
		t.Fatalf("brücke %+v %v", sicht.Vorhanden, err)
	}

	verfälscht, err := os.ReadFile(pfad)
	if err != nil {
		t.Fatal(err)
	}
	verfälscht[len(verfälscht)-1] ^= 0xff
	if err := os.WriteFile(pfad, verfälscht, 0o600); err != nil {
		t.Fatal(err)
	}
	blind := cacheAuf(t, tot, func() time.Time { return clock }, pfad, geheimnis, mandant, ca)
	sicht, err = blind.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("verfälscht %+v %v", sicht.Vorhanden, err)
	}
	fremd := bytes.Repeat([]byte{9}, 32)
	if _, err := cache.Oeffentlich(mandant); err != nil {
		t.Fatal(err)
	}
	falsch := cacheAuf(t, tot, func() time.Time { return clock }, pfad, fremd, mandant, ca)
	sicht, err = falsch.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("fremder cache-schlüssel %+v %v", sicht.Vorhanden, err)
	}
	if _, err := NeuerCache(CacheKonfig{Quelle: tot, Pfad: pfad}); !errors.Is(err, ErrGeheimnis) {
		t.Fatalf("ohne geheimnis %v", err)
	}
}

func TestAblehnung(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 17, 0, 0, 0, time.UTC)
	ca, v, mandant := verwaltungEinfach(t, func() time.Time { return jetzt })
	anker, _ := ca.Fingerabdruck()
	if err := v.AnkerQuittieren(mandant, "Ada", anker); err != nil {
		t.Fatal(err)
	}
	schwach, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v.Hinterlegen(mandant, "Ada", Material{
		Oeffentlich: spki(t, &schwach.PublicKey), Privat: verschluesseltBeispiel(t), Bis: jetzt.Add(time.Hour),
	})
	if !errors.Is(err, ErrZertifikat) {
		t.Fatalf("rsa 2048 %v", err)
	}
	klar, err := x509.MarshalPKCS8PrivateKey(paeckchen(t))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v.Hinterlegen(mandant, "Ada", Material{
		Oeffentlich: spki(t, &paeckchen(t).PublicKey), Privat: klar, Bis: jetzt.Add(time.Hour),
	})
	if !errors.Is(err, ErrPrivat) {
		t.Fatalf("klartext %v", err)
	}
	_, _, err = v.Hinterlegen(mandant, "Ada", Material{Zertifikat: ca.Zertifikat().Raw})
	if !errors.Is(err, ErrModus) {
		t.Fatalf("modus %v", err)
	}

	key := paeckchen(t)
	finger, raw, err := v.Hinterlegen(mandant, "Ada", Material{
		Oeffentlich: spki(t, &key.PublicKey), Privat: verschluesseltBeispiel(t), Bis: jetzt.Add(time.Minute),
	})
	if err != nil || v.Quittieren(mandant, "Ada", finger) != nil || v.Festschreiben(mandant, raw, nil) != nil {
		t.Fatal(err)
	}
	cert := zertifikatAus(t, v, mandant)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: jetzt, NextUpdate: jetzt.Add(2 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber: cert.SerialNumber, RevocationTime: jetzt,
		}},
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	summe, raw, err := v.Sperrliste(mandant, "Ada", crl)
	if err != nil || v.Quittieren(mandant, "Ada", summe) != nil || v.Festschreiben(mandant, raw, nil) != nil {
		t.Fatal(err)
	}
	clock := jetzt.Add(61 * time.Second)
	cache := cacheAuf(t, v.sp, func() time.Time { return clock }, "", nil, mandant, ca)
	sicht, err := cache.Oeffentlich(mandant)
	if err != nil || sicht.Vorhanden {
		t.Fatalf("gesperrt %+v %v", sicht.Vorhanden, err)
	}
}

func TestHTTPUndGrenze(t *testing.T) {
	jetzt := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	ca, server, v, mandant := verwaltungSicher(t, func() time.Time { return jetzt })
	anker, _ := ca.Fingerabdruck()
	if err := v.AnkerQuittieren(mandant, "Bea", anker); err != nil {
		t.Fatal(err)
	}
	blatt := blatt(t, ca, mandant, "Bea", jetzt, jetzt.Add(time.Hour), true)
	finger, raw, err := v.Hinterlegen(mandant, "Bea", Material{Zertifikat: blatt.Raw})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Signieren(nil, ca.key, raw)
	if err != nil || v.Quittieren(mandant, "Bea", finger) != nil || v.Festschreiben(mandant, raw, sig) != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(server)
	defer httpSrv.Close()
	pub, gotSig, da, err := (HTTPQuelle{Basis: httpSrv.URL}).Lesen(mandant)
	if err != nil || !da || !bytes.Equal(pub, raw) || !bytes.Equal(gotSig, sig) {
		t.Fatalf("http %v %v", da, err)
	}
	anderer := protocol.ID{2}
	if _, _, da, err := (HTTPQuelle{Basis: httpSrv.URL}).Lesen(anderer); err != nil || da {
		t.Fatalf("fremd %v %v", da, err)
	}
	if _, err := cacheAuf(t, server, func() time.Time { return jetzt }, "", nil, anderer, ca).Oeffentlich(mandant); !errors.Is(err, ErrMandant) {
		t.Fatalf("mandant %v", err)
	}
}

type quelleFunc func(protocol.ID) ([]byte, []byte, bool, error)

func (f quelleFunc) Lesen(id protocol.ID) ([]byte, []byte, bool, error) { return f(id) }

type umschalt struct {
	mu      sync.Mutex
	innen   Quelle
	pub     []byte
	sig     []byte
	zwingen bool
}

func (u *umschalt) setzen(pub, sig []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pub, u.sig, u.zwingen = append([]byte(nil), pub...), append([]byte(nil), sig...), true
}

func (u *umschalt) loesen() {
	u.mu.Lock()
	u.zwingen = false
	u.mu.Unlock()
}

func (u *umschalt) Lesen(id protocol.ID) ([]byte, []byte, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.zwingen {
		return append([]byte(nil), u.pub...), append([]byte(nil), u.sig...), true, nil
	}
	return u.innen.Lesen(id)
}

func verwaltungEinfach(t *testing.T, jetzt func() time.Time) (*CA, *Verwaltung, protocol.ID) {
	t.Helper()
	anfang := jetzt()
	ca, err := NeueCA("lokal", anfang, anfang.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	verz, err := OeffnenVerzeichnis(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := NeueVerwaltung(VerwKonfig{Speicher: verz, CA: ca, Jetzt: jetzt})
	if err != nil {
		t.Fatal(err)
	}
	mandant := protocol.ID{1}
	if _, err := v.Anlegen(mandant, ModusEinfach, "Ada", ca.Zertifikat()); err != nil {
		t.Fatal(err)
	}
	return ca, v, mandant
}

func verwaltungSicher(t *testing.T, jetzt func() time.Time) (*CA, *Server, *Verwaltung, protocol.ID) {
	t.Helper()
	anfang := jetzt()
	ca, err := NeueCA("anker", anfang, anfang.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NeuerServer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := NeueVerwaltung(VerwKonfig{Speicher: server, Jetzt: jetzt})
	if err != nil {
		t.Fatal(err)
	}
	mandant := protocol.ID{3}
	if _, err := v.Anlegen(mandant, ModusSicher, "Bea", ca.Zertifikat()); err != nil {
		t.Fatal(err)
	}
	return ca, server, v, mandant
}

func cacheAuf(t *testing.T, quelle Quelle, jetzt func() time.Time, pfad string, geheimnis []byte, mandant protocol.ID, ca *CA) *Cache {
	t.Helper()
	name := "Ada"
	if mandant == (protocol.ID{3}) {
		name = "Bea"
	}
	c, err := NeuerCache(CacheKonfig{
		Quelle: quelle, Pfad: pfad, Geheimnis: geheimnis, Jetzt: jetzt,
		Mandanten: map[protocol.ID]Mandant{
			mandant: {Modus: modusVon(t, ca, mandant), Name: name, Anker: ca.Zertifikat()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func modusVon(t *testing.T, ca *CA, mandant protocol.ID) Modus {
	t.Helper()
	if mandant == (protocol.ID{3}) {
		return ModusSicher
	}
	return ModusEinfach
}

func paeckchen(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func spki(t *testing.T, pub any) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func blatt(t *testing.T, ca *CA, mandant protocol.ID, name string, jetzt, bis time.Time, kek bool) *x509.Certificate {
	t.Helper()
	cert, err := ca.Ausstellen(&paeckchen(t).PublicKey, mandant, name, bis, jetzt, kek)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func verschluesseltBeispiel(t *testing.T) []byte {
	t.Helper()
	type algo struct {
		OID asn1.ObjectIdentifier
	}
	type info struct {
		Algo algo
		Data []byte
	}
	b, err := asn1.Marshal(info{
		Algo: algo{OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}},
		Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func protokoll(t *testing.T, wurzel string, id protocol.ID) []Eintrag {
	t.Helper()
	ein, err := leseProtokoll(filepath.Join(wurzel, id.Hex()))
	if err != nil {
		t.Fatal(err)
	}
	return ein
}

func zertifikatAus(t *testing.T, v *Verwaltung, id protocol.ID) *x509.Certificate {
	t.Helper()
	st, err := v.sp.Stand(id)
	if err != nil {
		t.Fatal(err)
	}
	gefasst, err := ParseVeroeffentlichung(st.Pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range gefasst.Zertifikate {
		if z.Status == StatusAktuell {
			cert, err := x509.ParseCertificate(z.DER)
			if err != nil {
				t.Fatal(err)
			}
			return cert
		}
	}
	t.Fatal("kein aktuelles zertifikat")
	return nil
}
