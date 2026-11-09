package werkzeug_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestPruefenAuswahl(t *testing.T) {
	w := logEpoche(t, []string{"eins", "zwei"}, true, false)
	a := w.auftrag(werkzeug.StatusAktuell)
	a.Auswahl = []uint64{w.seqs[0][0]}
	got, err := werkzeug.Pruefen(a)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Vertraulich || got.Luecke || got.Verzweigung || got.VorgaengerBruch || got.Bind != w.bind {
		t.Fatalf("%+v", got)
	}
	if got.EpochHash != w.epochHash || got.Fingerabdruck != w.fp || len(got.Eintraege) != 1 {
		t.Fatalf("hash %d einträge", len(got.Eintraege))
	}
	if string(got.Eintraege[0].Text) != "eins" || !got.Eintraege[0].Gueltig || got.Eintraege[0].Seq != w.seqs[0][0] {
		t.Fatalf("%+v", got.Eintraege[0])
	}
	if !bytes.Equal(seqListe(got.Geoeffnet), seqListe(w.seqs[0])) {
		t.Fatalf("geöffnet %v, Ereignis %v", got.Geoeffnet, w.seqs[0])
	}
	for _, seq := range w.seqs[1] {
		for _, offen := range got.Geoeffnet {
			if offen == seq {
				t.Fatalf("zweiter Eintrag geöffnet: %d", seq)
			}
		}
	}

	a.Auswahl = nil
	a.Alles = true
	alle, err := werkzeug.Pruefen(a)
	if err != nil || len(alle.Eintraege) != 2 || string(alle.Eintraege[1].Text) != "zwei" || len(alle.Geoeffnet) != int(alle.EintragZahl) {
		t.Fatalf("alle %d %v", len(alle.Eintraege), err)
	}

	a.Alles = false
	kette, err := werkzeug.Pruefen(a)
	if err != nil || len(kette.Eintraege) != 0 || len(kette.Geoeffnet) != 0 || kette.EpochHash != w.epochHash {
		t.Fatalf("nur kette %v", err)
	}

	a.Auswahl = []uint64{kette.EintragZahl}
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrAuswahl) {
		t.Fatalf("füllung %v", err)
	}
}

type oeffner struct{ priv crypto.PrivateKey }

func (o oeffner) Unwrap(wrapped, ctx []byte) ([]byte, error) {
	return crypt.Unwrap(o.priv, wrapped, ctx)
}

func TestOeffner(t *testing.T) {
	w := logEpoche(t, []string{"eins"}, true, false)
	a := w.auftrag(werkzeug.StatusAktuell)
	a.Oeffner = oeffner{priv: a.Priv}
	a.Priv = nil
	a.Alles = true
	got, err := werkzeug.Pruefen(a)
	if err != nil || len(got.Eintraege) != 1 || string(got.Eintraege[0].Text) != "eins" {
		t.Fatalf("%v %+v", err, got)
	}
	a.Priv = w.kek
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrSchluessel) {
		t.Fatalf("beides %v", err)
	}
}

func TestBefunde(t *testing.T) {
	w := logEpoche(t, []string{"eins"}, true, false)
	a := w.auftrag(werkzeug.StatusAktuell)

	kaputt := append([]werkzeug.Segment(nil), a.Segmente...)
	roh := append([]byte(nil), kaputt[0].Bytes...)
	roh[300] ^= 1
	kaputt[0].Bytes = roh
	a.Segmente = kaputt
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrKette) {
		t.Fatalf("kette %v", err)
	}

	a = w.auftrag(werkzeug.StatusAktuell)
	a.Vorgaenger[0] ^= 1
	bruch, err := werkzeug.Pruefen(a)
	if err != nil || !bruch.VorgaengerBruch || len(bruch.Eintraege) != 0 {
		t.Fatalf("vorgänger %+v %v", bruch, err)
	}

	a = w.auftrag(werkzeug.StatusAktuell)
	a.Bestaetigung = nil
	luecke, err := werkzeug.Pruefen(a)
	if err != nil || !luecke.Luecke || len(luecke.Eintraege) != 0 {
		t.Fatalf("lücke %+v %v", luecke, err)
	}

	a = w.auftrag(werkzeug.StatusAktuell)
	var andere protocol.Hash
	andere[0] = 9
	sig, err := crypt.SignP256(w.best, protocol.ConfirmationPayload(andere))
	if err != nil {
		t.Fatal(err)
	}
	a.AbschlussHash = andere
	a.BestaetigungsSignatur = sig
	zweig, err := werkzeug.Pruefen(a)
	if err != nil || !zweig.Verzweigung || len(zweig.Eintraege) != 0 {
		t.Fatalf("verzweigung %+v %v", zweig, err)
	}

	a = w.auftrag(werkzeug.StatusAktuell)
	a.Auswahl = []uint64{w.seqs[0][0]}
	nutz := protocol.ManifestPayload(w.epoch, w.previous, w.kette, a.Auswahl[0], 1, 1, protocol.Hash{9})
	zs, err := crypt.SignP256(w.hsm, nutz)
	if err != nil {
		t.Fatal(err)
	}
	a.Zweige = []werkzeug.Zweig{{Nutzlast: nutz, Signatur: zs}}
	neben, err := werkzeug.Pruefen(a)
	if err != nil || !neben.Verzweigung || len(neben.Eintraege) != 1 {
		t.Fatalf("nebenfassung %+v %v", neben, err)
	}

	a = w.auftrag(werkzeug.StatusVerloren)
	a.Auswahl = []uint64{w.seqs[0][0]}
	verloren, err := werkzeug.Pruefen(a)
	if err != nil || !verloren.Verloren || verloren.Vertraulich || len(verloren.Eintraege) != 0 {
		t.Fatalf("verloren %+v %v", verloren, err)
	}

	a = w.auftrag(werkzeug.StatusKompromittiert)
	a.Auswahl = []uint64{w.seqs[0][0]}
	offen, err := werkzeug.Pruefen(a)
	if err != nil || !offen.Kompromittiert || offen.Vertraulich || len(offen.Eintraege) != 1 {
		t.Fatalf("kompromittiert %+v %v", offen, err)
	}

	a = w.auftrag(werkzeug.StatusAbgeloest)
	a.Auswahl = []uint64{w.seqs[0][0]}
	a.RasterEnde = 1499
	raster, err := werkzeug.Pruefen(a)
	if err != nil || !raster.Vertraulich || !raster.Eintraege[0].NachRaster || !raster.Eintraege[0].Gueltig {
		t.Fatalf("raster %+v %v", raster.Eintraege, err)
	}

	fremd := schluessel(t)
	fremdCert, _ := zertifikat(t, fremd)
	a = w.auftrag(werkzeug.StatusAktuell)
	a.Zertifikat = fremdCert
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrFinger) {
		t.Fatalf("finger %v", err)
	}
	a.Zertifikat = w.cert
	a.HSM = &fremd.PublicKey
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrSignatur) {
		t.Fatalf("hsm %v", err)
	}
}

func TestAussageUndAuffang(t *testing.T) {
	schlecht := logEpoche(t, []string{"eins"}, false, false)
	a := schlecht.auftrag(werkzeug.StatusAktuell)
	a.Auswahl = []uint64{schlecht.seqs[0][0]}
	got, err := werkzeug.Pruefen(a)
	if err != nil || len(got.Eintraege) != 1 || got.Eintraege[0].Gueltig {
		t.Fatalf("aussage %+v %v", got.Eintraege, err)
	}

	fremd := logEpoche(t, []string{"eins"}, true, true)
	a = fremd.auftrag(werkzeug.StatusAktuell)
	a.Auswahl = []uint64{fremd.seqs[0][0]}
	got, err = werkzeug.Pruefen(a)
	if err != nil || got.Eintraege[0].Gueltig || got.Eintraege[0].Bind == fremd.bind {
		t.Fatalf("bind %+v %v", got.Eintraege, err)
	}

	auf := auffangEpoche(t, protocol.GrundUnbekannt, false)
	a = auf.auftrag(werkzeug.StatusAktuell)
	a.Rolle = protocol.RolleAuffang
	a.Auswahl = []uint64{auf.seqs[0][0]}
	a.Pruef = nil
	got, err = werkzeug.Pruefen(a)
	if err != nil || !got.Eintraege[0].Gueltig || !got.Eintraege[0].Unzugeordnet || got.Eintraege[0].Grund != protocol.GrundUnbekannt || string(got.Eintraege[0].Text) != "tot" {
		t.Fatalf("auffang %+v %v", got.Eintraege, err)
	}

	ziel := auffangEpoche(t, protocol.GrundZielFehlt, true)
	a = ziel.auftrag(werkzeug.StatusAktuell)
	a.Rolle = protocol.RolleAuffang
	a.Auswahl = []uint64{ziel.seqs[0][0]}
	got, err = werkzeug.Pruefen(a)
	if err != nil || !got.Eintraege[0].Gueltig || got.Eintraege[0].Grund != protocol.GrundZielFehlt {
		t.Fatalf("ziel %+v %v", got.Eintraege, err)
	}
}

type welt struct {
	mandant, ablage, bind protocol.ID
	epoch                 protocol.EpochID
	kek, hsm, best, pruef *ecdsa.PrivateKey
	cert                  *x509.Certificate
	fp                    protocol.Hash
	segs                  []werkzeug.Segment
	seqs                  [][]uint64
	previous, epochHash   protocol.Hash
	kette                 protocol.Hash
	confirm               protocol.Signature
	rahmen                int
}

func (w welt) auftrag(status werkzeug.Status) werkzeug.Auftrag {
	return werkzeug.Auftrag{
		Mandant:               w.mandant,
		Ablage:                w.ablage,
		Epoch:                 w.epoch,
		Rahmen:                w.rahmen,
		Rolle:                 protocol.RolleGruppe,
		Segmente:              w.segs,
		HSM:                   &w.hsm.PublicKey,
		Bestaetigung:          &w.best.PublicKey,
		BestaetigungsSignatur: w.confirm,
		AbschlussHash:         w.epochHash,
		Vorgaenger:            w.previous,
		Zertifikat:            w.cert,
		Priv:                  w.kek,
		Pruef:                 &w.pruef.PublicKey,
		Status:                status,
	}
}

func logEpoche(t *testing.T, texte []string, sigOK, fremdBind bool) welt {
	t.Helper()
	w := basis(t)
	ep := oeffnen(t, w)
	for i, text := range texte {
		teil := aussage(t, w, sigOK || i > 0)
		bind := w.bind
		if fremdBind {
			bind = fill(0x99)
		}
		var event protocol.ID
		event[0] = byte(0x10 + i)
		klar, err := protocol.EreignisKlartext(event, 1500, bind, logInhalt(t, text, teil))
		if err != nil {
			t.Fatal(err)
		}
		_, glieder, err := ep.Ereignis(klar)
		if err != nil {
			t.Fatal(err)
		}
		var seqs []uint64
		for _, g := range glieder {
			seqs = append(seqs, g.Seq)
		}
		w.seqs = append(w.seqs, seqs)
	}
	w.abschluss(t, ep)
	return w
}

func auffangEpoche(t *testing.T, grund protocol.Grund, mitAussage bool) welt {
	t.Helper()
	w := basis(t)
	ep := oeffnen(t, w)
	var teile []protocol.AussageTeil
	var personen []string
	if mitAussage {
		teile = []protocol.AussageTeil{aussage(t, w, true)}
		personen = []string{"Ada"}
	} else if grund != protocol.GrundOhneBezug {
		personen = []string{"Cleo"}
	}
	inhalt, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:    grund,
		Text:     []byte("tot"),
		Personen: personen,
		Aussagen: teile,
	})
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.ID
	event[0] = 0x61
	klar, err := protocol.EreignisKlartext(event, 1500, w.bind, inhalt)
	if err != nil {
		t.Fatal(err)
	}
	_, glieder, err := ep.Ereignis(klar)
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, g := range glieder {
		seqs = append(seqs, g.Seq)
	}
	w.seqs = [][]uint64{seqs}
	w.abschluss(t, ep)
	return w
}

func (w *welt) abschluss(t *testing.T, ep *epoch.Epoche) {
	t.Helper()
	hsm := w.hsm
	erg, err := ep.Abschluss(w.previous, 1, 1, protocol.Hash{7}, func(p []byte) (protocol.Signature, error) {
		return crypt.SignP256(hsm, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(w.best, protocol.ConfirmationPayload(erg.EpochHash))
	if err != nil {
		t.Fatal(err)
	}
	w.segs = make([]werkzeug.Segment, len(erg.Segmente))
	for i, seg := range erg.Segmente {
		w.segs[i] = werkzeug.Segment{Schluessel: seg.Schluessel, Bytes: seg.Bytes}
	}
	w.epochHash = erg.EpochHash
	w.kette = erg.Kettenkopf
	w.confirm = sig
}

func basis(t *testing.T) welt {
	t.Helper()
	kek, hsm, best, pruef := schluessel(t), schluessel(t), schluessel(t), schluessel(t)
	cert, fp := zertifikat(t, kek)
	mandant, ablage := fill(0x11), fill(0x22)
	var prefix protocol.Prefix
	if _, err := rand.Read(prefix[:]); err != nil {
		t.Fatal(err)
	}
	id, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC), fill(0x44), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return welt{
		mandant:  mandant,
		ablage:   ablage,
		bind:     ablage,
		epoch:    id,
		kek:      kek,
		hsm:      hsm,
		best:     best,
		pruef:    pruef,
		cert:     cert,
		fp:       fp,
		previous: protocol.Genesis(ablage, id.Instanz()),
		rahmen:   256,
	}
}

func oeffnen(t *testing.T, w welt) *epoch.Epoche {
	t.Helper()
	var dek crypt.DEK
	if _, err := rand.Read(dek[:]); err != nil {
		t.Fatal(err)
	}
	var dekID protocol.ID
	dekID[0] = 0xee
	wrapped, err := crypt.WrapDEK(nil, &w.kek.PublicKey, dek, w.bind, protocol.WrapContext(w.mandant, w.ablage, w.epoch, w.fp))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: w.mandant,
		Ablage:  w.ablage,
		DekID:   dekID,
		Epoch:   w.epoch,
		KEK:     w.fp,
		Wrapped: wrapped,
		DEK:     dek,
		Rahmen:  w.rahmen,
		Klasse:  protocol.Segment256KiB,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func aussage(t *testing.T, w welt, ok bool) protocol.AussageTeil {
	t.Helper()
	nutz := protocol.Aussage{Mandant: w.mandant, Person: "Ada", Rolle: protocol.RollePerson, Von: 1000, Bis: 5000}
	raw, err := protocol.AussageBytes(nutz)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(w.pruef, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		sig[0] ^= 0xff
	}
	return protocol.AussageTeil{Nutzlast: nutz, Signatur: append([]byte(nil), sig[:]...)}
}

func logInhalt(t *testing.T, text string, teil protocol.AussageTeil) []byte {
	t.Helper()
	inhalt, err := protocol.LogBytes(protocol.LogInhalt{
		Text:     []byte(text),
		Vorgang:  "V-1",
		Aussagen: []protocol.AussageTeil{teil},
		Bezuege:  []string{"Ada"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return inhalt
}

func zertifikat(t *testing.T, key *ecdsa.PrivateKey) (*x509.Certificate, protocol.Hash) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kek"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	return cert, fp
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

func seqListe(s []uint64) []byte {
	var b []byte
	for _, n := range s {
		b = append(b, byte(n))
	}
	return b
}
