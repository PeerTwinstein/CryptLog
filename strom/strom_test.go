package strom_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/strom"
)

func TestZuordnungGruppe(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	reg := memReg{
		"Ada": eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
		"Bea": eintrag(t, key, mandant, "Bea", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
	}
	ev := ereignis(mandant, "V-1", "Ada", "Bea")
	z, err := strom.Zuordnen(ev, strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if z.Wrap != strom.WrapMandant || z.Mandant != mandant || len(z.Ziele) != 1 {
		t.Fatalf("wrap %d ziele %d", z.Wrap, len(z.Ziele))
	}
	ziel := z.Ziele[0]
	if ziel.Rolle != protocol.RolleGruppe || ziel.Ablage != fill(0x22) || ziel.Kohorte != "Nord" || ziel.Grund != 0 {
		t.Fatalf("ziel %+v", ziel)
	}
	log, err := protocol.ParseLog(ziel.Inhalt)
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Aussagen) != 2 || len(log.Bezuege) != 2 || log.Bezuege[0] != "Ada" || log.Vorgang != "V-1" || string(log.Text) != "text" {
		t.Fatalf("log %+v", log)
	}
	nochmal, err := strom.Zuordnen(ev, strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey})
	if err != nil || nochmal.Hash != z.Hash {
		t.Fatal("hash")
	}
}

func TestZweiKohorten(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	reg := memReg{
		"Ada": eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
		"Bea": eintrag(t, key, mandant, "Bea", protocol.MerkmalGruppe, fill(0x23), fill(0x23), "Sued"),
	}
	z, err := strom.Zuordnen(ereignis(mandant, "", "Ada", "Bea"), strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey})
	if err != nil || len(z.Ziele) != 2 || z.Ziele[0].Kohorte != "Nord" || z.Ziele[1].Kohorte != "Sued" {
		t.Fatalf("%d %v", len(z.Ziele), err)
	}
	for _, ziel := range z.Ziele {
		log, err := protocol.ParseLog(ziel.Inhalt)
		if err != nil || len(log.Aussagen) != 1 || len(log.Bezuege) != 2 {
			t.Fatalf("log %+v %v", log, err)
		}
	}
}

func TestEinzelnSchlucktGruppe(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	reg := memReg{
		"Ada": eintrag(t, key, mandant, "Ada", protocol.MerkmalEinzeln, fill(0x30), fill(0x31), ""),
		"Bea": eintrag(t, key, mandant, "Bea", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
	}
	z, err := strom.Zuordnen(ereignis(mandant, "V-1", "Ada", "Bea"), strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey})
	if err != nil || len(z.Ziele) != 1 {
		t.Fatalf("%d %v", len(z.Ziele), err)
	}
	ziel := z.Ziele[0]
	if ziel.Rolle != protocol.RolleEinzel || ziel.Bind != fill(0x31) || ziel.Ablage != fill(0x30) || ziel.Kohorte != "" {
		t.Fatalf("%+v", ziel)
	}
	log, err := protocol.ParseLog(ziel.Inhalt)
	if err != nil || len(log.Aussagen) != 1 || log.Aussagen[0].Nutzlast.Person != "Ada" || len(log.Bezuege) != 2 {
		t.Fatalf("%+v %v", log, err)
	}
}

func TestAuffangLagen(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	ada := eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord")
	reg := memReg{"Ada": ada}
	eingang := strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey}

	unbekannt, err := strom.Zuordnen(ereignis(mandant, "", "Cleo"), eingang)
	if err != nil || unbekannt.Ziele[0].Grund != protocol.GrundUnbekannt {
		t.Fatalf("unbekannt %v %+v", err, unbekannt.Ziele)
	}
	body, err := protocol.ParseAuffang(unbekannt.Ziele[0].Inhalt)
	if err != nil || len(body.Aussagen) != 0 || body.Personen[0] != "Cleo" {
		t.Fatalf("%+v %v", body, err)
	}

	ada.Signatur[0] ^= 0xff
	reg["Ada"] = ada
	ungueltig, err := strom.Zuordnen(ereignis(mandant, "", "Ada"), eingang)
	if err != nil || ungueltig.Ziele[0].Grund != protocol.GrundAussageUngueltig {
		t.Fatalf("signatur %v %+v", err, ungueltig.Ziele)
	}

	ada = eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord")
	reg["Ada"] = ada
	ev := ereignis(mandant, "", "Ada")
	ev.Zeit = 1
	ausserhalb, err := strom.Zuordnen(ev, eingang)
	if err != nil || ausserhalb.Ziele[0].Grund != protocol.GrundAussageUngueltig {
		t.Fatalf("zeit %v", err)
	}

	ziel := ada
	ziel.ZielFehlt = true
	reg = memReg{"Ada": ziel}
	eingang.Register = reg
	fehlt, err := strom.Zuordnen(ereignis(mandant, "", "Ada"), eingang)
	if err != nil || fehlt.Ziele[0].Grund != protocol.GrundZielFehlt {
		t.Fatalf("ziel %v %+v", err, fehlt.Ziele)
	}
	body, err = protocol.ParseAuffang(fehlt.Ziele[0].Inhalt)
	if err != nil || len(body.Aussagen) != 1 || body.Aussagen[0].Nutzlast.Person != "Ada" {
		t.Fatalf("aussage %+v %v", body, err)
	}

	reg = memReg{"Ada": ada}
	eingang.Register = reg
	gemischt, err := strom.Zuordnen(ereignis(mandant, "", "Ada", "Cleo"), eingang)
	if err != nil || len(gemischt.Ziele) != 1 || gemischt.Ziele[0].Rolle != protocol.RolleGruppe {
		t.Fatalf("gemischt %v %+v", err, gemischt.Ziele)
	}
	log, err := protocol.ParseLog(gemischt.Ziele[0].Inhalt)
	if err != nil || len(log.Bezuege) != 2 || len(log.Aussagen) != 1 {
		t.Fatalf("bezug %+v %v", log, err)
	}

	ungueltigUndUnbekannt := memReg{}
	schlecht := ada
	schlecht.Signatur[0] ^= 0xff
	ungueltigUndUnbekannt["Ada"] = schlecht
	eingang.Register = ungueltigUndUnbekannt
	prio, err := strom.Zuordnen(ereignis(mandant, "", "Ada", "Cleo"), eingang)
	if err != nil || prio.Ziele[0].Grund != protocol.GrundAussageUngueltig {
		t.Fatalf("prio invalid %v", err)
	}
	frisch := eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord")
	frisch.ZielFehlt = true
	eingang.Register = memReg{"Ada": frisch}
	prio, err = strom.Zuordnen(ereignis(mandant, "", "Ada", "Cleo"), eingang)
	if err != nil || prio.Ziele[0].Grund != protocol.GrundUnbekannt {
		t.Fatalf("prio unbekannt %v %+v", err, prio.Ziele)
	}

	ohne, err := strom.Zuordnen(ereignis(mandant, "V-9"), strom.Eingang{KEKVorhanden: true})
	if err != nil || ohne.Ziele[0].Grund != protocol.GrundOhneBezug || ohne.Ziele[0].Vorgang != "V-9" {
		t.Fatalf("ohne %v %+v", err, ohne.Ziele)
	}
	stelle := strom.Stelle{Seq: 3}
	if _, _, err := ohne.Ziele[0].Nachweise(stelle, fill(0x70), fill(0x71)); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("bind leer %v", err)
	}
	ohne.Ziele[0].Bind = fill(0x40)
	verweise, index, err := ohne.Ziele[0].Nachweise(stelle, fill(0x70), fill(0x71))
	if err != nil || len(verweise) != 1 || index != nil {
		t.Fatalf("nur vorgang %d %v", len(verweise), err)
	}
	_, _, _, inhalt, err := protocol.ParseEreignisKlartext(verweise[0])
	if err != nil {
		t.Fatal(err)
	}
	zeig, err := protocol.ParseVerweis(inhalt)
	if err != nil || zeig.Art != protocol.VerweisVorgang || zeig.Schluessel != "V-9" || zeig.Seq != 3 || zeig.Bind != fill(0x40) {
		t.Fatalf("%+v %v", zeig, err)
	}
}

func TestMandantUndKEK(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	reg := memReg{"Ada": eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord")}
	ev := ereignis(mandant, "", "Ada")
	fehlt, err := strom.Zuordnen(ev, strom.Eingang{Register: reg, Pruef: &key.PublicKey})
	if err != nil || fehlt.Wrap != strom.WrapPlattform || fehlt.Mandant != mandant || fehlt.Ziele[0].Grund != protocol.GrundKEKFehlt {
		t.Fatalf("kek %v %+v", err, fehlt)
	}
	body, err := protocol.ParseAuffang(fehlt.Ziele[0].Inhalt)
	if err != nil || len(body.Aussagen) != 0 || body.Personen[0] != "Ada" {
		t.Fatalf("%+v %v", body, err)
	}
	ev.Mandant = protocol.ID{}
	ev.Angabe = "Niemand"
	plattform, err := strom.Zuordnen(ev, strom.Eingang{})
	if err != nil || plattform.Mandant != protocol.PlattformMandant() || plattform.Ziele[0].Grund != protocol.GrundMandantUnbekannt {
		t.Fatalf("plattform %v %+v", err, plattform)
	}
	body, err = protocol.ParseAuffang(plattform.Ziele[0].Inhalt)
	if err != nil || body.Angabe != "Niemand" {
		t.Fatalf("%+v %v", body, err)
	}
	ev.Mandant = mandant
	ev.Angabe = "Niemand"
	if _, err := strom.Zuordnen(ev, strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey}); !errors.Is(err, strom.ErrEreignis) {
		t.Fatalf("angabe %v", err)
	}
}

func TestRegisterUndAufruf(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	kaputt := eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x23), "Nord")
	if _, err := strom.Zuordnen(ereignis(mandant, "", "Ada"), strom.Eingang{KEKVorhanden: true, Register: memReg{"Ada": kaputt}, Pruef: &key.PublicKey}); !errors.Is(err, strom.ErrRegister) {
		t.Fatalf("bind %v", err)
	}
	if _, err := strom.Zuordnen(ereignis(mandant, "", "Ada", "Ada"), strom.Eingang{KEKVorhanden: true}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("doppelt %v", err)
	}
	if _, err := strom.Zuordnen(strom.Ereignis{Mandant: mandant}, strom.Eingang{KEKVorhanden: true}); !errors.Is(err, strom.ErrEreignis) {
		t.Fatalf("id %v", err)
	}
}

func TestKatalogSchreiben(t *testing.T) {
	mandant := fill(0x11)
	ep := oeffnen(t, mandant, fill(0x80))
	stand := protocol.Stand{
		Name: "Nordlicht",
		Kennungen: []protocol.Kennung{{
			Rolle:   protocol.RolleGruppe,
			Ablage:  fill(0x22),
			Bind:    fill(0x22),
			Kohorte: "Nord",
			Aktiv:   protocol.KennungAn,
		}},
	}
	var event protocol.ID
	event[0] = 0x91
	segs, eintraege, err := strom.KatalogSchreiben(strom.Bahn{Bind: fill(0x80), Epoche: ep}, event, 50, stand)
	if err != nil || len(segs) != 0 || len(eintraege) == 0 || eintraege[0].Event != event || eintraege[0].Art != protocol.ArtEreignis {
		t.Fatalf("%v %+v", err, eintraege)
	}
}

func TestSchreiben(t *testing.T) {
	mandant := fill(0x11)
	key := schluessel(t)
	reg := memReg{
		"Ada": eintrag(t, key, mandant, "Ada", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
		"Bea": eintrag(t, key, mandant, "Bea", protocol.MerkmalGruppe, fill(0x22), fill(0x22), "Nord"),
	}
	z, err := strom.Zuordnen(ereignis(mandant, "V-1", "Ada", "Bea"), strom.Eingang{KEKVorhanden: true, Register: reg, Pruef: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	log := oeffnen(t, mandant, fill(0x22))
	verzeichnis := oeffnen(t, mandant, fill(0x70))
	index := oeffnen(t, mandant, fill(0x71))
	bahnen := strom.Bahnen{
		Gruppe:      map[protocol.ID]strom.Bahn{fill(0x22): {Bind: fill(0x22), Epoche: log}},
		Verzeichnis: strom.Bahn{Bind: fill(0x70), Epoche: verzeichnis},
		Vorgang:     strom.Bahn{Bind: fill(0x71), Epoche: index},
	}
	if _, err := strom.Schreiben(z, strom.Bahnen{Gruppe: bahnen.Gruppe}); !errors.Is(err, strom.ErrBahn) {
		t.Fatalf("ohne verzeichnis %v", err)
	}
	probe, err := protocol.EreignisKlartext(fill(0x99), 1, fill(0x22), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, glieder, err := log.Ereignis(probe)
	if err != nil || len(glieder) != 1 || glieder[0].Seq != 1 {
		t.Fatalf("seq blieb nicht 1: %+v %v", glieder, err)
	}
	log = oeffnen(t, mandant, fill(0x22))
	bahnen.Gruppe[fill(0x22)] = strom.Bahn{Bind: fill(0x22), Epoche: log}
	geschrieben, err := strom.Schreiben(z, bahnen)
	if err != nil {
		t.Fatal(err)
	}
	if len(geschrieben.Segmente) != 0 {
		t.Fatalf("segmente %d", len(geschrieben.Segmente))
	}
	if len(geschrieben.Log) == 0 || geschrieben.Log[0].Seq != 1 || geschrieben.Log[0].Art != protocol.ArtEreignis || geschrieben.Log[0].Event != z.Ziele[0].Event {
		t.Fatalf("log %+v", geschrieben.Log)
	}
	var leer protocol.ID
	for _, e := range geschrieben.Log[1:] {
		if e.Art != protocol.ArtFortsetzung || e.Event != leer {
			t.Fatalf("fortsetzung %+v", geschrieben.Log)
		}
	}
	if len(geschrieben.Verzeichnis) != 3 || geschrieben.Verzeichnis[0].Seq != 1 || geschrieben.Verzeichnis[2].Seq != 3 {
		t.Fatalf("verzeichnis %+v", geschrieben.Verzeichnis)
	}
	if len(geschrieben.Index) != 2 || geschrieben.Index[0].Seq != 1 || geschrieben.Index[1].Event != z.Ziele[0].Event {
		t.Fatalf("index %+v", geschrieben.Index)
	}
	for _, e := range append(append([]protocol.SeqEintrag{}, geschrieben.Verzeichnis...), geschrieben.Index...) {
		if e.Event != z.Ziele[0].Event || e.Art != protocol.ArtEreignis {
			t.Fatalf("eintrag %+v", e)
		}
	}
}

func ereignis(mandant protocol.ID, vorgang string, personen ...string) strom.Ereignis {
	var id protocol.ID
	id[0] = 0x42
	return strom.Ereignis{
		ID:       id,
		Zeit:     1_500,
		Mandant:  mandant,
		Personen: personen,
		Vorgang:  vorgang,
		Text:     []byte("text"),
	}
}

func schluessel(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func eintrag(t *testing.T, key *ecdsa.PrivateKey, mandant protocol.ID, person string, merkmal protocol.Merkmal, ablage, bind protocol.ID, kohorte string) strom.Eintrag {
	t.Helper()
	a := protocol.Aussage{Mandant: mandant, Person: person, Rolle: protocol.RollePerson, Von: 1_000, Bis: 2_000}
	raw, err := protocol.AussageBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypt.SignP256(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	return strom.Eintrag{
		Merkmal:  merkmal,
		Ablage:   ablage,
		Bind:     bind,
		Kohorte:  kohorte,
		Rolle:    protocol.RollePerson,
		Von:      1_000,
		Bis:      2_000,
		Signatur: sig[:],
	}
}

type memReg map[string]strom.Eintrag

func (m memReg) Person(name string) (strom.Eintrag, bool, error) {
	e, ok := m[name]
	return e, ok, nil
}

type padReader struct{ b byte }

func (p padReader) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = p.b
	}
	return len(dst), nil
}

func fill(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func oeffnen(t *testing.T, mandant, ablage protocol.ID) *epoch.Epoche {
	t.Helper()
	var prefix protocol.Prefix
	prefix[0] = ablage[0]
	id, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC), fill(0x44), prefix)
	if err != nil {
		t.Fatal(err)
	}
	var dek crypt.DEK
	if _, err := rand.Read(dek[:]); err != nil {
		t.Fatal(err)
	}
	var dekID protocol.ID
	dekID[0] = ablage[0]
	dekID[1] = 0xee
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant,
		Ablage:  ablage,
		DekID:   dekID,
		Epoch:   id,
		KEK:     protocol.Hash{0xcd},
		Wrapped: bytes.Repeat([]byte{0x7e}, 32),
		DEK:     dek,
		Rahmen:  256,
		Klasse:  protocol.Segment256KiB,
		Rand:    padReader{0x5a},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ep
}
