package epoch_test

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
)

const rahmen = 8192

func testEpoch(t *testing.T) (protocol.ID, protocol.ID, protocol.ID, protocol.EpochID, protocol.Hash, []byte) {
	t.Helper()
	mandant := fill(0x11)
	ablage := fill(0x22)
	instanz := fill(0x44)
	var prefix protocol.Prefix
	prefix[0] = 0xab
	id, err := protocol.NewEpochID(time.Date(2026, 11, 6, 16, 0, 0, 0, time.UTC), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var kek protocol.Hash
	for i := range kek {
		kek[i] = 0xcd
	}
	return mandant, ablage, fill(0xee), id, kek, bytes.Repeat([]byte{0x7e}, 64)
}

func fill(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func oeffnen(t *testing.T, klasse int) (*epoch.Epoche, crypt.DEK, protocol.ID, protocol.ID, protocol.ID, protocol.EpochID, protocol.Hash, []byte) {
	t.Helper()
	mandant, ablage, dekID, id, kek, wrapped := testEpoch(t)
	var dek crypt.DEK
	if _, err := rand.Read(dek[:]); err != nil {
		t.Fatal(err)
	}
	ep, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant,
		Ablage:  ablage,
		DekID:   dekID,
		Epoch:   id,
		KEK:     kek,
		Wrapped: wrapped,
		DEK:     dek,
		Rahmen:  rahmen,
		Klasse:  klasse,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ep, dek, mandant, ablage, dekID, id, kek, wrapped
}

func signatur(t *testing.T) (*ecdsa.PrivateKey, func([]byte) (protocol.Signature, error)) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, func(p []byte) (protocol.Signature, error) {
		return crypt.SignP256(key, p)
	}
}

func klartext(t *testing.T, event byte, inhalt []byte) []byte {
	t.Helper()
	got, err := protocol.EreignisKlartext(fill(event), uint64(event), fill(0x22), inhalt)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestLeereEpocheKleinsteKlasse(t *testing.T) {
	ep, dek, mandant, ablage, dekID, id, kek, wrapped := oeffnen(t, protocol.Segment1MiB)
	key, sign := signatur(t)
	previous := protocol.Genesis(ablage, id.Instanz())
	erg, err := ep.Abschluss(previous, 0, 0, protocol.Hash{}, sign)
	if err != nil {
		t.Fatal(err)
	}
	if len(erg.Segmente) != 1 || len(erg.Segmente[0].Bytes) != protocol.Segment256KiB {
		t.Fatalf("segment %d", len(erg.Segmente[0].Bytes))
	}
	if erg.Segmente[0].Nr != 1 || erg.Eintraege != 30 || len(erg.Glieder) != 30 {
		t.Fatalf("nr %d einträge %d glieder %d", erg.Segmente[0].Nr, erg.Eintraege, len(erg.Glieder))
	}
	wantKey := mandant.Hex() + "/" + ablage.Hex() + "/" + id.String() + "/1"
	if erg.Segmente[0].Schluessel != wantKey || erg.Segmente[0].Hash != protocol.SegmentHash(erg.Segmente[0].Bytes) {
		t.Fatalf("schlüssel %s", erg.Segmente[0].Schluessel)
	}
	plains := pruefe(t, dek, mandant, ablage, dekID, id, kek, wrapped, erg)
	ereignisse, err := protocol.Lesen(plains)
	if err != nil || len(ereignisse) != 0 {
		t.Fatalf("lesen %d %v", len(ereignisse), err)
	}
	for _, p := range plains {
		if p[0] != byte(protocol.ArtFuellung) {
			t.Fatalf("art %d", p[0])
		}
	}
	if !crypt.VerifyP256(&key.PublicKey, erg.Nutzlast, erg.Signatur) {
		t.Fatal("signatur")
	}
	if _, _, err := ep.Ereignis([]byte("danach")); !errors.Is(err, epoch.ErrZustand) {
		t.Fatalf("danach %v", err)
	}
	if _, err := ep.Abschluss(previous, 0, 0, protocol.Hash{}, sign); !errors.Is(err, epoch.ErrZustand) {
		t.Fatalf("zweiter abschluss %v", err)
	}
}

func TestEreignisPasstInEinSegment(t *testing.T) {
	ep, dek, mandant, ablage, dekID, id, kek, wrapped := oeffnen(t, protocol.Segment256KiB)
	_, sign := signatur(t)
	var want [][]byte
	for i := byte(1); i <= 30; i++ {
		k := klartext(t, i, []byte{i})
		want = append(want, k)
		segs, glieder, err := ep.Ereignis(k)
		if err != nil || len(segs) != 0 || len(glieder) != 1 || glieder[0].Seq != uint64(i) || glieder[0].Art != protocol.ArtEreignis || glieder[0].Event != fill(i) {
			t.Fatalf("ereignis %d segs %d glieder %v %v", i, len(segs), glieder, err)
		}
	}
	previous := protocol.Genesis(ablage, id.Instanz())
	var kopf protocol.Hash
	kopf[0] = 9
	erg, err := ep.Abschluss(previous, 4, 9, kopf, sign)
	if err != nil {
		t.Fatal(err)
	}
	if len(erg.Segmente) != 1 || erg.Eintraege != 30 {
		t.Fatalf("segmente %d einträge %d", len(erg.Segmente), erg.Eintraege)
	}
	plains := pruefe(t, dek, mandant, ablage, dekID, id, kek, wrapped, erg)
	got, err := protocol.Lesen(plains)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("lesen %d", len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("klartext %d", i)
		}
	}
	nutz := protocol.ManifestPayload(id, previous, erg.Kettenkopf, erg.Eintraege, 4, 9, kopf)
	if !bytes.Equal(erg.Nutzlast, nutz) {
		t.Fatal("nutzlast")
	}
}

func TestEreignisUeberZweiSegmente(t *testing.T) {
	ep, dek, mandant, ablage, dekID, id, kek, wrapped := oeffnen(t, protocol.Segment256KiB)
	_, sign := signatur(t)
	for i := byte(1); i <= 30; i++ {
		if _, _, err := ep.Ereignis(klartext(t, i, []byte{i})); err != nil {
			t.Fatal(err)
		}
	}
	gross := klartext(t, 0x7f, bytes.Repeat([]byte{0x5a}, 9000))
	segs, glieder, err := ep.Ereignis(gross)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || segs[0].Nr != 1 || len(segs[0].Bytes) != protocol.Segment256KiB {
		t.Fatalf("schnitt %d", len(segs))
	}
	if len(glieder) != 2 || glieder[0].Art != protocol.ArtEreignis || glieder[0].Event != fill(0x7f) || glieder[1].Art != protocol.ArtFortsetzung || glieder[1].Event != (protocol.ID{}) || glieder[1].Seq != glieder[0].Seq+1 {
		t.Fatalf("glieder %+v", glieder)
	}
	erg, err := ep.Abschluss(protocol.Hash{}, 1, 1, protocol.Hash{3}, sign)
	if err != nil {
		t.Fatal(err)
	}
	if len(erg.Segmente) != 2 || erg.Segmente[1].Nr != 2 || len(erg.Segmente[1].Bytes) != protocol.Segment256KiB {
		t.Fatalf("zweites %d", len(erg.Segmente))
	}
	if erg.Segmente[1].Schluessel[len(erg.Segmente[1].Schluessel)-2:] != "/2" {
		t.Fatalf("schlüssel %s", erg.Segmente[1].Schluessel)
	}
	plains := pruefe(t, dek, mandant, ablage, dekID, id, kek, wrapped, erg)
	got, err := protocol.Lesen(plains)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 31 || !bytes.Equal(got[30], gross) {
		t.Fatalf("lesen %d", len(got))
	}
}

func TestSchnitt(t *testing.T) {
	ep, dek, mandant, ablage, dekID, id, kek, wrapped := oeffnen(t, protocol.Segment256KiB)
	_, sign := signatur(t)
	k := klartext(t, 1, []byte("a"))
	if _, _, err := ep.Ereignis(k); err != nil {
		t.Fatal(err)
	}
	seg, glieder, err := ep.Schnitt()
	if err != nil {
		t.Fatal(err)
	}
	if seg.Nr != 1 || len(seg.Bytes) != protocol.Segment256KiB || len(glieder) != 30 {
		t.Fatalf("schnitt nr %d glieder %d", seg.Nr, len(glieder))
	}
	for _, g := range glieder {
		if g.Art != protocol.ArtFuellung {
			t.Fatalf("art %d", g.Art)
		}
	}
	if _, _, err := ep.Ereignis(klartext(t, 2, []byte("b"))); err != nil {
		t.Fatal(err)
	}
	erg, err := ep.Abschluss(protocol.Hash{}, 1, 2, protocol.Hash{1}, sign)
	if err != nil {
		t.Fatal(err)
	}
	if len(erg.Segmente) != 2 || !bytes.Equal(erg.Segmente[0].Bytes, seg.Bytes) {
		t.Fatal("erstes segment")
	}
	plains := pruefe(t, dek, mandant, ablage, dekID, id, kek, wrapped, erg)
	got, err := protocol.Lesen(plains)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], k) {
		t.Fatalf("lesen %d", len(got))
	}
	_, kette, manifest, err := protocol.Zerlegen(erg.Segmente[0].Bytes, rahmen, true, false)
	if err != nil || manifest != nil || len(kette) != 31 {
		t.Fatalf("segment 1 kette %d %v", len(kette), err)
	}
	kopf, _, _, err := protocol.Zerlegen(erg.Segmente[1].Bytes, rahmen, false, true)
	if err != nil || kopf != nil {
		t.Fatalf("segment 2 kopf %d %v", len(kopf), err)
	}
}

func TestOeffnenGrenze(t *testing.T) {
	mandant, ablage, dekID, id, kek, wrapped := testEpoch(t)
	_, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant, Ablage: ablage, DekID: dekID, Epoch: id, KEK: kek, Wrapped: wrapped,
		Rahmen: 100, Klasse: protocol.Segment256KiB,
	})
	if !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("rahmen %v", err)
	}
	if _, err := epoch.Oeffnen(epoch.Config{
		Mandant: mandant, Ablage: ablage, DekID: dekID, Epoch: id, KEK: kek, Wrapped: wrapped,
		Rahmen: rahmen, Klasse: 1000,
	}); !errors.Is(err, protocol.ErrLength) {
		t.Fatalf("klasse %v", err)
	}
}

func TestVerwerfen(t *testing.T) {
	ep, _, _, _, _, _, _, _ := oeffnen(t, protocol.Segment256KiB)
	ep.Verwerfen()
	if ep.Offen() {
		t.Fatal("offen")
	}
	if _, _, err := ep.Ereignis(klartext(t, 1, []byte{1})); !errors.Is(err, epoch.ErrZustand) {
		t.Fatalf("ereignis %v", err)
	}
	ep.Verwerfen()
}

func TestSchnittOhneOffenesSegment(t *testing.T) {
	ep, _, _, _, _, _, _, _ := oeffnen(t, protocol.Segment256KiB)
	var geschlossen []epoch.Segment
	for i := byte(1); i <= 31; i++ {
		segs, _, err := ep.Ereignis(klartext(t, i, []byte{i}))
		if err != nil {
			t.Fatal(err)
		}
		geschlossen = append(geschlossen, segs...)
	}
	if len(geschlossen) != 1 || geschlossen[0].Nr != 1 {
		t.Fatalf("geschlossen %d", len(geschlossen))
	}
	if _, _, err := ep.Schnitt(); !errors.Is(err, epoch.ErrSchnitt) {
		t.Fatalf("schnitt %v", err)
	}
}

func pruefe(t *testing.T, dek crypt.DEK, mandant, ablage, dekID protocol.ID, id protocol.EpochID, kek protocol.Hash, wrapped []byte, erg epoch.Ergebnis) [][]byte {
	t.Helper()
	chain, err := protocol.NewChain(mandant, ablage, id, dekID, kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	var plains [][]byte
	seq := uint64(1)
	for i, seg := range erg.Segmente {
		if seg.Hash != protocol.SegmentHash(seg.Bytes) {
			t.Fatalf("hash %d", seg.Nr)
		}
		letzter := i == len(erg.Segmente)-1
		_, kette, manifest, err := protocol.Zerlegen(seg.Bytes, rahmen, i == 0, letzter)
		if err != nil {
			t.Fatal(err)
		}
		if letzter {
			got, sig, err := protocol.ParseManifestRahmen(manifest)
			if err != nil || !bytes.Equal(got, erg.Nutzlast) || sig != erg.Signatur {
				t.Fatalf("manifest %v", err)
			}
		}
		for _, fr := range kette {
			var nonce protocol.Nonce
			copy(nonce[:], fr[:protocol.NonceLen])
			want := protocol.MakeNonce(id.Prefix(), seq)
			if nonce != want {
				t.Fatalf("nonce seq %d", seq)
			}
			ct := fr[protocol.NonceLen : len(fr)-protocol.TagLen]
			tag := fr[len(fr)-protocol.TagLen:]
			if err := chain.Append(seq, nonce, ct, tag); err != nil {
				t.Fatal(err)
			}
			plain, err := crypt.Open(dek, nonce, ct, tag, protocol.AAD(mandant, ablage, id, dekID, seq))
			if err != nil {
				t.Fatal(err)
			}
			plains = append(plains, plain)
			seq++
		}
	}
	head, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	count, err := chain.Count()
	if err != nil {
		t.Fatal(err)
	}
	if head != erg.Kettenkopf || count != erg.Eintraege || count != uint64(len(plains)) {
		t.Fatalf("kette %d/%d", count, erg.Eintraege)
	}
	hash, err := protocol.EpochHash(erg.Nutzlast, erg.Signatur)
	if err != nil || hash != erg.EpochHash {
		t.Fatal(err)
	}
	return plains
}
