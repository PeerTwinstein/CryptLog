package abschluss_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"cryptlog/abschluss"
	"cryptlog/crypt"
	"cryptlog/protocol"
)

func fill(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func schluessel(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func auftrag(key *ecdsa.PrivateKey, ereignisse []protocol.Slot, anteile []abschluss.Anteil) abschluss.Auftrag {
	seg := []byte("segment")
	return abschluss.Auftrag{
		Batch:      fill(0x0b),
		Instanz:    fill(0x22),
		BatchSeq:   10,
		Previous:   protocol.AnnahmeGenesis(fill(0x22)),
		Ereignisse: ereignisse,
		Segmente: []protocol.SegmentRef{{
			ObjectKey: "aa/bb/20261106T160000Z-cc/1",
			Hash:      protocol.SegmentHash(seg),
		}},
		Anteile: anteile,
	}
}

func TestBauenUndAblegen(t *testing.T) {
	key := schluessel(t)
	ev := protocol.Slot{Event: fill(0x11), Hash: protocol.Hash{0x44}}
	anteil := abschluss.Anteil{
		Mandant: fill(0x01),
		KEK:     protocol.Hash{0x55},
		Pub:     &key.PublicKey,
		Eintraege: []protocol.SeqEintrag{
			{Seq: 1, Art: protocol.ArtEreignis, Event: ev.Event},
			{Seq: 2, Art: protocol.ArtFuellung},
		},
	}
	gebaut, err := abschluss.Bauen(auftrag(key, []protocol.Slot{ev}, []abschluss.Anteil{anteil}))
	if err != nil {
		t.Fatal(err)
	}
	if len(gebaut.Belegungen) != 1 || len(gebaut.Plaetze) != 8 || gebaut.Plaetze[0] != ev {
		t.Fatalf("plätze %d belegungen %d", len(gebaut.Plaetze), len(gebaut.Belegungen))
	}
	beleg, err := protocol.ParseBelegung(gebaut.Belegungen[0].Bytes)
	if err != nil || beleg.Generation != 1 || beleg.Event != ev.Event || beleg.Hash != ev.Hash || beleg.Batch != fill(0x0b) {
		t.Fatalf("belegung %+v %v", beleg, err)
	}
	if gebaut.Belegungen[0].Schluessel != "belegt/"+ev.Event.Hex() {
		t.Fatal(gebaut.Belegungen[0].Schluessel)
	}
	if gebaut.Vorbereitung.Schluessel != "vorbereitung/"+fill(0x22).Hex()+"/10" || gebaut.Annahme.Schluessel != "annahme/"+fill(0x22).Hex()+"/10" {
		t.Fatal(gebaut.Annahme.Schluessel)
	}
	wantVor, err := protocol.VorbereitungPayload(fill(0x0b), fill(0x22), 10, gebaut.Plaetze, gebaut.Segmente, gebaut.Bloecke)
	if err != nil || !bytes.Equal(wantVor, gebaut.Vorbereitung.Bytes) {
		t.Fatal(err)
	}
	wantAnn, err := protocol.AnnahmePayload(fill(0x0b), fill(0x22), 10, protocol.AnnahmeGenesis(fill(0x22)), gebaut.Plaetze, gebaut.Segmente, gebaut.Bloecke)
	if err != nil || !bytes.Equal(wantAnn, gebaut.Annahme.Bytes) {
		t.Fatal(err)
	}
	sum, err := protocol.AnnahmeHash(wantAnn)
	if err != nil || sum != gebaut.Hash {
		t.Fatal(err)
	}
	blob := gebaut.Bloecke[0]
	klar, err := crypt.OpenBindung(key, fill(0x0b), blob.WrappedKey, blob.Nonce, blob.Ciphertext, blob.Tag, protocol.BindungContext(fill(0x01), fill(0x0b), protocol.Hash{0x55}), protocol.BindungAAD(fill(0x01), fill(0x0b), protocol.Hash{0x55}))
	if err != nil {
		t.Fatal(err)
	}
	wantBindung, err := protocol.Bindung(fill(0x0b), anteil.Eintraege)
	if err != nil || !bytes.Equal(klar, wantBindung) {
		t.Fatal(err)
	}

	ziel := &abschluss.Speicher{}
	seg := abschluss.Segmentobjekt{Schluessel: gebaut.Segmente[0].ObjectKey, Bytes: []byte("segment")}
	auf := &reihe{Speicher: ziel}
	if err := abschluss.Ablegen(auf, gebaut, []abschluss.Segmentobjekt{seg}); err != nil {
		t.Fatal(err)
	}
	wantReihe := []string{
		gebaut.Belegungen[0].Schluessel,
		gebaut.Vorbereitung.Schluessel,
		seg.Schluessel,
		gebaut.Annahme.Schluessel,
	}
	if !bytes.Equal([]byte(join(auf.schritte)), []byte(join(wantReihe))) {
		t.Fatalf("reihenfolge %v", auf.schritte)
	}
	if err := abschluss.Ablegen(ziel, gebaut, []abschluss.Segmentobjekt{seg}); err != nil {
		t.Fatalf("wiederholt %v", err)
	}
	if _, ok, err := ziel.Lesen(gebaut.Annahme.Schluessel); err != nil || !ok {
		t.Fatal("annahme fehlt")
	}

	ohne := &abschluss.Speicher{}
	if err := abschluss.Ablegen(ohne, gebaut, nil); !errors.Is(err, abschluss.ErrSegment) {
		t.Fatalf("ohne segment %v", err)
	}
	if _, ok, _ := ohne.Lesen(gebaut.Annahme.Schluessel); ok {
		t.Fatal("annahme ohne segment")
	}
	if _, ok, _ := ohne.Lesen(gebaut.Vorbereitung.Schluessel); !ok {
		t.Fatal("vorbereitung fehlt")
	}

	fremd := &abschluss.Speicher{}
	if err := fremd.Schreiben(gebaut.Annahme.Schluessel, []byte("andere")); err != nil {
		t.Fatal(err)
	}
	if err := abschluss.Ablegen(fremd, gebaut, []abschluss.Segmentobjekt{seg}); !errors.Is(err, abschluss.ErrObjekt) {
		t.Fatalf("fremde annahme %v", err)
	}
	liegen, _, _ := fremd.Lesen(gebaut.Annahme.Schluessel)
	if string(liegen) != "andere" {
		t.Fatal("annahme ersetzt")
	}
}

func TestZweiAnteileUndUebernahme(t *testing.T) {
	key := schluessel(t)
	a := protocol.Slot{Event: fill(0xa1), Hash: protocol.Hash{1}}
	b := protocol.Slot{Event: fill(0xb2), Hash: protocol.Hash{2}}
	anteile := []abschluss.Anteil{
		{
			Mandant: fill(0x01), KEK: protocol.Hash{0x11}, Pub: &key.PublicKey,
			Eintraege: []protocol.SeqEintrag{{Seq: 1, Art: protocol.ArtEreignis, Event: a.Event}},
		},
		{
			Mandant: fill(0x02), KEK: protocol.Hash{0x22}, Pub: &key.PublicKey,
			Eintraege: []protocol.SeqEintrag{{Seq: 4, Art: protocol.ArtEreignis, Event: b.Event}},
		},
	}
	gebaut, err := abschluss.Bauen(auftrag(key, []protocol.Slot{a, b}, anteile))
	if err != nil {
		t.Fatal(err)
	}
	if len(gebaut.Bloecke) != 2 || len(gebaut.Belegungen) != 2 || len(gebaut.Plaetze) != 8 {
		t.Fatalf("blobs %d belegungen %d plätze %d", len(gebaut.Bloecke), len(gebaut.Belegungen), len(gebaut.Plaetze))
	}
	for i, anteil := range anteile {
		blob := gebaut.Bloecke[i]
		klar, err := crypt.OpenBindung(key, fill(0x0b), blob.WrappedKey, blob.Nonce, blob.Ciphertext, blob.Tag, protocol.BindungContext(anteil.Mandant, fill(0x0b), anteil.KEK), protocol.BindungAAD(anteil.Mandant, fill(0x0b), anteil.KEK))
		if err != nil {
			t.Fatal(err)
		}
		want, err := protocol.Bindung(fill(0x0b), anteil.Eintraege)
		if err != nil || !bytes.Equal(klar, want) {
			t.Fatalf("blob %d", i)
		}
	}

	leer, err := abschluss.Bauen(auftrag(key, nil, []abschluss.Anteil{{
		Mandant: fill(0x01), KEK: protocol.Hash{1}, Pub: &key.PublicKey,
		Eintraege: []protocol.SeqEintrag{{Seq: 1, Art: protocol.ArtFuellung}},
	}}))
	if err != nil || len(leer.Belegungen) != 0 || len(leer.Plaetze) != 8 {
		t.Fatalf("leer %d %v", len(leer.Plaetze), err)
	}

	if _, err := abschluss.Bauen(auftrag(key, []protocol.Slot{b}, anteile[:1])); !errors.Is(err, protocol.ErrEvent) {
		t.Fatalf("ereignis fehlt im anteil %v", err)
	}

	ziel := &abschluss.Speicher{}
	alt, err := protocol.ParseBelegung(gebaut.Belegungen[0].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben(gebaut.Belegungen[0].Schluessel, gebaut.Belegungen[0].Bytes); err != nil {
		t.Fatal(err)
	}
	neu, err := alt.Nachfolger(fill(0x99), fill(0x77))
	if err != nil {
		t.Fatal(err)
	}
	if err := abschluss.Uebernehmen(ziel, alt, neu); err != nil {
		t.Fatal(err)
	}
	raw, ok, err := ziel.Lesen(gebaut.Belegungen[0].Schluessel)
	if err != nil || !ok {
		t.Fatal(err)
	}
	liegen, err := protocol.ParseBelegung(raw)
	if err != nil || liegen != neu {
		t.Fatalf("liegen %+v", liegen)
	}
	if err := abschluss.Uebernehmen(ziel, alt, neu); !errors.Is(err, abschluss.ErrObjekt) {
		t.Fatalf("veraltete übernahme %v", err)
	}
}

type reihe struct {
	*abschluss.Speicher
	schritte []string
}

func (r *reihe) Schreiben(schluessel string, inhalt []byte) error {
	if err := r.Speicher.Schreiben(schluessel, inhalt); err != nil {
		return err
	}
	r.schritte = append(r.schritte, schluessel)
	return nil
}

func (r *reihe) Ersetzen(schluessel string, bisher, neu []byte) error {
	return r.Speicher.Ersetzen(schluessel, bisher, neu)
}

func join(s []string) string {
	out := ""
	for _, p := range s {
		out += p + "\n"
	}
	return out
}
