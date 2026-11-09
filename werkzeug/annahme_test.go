package werkzeug_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"cryptlog/abschluss"
	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

func TestAnnahmeNimmtSegmente(t *testing.T) {
	w, glieder, event := epocheFuerAnnahme(t)
	raw := annahmeVon(t, w, glieder, event, false, nil)
	objekte := objekteVon(w)
	a := w.auftrag(werkzeug.StatusAktuell)
	a.Alles = true
	a.Segmente = []werkzeug.Segment{{Schluessel: "nein", Bytes: []byte{1, 2, 3}}}
	a.Annahmen = [][]byte{raw}
	a.Objekte = objekte
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrAnnahme) {
		t.Fatalf("kopf %v", err)
	}

	a.Priv = nil
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrAnnahme) {
		t.Fatalf("ohne schlüssel %v", err)
	}

	fremd := append([]byte(nil), objekte[w.segs[0].Schluessel]...)
	fremd[0] ^= 1
	a = w.auftrag(werkzeug.StatusAktuell)
	a.Annahmen = [][]byte{raw}
	a.Objekte = map[string][]byte{w.segs[0].Schluessel: fremd}
	for _, seg := range w.segs[1:] {
		a.Objekte[seg.Schluessel] = seg.Bytes
	}
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrKette) {
		t.Fatalf("hash %v", err)
	}
}

func TestZeitraumAusAnnahme(t *testing.T) {
	w, glieder, event := epocheFuerAnnahme(t)
	raw := annahmeVon(t, w, glieder, event, false, nil)
	lage := w.lage()
	lage.Auftrag.Segmente = nil
	lage.Auftrag.Annahmen = [][]byte{raw}
	lage.Auftrag.Objekte = map[string][]byte{}
	anfrage := stromAnfrage(w, stunde8, stunde10, stunde8, lage)
	got, err := werkzeug.Zeitraum(anfrage)
	if err != nil || len(got) != 1 || !got[0].Bericht.Luecke || len(got[0].Bericht.Eintraege) != 0 {
		t.Fatalf("fehlend %+v %v", got, err)
	}

	lage.Auftrag.Objekte = objekteVon(w)
	anfrage.Epochen = []werkzeug.Lage{lage}
	if _, err := werkzeug.Zeitraum(anfrage); !errors.Is(err, werkzeug.ErrAnnahme) {
		t.Fatalf("vorhanden %v", err)
	}
}

func TestBindungBatch(t *testing.T) {
	w, glieder, event := epocheFuerAnnahme(t)
	a := auftragAusAnnahme(t, w, annahmeVon(t, w, glieder, event, true, nil))
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrBindung) {
		t.Fatalf("batch %v", err)
	}

	ohne := glieder[:len(glieder)-1]
	a = auftragAusAnnahme(t, w, annahmeVon(t, w, ohne, event, false, nil))
	if _, err := werkzeug.Pruefen(a); !errors.Is(err, werkzeug.ErrBindung) {
		t.Fatalf("sequenz %v", err)
	}
}

func epocheFuerAnnahme(t *testing.T) (welt, []epoch.Glied, protocol.ID) {
	t.Helper()
	w := basis(t)
	ep := oeffnen(t, w)
	var event protocol.ID
	event[0] = 0x10
	klar, err := protocol.EreignisKlartext(event, 1500, w.bind, logInhalt(t, "eins", aussage(t, w, true)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ep.Ereignis(klar); err != nil {
		t.Fatal(err)
	}
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
	w.seqs = [][]uint64{{erg.Glieder[0].Seq}}
	return w, erg.Glieder, event
}

func annahmeVon(t *testing.T, w welt, glieder []epoch.Glied, event protocol.ID, fremdBatch bool, eintraege []protocol.SeqEintrag) []byte {
	t.Helper()
	refs := make([]protocol.SegmentRef, len(w.segs))
	for i, seg := range w.segs {
		refs[i] = protocol.SegmentRef{ObjectKey: seg.Schluessel, Hash: protocol.SegmentHash(seg.Bytes)}
	}
	if eintraege == nil {
		eintraege = make([]protocol.SeqEintrag, len(glieder))
		for i, g := range glieder {
			eintraege[i] = protocol.SeqEintrag{Seq: g.Seq, Art: g.Art, Event: g.Event}
		}
	}
	var batch protocol.ID
	batch[0] = 0x0b
	if fremdBatch {
		return annahmeMitFremderBatch(t, w, batch, event, refs, eintraege)
	}
	gebaut, err := abschluss.Bauen(abschluss.Auftrag{
		Batch:      batch,
		Instanz:    w.epoch.Instanz(),
		BatchSeq:   1,
		Previous:   protocol.AnnahmeGenesis(w.epoch.Instanz()),
		Ereignisse: []protocol.Slot{{Event: event, Hash: protocol.Hash{1}}},
		Segmente:   refs,
		Anteile: []abschluss.Anteil{{
			Mandant:   w.mandant,
			KEK:       w.fp,
			Pub:       &w.kek.PublicKey,
			Eintraege: eintraege,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gebaut.Annahme.Bytes
}

func annahmeMitFremderBatch(t *testing.T, w welt, batch, event protocol.ID, refs []protocol.SegmentRef, eintraege []protocol.SeqEintrag) []byte {
	t.Helper()
	klar, err := protocol.Bindung(batch, eintraege)
	if err != nil {
		t.Fatal(err)
	}
	other := batch
	other[1] = 0xff
	wrapped, nonce, ct, tag, err := crypt.SealBindung(nil, &w.kek.PublicKey, other, klar,
		protocol.BindungContext(w.mandant, other, w.fp), protocol.BindungAAD(w.mandant, other, w.fp))
	if err != nil {
		t.Fatal(err)
	}
	plaetze, err := protocol.Plaetze([]protocol.Slot{{Event: event, Hash: protocol.Hash{1}}}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protocol.AnnahmePayload(batch, w.epoch.Instanz(), 1, protocol.AnnahmeGenesis(w.epoch.Instanz()), plaetze, refs, []protocol.Blob{{
		Mandant: w.mandant, WrappedKey: wrapped, Nonce: nonce, Ciphertext: ct, Tag: tag,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func auftragAusAnnahme(t *testing.T, w welt, raw []byte) werkzeug.Auftrag {
	t.Helper()
	a := w.auftrag(werkzeug.StatusAktuell)
	a.Alles = true
	a.Segmente = []werkzeug.Segment{{Schluessel: "nein", Bytes: []byte{9}}}
	a.Annahmen = [][]byte{raw}
	a.Objekte = objekteVon(w)
	return a
}

func objekteVon(w welt) map[string][]byte {
	objekte := make(map[string][]byte, len(w.segs))
	for _, seg := range w.segs {
		objekte[seg.Schluessel] = seg.Bytes
	}
	return objekte
}
