package fenster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/suchen"
)

func TestSpeicherAbschluss(t *testing.T) {
	var _ Abschluss = SpeicherAbschluss{}
	var _ suchen.Abschluss = (*bestaetigung.Speicher)(nil)

	s, err := bestaetigung.Oeffnen(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hsm, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	best, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mandant, ablage, instanz protocol.ID
	mandant[0], ablage[0], instanz[0] = 0x11, 0x22, 0x44
	var prefix protocol.Prefix
	prefix[0] = 1
	epoch, err := protocol.NewEpochID(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC), instanz, prefix)
	if err != nil {
		t.Fatal(err)
	}
	genesis := protocol.Genesis(ablage, epoch.Instanz())
	nutz, sig, hash := manifestAbschluss(t, hsm, epoch, genesis, protocol.Hash{1})
	folge, err := s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey)
	if err != nil || folge != bestaetigung.FolgeAbschluss {
		t.Fatalf("%v %v", folge, err)
	}
	andere, asig, ahash := manifestAbschluss(t, hsm, epoch, genesis, protocol.Hash{2})
	folge, err = s.Einreichen(mandant, ablage, andere, asig, &hsm.PublicKey)
	if err != nil || folge != bestaetigung.FolgeZweig {
		t.Fatalf("zweig %v %v", folge, err)
	}

	finger, err := crypt.FingerprintSPKI(&best.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bestaetigt, err := crypt.SignP256(best, protocol.ConfirmationPayload(hash))
	if err != nil {
		t.Fatal(err)
	}
	a := SpeicherAbschluss{Speicher: s, Schluessel: &best.PublicKey}
	ok, err := a.Anhaengen(Bestaetigung{
		Mandant: mandant, Ablage: ablage, Epoch: epoch, Previous: genesis,
		Hash: hash, Signatur: bestaetigt, Finger: finger,
	})
	if err != nil || !ok {
		t.Fatalf("anhängen %v %v", ok, err)
	}
	zweite, err := crypt.SignP256(best, protocol.ConfirmationPayload(ahash))
	if err != nil {
		t.Fatal(err)
	}
	ok, err = a.Anhaengen(Bestaetigung{
		Mandant: mandant, Ablage: ablage, Epoch: epoch, Previous: genesis,
		Hash: ahash, Signatur: zweite, Finger: finger,
	})
	if err != nil || ok {
		t.Fatalf("zweite fassung %v %v", ok, err)
	}
	if _, err := a.Anhaengen(Bestaetigung{
		Mandant: mandant, Ablage: ablage, Epoch: epoch, Previous: genesis,
		Hash: hash, Signatur: bestaetigt, Finger: protocol.Hash{1},
	}); !errors.Is(err, ErrBestaetigung) {
		t.Fatalf("finger %v", err)
	}
	got, gsig, da, err := a.Bestaetigung(mandant, ablage, epoch)
	if err != nil || !da || got != hash || gsig != bestaetigt {
		t.Fatalf("%v %v", err, da)
	}
	zweige, err := a.Zweige(mandant, ablage, epoch)
	if err != nil || len(zweige) != 1 || string(zweige[0].Nutzlast) != string(andere) || zweige[0].Signatur != asig {
		t.Fatalf("%v %d", err, len(zweige))
	}
}

func manifestAbschluss(t *testing.T, key *ecdsa.PrivateKey, epoch protocol.EpochID, previous, kopf protocol.Hash) ([]byte, protocol.Signature, protocol.Hash) {
	t.Helper()
	nutz := protocol.ManifestPayload(epoch, previous, kopf, 1, 1, 1, protocol.Hash{9})
	sig, err := crypt.SignP256(key, nutz)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocol.EpochHash(nutz, sig)
	if err != nil {
		t.Fatal(err)
	}
	return nutz, sig, hash
}
