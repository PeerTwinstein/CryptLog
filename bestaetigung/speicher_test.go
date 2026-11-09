package bestaetigung

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

var stunde = time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)

func TestEineFassungJeEpocheUndVorgaenger(t *testing.T) {
	dir := t.TempDir()
	s := oeffnen(t, dir)
	hsm := paar(t)
	mandant, ablage := kennung(0x11), kennung(0x22)
	ersteID := epoche(t, 0x44, 0x01, stunde)
	genesis := protocol.Genesis(ablage, ersteID.Instanz())
	nutz, sig, hash := manifest(t, hsm, ersteID, genesis, protocol.Hash{1})

	folge, err := s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss {
		t.Fatalf("abschluss %v %v", folge, err)
	}
	vorher := groesse(t, s)
	folge, err = s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss || groesse(t, s) != vorher {
		t.Fatalf("doppelt %v %v", folge, err)
	}
	fassung, ok := s.Abschluss(mandant, ablage, ersteID)
	if !ok || fassung.Hash != hash || fassung.Previous != genesis || fassung.Signiert {
		t.Fatalf("%+v %v", fassung, ok)
	}

	andere, asig, _ := manifest(t, hsm, ersteID, genesis, protocol.Hash{2})
	folge, err = s.Einreichen(mandant, ablage, andere, asig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig {
		t.Fatalf("zweig %v %v", folge, err)
	}
	fassung, _ = s.Abschluss(mandant, ablage, ersteID)
	if fassung.Hash != hash {
		t.Fatal("abschluss ersetzt")
	}
	zweige, err := s.Zweige(mandant, ablage, ersteID)
	if err != nil || len(zweige) != 1 || string(zweige[0].Nutzlast) != string(andere) || zweige[0].Signatur != asig {
		t.Fatalf("%v %+v", err, zweige)
	}
	folge, err = s.Einreichen(mandant, ablage, andere, asig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig || groesse(t, s) == vorher {
		t.Fatalf("zweig doppelt %v %v", folge, err)
	}
	still := groesse(t, s)
	folge, err = s.Einreichen(mandant, ablage, andere, asig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig || groesse(t, s) != still {
		t.Fatal("zweig wächst")
	}

	zweiteID := epoche(t, 0x44, 0x02, stunde.Add(time.Hour))
	gabel, gsig, _ := manifest(t, hsm, zweiteID, genesis, protocol.Hash{3})
	folge, err = s.Einreichen(mandant, ablage, gabel, gsig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig {
		t.Fatalf("vorgänger %v %v", folge, err)
	}
	if _, ok := s.Abschluss(mandant, ablage, zweiteID); ok {
		t.Fatal("zweiter abschluss auf demselben vorgänger")
	}

	nutz2, sig2, _ := manifest(t, hsm, zweiteID, hash, protocol.Hash{4})
	folge, err = s.Einreichen(mandant, ablage, nutz2, sig2, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss {
		t.Fatalf("nachfolger %v %v", folge, err)
	}
	dritteID := epoche(t, 0x44, 0x03, stunde.Add(2*time.Hour))
	sprung, ssig, _ := manifest(t, hsm, dritteID, hash, protocol.Hash{5})
	folge, err = s.Einreichen(mandant, ablage, sprung, ssig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig {
		t.Fatalf("sprung %v %v", folge, err)
	}
	if _, ok := s.Abschluss(mandant, ablage, dritteID); ok {
		t.Fatal("sprung wurde abschluss")
	}

	fremd := epoche(t, 0x45, 0x01, stunde)
	fnutz, fsig, _ := manifest(t, hsm, fremd, protocol.Genesis(ablage, fremd.Instanz()), protocol.Hash{6})
	folge, err = s.Einreichen(mandant, ablage, fnutz, fsig, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss {
		t.Fatalf("instanz %v %v", folge, err)
	}
	andereAblage := kennung(0x23)
	anutz, as, _ := manifest(t, hsm, ersteID, protocol.Genesis(andereAblage, ersteID.Instanz()), protocol.Hash{7})
	folge, err = s.Einreichen(mandant, andereAblage, anutz, as, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss {
		t.Fatalf("ablage %v %v", folge, err)
	}

	kaputt := sig
	kaputt[0] ^= 0xff
	stand := groesse(t, s)
	if _, err := s.Einreichen(mandant, ablage, nutz, kaputt, &hsm.PublicKey); !errors.Is(err, ErrSignatur) || groesse(t, s) != stand {
		t.Fatalf("sig %v", err)
	}
	if _, err := s.Einreichen(protocol.ID{}, ablage, nutz, sig, &hsm.PublicKey); !errors.Is(err, ErrFassung) {
		t.Fatalf("mandant %v", err)
	}
}

func TestErstesGlied(t *testing.T) {
	s := oeffnen(t, t.TempDir())
	hsm := paar(t)
	mandant, ablage := kennung(0x11), kennung(0x22)
	id := epoche(t, 0x44, 0x01, stunde)
	genesis := protocol.Genesis(ablage, id.Instanz())
	falsch, fsig, _ := manifest(t, hsm, id, protocol.Hash{9}, protocol.Hash{1})
	folge, err := s.Einreichen(mandant, ablage, falsch, fsig, &hsm.PublicKey)
	if err != nil || folge != FolgeZweig {
		t.Fatalf("ohne kette %v %v", folge, err)
	}
	if _, ok := s.Abschluss(mandant, ablage, id); ok {
		t.Fatal("ohne vorgänger bestätigt")
	}
	nutz, sig, hash := manifest(t, hsm, id, genesis, protocol.Hash{2})
	folge, err = s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey)
	if err != nil || folge != FolgeAbschluss {
		t.Fatalf("glied %v %v", folge, err)
	}
	fassung, ok := s.Abschluss(mandant, ablage, id)
	if !ok || fassung.Hash != hash || fassung.Previous != genesis {
		t.Fatalf("%+v", fassung)
	}
	zweige, err := s.Zweige(mandant, ablage, id)
	if err != nil || len(zweige) != 1 {
		t.Fatalf("%v %d", err, len(zweige))
	}
}

func TestSignaturUndVermerk(t *testing.T) {
	dir := t.TempDir()
	s := oeffnen(t, dir)
	hsm, best := paar(t), paar(t)
	mandant, ablage := kennung(0x11), kennung(0x22)
	id := epoche(t, 0x44, 0x01, stunde)
	genesis := protocol.Genesis(ablage, id.Instanz())
	nutz, sig, hash := manifest(t, hsm, id, genesis, protocol.Hash{1})
	if err := s.Signieren(mandant, ablage, id, genesis, hash, protocol.Signature{}, &best.PublicKey); !errors.Is(err, ErrFassung) {
		t.Fatalf("ohne fassung %v", err)
	}
	if _, err := s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey); err != nil {
		t.Fatal(err)
	}
	zweig, zsig, zhash := manifest(t, hsm, id, genesis, protocol.Hash{2})
	if _, err := s.Einreichen(mandant, ablage, zweig, zsig, &hsm.PublicKey); err != nil {
		t.Fatal(err)
	}
	bestaetigt := signatur(t, best, hash)
	if err := s.Signieren(mandant, ablage, id, genesis, hash, bestaetigt, &best.PublicKey); err != nil {
		t.Fatal(err)
	}
	got, gsig, ok, err := s.Bestaetigung(mandant, ablage, id)
	if err != nil || !ok || got != hash || gsig != bestaetigt {
		t.Fatalf("%v %v %x", err, ok, got)
	}
	stand := groesse(t, s)
	if err := s.Signieren(mandant, ablage, id, genesis, hash, bestaetigt, &best.PublicKey); err != nil || groesse(t, s) != stand {
		t.Fatalf("dieselbe signatur %v", err)
	}
	andere := signatur(t, paar(t), hash)
	if err := s.Signieren(mandant, ablage, id, genesis, hash, andere, &best.PublicKey); !errors.Is(err, ErrSignatur) || groesse(t, s) != stand {
		t.Fatalf("fremde signatur %v", err)
	}
	zweite := signatur(t, best, hash)
	if zweite != bestaetigt {
		if err := s.Signieren(mandant, ablage, id, genesis, hash, zweite, &best.PublicKey); !errors.Is(err, ErrFassung) {
			t.Fatalf("zweite signatur %v", err)
		}
	}
	if err := s.Signieren(mandant, ablage, id, genesis, zhash, signatur(t, best, zhash), &best.PublicKey); !errors.Is(err, ErrFassung) {
		t.Fatalf("zweig signiert %v", err)
	}
	if err := s.Vermerken(mandant, ablage, id, stunde); !errors.Is(err, ErrVermerk) {
		t.Fatalf("tag %v", err)
	}
	tag := time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)
	if err := s.Vermerken(kennung(0x99), ablage, id, tag); !errors.Is(err, ErrVermerk) {
		t.Fatalf("fremde epoche %v", err)
	}
	if err := s.Vermerken(mandant, ablage, id, tag); err != nil {
		t.Fatal(err)
	}
	if err := s.Vermerken(mandant, ablage, id, tag.AddDate(0, 0, 1)); !errors.Is(err, ErrVermerk) {
		t.Fatalf("zweiter tag %v", err)
	}
	nach := groesse(t, s)
	if err := s.Vermerken(mandant, ablage, id, tag); err != nil || groesse(t, s) != nach {
		t.Fatal("vermerk wächst")
	}
	gotTag, da, err := s.Vermerk(mandant, ablage, id)
	if err != nil || !da || !gotTag.Equal(tag) {
		t.Fatalf("%v %v", gotTag, err)
	}
	fassung, ok := s.Abschluss(mandant, ablage, id)
	if !ok || !fassung.Signiert || fassung.Hash != hash {
		t.Fatal("fassung weg")
	}

	wieder := oeffnen(t, dir)
	got, gsig, ok, err = wieder.Bestaetigung(mandant, ablage, id)
	if err != nil || !ok || got != hash || gsig != bestaetigt {
		t.Fatal("signatur fehlt nach neustart")
	}
	gotTag, da, err = wieder.Vermerk(mandant, ablage, id)
	if err != nil || !da || !gotTag.Equal(tag) {
		t.Fatal("vermerk fehlt nach neustart")
	}
	liste, err := wieder.Zweige(mandant, ablage, id)
	if err != nil || len(liste) != 1 || liste[0].Signatur != zsig {
		t.Fatal("zweig fehlt nach neustart")
	}
}

func TestNeustart(t *testing.T) {
	dir := t.TempDir()
	s := oeffnen(t, dir)
	hsm := paar(t)
	mandant, ablage := kennung(0x11), kennung(0x22)
	id := epoche(t, 0x44, 0x01, stunde)
	nutz, sig, hash := manifest(t, hsm, id, protocol.Genesis(ablage, id.Instanz()), protocol.Hash{1})
	if _, err := s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey); err != nil {
		t.Fatal(err)
	}
	ganz := groesse(t, s)
	f, err := os.OpenFile(s.pfad, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{1, 2, 3, 4, 5, 6, 7}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s = oeffnen(t, dir)
	if groesse(t, s) != ganz {
		t.Fatalf("riss %d %d", groesse(t, s), ganz)
	}
	if fassung, ok := s.Abschluss(mandant, ablage, id); !ok || fassung.Hash != hash {
		t.Fatal("fassung nach riss")
	}

	b, err := os.ReadFile(s.pfad)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(s.pfad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Oeffnen(dir); !errors.Is(err, ErrBestand) {
		t.Fatalf("beschädigt %v", err)
	}
	info, err := os.Stat(s.pfad)
	if err != nil || info.Size() != int64(len(b)) {
		t.Fatal("beschädigt gekürzt")
	}
}

func TestNebenlaeufig(t *testing.T) {
	dir := t.TempDir()
	s := oeffnen(t, dir)
	hsm := paar(t)
	mandant, ablage := kennung(0x11), kennung(0x22)
	id := epoche(t, 0x44, 0x01, stunde)
	nutz, sig, hash := manifest(t, hsm, id, protocol.Genesis(ablage, id.Instanz()), protocol.Hash{1})
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			folge, err := s.Einreichen(mandant, ablage, nutz, sig, &hsm.PublicKey)
			if err != nil || folge != FolgeAbschluss {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	wieder := oeffnen(t, dir)
	fassung, ok := wieder.Abschluss(mandant, ablage, id)
	if !ok || fassung.Hash != hash {
		t.Fatal("eine fassung")
	}
	if zweige, err := wieder.Zweige(mandant, ablage, id); err != nil || len(zweige) != 0 {
		t.Fatalf("zweige %v %d", err, len(zweige))
	}
}

func oeffnen(t *testing.T, dir string) *Speicher {
	t.Helper()
	s, err := Oeffnen(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func groesse(t *testing.T, s *Speicher) int64 {
	t.Helper()
	info, err := os.Stat(s.pfad)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func manifest(t *testing.T, key *ecdsa.PrivateKey, epoch protocol.EpochID, previous, kopf protocol.Hash) ([]byte, protocol.Signature, protocol.Hash) {
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

func signatur(t *testing.T, key *ecdsa.PrivateKey, hash protocol.Hash) protocol.Signature {
	t.Helper()
	sig, err := crypt.SignP256(key, protocol.ConfirmationPayload(hash))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func epoche(t *testing.T, instanz, prefix byte, raster time.Time) protocol.EpochID {
	t.Helper()
	var id protocol.ID
	id[0] = instanz
	var p protocol.Prefix
	p[0] = prefix
	epoch, err := protocol.NewEpochID(raster, id, p)
	if err != nil {
		t.Fatal(err)
	}
	return epoch
}

func kennung(b byte) protocol.ID {
	var id protocol.ID
	id[0] = b
	return id
}

func paar(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
