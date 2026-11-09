package schreiben

import (
	"bytes"
	"testing"

	"cryptlog/abschluss"
)

func TestPlatteSchreibenUndErsetzen(t *testing.T) {
	p, err := OeffnenPlatte(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := p.Lesen("belegt/aa"); err != nil || ok {
		t.Fatalf("leer %v %v", ok, err)
	}
	if err := p.Schreiben("belegt/aa", []byte("eins")); err != nil {
		t.Fatal(err)
	}
	if err := p.Schreiben("belegt/aa", []byte("eins")); err != nil {
		t.Fatal(err)
	}
	if err := p.Schreiben("belegt/aa", []byte("zwei")); err != abschluss.ErrObjekt {
		t.Fatalf("ersetzt %v", err)
	}
	if err := p.Ersetzen("belegt/aa", []byte("eins"), []byte("zwei")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := p.Lesen("belegt/aa")
	if err != nil || !ok || !bytes.Equal(got, []byte("zwei")) {
		t.Fatalf("%q %v %v", got, ok, err)
	}
	if err := p.Ersetzen("belegt/aa", []byte("eins"), []byte("drei")); err != abschluss.ErrObjekt {
		t.Fatal(err)
	}
	if err := p.Schreiben("annahme/ii/1", []byte("ann")); err != nil {
		t.Fatal(err)
	}
	liste, err := p.Liste("annahme/ii/")
	if err != nil || len(liste) != 1 || liste[0] != "annahme/ii/1" {
		t.Fatalf("%v %v", liste, err)
	}
	if err := p.Schreiben("../aussen", []byte("x")); err == nil {
		t.Fatal("pfad")
	}
}
