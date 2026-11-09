// Package oberflaeche ist das Fenster von cryptlog werkzeug.
// Eine Datei startet dort keine Prüfung. Die Passphrase wird nicht abgelegt.
package oberflaeche

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/fenster"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/schreiben"
	"cryptlog/werkzeug"
)

var (
	// ErrAngabe heißt, Zertifikat, öffentlicher Schlüssel oder eine Zahl passen nicht.
	ErrAngabe = errors.New("oberflaeche: Angabe passt nicht")
)

// Vorlage ist eine gelesene Verbindung und die öffentlichen Dateien daneben.
// Sie entsperrt nichts.
type Vorlage struct {
	Pfad         string
	Verbindung   fenster.Verbindung
	Pruef        string
	HSM          string
	Bestaetigung string
	Speicher     string
	Modus        schluessel.Modus
}

// Angaben öffnen die Sitzung. Geheimnis wird überschrieben.
// Eine Passphrase gehört nicht hierher.
type Angaben struct {
	Vorlage   Vorlage
	Status    werkzeug.Status
	Person    string
	Suche     string
	Instanz   protocol.ID
	Rahmen    int
	Intervall time.Duration
	Frist     time.Duration
	Region    string
	Zugang    string
	Geheimnis []byte
}

// Sitzung ist das entsperrbare Fenster. Der Klartext liegt in fenster.Fenster.
type Sitzung struct {
	Fenster *fenster.Fenster
	HSM     *ecdsa.PublicKey
	halt    *hsmHalt
}

// LesenVorlage liest die Verbindung und sucht die öffentlichen Schlüssel
// im Verzeichnis des Zertifikats. Eine Prüfung öffnet das nicht.
func LesenVorlage(pfad string) (Vorlage, error) {
	v, err := fenster.Lesen(pfad)
	if err != nil {
		return Vorlage{}, err
	}
	modus := schluessel.ModusSicher
	if v.KEK != "" {
		modus = schluessel.ModusEinfach
	}
	dir := filepath.Dir(v.Zertifikat)
	speicher := ""
	if v.Ziel == fenster.ZielPlatte {
		speicher = filepath.Join(filepath.Dir(v.Pfad), "bestaetigung")
	}
	return Vorlage{
		Pfad: pfad, Verbindung: v, Modus: modus, Speicher: speicher,
		Pruef:        vorhanden(filepath.Join(dir, "pruef.pem")),
		HSM:          vorhanden(filepath.Join(dir, "hsm.pem")),
		Bestaetigung: vorhanden(filepath.Join(dir, "best.pem")),
	}, nil
}

// Oeffnen baut das Fenster. Es entsperrt den Schlüssel nicht.
func Oeffnen(a Angaben) (*Sitzung, error) {
	defer crypt.Wipe(a.Geheimnis)
	if a.Vorlage.Verbindung.Zertifikat == "" || a.SpeicherAus() {
		return nil, ErrAngabe
	}
	cert, err := zertifikatLesen(a.Vorlage.Verbindung.Zertifikat)
	if err != nil {
		return nil, err
	}
	pruef, err := oeffentlichLesen(a.Vorlage.Pruef)
	if err != nil {
		return nil, err
	}
	hsm, err := oeffentlichLesen(a.Vorlage.HSM)
	if err != nil {
		return nil, err
	}
	best, err := oeffentlichLesen(a.Vorlage.Bestaetigung)
	if err != nil {
		return nil, err
	}
	speicher, err := bestaetigung.Oeffnen(a.Vorlage.Speicher)
	if err != nil {
		return nil, err
	}
	ziel, err := zielOeffnen(a)
	if err != nil {
		return nil, err
	}
	halt := &hsmHalt{}
	f, err := fenster.Neu(fenster.Konfig{
		Verbindung: a.Vorlage.Verbindung, Ziel: ziel,
		Abschluss:  fenster.SpeicherAbschluss{Speicher: speicher, Schluessel: best},
		Zertifikat: cert, Status: a.Status, Modus: a.Vorlage.Modus,
		Pruef: pruef, HSM: hsm, Bestaetigung: best,
		Rahmen: a.Rahmen, Intervall: a.Intervall, Frist: a.Frist,
		Instanz: a.Instanz, Signatur: halt.signieren,
		Person: strings.TrimSpace(a.Person), Suche: strings.TrimSpace(a.Suche),
	})
	if err != nil {
		return nil, err
	}
	return &Sitzung{Fenster: f, HSM: hsm, halt: halt}, nil
}

// SpeicherAus sagt, ob der Bestätigungsspeicher fehlt.
func (a Angaben) SpeicherAus() bool { return strings.TrimSpace(a.Vorlage.Speicher) == "" }

// Signieren setzt den HSM-Schlüssel für diese eine Handlung.
// Der öffentliche Schlüssel muss der der Sitzung sein.
func (s *Sitzung) Signieren(key *ecdsa.PrivateKey) error {
	if s == nil || s.halt == nil || key == nil || s.HSM == nil || !key.PublicKey.Equal(s.HSM) {
		privatWeg(key)
		return ErrAngabe
	}
	s.halt.setzen(key)
	return nil
}

// SignaturWeg überschreibt den HSM-Schlüssel der Handlung.
func (s *Sitzung) SignaturWeg() {
	if s != nil && s.halt != nil {
		s.halt.weg()
	}
}

// Schliessen verwirft Klartext und entsperrte Schlüssel.
func (s *Sitzung) Schliessen() {
	if s == nil {
		return
	}
	if s.Fenster != nil {
		s.Fenster.Schliessen()
	}
	s.SignaturWeg()
}

type hsmHalt struct {
	mu  sync.Mutex
	key *ecdsa.PrivateKey
}

func (h *hsmHalt) signieren(p []byte) (protocol.Signature, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.key == nil {
		return protocol.Signature{}, fenster.ErrSumme
	}
	return crypt.SignP256(h.key, p)
}

func (h *hsmHalt) setzen(key *ecdsa.PrivateKey) {
	h.mu.Lock()
	alt := h.key
	h.key = key
	h.mu.Unlock()
	privatWeg(alt)
}

func (h *hsmHalt) weg() { h.setzen(nil) }

func zielOeffnen(a Angaben) (fenster.Ziel, error) {
	switch a.Vorlage.Verbindung.Ziel {
	case fenster.ZielPlatte:
		p, err := schreiben.OeffnenPlatte(a.Vorlage.Verbindung.Pfad)
		if err != nil {
			return nil, err
		}
		return plattenZiel{p}, nil
	case fenster.ZielS3:
		if a.Region == "" || a.Zugang == "" || len(a.Geheimnis) == 0 {
			return nil, ErrAngabe
		}
		s, err := schreiben.OeffnenS3(schreiben.S3Konfig{
			Endpunkt: a.Vorlage.Verbindung.Endpunkt, Bucket: a.Vorlage.Verbindung.Bucket,
			Region: a.Region, Zugang: a.Zugang, Geheimnis: string(a.Geheimnis),
		})
		if err != nil {
			return nil, err
		}
		return s3Ziel{s}, nil
	default:
		return nil, fenster.ErrVerbindung
	}
}

func vorhanden(pfad string) string {
	st, err := os.Stat(pfad)
	if err != nil || st.IsDir() {
		return ""
	}
	return pfad
}

func zertifikatLesen(pfad string) (*x509.Certificate, error) {
	block, err := pemBlock(pfad)
	if err != nil || block.Type != "CERTIFICATE" {
		return nil, ErrAngabe
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrAngabe
	}
	return cert, nil
}

func oeffentlichLesen(pfad string) (*ecdsa.PublicKey, error) {
	block, err := pemBlock(pfad)
	if err != nil {
		return nil, err
	}
	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			pub = cert.PublicKey
		}
	default:
		return nil, ErrAngabe
	}
	if err != nil {
		return nil, ErrAngabe
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve == nil || ec.Curve.Params().Name != "P-256" {
		return nil, ErrAngabe
	}
	return ec, nil
}

// PrivaterSchluessel liest ein unverschlüsseltes PKCS#8, P-256.
// Die Dateibytes werden überschrieben. Der Schlüssel selbst bleibt beim Aufrufer.
func PrivaterSchluessel(pfad string) (*ecdsa.PrivateKey, error) {
	roh, err := os.ReadFile(pfad)
	if err != nil || len(roh) == 0 || len(roh) > 1<<16 {
		return nil, ErrAngabe
	}
	defer crypt.Wipe(roh)
	block, rest := pemDecode(roh)
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrAngabe
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrAngabe
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve == nil || priv.Curve.Params().Name != "P-256" {
		privatWeg(priv)
		return nil, ErrAngabe
	}
	return priv, nil
}
