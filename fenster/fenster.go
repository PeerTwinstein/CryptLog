package fenster

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/werkzeug"
)

var (
	// ErrFenster heißt, die Handlung braucht eine entsperrte Sitzung.
	ErrFenster = errors.New("fenster: ohne Entsperrung")
	// ErrPassphrase heißt, der einfache Modus hat keine Passphrase für diese Sitzung.
	ErrPassphrase = errors.New("fenster: Passphrase fehlt")
	// ErrModus heißt, Träger und Passphrase passen nicht zum Modus des Mandanten.
	ErrModus = errors.New("fenster: Modus passt nicht")
	// ErrVerbindung heißt, Ziel, Abschluss oder Schlüssel der Sitzung fehlen.
	ErrVerbindung = errors.New("fenster: Verbindung ungültig")
	// ErrArt heißt, die Prüfungsart passt nicht zu dieser Sitzung.
	ErrArt = errors.New("fenster: Prüfungsart passt nicht")
	// ErrPruefung heißt, eine Prüfung hält den Klartext noch.
	ErrPruefung = errors.New("fenster: Prüfung läuft")
	// ErrBestaetigung heißt, die Epoche wird nicht bestätigt.
	ErrBestaetigung = errors.New("fenster: Epoche wird nicht bestätigt")
	// ErrSumme heißt, die Verzeichnis-Summenepoche passt nicht.
	ErrSumme = errors.New("fenster: Verzeichnis-Summe passt nicht")
	// ErrAufruf heißt, die Anfrage an den Suchprozess hat keinen Aufrufschlüssel.
	ErrAufruf = errors.New("fenster: Aufrufschlüssel fehlt")
	// ErrZiel heißt, die Ablage passt nicht zur Sitzung.
	ErrZiel = errors.New("fenster: Ablage passt nicht")
	// ErrSchluessel heißt, Zertifikat oder privater Schlüssel passen nicht.
	ErrSchluessel = errors.New("fenster: Schlüssel passt nicht")
)

// Art ist eine der vier Prüfungen. Eine Handlung für den ganzen Bucket gibt es nicht.
type Art int

const (
	// ArtGruppe prüft einen Gruppenstrom über einen Zeitraum.
	ArtGruppe Art = iota + 1
	// ArtGezielt öffnet die Verweise einer Person, einer Vorgangsnummer oder beider.
	ArtGezielt
	// ArtAuffang prüft den Auffangstrom über einen Zeitraum.
	ArtAuffang
	// ArtPlattform prüft den Plattform-Auffang über einen Zeitraum.
	ArtPlattform
)

// Ziel ist die Ablage. Das Fenster schreibt dort die Verzeichnis-Summenepoche
// und sonst nur gelesene Segmente. Den Klartext schreibt es nicht.
type Ziel interface {
	Lesen(schluessel string) ([]byte, bool, error)
	Liste(prefix string) ([]string, error)
	Schreiben(schluessel string, inhalt []byte) error
	Mandanten() ([]protocol.ID, error)
}

// Bestaetigung ist ein Eintrag des Bestätigungsspeichers, außerhalb des Log-Buckets.
type Bestaetigung struct {
	Mandant  protocol.ID
	Ablage   protocol.ID
	Epoch    protocol.EpochID
	Previous protocol.Hash
	Hash     protocol.Hash
	Signatur protocol.Signature
	Finger   protocol.Hash
}

// Abschluss ist die Epochenbestätigung. Er hängt an und ersetzt nicht.
type Abschluss interface {
	Bestaetigung(mandant, ablage protocol.ID, epoch protocol.EpochID) (hash protocol.Hash, sig protocol.Signature, ok bool, err error)
	Vermerk(mandant, ablage protocol.ID, epoch protocol.EpochID) (tag time.Time, ok bool, err error)
	Anhaengen(Bestaetigung) (ok bool, err error)
	Zweige(mandant, ablage protocol.ID, epoch protocol.EpochID) ([]werkzeug.Zweig, error)
}

// Traeger ist HSM oder Smartcard. Der private Schlüssel verlässt ihn nicht.
type Traeger interface {
	Oeffentlich() (crypto.PublicKey, error)
	Unwrap(wrapped, ctx []byte) ([]byte, error)
	Signieren(payload []byte) (protocol.Signature, error)
}

// Konfig öffnet das Fenster, nicht eine Prüfung.
// Zertifikat, Status und die öffentlichen Schlüssel liegen vor.
// Eine Passphrase nimmt Neu nicht an.
type Konfig struct {
	Verbindung   Verbindung
	Ziel         Ziel
	Abschluss    Abschluss
	Zertifikat   *x509.Certificate
	Status       werkzeug.Status
	Modus        schluessel.Modus
	Pruef        *ecdsa.PublicKey
	HSM          *ecdsa.PublicKey
	Bestaetigung *ecdsa.PublicKey
	Rahmen       int
	Intervall    time.Duration
	Frist        time.Duration
	Instanz      protocol.ID
	Signatur     func([]byte) (protocol.Signature, error)
	Person       string
	Suche        string
	Jetzt        func() time.Time
	Client       *http.Client
}

// Sicht ist Fingerabdruck und Status, bevor ein Schlüssel geöffnet wird.
type Sicht struct {
	Finger protocol.Hash
	Status werkzeug.Status
	Modus  schluessel.Modus
}

// Auswahl ist eine Prüfung. Die Art bestimmt, was geöffnet wird.
type Auswahl struct {
	Art     Art
	Von     time.Time
	Bis     time.Time
	Kohorte string
	Person  string
	Vorgang string
}

// Zeile ist ein geöffneter Eintrag. Die Bytefelder gehören dem Fenster
// und werden mit Ende überschrieben.
type Zeile struct {
	Seq          uint64
	Zeit         uint64
	Text         []byte
	Vorgang      []byte
	Personen     [][]byte
	Grund        protocol.Grund
	Angabe       []byte
	Unzugeordnet bool
	NachRaster   bool
	Gueltig      bool
}

// Befund ist die Epoche und, soweit sie geöffnet wurde, ihre Einträge.
// Name ist die Beschriftung aus dem Katalog. Ablage bleibt daneben prüfbar.
type Befund struct {
	Epoch           protocol.EpochID
	Ablage          protocol.ID
	Name            string
	Rolle           protocol.StromRolle
	Luecke          bool
	Verzweigung     bool
	VorgaengerBruch bool
	Geloescht       bool
	Kompromittiert  bool
	Verloren        bool
	Vertraulich     bool
	Eintraege       []Zeile
}

// Ergebnis hält den Klartext der Auswahl für die Dauer dieser Prüfung.
type Ergebnis struct {
	Art     Art
	Epochen int
	Befunde []Befund
}

// Fenster ist die Sitzung auf dem Rechner des Empfängers.
type Fenster struct {
	mu        sync.Mutex
	verb      Verbindung
	ziel      Ziel
	abschluss Abschluss
	cert      *x509.Certificate
	finger    protocol.Hash
	status    werkzeug.Status
	modus     schluessel.Modus
	pruef     *ecdsa.PublicKey
	hsm       *ecdsa.PublicKey
	bestPub   *ecdsa.PublicKey
	plattform bool
	rahmen    int
	intervall time.Duration
	frist     time.Duration
	instanz   protocol.ID
	sign      func([]byte) (protocol.Signature, error)
	person    string
	suche     string
	uhr       func() time.Time
	client    *http.Client
	priv      crypto.PrivateKey
	traeger   Traeger
	aufruf    *ecdsa.PrivateKey
	aufrufT   Traeger
	katalog   *protocol.Stand
	sitzung   *Ergebnis
}

// Neu legt das Fenster an. Es liest keine Segmente und entsperrt nichts.
func Neu(k Konfig) (*Fenster, error) {
	if k.Ziel == nil || k.Abschluss == nil || k.Zertifikat == nil || k.HSM == nil || k.Pruef == nil || k.Bestaetigung == nil {
		return nil, ErrVerbindung
	}
	switch k.Status {
	case werkzeug.StatusAktuell, werkzeug.StatusAbgeloest, werkzeug.StatusAbgelaufen,
		werkzeug.StatusKompromittiert, werkzeug.StatusVerloren:
	default:
		return nil, werkzeug.ErrStatus
	}
	if _, err := protocol.RahmenNutz(k.Rahmen); err != nil {
		return nil, err
	}
	if !intervallOK(k.Intervall) || !fristOK(k.Frist) {
		return nil, werkzeug.ErrZeitraum
	}
	if err := k.Verbindung.zumModus(k.Modus); err != nil {
		return nil, err
	}
	finger, err := crypt.FingerprintCertificate(k.Zertifikat)
	if err != nil {
		return nil, err
	}
	uhr := k.Jetzt
	if uhr == nil {
		uhr = time.Now
	}
	return &Fenster{
		verb: k.Verbindung, ziel: k.Ziel, abschluss: k.Abschluss,
		cert: k.Zertifikat, finger: finger, status: k.Status, modus: k.Modus,
		pruef: k.Pruef, hsm: k.HSM, bestPub: k.Bestaetigung,
		plattform: k.Verbindung.Plattform, rahmen: k.Rahmen, intervall: k.Intervall,
		frist: k.Frist, instanz: k.Instanz, sign: k.Signatur, person: k.Person,
		suche: k.Suche, uhr: uhr, client: k.Client,
	}, nil
}

// Sicht nennt Fingerabdruck und Status, bevor der Empfänger entsperrt.
func (f *Fenster) Sicht() Sicht {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Sicht{Finger: f.finger, Status: f.lageStatus(), Modus: f.modus}
}

// Einfach wickelt den gespeicherten privaten Schlüssel mit der Passphrase aus.
// Die Passphrase wird überschrieben und nicht behalten.
func (f *Fenster) Einfach(passphrase []byte) error {
	defer crypt.Wipe(passphrase)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modus != schluessel.ModusEinfach || f.priv != nil || f.traeger != nil {
		return ErrModus
	}
	if len(passphrase) == 0 {
		return ErrPassphrase
	}
	roh, err := datei(f.verb.KEK)
	if err != nil {
		return err
	}
	defer crypt.Wipe(roh)
	key, err := Entschluesseln(roh, passphrase)
	if err != nil {
		return err
	}
	pub, err := oeffentlich(key)
	if err != nil || !gleich(pub, f.cert.PublicKey) {
		verwerfen(key)
		return ErrSchluessel
	}
	f.priv = key
	return nil
}

// Sicher verwendet den Schlüssel am Träger. Der private Schlüssel kommt nicht herein.
func (f *Fenster) Sicher(t Traeger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modus != schluessel.ModusSicher || f.priv != nil || f.traeger != nil || t == nil {
		return ErrModus
	}
	pub, err := t.Oeffentlich()
	if err != nil || !gleich(pub, f.cert.PublicKey) {
		return ErrSchluessel
	}
	f.traeger = t
	return nil
}

// AufrufEinfach entsperrt den Aufrufschlüssel. Seine Passphrase öffnet keinen DEK.
func (f *Fenster) AufrufEinfach(passphrase []byte) error {
	defer crypt.Wipe(passphrase)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.aufruf != nil || f.aufrufT != nil {
		return ErrModus
	}
	if len(passphrase) == 0 || f.verb.Aufruf == "" {
		return ErrPassphrase
	}
	roh, err := datei(f.verb.Aufruf)
	if err != nil {
		return err
	}
	defer crypt.Wipe(roh)
	key, err := Entschluesseln(roh, passphrase)
	if err != nil {
		return err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve == nil || ec.Curve.Params().Name != "P-256" {
		verwerfen(key)
		return ErrAufruf
	}
	f.aufruf = ec
	return nil
}

// AufrufSicher signiert später mit dem Träger. Der Schlüssel bleibt dort.
func (f *Fenster) AufrufSicher(t Traeger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.aufruf != nil || f.aufrufT != nil || t == nil {
		return ErrModus
	}
	pub, err := t.Oeffentlich()
	if err != nil {
		return ErrAufruf
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve == nil || ec.Curve.Params().Name != "P-256" {
		return ErrAufruf
	}
	f.aufrufT = t
	return nil
}

// Arten nennt die Prüfungen, die dieser entsperrte Schlüssel anbietet.
// Den Plattform-Auffang nur, wenn der Schlüssel der Plattform-KEK ist.
func (f *Fenster) Arten() []Art {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.entsperrt() {
		return nil
	}
	arten := []Art{ArtGruppe, ArtGezielt, ArtAuffang}
	if f.plattform {
		arten = append(arten, ArtPlattform)
	}
	return arten
}

// Schliessen verwirft den Klartext und die entsperrten Schlüssel.
func (f *Fenster) Schliessen() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ende()
	verwerfen(f.priv)
	verwerfen(f.aufruf)
	f.priv = nil
	f.traeger = nil
	f.aufruf = nil
	f.aufrufT = nil
	f.katalog = nil
}

func (f *Fenster) entsperrt() bool { return f.priv != nil || f.traeger != nil }

func (f *Fenster) jetzt() time.Time { return f.uhr().UTC() }

func (f *Fenster) lageStatus() werkzeug.Status {
	if f.status == werkzeug.StatusAktuell && f.cert != nil && !f.jetzt().Before(f.cert.NotAfter) {
		return werkzeug.StatusAbgelaufen
	}
	return f.status
}

func (f *Fenster) belegen(a werkzeug.Auftrag) werkzeug.Auftrag {
	a.Status = f.lageStatus()
	a.Zertifikat = f.cert
	a.HSM = f.hsm
	a.Pruef = f.pruef
	a.Rahmen = f.rahmen
	if f.traeger != nil {
		a.Oeffner = f.traeger
		a.Priv = nil
	} else {
		a.Priv = f.priv
	}
	return a
}

func datei(pfad string) ([]byte, error) {
	f, err := os.Open(pfad)
	if err != nil {
		return nil, ErrPassphrase
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<16+1))
	if err != nil || len(b) == 0 || len(b) > 1<<16 {
		crypt.Wipe(b)
		return nil, ErrPassphrase
	}
	return b, nil
}

func oeffentlich(k crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, ErrSchluessel
		}
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		if key == nil {
			return nil, ErrSchluessel
		}
		return &key.PublicKey, nil
	default:
		return nil, ErrSchluessel
	}
}

func gleich(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	da, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	db, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	if len(da) != len(db) {
		return false
	}
	diff := 0
	for i := range da {
		diff |= int(da[i] ^ db[i])
	}
	return diff == 0
}

func verwerfen(k crypto.PrivateKey) {
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		if key != nil {
			nullen(key.D)
		}
	case *rsa.PrivateKey:
		if key != nil {
			nullen(key.D)
			nullen(key.Precomputed.Dp)
			nullen(key.Precomputed.Dq)
			nullen(key.Precomputed.Qinv)
			for _, prime := range key.Primes {
				nullen(prime)
			}
		}
	}
	runtime.KeepAlive(k)
}

func nullen(n *big.Int) {
	if n == nil {
		return
	}
	w := n.Bits()
	for i := range w {
		w[i] = 0
	}
	runtime.KeepAlive(n)
}

func intervallOK(d time.Duration) bool {
	if d < 15*time.Minute || d > 8*time.Hour {
		return false
	}
	return (24*time.Hour)%d == 0
}

func fristOK(d time.Duration) bool {
	return d > 0 && d%(24*time.Hour) == 0
}
