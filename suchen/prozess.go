package suchen

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/werkzeug"
)

const maxAnfrage = 8 << 10

// Register ist lesend. Eine vom Aufrufer vorgelegte Abschrift ersetzt den Eintrag nicht.
type Register interface {
	Datenschuetzer(mandant protocol.ID, person string) (Eintrag, bool, error)
}

// Eintrag ist die Aussage, die im Register steht, und der öffentliche Aufrufschlüssel.
type Eintrag struct {
	Aussage protocol.Aussage
	Sig     protocol.Signature
	Aufruf  *ecdsa.PublicKey
}

// Pruefer liefert den öffentlichen Prüfschlüssel des Mandanten, für den Bucket
// plattform den der Plattform.
type Pruefer interface {
	Schluessel(mandant protocol.ID) (*ecdsa.PublicKey, bool, error)
}

// Konfig startet die Zone. Schluessel ist die Datei mit dem privaten Index-Schlüssel.
// Protokoll ist die Datei der Zone, nicht das technische Log.
type Konfig struct {
	Schluessel string
	Protokoll  string
	Ziel       Ziel
	Register   Register
	Pruef      Pruefer
	Bestand    Bestand
	Abschluss  Abschluss
	Instanz    protocol.ID
	Signatur   func([]byte) (protocol.Signature, error)
	Jetzt      func() time.Time
	Version    string
	Digest     string
}

// Prozess ist die Sicherheitszone. Er gibt den privaten Index-Schlüssel nicht heraus.
type Prozess struct {
	mu          sync.Mutex
	pfad        string
	priv        crypto.PrivateKey
	ziel        Ziel
	register    Register
	pruef       Pruefer
	bestand     Bestand
	abschluss   Abschluss
	instanz     protocol.ID
	sign        func([]byte) (protocol.Signature, error)
	jetzt       func() time.Time
	version     string
	digest      string
	datei       *os.File
	gesehen     *menge
	halt        bool
	abgelehnt   uint64
	autorisiert uint64
	wiederholt  uint64
	hist        histogramm
}

var zeitGrenzen = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogramm struct {
	grenzen []float64
	zahl    []uint64
	summe   float64
	anzahl  uint64
}

func (h *histogramm) beobachten(sec float64) {
	h.summe += sec
	h.anzahl++
	for i, grenze := range h.grenzen {
		if sec <= grenze {
			h.zahl[i]++
		}
	}
}

// Start liest den privaten Index-Schlüssel. Ohne diese Datei startet der Prozess nicht.
// Eine Passphrase nimmt er nicht entgegen.
func Start(k Konfig) (*Prozess, error) {
	if k.Schluessel == "" {
		return nil, ErrGeheimnis
	}
	priv, err := schluesselLesen(k.Schluessel)
	if err != nil {
		return nil, err
	}
	if err := konfigGueltig(k); err != nil {
		verwerfen(priv)
		return nil, err
	}
	jetzt := k.Jetzt
	if jetzt == nil {
		jetzt = func() time.Time { return time.Now().UTC() }
	}
	bisher, err := protokollBisher(k.Protokoll)
	if err != nil {
		verwerfen(priv)
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(k.Protokoll), 0o700); err != nil {
		verwerfen(priv)
		return nil, err
	}
	datei, err := os.OpenFile(k.Protokoll, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		verwerfen(priv)
		return nil, err
	}
	p := &Prozess{
		pfad:      k.Schluessel,
		priv:      priv,
		ziel:      k.Ziel,
		register:  k.Register,
		pruef:     k.Pruef,
		bestand:   k.Bestand,
		abschluss: k.Abschluss,
		instanz:   k.Instanz,
		sign:      k.Signatur,
		jetzt:     jetzt,
		version:   k.Version,
		digest:    k.Digest,
		datei:     datei,
		gesehen:   neueMenge(jetzt),
		hist:      histogramm{grenzen: zeitGrenzen, zahl: make([]uint64, len(zeitGrenzen))},
	}
	if err := p.protokollLaden(bisher); err != nil {
		_ = datei.Close()
		verwerfen(priv)
		p.priv = nil
		return nil, err
	}
	return p, nil
}

func konfigGueltig(k Konfig) error {
	var leer protocol.ID
	if k.Protokoll == "" || k.Ziel == nil || k.Register == nil || k.Pruef == nil || k.Bestand == nil || k.Abschluss == nil || k.Instanz == leer {
		return ErrKonfig
	}
	if k.Version != "" || k.Digest != "" {
		if !labelOK(k.Version) || !labelOK(k.Digest) {
			return ErrKonfig
		}
	}
	return nil
}

func labelOK(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// Anfrage prüft die Signatur gegen das Register und öffnet danach nur den Index
// dieser Anfrage. Zurück gehen die Treffer, nicht die Epoche und nicht der DEK.
func (p *Prozess) Anfrage(roh []byte) (Treffer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok, grund := p.bereit(); !ok {
		if grund == "beenden" {
			return Treffer{}, ErrBeenden
		}
		return Treffer{}, ErrGeheimnis
	}
	anfrage, sig, err := teilen(roh)
	if err != nil {
		return Treffer{}, err
	}
	jetzt := p.jetzt().UTC()
	ein, pruef, err := p.autorisieren(jetzt, anfrage, sig)
	if err != nil {
		if errors.Is(err, ErrAnfrage) {
			p.abgelehnt++
		}
		return Treffer{}, err
	}
	if p.gesehen.hat(sig) {
		p.wiederholt++
		return Treffer{}, ErrWiederholt
	}
	st, ok, err := p.bestand.Index(anfrage.Mandant)
	if err != nil {
		return Treffer{}, err
	}
	if !ok {
		p.abgelehnt++
		return Treffer{}, ErrAnfrage
	}
	if err := st.gueltig(); err != nil {
		return Treffer{}, err
	}
	start := time.Now()
	index, summe, err := p.laden(anfrage.Mandant, st)
	if err != nil {
		return Treffer{}, err
	}
	p.gesehen.zeitSetzen(int64(anfrage.Zeitpunkt))
	antwort, err := werkzeug.Index(werkzeug.Zone{
		Aussage:    ein.Aussage,
		AussageSig: ein.Sig,
		Aufruf:     ein.Aufruf,
		Anfrage:    anfrage,
		AnfrageSig: sig,
		Pruef:      pruef,
		Jetzt:      jetzt,
		Gesehen:    p.gesehen,
		Frist:      st.Frist,
		Index:      index,
		Summen:     summe,
	})
	if errors.Is(err, werkzeug.ErrEinmal) {
		p.wiederholt++
		return Treffer{}, ErrWiederholt
	}
	if errors.Is(err, werkzeug.ErrAnfrage) {
		p.abgelehnt++
		return Treffer{}, ErrAnfrage
	}
	if err != nil {
		return Treffer{}, err
	}
	if err := p.protokollSchreiben(antwort.Protokoll, sig); err != nil {
		return Treffer{}, err
	}
	p.autorisiert++
	p.hist.beobachten(time.Since(start).Seconds())
	return Treffer{
		Personen:  append([]werkzeug.PersonTreffer(nil), antwort.Personen...),
		Vorgaenge: append([]werkzeug.VorgangTreffer(nil), antwort.Vorgaenge...),
	}, nil
}

func (p *Prozess) autorisieren(jetzt time.Time, a protocol.Indexanfrage, sig protocol.Signature) (Eintrag, *ecdsa.PublicKey, error) {
	ein, ok, err := p.register.Datenschuetzer(a.Mandant, a.Person)
	if err != nil {
		return Eintrag{}, nil, err
	}
	if !ok {
		return Eintrag{}, nil, ErrAnfrage
	}
	pruef, pok, err := p.pruef.Schluessel(a.Mandant)
	if err != nil {
		return Eintrag{}, nil, err
	}
	if !pok || !p256(pruef) || !p256(ein.Aufruf) || jetzt.IsZero() || a.Zone != p.instanz {
		return Eintrag{}, nil, ErrAnfrage
	}
	if ein.Aussage.Rolle != protocol.RolleDatenschuetzer || ein.Aussage.Mandant != a.Mandant || ein.Aussage.Person != a.Person || !ein.Aussage.Deckt(a.Zeitpunkt) {
		return Eintrag{}, nil, ErrAnfrage
	}
	if a.Zeitpunkt > uint64(math.MaxInt64) {
		return Eintrag{}, nil, ErrAnfrage
	}
	delta := jetzt.UnixMilli() - int64(a.Zeitpunkt)
	if delta < 0 {
		delta = -delta
	}
	if delta > werkzeug.Abweichung.Milliseconds() {
		return Eintrag{}, nil, ErrAnfrage
	}
	fp, err := crypt.FingerprintSPKI(ein.Aufruf)
	if err != nil || fp != ein.Aussage.Finger {
		return Eintrag{}, nil, ErrAnfrage
	}
	nutz, err := protocol.AussageBytes(ein.Aussage)
	if err != nil || !crypt.VerifyP256(pruef, nutz, ein.Sig) {
		return Eintrag{}, nil, ErrAnfrage
	}
	roh, err := protocol.IndexanfrageBytes(a)
	if err != nil || !crypt.VerifyP256(ein.Aufruf, roh, sig) {
		return Eintrag{}, nil, ErrAnfrage
	}
	return ein, pruef, nil
}

func teilen(roh []byte) (protocol.Indexanfrage, protocol.Signature, error) {
	if len(roh) <= protocol.SignatureLen || len(roh) > maxAnfrage {
		return protocol.Indexanfrage{}, protocol.Signature{}, ErrFormat
	}
	var sig protocol.Signature
	copy(sig[:], roh[len(roh)-protocol.SignatureLen:])
	a, err := protocol.ParseIndexanfrage(roh[:len(roh)-protocol.SignatureLen])
	if err != nil {
		return protocol.Indexanfrage{}, protocol.Signature{}, ErrFormat
	}
	return a, sig, nil
}

// Beenden verwirft den privaten Index-Schlüssel. Danach nimmt der Prozess nichts mehr an.
func (p *Prozess) Beenden() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.halt {
		return
	}
	p.halt = true
	verwerfen(p.priv)
	p.priv = nil
	if p.datei != nil {
		_ = p.datei.Sync()
		_ = p.datei.Close()
		p.datei = nil
	}
}

// Live ist wahr, solange der Prozess läuft und das Beenden nicht begonnen hat.
func (p *Prozess) Live() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.halt
}

// Ready ist wahr, wenn der private Index-Schlüssel lesbar ist und kein Beenden läuft.
// Der Grund ist sonst secret oder beenden.
func (p *Prozess) Ready() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bereit()
}

func (p *Prozess) bereit() (bool, string) {
	if p.halt {
		return false, "beenden"
	}
	if !dateiLesbar(p.pfad) {
		return false, "secret"
	}
	return true, ""
}
