package werkzeug

import (
	"crypto/ecdsa"
	"errors"
	"math"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

// Abweichung ist der größte Abstand zwischen der Uhr der Zone und dem
// Zeitpunkt der signierten Anfrage.
const Abweichung = 5 * time.Minute

// ErrAnfrage ist eine Abfrage, die die Zone nicht autorisiert.
var ErrAnfrage = errors.New("werkzeug: Anfrage nicht autorisiert")

// ErrEinmal ist eine Signatur, die in diesem Fenster schon angenommen wurde.
var ErrEinmal = errors.New("werkzeug: Anfrage schon verwendet")

// Einmal merkt sich angenommene Anfragesignaturen.
// Merken liefert falsch, wenn diese Signatur schon angenommen wurde.
type Einmal interface {
	Merken(protocol.Signature) bool
}

// Zone ist eine autorisierte Abfrage des Vorgangsindex.
// Die Anfrage ist die signierte Nutzlast. Jetzt ist die Uhr der Zone.
// Index ist der Strom der Rolle vorgang, Summen der Strom vorgang-summe.
type Zone struct {
	Aussage    protocol.Aussage
	AussageSig protocol.Signature
	Aufruf     *ecdsa.PublicKey
	Anfrage    protocol.Indexanfrage
	AnfrageSig protocol.Signature
	Pruef      *ecdsa.PublicKey
	Jetzt      time.Time
	Gesehen    Einmal
	Frist      time.Duration
	Index      Strom
	Summen     Strom
}

// Protokoll ist der Nachweis einer ausgeführten Abfrage.
// Er enthält keinen Logtext und keinen Indexeintrag.
type Protokoll struct {
	Person     string
	Finger     protocol.Hash
	Mandant    protocol.ID
	Art        protocol.AnfrageArt
	Schluessel string
	Von        uint64
	Bis        uint64
	Zeitpunkt  uint64
}

// PersonTreffer ist eine Person, die an der abgefragten Vorgangsnummer steht.
type PersonTreffer struct {
	Person  string
	Rolle   protocol.StromRolle
	Kohorte string
	Erster  uint64
	Letzter uint64
}

// VorgangTreffer ist eine Vorgangsnummer der abgefragten Person.
type VorgangTreffer struct {
	Nummer  string
	Rolle   protocol.StromRolle
	Kohorte string
	Erster  uint64
	Letzter uint64
}

// Antwort ist das Ergebnis einer Indexabfrage.
// Bei einer Vorgangsnummer sind die Personen gesetzt, bei einer Person die Vorgänge.
type Antwort struct {
	Protokoll Protokoll
	Personen  []PersonTreffer
	Vorgaenge []VorgangTreffer
}

type trefferSchluss struct {
	name    string
	rolle   protocol.StromRolle
	kohorte string
}

// Index prüft die Signatur der Anfrage und öffnet danach nur den Index
// dieser Anfrage. Ein abgeschlossener Monat kommt aus der Summenepoche,
// wenn deren Belege passen. Der laufende Monat kommt aus den Index-Epochen.
// Zurück gehen die Personen eines Vorgangs oder die Vorgänge einer Person,
// ohne den Logtext.
func Index(z Zone) (Antwort, error) {
	if err := zonePruefen(z); err != nil {
		return Antwort{}, err
	}
	von, bis, err := fenster(z.Anfrage)
	if err != nil {
		return Antwort{}, err
	}
	if err := stromGueltig(z.Index, protocol.RolleVorgang); err != nil {
		return Antwort{}, err
	}
	if summeVorhanden(z.Summen) {
		if err := summeStrom(z.Summen, protocol.RolleVorgangSumme); err != nil {
			return Antwort{}, err
		}
	}
	if !z.Gesehen.Merken(z.AnfrageSig) {
		return Antwort{}, ErrEinmal
	}
	var extra []Eintrag
	var aus map[protocol.EpochID]struct{}
	if summeVorhanden(z.Summen) {
		stand, err := summenLesen(summenAnfrage{
			Mandant: z.Anfrage.Mandant, Frist: z.Frist, Jetzt: z.Jetzt, Von: von, Bis: bis,
			Quellen: z.Index.Epochen, Summen: z.Summen,
		})
		if err != nil {
			return Antwort{}, err
		}
		aus = stand.auslassen
		for _, bericht := range stand.berichte {
			extra = append(extra, bericht.Eintraege...)
		}
	}
	staende, err := zeitraum(Anfrage{
		Mandant:   z.Anfrage.Mandant,
		Ablage:    z.Index.Ablage,
		Rolle:     protocol.RolleVorgang,
		Intervall: z.Index.Intervall,
		Frist:     z.Frist,
		Jetzt:     z.Jetzt,
		Von:       von,
		Bis:       bis,
		Epochen:   z.Index.Epochen,
	}, aus)
	if err != nil {
		return Antwort{}, err
	}
	gruppen := make(map[trefferSchluss]*spanne)
	merken := func(name string, rolle protocol.StromRolle, kohorte string, erster, letzter uint64) {
		k := trefferSchluss{name: name, rolle: rolle, kohorte: kohorte}
		s := gruppen[k]
		if s == nil {
			gruppen[k] = &spanne{erster: erster, letzter: letzter}
			return
		}
		if erster < s.erster {
			s.erster = erster
		}
		if letzter > s.letzter {
			s.letzter = letzter
		}
	}
	for _, stand := range staende {
		if !stand.ImZeitraum || stand.Geloescht {
			continue
		}
		for _, eintrag := range stand.Bericht.Eintraege {
			if !eintrag.Gueltig || eintrag.Index == nil {
				continue
			}
			if !indexTrifft(z.Anfrage, eintrag.Index) {
				continue
			}
			name := eintrag.Index.Person
			if z.Anfrage.Art == protocol.AnfragePerson {
				name = eintrag.Index.Nummer
			}
			merken(name, eintrag.Index.Rolle, eintrag.Index.Kohorte, eintrag.Index.Zeitpunkt, eintrag.Index.Zeitpunkt)
		}
	}
	for _, eintrag := range extra {
		if !eintrag.Gueltig {
			continue
		}
		switch z.Anfrage.Art {
		case protocol.AnfrageVorgang:
			if eintrag.VorgangSumme == nil || eintrag.VorgangSumme.Nummer != z.Anfrage.Schluessel {
				continue
			}
			for _, b := range eintrag.VorgangSumme.Personen {
				merken(b.Name, b.Rolle, b.Kohorte, b.Erster, b.Letzter)
			}
		case protocol.AnfragePerson:
			if eintrag.PersonSumme == nil || eintrag.PersonSumme.Person != z.Anfrage.Schluessel {
				continue
			}
			for _, b := range eintrag.PersonSumme.Nummern {
				merken(b.Name, b.Rolle, b.Kohorte, b.Erster, b.Letzter)
			}
		}
	}
	antwort := Antwort{Protokoll: protokoll(z)}
	reihen := make([]trefferSchluss, 0, len(gruppen))
	for k := range gruppen {
		reihen = append(reihen, k)
	}
	sortTreffer(reihen)
	for _, k := range reihen {
		s := gruppen[k]
		switch z.Anfrage.Art {
		case protocol.AnfrageVorgang:
			antwort.Personen = append(antwort.Personen, PersonTreffer{
				Person: k.name, Rolle: k.rolle, Kohorte: k.kohorte, Erster: s.erster, Letzter: s.letzter,
			})
		case protocol.AnfragePerson:
			antwort.Vorgaenge = append(antwort.Vorgaenge, VorgangTreffer{
				Nummer: k.name, Rolle: k.rolle, Kohorte: k.kohorte, Erster: s.erster, Letzter: s.letzter,
			})
		}
	}
	return antwort, nil
}

func zonePruefen(z Zone) error {
	if z.Gesehen == nil || z.Aufruf == nil || z.Pruef == nil || !utc(z.Jetzt) || z.Jetzt.IsZero() {
		return ErrAnfrage
	}
	if z.Aussage.Rolle != protocol.RolleDatenschuetzer || z.Aussage.Mandant != z.Anfrage.Mandant || z.Aussage.Person != z.Anfrage.Person || !z.Aussage.Deckt(z.Anfrage.Zeitpunkt) {
		return ErrAnfrage
	}
	if z.Anfrage.Zeitpunkt > uint64(math.MaxInt64) {
		return ErrAnfrage
	}
	delta := z.Jetzt.UnixMilli() - int64(z.Anfrage.Zeitpunkt)
	if delta < 0 {
		delta = -delta
	}
	if delta > Abweichung.Milliseconds() {
		return ErrAnfrage
	}
	fp, err := crypt.FingerprintSPKI(z.Aufruf)
	if err != nil || fp != z.Aussage.Finger {
		return ErrAnfrage
	}
	nutz, err := protocol.AussageBytes(z.Aussage)
	if err != nil || !signaturP256(z.Pruef, nutz, z.AussageSig) {
		return ErrAnfrage
	}
	anfrage, err := protocol.IndexanfrageBytes(z.Anfrage)
	if err != nil || !signaturP256(z.Aufruf, anfrage, z.AnfrageSig) {
		return ErrAnfrage
	}
	return nil
}

func signaturP256(pub *ecdsa.PublicKey, nutz []byte, sig protocol.Signature) bool {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil || pub.Curve.Params().Name != "P-256" || pub.Curve.Params().BitSize != 256 {
		return false
	}
	return crypt.VerifyP256(pub, nutz, sig)
}

func fenster(a protocol.Indexanfrage) (time.Time, time.Time, error) {
	if a.Von > uint64(math.MaxInt64) || a.Bis > uint64(math.MaxInt64) {
		return time.Time{}, time.Time{}, ErrAnfrage
	}
	return time.UnixMilli(int64(a.Von)).UTC(), time.UnixMilli(int64(a.Bis)).UTC(), nil
}

func indexTrifft(a protocol.Indexanfrage, idx *protocol.IndexEintrag) bool {
	switch a.Art {
	case protocol.AnfrageVorgang:
		return idx.Nummer == a.Schluessel
	case protocol.AnfragePerson:
		return idx.Person == a.Schluessel
	default:
		return false
	}
}

func protokoll(z Zone) Protokoll {
	return Protokoll{
		Person:     z.Anfrage.Person,
		Finger:     z.Aussage.Finger,
		Mandant:    z.Anfrage.Mandant,
		Art:        z.Anfrage.Art,
		Schluessel: z.Anfrage.Schluessel,
		Von:        z.Anfrage.Von,
		Bis:        z.Anfrage.Bis,
		Zeitpunkt:  z.Anfrage.Zeitpunkt,
	}
}

func sortTreffer(reihen []trefferSchluss) {
	for i := 1; i < len(reihen); i++ {
		j := i
		for j > 0 && trefferVor(reihen[j], reihen[j-1]) {
			reihen[j], reihen[j-1] = reihen[j-1], reihen[j]
			j--
		}
	}
}

func trefferVor(a, b trefferSchluss) bool {
	if a.name != b.name {
		return a.name < b.name
	}
	if a.rolle != b.rolle {
		return a.rolle < b.rolle
	}
	return a.kohorte < b.kohorte
}
