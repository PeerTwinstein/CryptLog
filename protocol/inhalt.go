package protocol

import (
	"bytes"
	"time"
	"unicode/utf8"
)

const (
	// SignaturMax ist die größte Signatur einer Zugehörigkeitsaussage.
	SignaturMax = 1024
)

// StromRolle ist die Rolle einer Ablage.
type StromRolle byte

const (
	// RolleGruppe ist der Gruppenstrom.
	RolleGruppe StromRolle = 1
	// RolleEinzel ist der Einzelstrom.
	RolleEinzel StromRolle = 2
	// RolleAuffang ist die Dead Letter Box des Mandanten.
	RolleAuffang StromRolle = 3
	// RolleVerzeichnis ist das Verzeichnis.
	RolleVerzeichnis StromRolle = 4
	// RolleVorgang ist der Vorgangsindex.
	RolleVorgang StromRolle = 5
	// RolleKatalog ist der Stromkatalog.
	RolleKatalog StromRolle = 6
	// RolleVerzeichnisSumme ist der Summenindex des Verzeichnisses.
	RolleVerzeichnisSumme StromRolle = 7
	// RolleVorgangSumme ist der Summenindex des Vorgangsindex.
	RolleVorgangSumme StromRolle = 8
)

// PersonRolle steht in der Zugehörigkeitsaussage.
type PersonRolle byte

const (
	// RollePerson ist eine Person ohne Datenschützerrolle.
	RollePerson PersonRolle = 1
	// RolleDatenschuetzer darf den Vorgangsindex ihres Mandanten abfragen.
	RolleDatenschuetzer PersonRolle = 2
)

// Merkmal ist das Ablagemerkmal einer Person. Es steht nicht in der Aussage.
type Merkmal byte

const (
	// MerkmalGruppe führt die Person im Gruppenstrom.
	MerkmalGruppe Merkmal = 1
	// MerkmalEinzeln führt die Person im Einzelstrom.
	MerkmalEinzeln Merkmal = 2
)

// Grund ist der Grund eines Auffang-Eintrags.
type Grund byte

const (
	// GrundUnbekannt heißt, die Person steht nicht im Register.
	GrundUnbekannt Grund = 1
	// GrundAussageUngueltig heißt, die Zugehörigkeitsaussage prüft nicht.
	GrundAussageUngueltig Grund = 2
	// GrundZielFehlt heißt, die Aussage gilt und das Ablagemerkmal zeigt auf keinen Strom.
	GrundZielFehlt Grund = 3
	// GrundOhneBezug heißt, der Aufruf nennt keine Person.
	GrundOhneBezug Grund = 4
	// GrundKEKFehlt heißt, der Mandant hat keinen aktuellen KEK.
	GrundKEKFehlt Grund = 5
	// GrundMandantUnbekannt heißt, der Aufruf nennt keinen Mandanten.
	GrundMandantUnbekannt Grund = 6
)

// VerweisArt unterscheidet Personen- und Vorgangsverweis.
type VerweisArt byte

const (
	// VerweisPerson zeigt von einer Person auf Strom, Epoche und Eintrag.
	VerweisPerson VerweisArt = 1
	// VerweisVorgang zeigt von einer Vorgangsnummer auf Strom, Epoche und Eintrag.
	VerweisVorgang VerweisArt = 2
)

// Aktiv sagt, ob eine Katalogkennung noch vergeben wird.
type Aktiv byte

const (
	// KennungAus heißt, die Katalogkennung wird nicht mehr vergeben.
	KennungAus Aktiv = 0
	// KennungAn heißt, die Katalogkennung wird vergeben.
	KennungAn Aktiv = 1
)

// PlattformMandant ist die mandant_id im Bucket plattform:
// die ASCII-Zeichenfolge "plattform", aufgefüllt mit Nullbytes.
func PlattformMandant() ID {
	var id ID
	copy(id[:], "plattform")
	return id
}

// Aussage ist die signierte Nutzlast der Zugehörigkeit.
// Der Fingerabdruck ist bei RollePerson 32 Nullbytes.
type Aussage struct {
	Mandant ID
	Person  string
	Rolle   PersonRolle
	Von     uint64
	Bis     uint64
	Finger  Hash
}

// AussageTeil ist die Aussage samt Signatur, wie sie im Log steht.
type AussageTeil struct {
	Nutzlast Aussage
	Signatur []byte
}

// LogInhalt ist der Inhalt eines Gruppen- oder Einzeleintrags.
type LogInhalt struct {
	Text     []byte
	Vorgang  string
	Aussagen []AussageTeil
	Bezuege  []string
}

// AuffangInhalt ist der Inhalt eines Auffang-Eintrags.
type AuffangInhalt struct {
	Grund    Grund
	Text     []byte
	Vorgang  string
	Angabe   string
	Aussagen []AussageTeil
	Personen []string
}

// Verweis zeigt von einer Person oder einer Vorgangsnummer auf einen Logeintrag.
type Verweis struct {
	Art        VerweisArt
	Schluessel string
	Mandant    ID
	Bind       ID
	Epoch      EpochID
	Seq        uint64
}

// IndexEintrag ist ein Eintrag des Vorgangsindex.
type IndexEintrag struct {
	Nummer    string
	Person    string
	Rolle     StromRolle
	Kohorte   string
	Epoch     EpochID
	Seq       uint64
	Zeitpunkt uint64
}

// Beleg nennt eine Epoche des zugrunde liegenden Stroms und den Hash
// ihres bestätigten Manifests.
type Beleg struct {
	Epoch EpochID
	Hash  Hash
}

// Bezug ist eine Person oder eine Vorgangsnummer in einem Strom.
// Name ist die Person oder die Nummer. Erster und Letzter sind die Unix-Zeit
// in Millisekunden.
type Bezug struct {
	Name    string
	Rolle   StromRolle
	Kohorte string
	Erster  uint64
	Letzter uint64
}

// VorgangSumme nennt zu einer Vorgangsnummer die verschiedenen Personen.
type VorgangSumme struct {
	Nummer   string
	Personen []Bezug
}

// PersonSumme nennt zu einer Person die Vorgangsnummern.
type PersonSumme struct {
	Person  string
	Nummern []Bezug
}

// AnfrageArt unterscheidet die beiden Richtungen der Indexabfrage.
type AnfrageArt byte

const (
	// AnfrageVorgang fragt die Personen eines Vorgangs.
	AnfrageVorgang AnfrageArt = 1
	// AnfragePerson fragt die Vorgänge einer Person.
	AnfragePerson AnfrageArt = 2
)

// Indexanfrage ist die signierte Nutzlast einer Abfrage des Vorgangsindex.
// Zone ist die Instanz des Suchprozesses. Von und Bis sind die Unix-Zeit in
// Millisekunden, Bis ist größer als Von. Zeitpunkt ist der Zeitpunkt der Anfrage.
type Indexanfrage struct {
	Mandant    ID
	Zone       ID
	Person     string
	Art        AnfrageArt
	Schluessel string
	Von        uint64
	Bis        uint64
	Zeitpunkt  uint64
}

// Kennung ist eine vergebene Stromkennung im Katalog.
type Kennung struct {
	Rolle   StromRolle
	Ablage  ID
	Bind    ID
	Kohorte string
	Aktiv   Aktiv
}

// Stand ist ein Katalogstand.
type Stand struct {
	Name      string
	Kennungen []Kennung
}

// AufrufBytes ist die Bytefolge, die event_hash deckt.
// Personen stehen in der Reihenfolge des Aufrufs. text ist keine UTF-8-Prüfung unterworfen.
func AufrufBytes(zeit uint64, vorgang string, personen []string, text []byte) ([]byte, error) {
	buf := AppendText(nil, "aufruf")
	buf = AppendU64(buf, zeit)
	var err error
	buf, err = appendUTF8(buf, vorgang)
	if err != nil {
		return nil, err
	}
	buf, err = appendPersonen(buf, personen)
	if err != nil {
		return nil, err
	}
	return appendLen(buf, text)
}

// AufrufHash ist der event_hash des Aufrufs.
// mandant ist bei einem nicht ermittelten Mandanten die Plattformkennung.
func AufrufHash(mandant, event ID, aufruf []byte) (Hash, error) {
	if !bytes.HasPrefix(aufruf, Domain("aufruf")) {
		return Hash{}, ErrDomain
	}
	return EventHash(mandant, event, aufruf)
}

// Deckt sagt, ob der Zeitpunkt in der Gültigkeit liegt, beide Grenzen einschließlich.
func (a Aussage) Deckt(zeit uint64) bool {
	return a.Von <= zeit && zeit <= a.Bis
}

// AussageBytes ist die signierte Nutzlast.
func AussageBytes(a Aussage) ([]byte, error) {
	var zero ID
	if a.Mandant == zero || a.Person == "" {
		return nil, ErrLength
	}
	var zeroHash Hash
	switch a.Rolle {
	case RollePerson:
		if a.Finger != zeroHash {
			return nil, ErrRolle
		}
	case RolleDatenschuetzer:
		if a.Finger == zeroHash {
			return nil, ErrRolle
		}
	default:
		return nil, ErrRolle
	}
	if a.Bis < a.Von {
		return nil, ErrLength
	}
	buf := AppendText(nil, "aussage")
	buf = append(buf, a.Mandant[:]...)
	var err error
	buf, err = appendUTF8(buf, a.Person)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(a.Rolle))
	buf = AppendU64(buf, a.Von)
	buf = AppendU64(buf, a.Bis)
	buf = append(buf, a.Finger[:]...)
	return buf, nil
}

// ParseAussage liest eine vollständige Aussage.
func ParseAussage(b []byte) (Aussage, error) {
	c := cursor{b: b}
	if err := c.domain("aussage"); err != nil {
		return Aussage{}, err
	}
	var a Aussage
	var err error
	if a.Mandant, err = c.id(); err != nil {
		return Aussage{}, err
	}
	if a.Person, err = c.text(); err != nil {
		return Aussage{}, err
	}
	raw, err := c.one()
	if err != nil {
		return Aussage{}, err
	}
	a.Rolle = PersonRolle(raw)
	if a.Von, err = c.u64(); err != nil {
		return Aussage{}, err
	}
	if a.Bis, err = c.u64(); err != nil {
		return Aussage{}, err
	}
	if a.Finger, err = c.hash(); err != nil {
		return Aussage{}, err
	}
	if err := c.done(); err != nil {
		return Aussage{}, err
	}
	if _, err := AussageBytes(a); err != nil {
		return Aussage{}, err
	}
	return a, nil
}

// TeilBytes ist L(aussage) || aussage || L(signatur) || signatur.
func TeilBytes(t AussageTeil) ([]byte, error) {
	nutz, err := AussageBytes(t.Nutzlast)
	if err != nil {
		return nil, err
	}
	if len(t.Signatur) == 0 || len(t.Signatur) > SignaturMax {
		return nil, ErrLength
	}
	buf, err := appendLen(nil, nutz)
	if err != nil {
		return nil, err
	}
	return appendLen(buf, t.Signatur)
}

// ParseTeil liest einen Aussageteil.
func ParseTeil(b []byte) (AussageTeil, int, error) {
	c := cursor{b: b}
	nutz, err := c.lp()
	if err != nil {
		return AussageTeil{}, 0, err
	}
	sig, err := c.lp()
	if err != nil {
		return AussageTeil{}, 0, err
	}
	a, err := ParseAussage(nutz)
	if err != nil {
		return AussageTeil{}, 0, err
	}
	if len(sig) == 0 || len(sig) > SignaturMax {
		return AussageTeil{}, 0, ErrLength
	}
	return AussageTeil{Nutzlast: a, Signatur: sig}, c.i, nil
}

// LogBytes ist der Inhalt eines Gruppen- oder Einzeleintrags.
func LogBytes(in LogInhalt) ([]byte, error) {
	if len(in.Aussagen) == 0 || len(in.Bezuege) == 0 {
		return nil, ErrLength
	}
	buf := AppendText(nil, "log")
	var err error
	buf, err = appendLen(buf, in.Text)
	if err != nil {
		return nil, err
	}
	buf, err = appendUTF8(buf, in.Vorgang)
	if err != nil {
		return nil, err
	}
	buf, err = appendTeile(buf, in.Aussagen)
	if err != nil {
		return nil, err
	}
	gesehen := make(map[string]struct{}, len(in.Bezuege))
	buf, err = appendPersonen(buf, in.Bezuege)
	if err != nil {
		return nil, err
	}
	for _, name := range in.Bezuege {
		gesehen[name] = struct{}{}
	}
	owner := make(map[string]struct{}, len(in.Aussagen))
	for _, teil := range in.Aussagen {
		name := teil.Nutzlast.Person
		if _, ok := gesehen[name]; !ok {
			return nil, ErrLength
		}
		if _, ok := owner[name]; ok {
			return nil, ErrLength
		}
		owner[name] = struct{}{}
	}
	return buf, nil
}

// ParseLog liest einen Log-Inhalt.
func ParseLog(b []byte) (LogInhalt, error) {
	c := cursor{b: b}
	if err := c.domain("log"); err != nil {
		return LogInhalt{}, err
	}
	var in LogInhalt
	var err error
	if in.Text, err = c.lp(); err != nil {
		return LogInhalt{}, err
	}
	if in.Vorgang, err = c.feld(); err != nil {
		return LogInhalt{}, err
	}
	if in.Aussagen, err = c.teile(); err != nil {
		return LogInhalt{}, err
	}
	if in.Bezuege, err = c.personen(); err != nil {
		return LogInhalt{}, err
	}
	if err := c.done(); err != nil {
		return LogInhalt{}, err
	}
	if _, err := LogBytes(in); err != nil {
		return LogInhalt{}, err
	}
	return in, nil
}

// AuffangBytes ist der Inhalt eines Auffang-Eintrags.
func AuffangBytes(in AuffangInhalt) ([]byte, error) {
	switch in.Grund {
	case GrundUnbekannt, GrundAussageUngueltig, GrundZielFehlt, GrundOhneBezug, GrundKEKFehlt, GrundMandantUnbekannt:
	default:
		return nil, ErrGrund
	}
	if in.Grund == GrundMandantUnbekannt {
		if _, err := appendUTF8(nil, in.Angabe); err != nil {
			return nil, err
		}
	} else if in.Angabe != "" {
		return nil, ErrGrund
	}
	if in.Grund == GrundZielFehlt {
		if len(in.Aussagen) == 0 || len(in.Aussagen) != len(in.Personen) {
			return nil, ErrLength
		}
		for i, teil := range in.Aussagen {
			if teil.Nutzlast.Person != in.Personen[i] {
				return nil, ErrLength
			}
		}
	} else if len(in.Aussagen) != 0 {
		return nil, ErrGrund
	}
	if in.Grund == GrundOhneBezug && len(in.Personen) != 0 {
		return nil, ErrGrund
	}
	buf := AppendText(nil, "auffang")
	buf = append(buf, byte(in.Grund))
	var err error
	buf, err = appendLen(buf, in.Text)
	if err != nil {
		return nil, err
	}
	buf, err = appendUTF8(buf, in.Vorgang)
	if err != nil {
		return nil, err
	}
	buf, err = appendUTF8(buf, in.Angabe)
	if err != nil {
		return nil, err
	}
	buf, err = appendTeile(buf, in.Aussagen)
	if err != nil {
		return nil, err
	}
	buf, err = appendPersonen(buf, in.Personen)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ParseAuffang liest einen Auffang-Inhalt.
func ParseAuffang(b []byte) (AuffangInhalt, error) {
	c := cursor{b: b}
	if err := c.domain("auffang"); err != nil {
		return AuffangInhalt{}, err
	}
	raw, err := c.one()
	if err != nil {
		return AuffangInhalt{}, err
	}
	var in AuffangInhalt
	in.Grund = Grund(raw)
	if in.Text, err = c.lp(); err != nil {
		return AuffangInhalt{}, err
	}
	if in.Vorgang, err = c.feld(); err != nil {
		return AuffangInhalt{}, err
	}
	if in.Angabe, err = c.feld(); err != nil {
		return AuffangInhalt{}, err
	}
	if in.Aussagen, err = c.teile(); err != nil {
		return AuffangInhalt{}, err
	}
	if in.Personen, err = c.personen(); err != nil {
		return AuffangInhalt{}, err
	}
	if err := c.done(); err != nil {
		return AuffangInhalt{}, err
	}
	if _, err := AuffangBytes(in); err != nil {
		return AuffangInhalt{}, err
	}
	return in, nil
}

// VerweisBytes ist ein Verzeichnisverweis.
func VerweisBytes(v Verweis) ([]byte, error) {
	switch v.Art {
	case VerweisPerson, VerweisVorgang:
	default:
		return nil, ErrArt
	}
	if v.Schluessel == "" || v.Seq == 0 {
		return nil, ErrLength
	}
	var zero ID
	if v.Mandant == zero || v.Bind == zero {
		return nil, ErrLength
	}
	buf := AppendText(nil, "verweis")
	buf = append(buf, byte(v.Art))
	var err error
	buf, err = appendUTF8(buf, v.Schluessel)
	if err != nil {
		return nil, err
	}
	buf = append(buf, v.Mandant[:]...)
	buf = append(buf, v.Bind[:]...)
	buf = append(buf, v.Epoch[:]...)
	buf = AppendU64(buf, v.Seq)
	return buf, nil
}

// ParseVerweis liest einen Verzeichnisverweis.
func ParseVerweis(b []byte) (Verweis, error) {
	c := cursor{b: b}
	if err := c.domain("verweis"); err != nil {
		return Verweis{}, err
	}
	raw, err := c.one()
	if err != nil {
		return Verweis{}, err
	}
	var v Verweis
	v.Art = VerweisArt(raw)
	if v.Schluessel, err = c.text(); err != nil {
		return Verweis{}, err
	}
	if v.Mandant, err = c.id(); err != nil {
		return Verweis{}, err
	}
	if v.Bind, err = c.id(); err != nil {
		return Verweis{}, err
	}
	if v.Epoch, err = c.epoch(); err != nil {
		return Verweis{}, err
	}
	if v.Seq, err = c.u64(); err != nil {
		return Verweis{}, err
	}
	if err := c.done(); err != nil {
		return Verweis{}, err
	}
	if _, err := VerweisBytes(v); err != nil {
		return Verweis{}, err
	}
	return v, nil
}

// IndexBytes ist ein Vorgangsindexeintrag.
func IndexBytes(e IndexEintrag) ([]byte, error) {
	if e.Nummer == "" || e.Person == "" || e.Seq == 0 {
		return nil, ErrLength
	}
	if err := kohorteZurRolle(e.Rolle, e.Kohorte); err != nil {
		return nil, err
	}
	buf := AppendText(nil, "vorgang")
	var err error
	buf, err = appendUTF8(buf, e.Nummer)
	if err != nil {
		return nil, err
	}
	buf, err = appendUTF8(buf, e.Person)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(e.Rolle))
	buf, err = appendUTF8(buf, e.Kohorte)
	if err != nil {
		return nil, err
	}
	buf = append(buf, e.Epoch[:]...)
	buf = AppendU64(buf, e.Seq)
	buf = AppendU64(buf, e.Zeitpunkt)
	return buf, nil
}

// ParseIndex liest einen Vorgangsindexeintrag.
func ParseIndex(b []byte) (IndexEintrag, error) {
	c := cursor{b: b}
	if err := c.domain("vorgang"); err != nil {
		return IndexEintrag{}, err
	}
	var e IndexEintrag
	var err error
	if e.Nummer, err = c.text(); err != nil {
		return IndexEintrag{}, err
	}
	if e.Person, err = c.text(); err != nil {
		return IndexEintrag{}, err
	}
	raw, err := c.one()
	if err != nil {
		return IndexEintrag{}, err
	}
	e.Rolle = StromRolle(raw)
	if e.Kohorte, err = c.feld(); err != nil {
		return IndexEintrag{}, err
	}
	if e.Epoch, err = c.epoch(); err != nil {
		return IndexEintrag{}, err
	}
	if e.Seq, err = c.u64(); err != nil {
		return IndexEintrag{}, err
	}
	if e.Zeitpunkt, err = c.u64(); err != nil {
		return IndexEintrag{}, err
	}
	if err := c.done(); err != nil {
		return IndexEintrag{}, err
	}
	if _, err := IndexBytes(e); err != nil {
		return IndexEintrag{}, err
	}
	return e, nil
}

// BelegBytes ist der Verweis einer Summenepoche auf eine Quell-Epoche.
func BelegBytes(b Beleg) ([]byte, error) {
	if _, err := time.Parse("20060102T150405Z", b.Epoch.Raster()); err != nil {
		return nil, ErrRaster
	}
	buf := AppendText(nil, "beleg")
	buf = append(buf, b.Epoch[:]...)
	buf = append(buf, b.Hash[:]...)
	return buf, nil
}

// ParseBeleg liest einen Beleg.
func ParseBeleg(b []byte) (Beleg, error) {
	c := cursor{b: b}
	if err := c.domain("beleg"); err != nil {
		return Beleg{}, err
	}
	var out Beleg
	var err error
	if out.Epoch, err = c.epoch(); err != nil {
		return Beleg{}, err
	}
	if out.Hash, err = c.hash(); err != nil {
		return Beleg{}, err
	}
	if err := c.done(); err != nil {
		return Beleg{}, err
	}
	if _, err := BelegBytes(out); err != nil {
		return Beleg{}, err
	}
	return out, nil
}

// VorgangSummeBytes nennt die Personen einer Vorgangsnummer.
// Die Personen stehen nach Person, Rolle und Kohorte, jede Kombination einmal.
func VorgangSummeBytes(v VorgangSumme) ([]byte, error) {
	if v.Nummer == "" || len(v.Personen) == 0 {
		return nil, ErrLength
	}
	if !bezuegeGeordnet(v.Personen) {
		return nil, ErrLength
	}
	buf := AppendText(nil, "vorgang-summe")
	var err error
	buf, err = appendUTF8(buf, v.Nummer)
	if err != nil {
		return nil, err
	}
	return appendBezuege(buf, v.Personen)
}

// ParseVorgangSumme liest die Personen einer Vorgangsnummer.
func ParseVorgangSumme(b []byte) (VorgangSumme, error) {
	c := cursor{b: b}
	if err := c.domain("vorgang-summe"); err != nil {
		return VorgangSumme{}, err
	}
	var v VorgangSumme
	var err error
	if v.Nummer, err = c.text(); err != nil {
		return VorgangSumme{}, err
	}
	if v.Personen, err = c.bezuege(); err != nil {
		return VorgangSumme{}, err
	}
	if err := c.done(); err != nil {
		return VorgangSumme{}, err
	}
	if _, err := VorgangSummeBytes(v); err != nil {
		return VorgangSumme{}, err
	}
	return v, nil
}

// PersonSummeBytes nennt die Vorgangsnummern einer Person.
// Die Nummern stehen nach Nummer, Rolle und Kohorte, jede Kombination einmal.
func PersonSummeBytes(p PersonSumme) ([]byte, error) {
	if p.Person == "" || len(p.Nummern) == 0 {
		return nil, ErrLength
	}
	if !bezuegeGeordnet(p.Nummern) {
		return nil, ErrLength
	}
	buf := AppendText(nil, "person-summe")
	var err error
	buf, err = appendUTF8(buf, p.Person)
	if err != nil {
		return nil, err
	}
	return appendBezuege(buf, p.Nummern)
}

// ParsePersonSumme liest die Vorgangsnummern einer Person.
func ParsePersonSumme(b []byte) (PersonSumme, error) {
	c := cursor{b: b}
	if err := c.domain("person-summe"); err != nil {
		return PersonSumme{}, err
	}
	var p PersonSumme
	var err error
	if p.Person, err = c.text(); err != nil {
		return PersonSumme{}, err
	}
	if p.Nummern, err = c.bezuege(); err != nil {
		return PersonSumme{}, err
	}
	if err := c.done(); err != nil {
		return PersonSumme{}, err
	}
	if _, err := PersonSummeBytes(p); err != nil {
		return PersonSumme{}, err
	}
	return p, nil
}

// IndexanfrageBytes ist die signierte Nutzlast einer Indexabfrage.
func IndexanfrageBytes(a Indexanfrage) ([]byte, error) {
	var zero ID
	if a.Mandant == zero || a.Zone == zero || a.Person == "" || a.Schluessel == "" || a.Bis <= a.Von {
		return nil, ErrLength
	}
	switch a.Art {
	case AnfrageVorgang, AnfragePerson:
	default:
		return nil, ErrArt
	}
	buf := AppendText(nil, "anfrage")
	buf = append(buf, a.Mandant[:]...)
	buf = append(buf, a.Zone[:]...)
	var err error
	buf, err = appendUTF8(buf, a.Person)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(a.Art))
	buf, err = appendUTF8(buf, a.Schluessel)
	if err != nil {
		return nil, err
	}
	buf = AppendU64(buf, a.Von)
	buf = AppendU64(buf, a.Bis)
	buf = AppendU64(buf, a.Zeitpunkt)
	return buf, nil
}

// ParseIndexanfrage liest eine Indexabfrage.
func ParseIndexanfrage(b []byte) (Indexanfrage, error) {
	c := cursor{b: b}
	if err := c.domain("anfrage"); err != nil {
		return Indexanfrage{}, err
	}
	var a Indexanfrage
	var err error
	if a.Mandant, err = c.id(); err != nil {
		return Indexanfrage{}, err
	}
	if a.Zone, err = c.id(); err != nil {
		return Indexanfrage{}, err
	}
	if a.Person, err = c.text(); err != nil {
		return Indexanfrage{}, err
	}
	raw, err := c.one()
	if err != nil {
		return Indexanfrage{}, err
	}
	a.Art = AnfrageArt(raw)
	if a.Schluessel, err = c.text(); err != nil {
		return Indexanfrage{}, err
	}
	if a.Von, err = c.u64(); err != nil {
		return Indexanfrage{}, err
	}
	if a.Bis, err = c.u64(); err != nil {
		return Indexanfrage{}, err
	}
	if a.Zeitpunkt, err = c.u64(); err != nil {
		return Indexanfrage{}, err
	}
	if err := c.done(); err != nil {
		return Indexanfrage{}, err
	}
	if _, err := IndexanfrageBytes(a); err != nil {
		return Indexanfrage{}, err
	}
	return a, nil
}

func kohorteZurRolle(rolle StromRolle, kohorte string) error {
	switch rolle {
	case RolleGruppe:
		if kohorte == "" {
			return ErrRolle
		}
	case RolleEinzel, RolleAuffang:
		if kohorte != "" {
			return ErrRolle
		}
	default:
		return ErrRolle
	}
	if !utf8.ValidString(kohorte) {
		return ErrUTF8
	}
	return nil
}

func appendBezuege(dst []byte, liste []Bezug) ([]byte, error) {
	if uint64(len(liste)) > 0xffffffff {
		return nil, ErrLength
	}
	buf := AppendU32(dst, uint32(len(liste)))
	for _, b := range liste {
		var err error
		buf, err = appendBezug(buf, b)
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func appendBezug(dst []byte, b Bezug) ([]byte, error) {
	if b.Name == "" || b.Letzter < b.Erster {
		return nil, ErrLength
	}
	if err := kohorteZurRolle(b.Rolle, b.Kohorte); err != nil {
		return nil, err
	}
	buf, err := appendUTF8(dst, b.Name)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(b.Rolle))
	buf, err = appendUTF8(buf, b.Kohorte)
	if err != nil {
		return nil, err
	}
	buf = AppendU64(buf, b.Erster)
	buf = AppendU64(buf, b.Letzter)
	return buf, nil
}

func bezuegeGeordnet(liste []Bezug) bool {
	for i := 1; i < len(liste); i++ {
		if !bezugVor(liste[i-1], liste[i]) {
			return false
		}
	}
	return true
}

func bezugVor(a, b Bezug) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Rolle != b.Rolle {
		return a.Rolle < b.Rolle
	}
	return a.Kohorte < b.Kohorte
}

// KatalogBytes ist ein Katalogstand.
func KatalogBytes(s Stand) ([]byte, error) {
	if s.Name == "" {
		return nil, ErrLength
	}
	buf := AppendText(nil, "katalog")
	var err error
	buf, err = appendUTF8(buf, s.Name)
	if err != nil {
		return nil, err
	}
	if uint64(len(s.Kennungen)) > 0xffffffff {
		return nil, ErrLength
	}
	buf = AppendU32(buf, uint32(len(s.Kennungen)))
	gesehen := make(map[[1 + IDLen + IDLen]byte]struct{}, len(s.Kennungen))
	for _, k := range s.Kennungen {
		roh, err := kennungBytes(k)
		if err != nil {
			return nil, err
		}
		var schluessel [1 + IDLen + IDLen]byte
		schluessel[0] = byte(k.Rolle)
		copy(schluessel[1:], k.Ablage[:])
		copy(schluessel[1+IDLen:], k.Bind[:])
		if _, ok := gesehen[schluessel]; ok {
			return nil, ErrLength
		}
		gesehen[schluessel] = struct{}{}
		buf = append(buf, roh...)
	}
	return buf, nil
}

// ParseKatalog liest einen Katalogstand.
func ParseKatalog(b []byte) (Stand, error) {
	c := cursor{b: b}
	if err := c.domain("katalog"); err != nil {
		return Stand{}, err
	}
	var s Stand
	var err error
	if s.Name, err = c.text(); err != nil {
		return Stand{}, err
	}
	n, err := c.u32()
	if err != nil {
		return Stand{}, err
	}
	s.Kennungen = make([]Kennung, 0, n)
	for i := uint32(0); i < n; i++ {
		k, err := c.kennung()
		if err != nil {
			return Stand{}, err
		}
		s.Kennungen = append(s.Kennungen, k)
	}
	if err := c.done(); err != nil {
		return Stand{}, err
	}
	if _, err := KatalogBytes(s); err != nil {
		return Stand{}, err
	}
	return s, nil
}

func kennungBytes(k Kennung) ([]byte, error) {
	var zero ID
	if k.Ablage == zero || k.Bind == zero {
		return nil, ErrLength
	}
	if k.Aktiv != KennungAus && k.Aktiv != KennungAn {
		return nil, ErrLength
	}
	switch k.Rolle {
	case RolleGruppe:
		if k.Bind != k.Ablage || k.Kohorte == "" {
			return nil, ErrRolle
		}
	case RolleEinzel:
		if k.Bind == k.Ablage || k.Kohorte != "" {
			return nil, ErrRolle
		}
	case RolleAuffang, RolleVerzeichnis, RolleVorgang, RolleKatalog, RolleVerzeichnisSumme, RolleVorgangSumme:
		if k.Bind != k.Ablage || k.Kohorte != "" {
			return nil, ErrRolle
		}
	default:
		return nil, ErrRolle
	}
	if !utf8.ValidString(k.Kohorte) {
		return nil, ErrUTF8
	}
	buf := []byte{byte(k.Rolle)}
	buf = append(buf, k.Ablage[:]...)
	buf = append(buf, k.Bind[:]...)
	var err error
	buf, err = appendUTF8(buf, k.Kohorte)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(k.Aktiv))
	return buf, nil
}

func appendUTF8(dst []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, ErrUTF8
	}
	if uint64(len(s)) > 0xffffffff {
		return nil, ErrLength
	}
	return AppendText(dst, s), nil
}

func appendPersonen(dst []byte, personen []string) ([]byte, error) {
	if uint64(len(personen)) > 0xffffffff {
		return nil, ErrLength
	}
	gesehen := make(map[string]struct{}, len(personen))
	buf := AppendU32(dst, uint32(len(personen)))
	for _, name := range personen {
		if name == "" {
			return nil, ErrLength
		}
		if _, ok := gesehen[name]; ok {
			return nil, ErrLength
		}
		gesehen[name] = struct{}{}
		var err error
		buf, err = appendUTF8(buf, name)
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func appendTeile(dst []byte, teile []AussageTeil) ([]byte, error) {
	if uint64(len(teile)) > 0xffffffff {
		return nil, ErrLength
	}
	buf := AppendU32(dst, uint32(len(teile)))
	for _, teil := range teile {
		roh, err := TeilBytes(teil)
		if err != nil {
			return nil, err
		}
		buf = append(buf, roh...)
	}
	return buf, nil
}

func (c *cursor) domain(name string) error {
	d := Domain(name)
	if len(c.b) < c.i+len(d) || !bytes.Equal(c.b[c.i:c.i+len(d)], d) {
		return ErrDomain
	}
	c.i += len(d)
	return nil
}

func (c *cursor) done() error {
	if c.i != len(c.b) {
		return ErrLength
	}
	return nil
}

func (c *cursor) one() (byte, error) {
	raw, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (c *cursor) epoch() (EpochID, error) {
	raw, err := c.take(EpochLen)
	if err != nil {
		return EpochID{}, err
	}
	var e EpochID
	copy(e[:], raw)
	return e, nil
}

// feld ist ein UTF-8-Text und darf leer sein. text lehnt die leere Zeichenfolge ab.
func (c *cursor) feld() (string, error) {
	raw, err := c.lp()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", ErrUTF8
	}
	return string(raw), nil
}

func (c *cursor) personen() ([]string, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		s, err := c.text()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (c *cursor) teile() ([]AussageTeil, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	out := make([]AussageTeil, 0, n)
	for i := uint32(0); i < n; i++ {
		teil, nread, err := ParseTeil(c.b[c.i:])
		if err != nil {
			return nil, err
		}
		c.i += nread
		out = append(out, teil)
	}
	return out, nil
}

func (c *cursor) bezuege() ([]Bezug, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	out := make([]Bezug, 0, n)
	for i := uint32(0); i < n; i++ {
		b, err := c.bezug()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (c *cursor) bezug() (Bezug, error) {
	var b Bezug
	var err error
	if b.Name, err = c.text(); err != nil {
		return Bezug{}, err
	}
	raw, err := c.one()
	if err != nil {
		return Bezug{}, err
	}
	b.Rolle = StromRolle(raw)
	if b.Kohorte, err = c.feld(); err != nil {
		return Bezug{}, err
	}
	if b.Erster, err = c.u64(); err != nil {
		return Bezug{}, err
	}
	if b.Letzter, err = c.u64(); err != nil {
		return Bezug{}, err
	}
	return b, nil
}

func (c *cursor) kennung() (Kennung, error) {
	raw, err := c.one()
	if err != nil {
		return Kennung{}, err
	}
	var k Kennung
	k.Rolle = StromRolle(raw)
	if k.Ablage, err = c.id(); err != nil {
		return Kennung{}, err
	}
	if k.Bind, err = c.id(); err != nil {
		return Kennung{}, err
	}
	if k.Kohorte, err = c.feld(); err != nil {
		return Kennung{}, err
	}
	aktiv, err := c.one()
	if err != nil {
		return Kennung{}, err
	}
	k.Aktiv = Aktiv(aktiv)
	return k, nil
}
