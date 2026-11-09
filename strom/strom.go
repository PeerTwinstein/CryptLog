// Package strom ordnet ein Audit-Ereignis den Strömen zu und schreibt die
// Klartexte in bereits geöffnete Epochen. Die Epoche, der DEK und der Wrap
// bleiben beim Aufrufer. Log, Verzeichnis und Vorgangsindex eines Ereignisses
// gehören in dieselbe Annahme.
package strom

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"unicode/utf8"

	"cryptlog/crypt"
	"cryptlog/epoch"
	"cryptlog/protocol"
)

var (
	// ErrEreignis heißt, der Aufruf lässt sich so nicht schreiben.
	ErrEreignis = errors.New("strom: Ereignis passt nicht")
	// ErrRegister heißt, das Register fehlt oder ein Eintrag passt nicht.
	ErrRegister = errors.New("strom: Register passt nicht")
	// ErrPruef heißt, der Prüfschlüssel ist kein P-256.
	ErrPruef = errors.New("strom: Prüfschlüssel fehlt")
	// ErrBahn heißt, der Strom für dieses Ziel ist nicht geöffnet.
	ErrBahn = errors.New("strom: Strom ist nicht geöffnet")
)

// Register löst Personen eines Mandanten auf.
type Register interface {
	// Person liefert den Eintrag dieses Mandanten. ok ist falsch, wenn die Person fehlt.
	Person(name string) (Eintrag, bool, error)
}

// Eintrag ist die aufgelöste Person. ZielFehlt heißt: die Aussage kann gelten,
// das Ablagemerkmal zeigt aber auf keinen Strom.
type Eintrag struct {
	Merkmal   protocol.Merkmal
	Ablage    protocol.ID
	Bind      protocol.ID
	Kohorte   string
	Rolle     protocol.PersonRolle
	Von       uint64
	Bis       uint64
	Finger    protocol.Hash
	Signatur  []byte
	ZielFehlt bool
}

// Ereignis ist der Aufruf. Mandant ist die Nullkennung, wenn kein Mandant ermittelt ist.
// Angabe ist dann der genannte Mandantenwert und sonst leer.
type Ereignis struct {
	ID       protocol.ID
	Zeit     uint64
	Mandant  protocol.ID
	Angabe   string
	Personen []string
	Vorgang  string
	Text     []byte
}

// Eingang ist die Lage des Mandanten beim Zuordnen.
// Register und Pruef bleiben ungenutzt, wenn der Mandant fehlt oder der KEK fehlt.
type Eingang struct {
	KEKVorhanden bool
	Register     Register
	Pruef        crypto.PublicKey
}

// Wrap sagt, welcher öffentliche Schlüssel Log und Verzeichnis dieses Ereignisses wickelt.
// Der Vorgangsindex bleibt am Index-Schlüssel.
type Wrap byte

const (
	// WrapMandant wickelt Log und Verzeichnis mit dem KEK des Mandanten.
	WrapMandant Wrap = 1
	// WrapPlattform wickelt mit dem Plattform-KEK.
	WrapPlattform Wrap = 2
)

// Ziel ist ein Logeintrag. Bei einem Auffang bleiben Ablage und Bind leer,
// bis Schreiben sie aus der offenen Epoche übernimmt.
type Ziel struct {
	Event    protocol.ID
	Zeit     uint64
	Rolle    protocol.StromRolle
	Mandant  protocol.ID
	Ablage   protocol.ID
	Bind     protocol.ID
	Kohorte  string
	Grund    protocol.Grund
	Inhalt   []byte
	Personen []string
	Vorgang  string
}

// Zuordnung ist das Ergebnis der Auflösung.
// Hash ist der event_hash des Aufrufs. Mandant ist bei einem nicht
// ermittelten Mandanten die Plattformkennung.
type Zuordnung struct {
	Hash    protocol.Hash
	Mandant protocol.ID
	Wrap    Wrap
	Ziele   []Ziel
}

// Stelle ist Epoche und erste Sequenz eines geschriebenen Logeintrags.
type Stelle struct {
	Epoch protocol.EpochID
	Seq   uint64
}

// Bahn ist eine offene Epoche. Bind ist bei Gruppe, Auffang, Verzeichnis
// und Index die ablage_id, bei einer Einzelperson deren bind_id.
type Bahn struct {
	Bind   protocol.ID
	Epoche *epoch.Epoche
}

// Bahnen sind die offenen Ströme für ein Ereignis dieses Mandanten.
// Verzeichnis und Vorgang wickelt der Aufrufer mit dem Schlüssel, den Wrap nennt.
type Bahnen struct {
	Gruppe      map[protocol.ID]Bahn
	Einzel      map[protocol.ID]Bahn
	Auffang     Bahn
	Verzeichnis Bahn
	Vorgang     Bahn
}

// Geschrieben sind die Rahmen, die Schreiben an die offenen Epochen gehängt hat.
// Log und Verzeichnis teilen sich den Wrap. Index hängt am Index-Schlüssel.
type Geschrieben struct {
	Segmente    []epoch.Segment
	Log         []protocol.SeqEintrag
	Verzeichnis []protocol.SeqEintrag
	Index       []protocol.SeqEintrag
}

// Zuordnen entscheidet die Logeinträge eines Aufrufs.
// Ist mindestens eine Person einzeln geführt, entstehen nur deren Einzelströme.
// Lässt sich sonst jemand nicht zuordnen, entsteht keine Kopie im Auffangstrom.
// Bleibt kein beschreibbares Ziel, entsteht genau ein Auffang-Eintrag.
// Ohne Zuordnung gilt die erste passende Lage: keine Person ergibt ohne_bezug,
// eine ungültige Aussage ergibt aussage_ungueltig, eine unbekannte Person
// ergibt unbekannt, sonst ziel_fehlt. kek_fehlt und mandant_unbekannt gelten
// davor und tragen keine Aussage.
func Zuordnen(ev Ereignis, in Eingang) (Zuordnung, error) {
	var zero protocol.ID
	if ev.ID == zero {
		return Zuordnung{}, ErrEreignis
	}
	if !utf8.ValidString(ev.Angabe) {
		return Zuordnung{}, protocol.ErrUTF8
	}
	if ev.Mandant != zero && ev.Angabe != "" {
		return Zuordnung{}, ErrEreignis
	}
	aufruf, err := protocol.AufrufBytes(ev.Zeit, ev.Vorgang, ev.Personen, ev.Text)
	if err != nil {
		return Zuordnung{}, err
	}
	mandant := ev.Mandant
	if mandant == zero {
		mandant = protocol.PlattformMandant()
	}
	hash, err := protocol.AufrufHash(mandant, ev.ID, aufruf)
	if err != nil {
		return Zuordnung{}, err
	}
	if ev.Mandant == zero {
		return einAuffang(ev, mandant, hash, protocol.GrundMandantUnbekannt, WrapPlattform, ev.Angabe, nil)
	}
	if !in.KEKVorhanden {
		return einAuffang(ev, mandant, hash, protocol.GrundKEKFehlt, WrapPlattform, "", nil)
	}
	if len(ev.Personen) == 0 {
		return einAuffang(ev, mandant, hash, protocol.GrundOhneBezug, WrapMandant, "", nil)
	}
	if in.Register == nil {
		return Zuordnung{}, ErrRegister
	}
	personen, err := aufloesen(ev, in)
	if err != nil {
		return Zuordnung{}, err
	}
	return ziele(ev, mandant, hash, personen)
}

// Nachweise baut die Klartexte der Verzeichnisverweise und Indexeinträge
// dieses Logeintrags. Die Hülle der Verweise trägt verzeichnisBind,
// die der Indexeinträge indexBind.
func (z Ziel) Nachweise(stelle Stelle, verzeichnisBind, indexBind protocol.ID) (verweise, index [][]byte, err error) {
	if stelle.Seq == 0 {
		return nil, nil, protocol.ErrSeq
	}
	var zero protocol.ID
	brauchtVerweis := len(z.Personen) > 0 || z.Vorgang != ""
	brauchtIndex := z.Vorgang != "" && len(z.Personen) > 0
	if brauchtVerweis && (verzeichnisBind == zero || z.Bind == zero || z.Mandant == zero) {
		return nil, nil, protocol.ErrLength
	}
	if brauchtIndex && indexBind == zero {
		return nil, nil, protocol.ErrLength
	}
	for _, person := range z.Personen {
		klar, err := verweisKlartext(z, stelle, verzeichnisBind, protocol.VerweisPerson, person)
		if err != nil {
			return nil, nil, err
		}
		verweise = append(verweise, klar)
	}
	if z.Vorgang != "" {
		klar, err := verweisKlartext(z, stelle, verzeichnisBind, protocol.VerweisVorgang, z.Vorgang)
		if err != nil {
			return nil, nil, err
		}
		verweise = append(verweise, klar)
	}
	if !brauchtIndex {
		return verweise, nil, nil
	}
	for _, person := range z.Personen {
		inhalt, err := protocol.IndexBytes(protocol.IndexEintrag{
			Nummer:    z.Vorgang,
			Person:    person,
			Rolle:     z.Rolle,
			Kohorte:   z.Kohorte,
			Epoch:     stelle.Epoch,
			Seq:       stelle.Seq,
			Zeitpunkt: z.Zeit,
		})
		if err != nil {
			return nil, nil, err
		}
		klar, err := protocol.EreignisKlartext(z.Event, z.Zeit, indexBind, inhalt)
		if err != nil {
			return nil, nil, err
		}
		index = append(index, klar)
	}
	return verweise, index, nil
}

// KatalogSchreiben hängt einen Stand an die Katalogepoche.
// Die Hülle trägt die bind_id der Katalogablage. Sie ist gleich der ablage_id.
func KatalogSchreiben(bahn Bahn, event protocol.ID, zeit uint64, stand protocol.Stand) ([]epoch.Segment, []protocol.SeqEintrag, error) {
	var zero protocol.ID
	if event == zero {
		return nil, nil, ErrEreignis
	}
	if !bahn.Epoche.Offen() || bahn.Bind == zero || bahn.Bind != bahn.Epoche.Ablage() {
		return nil, nil, ErrBahn
	}
	inhalt, err := protocol.KatalogBytes(stand)
	if err != nil {
		return nil, nil, err
	}
	klar, err := protocol.EreignisKlartext(event, zeit, bahn.Bind, inhalt)
	if err != nil {
		return nil, nil, err
	}
	segs, glieder, err := bahn.Epoche.Ereignis(klar)
	return segs, eintraege(glieder), err
}

// Schreiben hängt Log, Verweise und Index an die offenen Epochen.
// Vor dem ersten Rahmen müssen alle dafür nötigen Bahnen offen sein.
// Schlägt das Verschlüsseln danach fehl, bleiben die bereits angehängten
// Rahmen stehen. Die Epoche, deren Verschlüsseln fehlschlägt, endet.
func Schreiben(z Zuordnung, b Bahnen) (Geschrieben, error) {
	if len(z.Ziele) == 0 {
		return Geschrieben{}, ErrEreignis
	}
	type plan struct {
		ziel Ziel
		bahn Bahn
	}
	plaene := make([]plan, len(z.Ziele))
	var verzeichnis, index bool
	var zero protocol.ID
	for i, ziel := range z.Ziele {
		if ziel.Event == zero || ziel.Mandant != z.Mandant || ziel.Event != z.Ziele[0].Event {
			return Geschrieben{}, ErrEreignis
		}
		bahn, err := bahnVon(b, ziel)
		if err != nil {
			return Geschrieben{}, err
		}
		if err := passt(bahn, ziel); err != nil {
			return Geschrieben{}, err
		}
		if ziel.Rolle == protocol.RolleAuffang {
			ziel.Ablage = bahn.Epoche.Ablage()
			ziel.Bind = bahn.Bind
		}
		plaene[i] = plan{ziel: ziel, bahn: bahn}
		if len(ziel.Personen) > 0 || ziel.Vorgang != "" {
			verzeichnis = true
		}
		if ziel.Vorgang != "" && len(ziel.Personen) > 0 {
			index = true
		}
	}
	if verzeichnis {
		if err := huelleOffen(b.Verzeichnis, z.Mandant); err != nil {
			return Geschrieben{}, err
		}
	}
	if index {
		if err := huelleOffen(b.Vorgang, z.Mandant); err != nil {
			return Geschrieben{}, err
		}
	}
	var g Geschrieben
	for _, p := range plaene {
		klar, err := protocol.EreignisKlartext(p.ziel.Event, p.ziel.Zeit, p.ziel.Bind, p.ziel.Inhalt)
		if err != nil {
			return g, err
		}
		segs, glieder, err := p.bahn.Epoche.Ereignis(klar)
		g.Segmente = append(g.Segmente, segs...)
		g.Log = append(g.Log, eintraege(glieder)...)
		if err != nil {
			return g, err
		}
		if len(glieder) == 0 || glieder[0].Art != protocol.ArtEreignis {
			return g, protocol.ErrRahmen
		}
		stelle := Stelle{Epoch: p.bahn.Epoche.Kennung(), Seq: glieder[0].Seq}
		verweise, idx, err := p.ziel.Nachweise(stelle, b.Verzeichnis.Bind, b.Vorgang.Bind)
		if err != nil {
			return g, err
		}
		for _, klar := range verweise {
			segs, glieder, err = b.Verzeichnis.Epoche.Ereignis(klar)
			g.Segmente = append(g.Segmente, segs...)
			g.Verzeichnis = append(g.Verzeichnis, eintraege(glieder)...)
			if err != nil {
				return g, err
			}
		}
		for _, klar := range idx {
			segs, glieder, err = b.Vorgang.Epoche.Ereignis(klar)
			g.Segmente = append(g.Segmente, segs...)
			g.Index = append(g.Index, eintraege(glieder)...)
			if err != nil {
				return g, err
			}
		}
	}
	return g, nil
}

func verweisKlartext(z Ziel, stelle Stelle, bind protocol.ID, art protocol.VerweisArt, schluessel string) ([]byte, error) {
	inhalt, err := protocol.VerweisBytes(protocol.Verweis{
		Art:        art,
		Schluessel: schluessel,
		Mandant:    z.Mandant,
		Bind:       z.Bind,
		Epoch:      stelle.Epoch,
		Seq:        stelle.Seq,
	})
	if err != nil {
		return nil, err
	}
	return protocol.EreignisKlartext(z.Event, z.Zeit, bind, inhalt)
}

func bahnVon(b Bahnen, z Ziel) (Bahn, error) {
	switch z.Rolle {
	case protocol.RolleGruppe:
		bahn, ok := b.Gruppe[z.Ablage]
		if !ok {
			return Bahn{}, ErrBahn
		}
		return bahn, nil
	case protocol.RolleEinzel:
		bahn, ok := b.Einzel[z.Bind]
		if !ok {
			return Bahn{}, ErrBahn
		}
		return bahn, nil
	case protocol.RolleAuffang:
		return b.Auffang, nil
	default:
		return Bahn{}, ErrBahn
	}
}

func passt(bahn Bahn, z Ziel) error {
	if !bahn.Epoche.Offen() || bahn.Epoche.Mandant() != z.Mandant {
		return ErrBahn
	}
	var zero protocol.ID
	switch z.Rolle {
	case protocol.RolleGruppe:
		if bahn.Epoche.Ablage() != z.Ablage || bahn.Bind != z.Bind || z.Bind != z.Ablage {
			return ErrBahn
		}
	case protocol.RolleEinzel:
		if bahn.Epoche.Ablage() != z.Ablage || bahn.Bind != z.Bind || z.Bind == z.Ablage {
			return ErrBahn
		}
	case protocol.RolleAuffang:
		if bahn.Epoche.Ablage() == zero || bahn.Bind != bahn.Epoche.Ablage() {
			return ErrBahn
		}
	default:
		return ErrBahn
	}
	return nil
}

func huelleOffen(bahn Bahn, mandant protocol.ID) error {
	var zero protocol.ID
	if !bahn.Epoche.Offen() || bahn.Epoche.Mandant() != mandant || bahn.Bind == zero || bahn.Bind != bahn.Epoche.Ablage() {
		return ErrBahn
	}
	return nil
}

func eintraege(glieder []epoch.Glied) []protocol.SeqEintrag {
	out := make([]protocol.SeqEintrag, len(glieder))
	for i, g := range glieder {
		out[i] = protocol.SeqEintrag{Seq: g.Seq, Art: g.Art, Event: g.Event}
	}
	return out
}

type lage int

const (
	lageGruppe lage = iota
	lageEinzel
	lageUnbekannt
	lageUngueltig
	lageZiel
)

type geloest struct {
	name    string
	lage    lage
	eintrag Eintrag
	teil    protocol.AussageTeil
}

func aufloesen(ev Ereignis, in Eingang) ([]geloest, error) {
	out := make([]geloest, len(ev.Personen))
	for i, name := range ev.Personen {
		e, ok, err := in.Register.Person(name)
		if err != nil {
			return nil, err
		}
		p := geloest{name: name, lage: lageUnbekannt}
		if !ok {
			out[i] = p
			continue
		}
		if err := pruefeEintrag(e); err != nil {
			return nil, err
		}
		nutz := protocol.Aussage{
			Mandant: ev.Mandant,
			Person:  name,
			Rolle:   e.Rolle,
			Von:     e.Von,
			Bis:     e.Bis,
			Finger:  e.Finger,
		}
		if _, err := protocol.AussageBytes(nutz); err != nil {
			p.lage = lageUngueltig
			out[i] = p
			continue
		}
		gueltig, err := pruefeSignatur(in.Pruef, nutz, e.Signatur)
		if err != nil {
			return nil, err
		}
		if !gueltig || !nutz.Deckt(ev.Zeit) {
			p.lage = lageUngueltig
			out[i] = p
			continue
		}
		p.eintrag = e
		p.teil = protocol.AussageTeil{Nutzlast: nutz, Signatur: append([]byte(nil), e.Signatur...)}
		switch {
		case e.ZielFehlt:
			p.lage = lageZiel
		case e.Merkmal == protocol.MerkmalGruppe:
			p.lage = lageGruppe
		default:
			p.lage = lageEinzel
		}
		out[i] = p
	}
	return out, nil
}

func pruefeEintrag(e Eintrag) error {
	switch e.Merkmal {
	case protocol.MerkmalGruppe, protocol.MerkmalEinzeln:
	default:
		return ErrRegister
	}
	if e.ZielFehlt {
		return nil
	}
	var zero protocol.ID
	switch e.Merkmal {
	case protocol.MerkmalGruppe:
		if e.Ablage == zero || e.Bind != e.Ablage || e.Kohorte == "" || !utf8.ValidString(e.Kohorte) {
			return ErrRegister
		}
	default:
		if e.Ablage == zero || e.Bind == zero || e.Bind == e.Ablage || e.Kohorte != "" {
			return ErrRegister
		}
	}
	return nil
}

func pruefeSignatur(pub crypto.PublicKey, nutz protocol.Aussage, sig []byte) (bool, error) {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve == nil || key.X == nil || key.Y == nil || key.Curve.Params().Name != "P-256" || key.Curve.Params().BitSize != 256 {
		return false, ErrPruef
	}
	if len(sig) != protocol.SignatureLen {
		return false, nil
	}
	payload, err := protocol.AussageBytes(nutz)
	if err != nil {
		return false, nil
	}
	var signatur protocol.Signature
	copy(signatur[:], sig)
	return crypt.VerifyP256(key, payload, signatur), nil
}

func ziele(ev Ereignis, mandant protocol.ID, hash protocol.Hash, personen []geloest) (Zuordnung, error) {
	var einzel, gruppe []geloest
	var ungueltig, unbekannt, ziel bool
	for _, p := range personen {
		switch p.lage {
		case lageEinzel:
			einzel = append(einzel, p)
		case lageGruppe:
			gruppe = append(gruppe, p)
		case lageUngueltig:
			ungueltig = true
		case lageUnbekannt:
			unbekannt = true
		case lageZiel:
			ziel = true
		}
	}
	bezuege := namen(personen)
	if len(einzel) > 0 {
		return einzelZiele(ev, mandant, hash, einzel, bezuege)
	}
	if len(gruppe) > 0 {
		return gruppenZiele(ev, mandant, hash, gruppe, bezuege)
	}
	grund := protocol.GrundZielFehlt
	var teile []protocol.AussageTeil
	switch {
	case ungueltig:
		grund = protocol.GrundAussageUngueltig
	case unbekannt:
		grund = protocol.GrundUnbekannt
	case ziel:
		teile = make([]protocol.AussageTeil, len(personen))
		for i, p := range personen {
			teile[i] = p.teil
		}
	default:
		return Zuordnung{}, ErrEreignis
	}
	return einAuffang(ev, mandant, hash, grund, WrapMandant, "", teile)
}

func einzelZiele(ev Ereignis, mandant protocol.ID, hash protocol.Hash, einzel []geloest, bezuege []string) (Zuordnung, error) {
	gesehen := make(map[protocol.ID]struct{}, len(einzel))
	ziele := make([]Ziel, 0, len(einzel))
	for _, p := range einzel {
		if _, ok := gesehen[p.eintrag.Bind]; ok {
			return Zuordnung{}, ErrRegister
		}
		gesehen[p.eintrag.Bind] = struct{}{}
		inhalt, err := protocol.LogBytes(protocol.LogInhalt{
			Text:     ev.Text,
			Vorgang:  ev.Vorgang,
			Aussagen: []protocol.AussageTeil{p.teil},
			Bezuege:  bezuege,
		})
		if err != nil {
			return Zuordnung{}, err
		}
		ziele = append(ziele, logZiel(ev, mandant, protocol.RolleEinzel, p.eintrag.Ablage, p.eintrag.Bind, "", inhalt, bezuege))
	}
	return Zuordnung{Hash: hash, Mandant: mandant, Wrap: WrapMandant, Ziele: ziele}, nil
}

func gruppenZiele(ev Ereignis, mandant protocol.ID, hash protocol.Hash, gruppe []geloest, bezuege []string) (Zuordnung, error) {
	type sammel struct {
		kohorte string
		leute   []geloest
	}
	var reihe []protocol.ID
	gruppen := make(map[protocol.ID]*sammel)
	for _, p := range gruppe {
		s, ok := gruppen[p.eintrag.Ablage]
		if !ok {
			s = &sammel{kohorte: p.eintrag.Kohorte}
			gruppen[p.eintrag.Ablage] = s
			reihe = append(reihe, p.eintrag.Ablage)
		}
		if s.kohorte != p.eintrag.Kohorte {
			return Zuordnung{}, ErrRegister
		}
		s.leute = append(s.leute, p)
	}
	ziele := make([]Ziel, 0, len(reihe))
	for _, ablage := range reihe {
		s := gruppen[ablage]
		aussagen := make([]protocol.AussageTeil, len(s.leute))
		for i, p := range s.leute {
			aussagen[i] = p.teil
		}
		inhalt, err := protocol.LogBytes(protocol.LogInhalt{
			Text:     ev.Text,
			Vorgang:  ev.Vorgang,
			Aussagen: aussagen,
			Bezuege:  bezuege,
		})
		if err != nil {
			return Zuordnung{}, err
		}
		ziele = append(ziele, logZiel(ev, mandant, protocol.RolleGruppe, ablage, ablage, s.kohorte, inhalt, bezuege))
	}
	return Zuordnung{Hash: hash, Mandant: mandant, Wrap: WrapMandant, Ziele: ziele}, nil
}

func logZiel(ev Ereignis, mandant protocol.ID, rolle protocol.StromRolle, ablage, bind protocol.ID, kohorte string, inhalt []byte, bezuege []string) Ziel {
	return Ziel{
		Event:    ev.ID,
		Zeit:     ev.Zeit,
		Rolle:    rolle,
		Mandant:  mandant,
		Ablage:   ablage,
		Bind:     bind,
		Kohorte:  kohorte,
		Inhalt:   inhalt,
		Personen: append([]string(nil), bezuege...),
		Vorgang:  ev.Vorgang,
	}
}

func einAuffang(ev Ereignis, mandant protocol.ID, hash protocol.Hash, grund protocol.Grund, wrap Wrap, angabe string, teile []protocol.AussageTeil) (Zuordnung, error) {
	inhalt, err := protocol.AuffangBytes(protocol.AuffangInhalt{
		Grund:    grund,
		Text:     ev.Text,
		Vorgang:  ev.Vorgang,
		Angabe:   angabe,
		Aussagen: teile,
		Personen: ev.Personen,
	})
	if err != nil {
		return Zuordnung{}, err
	}
	return Zuordnung{
		Hash:    hash,
		Mandant: mandant,
		Wrap:    wrap,
		Ziele: []Ziel{{
			Event:    ev.ID,
			Zeit:     ev.Zeit,
			Rolle:    protocol.RolleAuffang,
			Mandant:  mandant,
			Grund:    grund,
			Inhalt:   inhalt,
			Personen: append([]string(nil), ev.Personen...),
			Vorgang:  ev.Vorgang,
		}},
	}, nil
}

func namen(personen []geloest) []string {
	out := make([]string, len(personen))
	for i, p := range personen {
		out[i] = p.name
	}
	return out
}
