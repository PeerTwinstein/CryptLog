// Package werkzeug prüft abgeschlossene Epochen und öffnet nur die Auswahl.
// Pruefen gilt eine Epoche. Liegt die Annahme vor, nimmt es die Segmente daraus
// und prüft die batch_id am gewrappten Bindungsschlüssel.
// Zeitraum gilt die Epochen eines Stroms, deren Raster den Zeitraum schneidet.
// Am Einzelpräfix hängen die Personen an der Manifestkette der Instanz.
// Suche liest das Verzeichnis, für einen abgeschlossenen Monat zuerst die
// Summenepoche. Index beantwortet die Frage des Vorgangsindex.
// KatalogLesen löst einen Namen in die ablage_id auf.
// Loeschen legt am Löschtag den Vermerk ab, entfernt die Segmente und lässt
// Annahmen fallen, sobald jede von ihnen genannte Epoche weg ist.
// Die Kette, die HSM-Signatur und die Epochenbestätigung brauchen den DEK nicht.
// Einträge, die nicht zur Auswahl gehören, bleiben Ciphertext.
package werkzeug

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

var (
	// ErrKette heißt, Manifest oder Hash-Kette passen nicht.
	ErrKette = errors.New("werkzeug: Kette oder Manifest passt nicht")
	// ErrSignatur heißt, die HSM-Signatur des Manifests prüft nicht.
	ErrSignatur = errors.New("werkzeug: HSM-Signatur ungültig")
	// ErrBestaetigung heißt, die Epochenbestätigung prüft nicht.
	ErrBestaetigung = errors.New("werkzeug: Epochenbestätigung ungültig")
	// ErrAuswahl heißt, die Auswahl passt nicht zur Epoche.
	ErrAuswahl = errors.New("werkzeug: Auswahl passt nicht zur Epoche")
	// ErrRolle heißt, diese Rolle wird nicht geöffnet.
	ErrRolle = errors.New("werkzeug: Rolle wird nicht geöffnet")
	// ErrStatus heißt, die Lage des Fingerabdrucks fehlt.
	ErrStatus = errors.New("werkzeug: Schlüsselstatus fehlt")
	// ErrFinger heißt, der Fingerabdruck im Epochenkopf passt nicht.
	ErrFinger = errors.New("werkzeug: Fingerabdruck passt nicht")
	// ErrPruef heißt, der Prüfschlüssel der Aussage fehlt.
	ErrPruef = errors.New("werkzeug: Prüfschlüssel fehlt")
	// ErrSchluessel heißt, der private Schlüssel zum Öffnen fehlt.
	ErrSchluessel = errors.New("werkzeug: privater Schlüssel fehlt")
	// ErrInhalt heißt, ein Eintrag lässt sich nicht lesen.
	ErrInhalt = errors.New("werkzeug: Eintrag lässt sich nicht lesen")
	// ErrAnnahme heißt, die Annahme passt nicht zur Epoche.
	ErrAnnahme = errors.New("werkzeug: Annahme passt nicht zur Epoche")
	// ErrBindung heißt, der Bindungsblob passt nicht zur Annahme.
	ErrBindung = errors.New("werkzeug: Bindung passt nicht")
	// ErrAufloesung heißt, der Katalog löst den Namen nicht auf.
	ErrAufloesung = errors.New("werkzeug: Name lässt sich nicht auflösen")
	// ErrLoeschen heißt, der Löschlauf hat keine gültige Frist oder Epoche.
	ErrLoeschen = errors.New("werkzeug: Löschlauf ungültig")
)

// Status ist die Lage des KEK, dessen Fingerabdruck im Epochenkopf steht.
type Status int

const (
	// StatusAktuell öffnet mit der Vertraulichkeitszusicherung dieser Epoche.
	StatusAktuell        Status = iota + 1
	StatusAbgeloest             // öffnet, der Schlüssel bleibt vertrauenswürdig
	StatusAbgelaufen            // öffnet, der abgelaufene Schlüssel bleibt der dieser Epoche
	StatusKompromittiert        // öffnet, ohne Vertraulichkeitszusicherung
	StatusVerloren              // der Inhalt bleibt zu
)

// Segment ist ein Segmentobjekt der Epoche, in der Reihenfolge der Segmentnummer.
// Ist Annahmen gesetzt, bildet Pruefen diese Folge aus den genannten Segmenten.
type Segment struct {
	Schluessel string
	Bytes      []byte
}

// Zweig ist eine weitere vom HSM signierte Fassung derselben Epoche.
type Zweig struct {
	Nutzlast []byte
	Signatur protocol.Signature
}

// Oeffner öffnet einen Wrap. Der private Schlüssel bleibt auf dem Träger.
type Oeffner interface {
	Unwrap(wrapped, ctx []byte) ([]byte, error)
}

// Auftrag prüft eine Epoche. Auswahl nennt die ersten Sequenzen der Einträge.
// Alles öffnet jeden Eintrag der Epoche. Eine leere Auswahl prüft nur die Kette.
// Bestaetigung nil ist eine Lücke: der Inhalt bleibt zu.
// AbschlussHash ist der bestätigte epoch_hash. Weicht er ab, ist das eine Verzweigung.
type Auftrag struct {
	Mandant               protocol.ID
	Ablage                protocol.ID
	Epoch                 protocol.EpochID
	Rahmen                int
	Rolle                 protocol.StromRolle
	Segmente              []Segment
	HSM                   *ecdsa.PublicKey
	Bestaetigung          *ecdsa.PublicKey
	BestaetigungsSignatur protocol.Signature
	AbschlussHash         protocol.Hash
	Vorgaenger            protocol.Hash
	Zertifikat            *x509.Certificate
	Priv                  crypto.PrivateKey
	// Oeffner öffnet den DEK, wenn der private Schlüssel den Träger nicht verlässt.
	// Priv und Oeffner zugleich ist ein Fehler. Die Kettenprüfung braucht keinen von beiden.
	Oeffner    Oeffner
	Pruef      crypto.PublicKey
	Status     Status
	RasterEnde uint64
	Auswahl    []uint64
	Alles      bool
	Zweige     []Zweig
	// Annahmen sind die annahme_payloads dieser Instanz. Ist die Liste gesetzt,
	// ersetzen die darin genannten Segmente das Feld Segmente. Objekte liefert
	// die Segmentbytes zum Objektschlüssel. Ein Objekt, das keine Annahme nennt,
	// ist kein Glied. nil lässt die übergebenen Segmente.
	Annahmen [][]byte
	Objekte  map[string][]byte
	// Katalog ist der letzte Katalogstand. Ist er gesetzt, muss die bind_id
	// der Epoche darin zur Rolle und zur Ablage passen.
	Katalog *protocol.Stand
}

// Eintrag ist ein geöffneter Log- oder Auffang-Eintrag.
// Gueltig heißt, dass die Zugehörigkeit besteht. Ein Auffang-Eintrag ohne
// Aussage bleibt sichtbar; Unzugeordnet und Grund sind dann der Befund.
type Eintrag struct {
	Seq          uint64
	Event        protocol.ID
	Zeit         uint64
	Bind         protocol.ID
	Text         []byte
	Vorgang      string
	Personen     []string
	Grund        protocol.Grund
	Angabe       string
	Unzugeordnet bool
	NachRaster   bool
	Gueltig      bool
	// Verweis ist gesetzt, wenn der Inhalt ein Verzeichnisverweis ist.
	// Er nennt den Logeintrag. Bind der Hülle bleibt das Feld Bind.
	Verweis *protocol.Verweis
	// Index ist gesetzt, wenn die Rolle vorgang ist.
	Index *protocol.IndexEintrag
	// Beleg nennt eine Quell-Epoche einer Summenepoche.
	Beleg *protocol.Beleg
	// VorgangSumme und PersonSumme stehen in der Rolle vorgang-summe.
	VorgangSumme *protocol.VorgangSumme
	PersonSumme  *protocol.PersonSumme
	// Katalog ist gesetzt, wenn die Rolle katalog ist.
	Katalog *protocol.Stand
}

// Bericht ist das Ergebnis. Geoeffnet sind die Sequenzen, deren Rahmen geöffnet wurden.
// Bei einer Lücke, einer Verzweigung, einem Bruch zum Vorgänger oder bei Status
// verloren bleibt die Auswahl Ciphertext.
type Bericht struct {
	Fingerabdruck   protocol.Hash
	DekID           protocol.ID
	Bind            protocol.ID
	Kettenkopf      protocol.Hash
	EintragZahl     uint64
	EpochHash       protocol.Hash
	Previous        protocol.Hash
	Vertraulich     bool
	Luecke          bool
	Verzweigung     bool
	VorgaengerBruch bool
	Kompromittiert  bool
	Verloren        bool
	Geoeffnet       []uint64
	Eintraege       []Eintrag
}

// Pruefen prüft die Epoche und öffnet danach nur die Auswahl.
// Der Klartext-DEK wird vor der Rückkehr verworfen.
func Pruefen(a Auftrag) (Bericht, error) {
	if a.Priv != nil && a.Oeffner != nil {
		return Bericht{}, ErrSchluessel
	}
	switch a.Rolle {
	case protocol.RolleGruppe, protocol.RolleEinzel, protocol.RolleAuffang, protocol.RolleVerzeichnis,
		protocol.RolleVorgang, protocol.RolleKatalog, protocol.RolleVerzeichnisSumme, protocol.RolleVorgangSumme:
	default:
		return Bericht{}, ErrRolle
	}
	var saetze []annahmeSatz
	if a.Annahmen != nil {
		var err error
		saetze, a.Segmente, err = segmenteAusAnnahme(a)
		if errors.Is(err, errObjektFehlt) {
			return Bericht{}, ErrKette
		}
		if err != nil {
			return Bericht{}, err
		}
	}
	if a.Alles && len(a.Auswahl) > 0 {
		return Bericht{}, ErrAuswahl
	}
	auswahl := make(map[uint64]struct{}, len(a.Auswahl))
	for _, seq := range a.Auswahl {
		if seq == 0 {
			return Bericht{}, ErrAuswahl
		}
		if _, ok := auswahl[seq]; ok {
			return Bericht{}, ErrAuswahl
		}
		auswahl[seq] = struct{}{}
	}
	var bericht Bericht
	switch a.Status {
	case StatusAktuell, StatusAbgeloest, StatusAbgelaufen:
		bericht.Vertraulich = true
	case StatusKompromittiert:
		bericht.Kompromittiert = true
	case StatusVerloren:
		bericht.Verloren = true
	default:
		return Bericht{}, ErrStatus
	}
	if a.HSM == nil || len(a.Segmente) == 0 {
		return Bericht{}, protocol.ErrLength
	}
	gel, err := lesen(a)
	if err != nil {
		return Bericht{}, err
	}
	manifest, err := protocol.ParseManifest(gel.nutzlast)
	if err != nil {
		return Bericht{}, err
	}
	if manifest.Epoch != a.Epoch || manifest.ChainHead != gel.kopf || manifest.Count != gel.anzahl {
		return Bericht{}, ErrKette
	}
	if !crypt.VerifyP256(a.HSM, gel.nutzlast, gel.signatur) {
		return Bericht{}, ErrSignatur
	}
	hash, err := protocol.EpochHash(gel.nutzlast, gel.signatur)
	if err != nil {
		return Bericht{}, err
	}
	if a.Zertifikat != nil {
		fp, err := crypt.FingerprintCertificate(a.Zertifikat)
		if err != nil {
			return Bericht{}, err
		}
		if fp != gel.finger {
			return Bericht{}, ErrFinger
		}
	}
	bericht.Fingerabdruck = gel.finger
	bericht.DekID = gel.dek
	bericht.Kettenkopf = gel.kopf
	bericht.EintragZahl = gel.anzahl
	bericht.EpochHash = hash
	bericht.Previous = manifest.Previous
	if manifest.Previous != a.Vorgaenger {
		bericht.VorgaengerBruch = true
	}
	for _, zweig := range a.Zweige {
		if !crypt.VerifyP256(a.HSM, zweig.Nutzlast, zweig.Signatur) {
			continue
		}
		zweigHash, err := protocol.EpochHash(zweig.Nutzlast, zweig.Signatur)
		if err != nil {
			return Bericht{}, err
		}
		if zweigHash != hash {
			bericht.Verzweigung = true
		}
	}
	offen := !bericht.VorgaengerBruch && !bericht.Verloren
	if a.Bestaetigung == nil {
		bericht.Luecke = true
		offen = false
	} else if !crypt.VerifyP256(a.Bestaetigung, protocol.ConfirmationPayload(a.AbschlussHash), a.BestaetigungsSignatur) {
		return Bericht{}, ErrBestaetigung
	} else if a.AbschlussHash != hash {
		bericht.Verzweigung = true
		offen = false
	}
	if a.Annahmen != nil {
		bereich, err := annahmeBereich(a, manifest, saetze)
		if err != nil {
			return Bericht{}, err
		}
		// Die Kette bleibt ohne den Blob prüfbar. Die batch_id prüft das Werkzeug,
		// sobald der Schlüssel vorliegt und die Epoche geöffnet werden darf.
		if offen && (a.Priv != nil || a.Oeffner != nil) {
			if err := bindungPruefen(a, gel.finger, gel.frames, bereich); err != nil {
				return Bericht{}, err
			}
		}
		if bereich[len(bereich)-1].hash != manifest.AnnahmeHead {
			return Bericht{}, ErrAnnahme
		}
	}
	if !offen || (!a.Alles && len(auswahl) == 0) {
		return bericht, nil
	}
	dek, bind, err := dekOeffnen(a, gel.wrapped, gel.finger)
	if err != nil {
		return Bericht{}, err
	}
	defer dek.Wipe()
	bericht.Bind = bind
	eintraege, geoeffnet, err := oeffnen(a, gel.frames, dek, gel.dek, bind, auswahl)
	if err != nil {
		return Bericht{}, err
	}
	bericht.Geoeffnet = geoeffnet
	bericht.Eintraege = eintraege
	return bericht, nil
}

// dek || bind_id, wie crypt.UnwrapDEK.
const wrapKlar = 48

func dekOeffnen(a Auftrag, wrapped []byte, finger protocol.Hash) (crypt.DEK, protocol.ID, error) {
	pt, err := wrapOeffnen(a, wrapped, protocol.WrapContext(a.Mandant, a.Ablage, a.Epoch, finger))
	if err != nil {
		return crypt.DEK{}, protocol.ID{}, err
	}
	defer crypt.Wipe(pt)
	if len(pt) != wrapKlar {
		return crypt.DEK{}, protocol.ID{}, crypt.ErrPlaintext
	}
	var dek crypt.DEK
	var bind protocol.ID
	copy(dek[:], pt[:32])
	copy(bind[:], pt[32:])
	return dek, bind, nil
}

func wrapOeffnen(a Auftrag, wrapped, ctx []byte) ([]byte, error) {
	if a.Priv != nil && a.Oeffner != nil {
		return nil, ErrSchluessel
	}
	if a.Oeffner != nil {
		pt, err := a.Oeffner.Unwrap(wrapped, ctx)
		if err != nil {
			return nil, err
		}
		if len(pt) == 0 {
			return nil, crypt.ErrOpen
		}
		return pt, nil
	}
	if a.Priv == nil {
		return nil, ErrSchluessel
	}
	return crypt.Unwrap(a.Priv, wrapped, ctx)
}

type gelesen struct {
	finger   protocol.Hash
	dek      protocol.ID
	wrapped  []byte
	nutzlast []byte
	signatur protocol.Signature
	kopf     protocol.Hash
	anzahl   uint64
	frames   []rahmen
}

type rahmen struct {
	seq   uint64
	nonce protocol.Nonce
	ct    []byte
	tag   []byte
}

func lesen(a Auftrag) (gelesen, error) {
	var out gelesen
	var chain protocol.Chain
	for i, seg := range a.Segmente {
		if err := schluesselPasst(a, seg.Schluessel, uint64(i+1)); err != nil {
			return gelesen{}, err
		}
		letzter := i == len(a.Segmente)-1
		_, kette, manifest, err := protocol.Zerlegen(seg.Bytes, a.Rahmen, i == 0, letzter)
		if err != nil {
			return gelesen{}, err
		}
		if i == 0 {
			finger, dek, wrapped, _, err := protocol.ParseKopf(seg.Bytes)
			if err != nil {
				return gelesen{}, err
			}
			chain, err = protocol.NewChain(a.Mandant, a.Ablage, a.Epoch, dek, finger, wrapped)
			if err != nil {
				return gelesen{}, err
			}
			out.finger = finger
			out.dek = dek
			out.wrapped = wrapped
		}
		if letzter {
			out.nutzlast, out.signatur, err = protocol.ParseManifestRahmen(manifest)
			if err != nil {
				return gelesen{}, err
			}
		}
		for _, fr := range kette {
			var nonce protocol.Nonce
			copy(nonce[:], fr[:protocol.NonceLen])
			seq := protocolNonceSeq(nonce)
			ct := append([]byte(nil), fr[protocol.NonceLen:len(fr)-protocol.TagLen]...)
			tag := append([]byte(nil), fr[len(fr)-protocol.TagLen:]...)
			if err := chain.Append(seq, nonce, ct, tag); err != nil {
				return gelesen{}, err
			}
			out.frames = append(out.frames, rahmen{seq: seq, nonce: nonce, ct: ct, tag: tag})
		}
	}
	kopf, err := chain.Head()
	if err != nil {
		return gelesen{}, err
	}
	anzahl, err := chain.Count()
	if err != nil {
		return gelesen{}, err
	}
	out.kopf = kopf
	out.anzahl = anzahl
	return out, nil
}

func schluesselPasst(a Auftrag, schluessel string, nr uint64) error {
	mandant, ablage, epoch, got, err := protocol.ParseObjektSchluessel(schluessel)
	if err != nil {
		return err
	}
	if mandant != a.Mandant || ablage != a.Ablage || epoch != a.Epoch || got != nr {
		return ErrKette
	}
	return nil
}

func protocolNonceSeq(n protocol.Nonce) uint64 {
	return binary.BigEndian.Uint64(n[protocol.PrefixLen:])
}

func oeffnen(a Auftrag, frames []rahmen, dek crypt.DEK, dekID, bind protocol.ID, auswahl map[uint64]struct{}) ([]Eintrag, []uint64, error) {
	var eintraege []Eintrag
	var geoeffnet []uint64
	if a.Alles {
		for i := 0; i < len(frames); {
			plain, err := auf(dek, a, dekID, frames[i])
			if err != nil {
				return nil, nil, err
			}
			geoeffnet = append(geoeffnet, frames[i].seq)
			if len(plain) == 0 {
				return nil, nil, ErrInhalt
			}
			switch protocol.Art(plain[0]) {
			case protocol.ArtFuellung:
				i++
			case protocol.ArtEreignis:
				eintrag, naechste, seqs, err := ereignis(a, frames, i, dek, dekID, bind, plain)
				if err != nil {
					return nil, nil, err
				}
				eintraege = append(eintraege, eintrag)
				geoeffnet = append(geoeffnet, seqs...)
				i = naechste
			default:
				return nil, nil, ErrInhalt
			}
		}
		return eintraege, geoeffnet, nil
	}
	for i := 0; i < len(frames); {
		if _, ok := auswahl[frames[i].seq]; !ok {
			i++
			continue
		}
		delete(auswahl, frames[i].seq)
		plain, err := auf(dek, a, dekID, frames[i])
		if err != nil {
			return nil, nil, err
		}
		geoeffnet = append(geoeffnet, frames[i].seq)
		if len(plain) == 0 || protocol.Art(plain[0]) != protocol.ArtEreignis {
			return nil, nil, ErrAuswahl
		}
		eintrag, naechste, seqs, err := ereignis(a, frames, i, dek, dekID, bind, plain)
		if err != nil {
			return nil, nil, err
		}
		eintraege = append(eintraege, eintrag)
		geoeffnet = append(geoeffnet, seqs...)
		i = naechste
	}
	if len(auswahl) > 0 {
		return nil, nil, ErrAuswahl
	}
	return eintraege, geoeffnet, nil
}

func ereignis(a Auftrag, frames []rahmen, i int, dek crypt.DEK, dekID, bind protocol.ID, erster []byte) (Eintrag, int, []uint64, error) {
	if len(erster) < protocol.EreignisKopf {
		return Eintrag{}, 0, nil, ErrInhalt
	}
	gesamt := binary.BigEndian.Uint64(erster[1:9])
	n, err := rahmenZahl(gesamt, a.Rahmen)
	if err != nil {
		return Eintrag{}, 0, nil, err
	}
	if i+n > len(frames) {
		return Eintrag{}, 0, nil, protocol.ErrRahmen
	}
	teile := [][]byte{erster}
	var seqs []uint64
	for k := 1; k < n; k++ {
		plain, err := auf(dek, a, dekID, frames[i+k])
		if err != nil {
			return Eintrag{}, 0, nil, err
		}
		if len(plain) == 0 || protocol.Art(plain[0]) != protocol.ArtFortsetzung {
			return Eintrag{}, 0, nil, ErrInhalt
		}
		teile = append(teile, plain)
		seqs = append(seqs, frames[i+k].seq)
	}
	klar, err := protocol.JoinEreignis(teile)
	if err != nil {
		return Eintrag{}, 0, nil, err
	}
	eintrag, err := lesenEintrag(a, klar, bind, frames[i].seq)
	if err != nil {
		return Eintrag{}, 0, nil, err
	}
	return geltend(a, eintrag, bind), i + n, seqs, nil
}

// geltend bindet den Eintrag an die geöffnete bind_id und, wenn ein Stand vorliegt, an den Katalog.
func geltend(a Auftrag, eintrag Eintrag, dekBind protocol.ID) Eintrag {
	if !katalogPasst(a, dekBind) || !katalogPasst(a, eintrag.Bind) {
		eintrag.Gueltig = false
	}
	if a.Rolle == protocol.RolleEinzel && (eintrag.Bind == a.Ablage || dekBind == a.Ablage) {
		eintrag.Gueltig = false
	}
	return eintrag
}

func katalogPasst(a Auftrag, bind protocol.ID) bool {
	if a.Katalog == nil {
		return true
	}
	for _, k := range a.Katalog.Kennungen {
		if k.Rolle != a.Rolle || k.Ablage != a.Ablage || k.Bind != bind {
			continue
		}
		if a.Rolle == protocol.RolleEinzel && k.Bind == k.Ablage {
			continue
		}
		return true
	}
	return false
}

func lesenEintrag(a Auftrag, klar []byte, dekBind protocol.ID, seq uint64) (Eintrag, error) {
	event, zeit, bind, inhalt, err := protocol.ParseEreignisKlartext(klar)
	if err != nil {
		return Eintrag{}, ErrInhalt
	}
	eintrag := Eintrag{
		Seq:   seq,
		Event: event,
		Zeit:  zeit,
		Bind:  bind,
	}
	if a.RasterEnde != 0 && zeit > a.RasterEnde {
		eintrag.NachRaster = true
	}
	bindOK := bind == dekBind
	switch a.Rolle {
	case protocol.RolleAuffang:
		body, err := protocol.ParseAuffang(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Text = body.Text
		eintrag.Vorgang = body.Vorgang
		eintrag.Personen = body.Personen
		eintrag.Grund = body.Grund
		eintrag.Angabe = body.Angabe
		eintrag.Unzugeordnet = true
		eintrag.Gueltig = bindOK
		if body.Grund == protocol.GrundZielFehlt {
			ok, err := aussagen(a, body.Aussagen, zeit, body.Personen)
			if err != nil {
				return Eintrag{}, err
			}
			eintrag.Gueltig = bindOK && ok
		}
	case protocol.RolleVerzeichnis:
		body, err := protocol.ParseVerweis(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Verweis = &body
		eintrag.Gueltig = bindOK
	case protocol.RolleVorgang:
		body, err := protocol.ParseIndex(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Index = &body
		eintrag.Gueltig = bindOK
	case protocol.RolleKatalog:
		body, err := protocol.ParseKatalog(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Katalog = &body
		eintrag.Gueltig = bindOK && bind == a.Ablage
	case protocol.RolleVerzeichnisSumme:
		if beleg, err := protocol.ParseBeleg(inhalt); err == nil {
			eintrag.Beleg = &beleg
			eintrag.Gueltig = bindOK
			return eintrag, nil
		} else if !errors.Is(err, protocol.ErrDomain) {
			return Eintrag{}, ErrInhalt
		}
		body, err := protocol.ParseVerweis(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Verweis = &body
		eintrag.Gueltig = bindOK
	case protocol.RolleVorgangSumme:
		if beleg, err := protocol.ParseBeleg(inhalt); err == nil {
			eintrag.Beleg = &beleg
			eintrag.Gueltig = bindOK
			return eintrag, nil
		} else if !errors.Is(err, protocol.ErrDomain) {
			return Eintrag{}, ErrInhalt
		}
		if summe, err := protocol.ParseVorgangSumme(inhalt); err == nil {
			eintrag.VorgangSumme = &summe
			eintrag.Gueltig = bindOK
			return eintrag, nil
		} else if !errors.Is(err, protocol.ErrDomain) {
			return Eintrag{}, ErrInhalt
		}
		summe, err := protocol.ParsePersonSumme(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.PersonSumme = &summe
		eintrag.Gueltig = bindOK
	default:
		body, err := protocol.ParseLog(inhalt)
		if err != nil {
			return Eintrag{}, ErrInhalt
		}
		eintrag.Text = body.Text
		eintrag.Vorgang = body.Vorgang
		eintrag.Personen = body.Bezuege
		ok, err := aussagen(a, body.Aussagen, zeit, body.Bezuege)
		if err != nil {
			return Eintrag{}, err
		}
		eintrag.Gueltig = bindOK && ok
	}
	return eintrag, nil
}

func aussagen(a Auftrag, teile []protocol.AussageTeil, zeit uint64, personen []string) (bool, error) {
	if len(teile) == 0 {
		return false, nil
	}
	key, ok := a.Pruef.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve == nil || key.X == nil || key.Y == nil || key.Curve.Params().Name != "P-256" || key.Curve.Params().BitSize != 256 {
		return false, ErrPruef
	}
	for _, teil := range teile {
		if teil.Nutzlast.Mandant != a.Mandant || !teil.Nutzlast.Deckt(zeit) || !enthalten(teil.Nutzlast.Person, personen) {
			return false, nil
		}
		if len(teil.Signatur) != protocol.SignatureLen {
			return false, nil
		}
		nutz, err := protocol.AussageBytes(teil.Nutzlast)
		if err != nil {
			return false, nil
		}
		var sig protocol.Signature
		copy(sig[:], teil.Signatur)
		if !crypt.VerifyP256(key, nutz, sig) {
			return false, nil
		}
	}
	return true, nil
}

func enthalten(name string, personen []string) bool {
	for _, p := range personen {
		if p == name {
			return true
		}
	}
	return false
}

func auf(dek crypt.DEK, a Auftrag, dekID protocol.ID, fr rahmen) ([]byte, error) {
	return crypt.Open(dek, fr.nonce, fr.ct, fr.tag, protocol.AAD(a.Mandant, a.Ablage, a.Epoch, dekID, fr.seq))
}

func rahmenZahl(gesamt uint64, rahmen int) (int, error) {
	nutz, err := protocol.RahmenNutz(rahmen)
	if err != nil {
		return 0, err
	}
	if gesamt == 0 || nutz <= protocol.EreignisKopf {
		return 0, protocol.ErrLength
	}
	first := nutz - protocol.EreignisKopf
	if gesamt <= uint64(first) {
		return 1, nil
	}
	rest := gesamt - uint64(first)
	step := uint64(nutz - 1)
	n := 1 + int((rest+step-1)/step)
	if n < 1 {
		return 0, protocol.ErrLength
	}
	return n, nil
}
