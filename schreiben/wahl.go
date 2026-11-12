package schreiben

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cryptlog/abschluss"
	"cryptlog/protocol"
)

// Wahl verteilt die Objektschlüssel eines Schreibprozesses.
// Segmente eines Mandanten mit eigenem Ziel gehen dorthin.
// Belegung, Instanz, Vorbereitung und Annahme bleiben im gemeinsamen Ziel,
// weil ein Abschluss Segmente mehrerer Mandanten nennen kann.
// Ein Segment, das schon im gemeinsamen Ziel liegt, wird nicht kopiert.
type Wahl struct {
	gemeinsam speicherOrt
	mandant   map[protocol.ID]speicherOrt
}

type speicherOrt struct {
	ziel Ziel
	art  string
}

// artFehler nennt die Art des Speichers, der den Fehler gemeldet hat.
type artFehler struct {
	art string
	err error
}

func (e artFehler) Error() string { return e.err.Error() }

func (e artFehler) Unwrap() error { return e.err }

// ZielArt ist s3 oder platte.
func (e artFehler) ZielArt() string { return e.art }

// NeueWahl prüft die Zuordnung. mandanten enthält nur abweichende Ziele.
func NeueWahl(gemeinsam Ziel, art string, mandanten map[protocol.ID]Ziel, arten map[protocol.ID]string) (*Wahl, error) {
	if gemeinsam == nil || (art != "s3" && art != "platte") || len(mandanten) == 0 || len(mandanten) != len(arten) {
		return nil, protocol.ErrLength
	}
	kopie := make(map[protocol.ID]speicherOrt, len(mandanten))
	for id, ziel := range mandanten {
		zart := arten[id]
		if id == (protocol.ID{}) || ziel == nil || (zart != "s3" && zart != "platte") {
			return nil, protocol.ErrLength
		}
		if gleichesZiel(gemeinsam, ziel) {
			return nil, protocol.ErrLength
		}
		kopie[id] = speicherOrt{ziel: ziel, art: zart}
	}
	return &Wahl{gemeinsam: speicherOrt{ziel: gemeinsam, art: art}, mandant: kopie}, nil
}

// Lesen sucht ein Segment zuerst im Ziel des Mandanten.
// Fehlt es dort, liegt eine ältere Fassung im gemeinsamen Ziel.
func (w *Wahl) Lesen(schluessel string) ([]byte, bool, error) {
	primaer, historisch := w.orten(schluessel)
	inhalt, ok, err := primaer.ziel.Lesen(schluessel)
	if err != nil {
		return nil, false, primaer.fehl(err)
	}
	if ok || historisch.ziel == nil {
		return inhalt, ok, nil
	}
	inhalt, ok, err = historisch.ziel.Lesen(schluessel)
	if err != nil {
		return nil, false, historisch.fehl(err)
	}
	return inhalt, ok, nil
}

// Schreiben legt ein neues Segment im Ziel des Mandanten ab.
// Dieselben Bytes im gemeinsamen Ziel sind ein wiederholtes Schreiben und werden nicht kopiert.
// Ein anderer Inhalt wird nicht ersetzt.
func (w *Wahl) Schreiben(schluessel string, inhalt []byte) error {
	primaer, historisch := w.orten(schluessel)
	if historisch.ziel == nil {
		return primaer.fehl(primaer.ziel.Schreiben(schluessel, inhalt))
	}
	fertig, err := w.gleich(primaer, schluessel, inhalt)
	if fertig || err != nil {
		return err
	}
	fertig, err = w.gleich(historisch, schluessel, inhalt)
	if fertig || err != nil {
		return err
	}
	return primaer.fehl(primaer.ziel.Schreiben(schluessel, inhalt))
}

// Ersetzen gilt der Belegung und damit dem gemeinsamen Ziel.
// Ein Segment liegt beim Mandanten; ein abweichender Inhalt wird dort nicht ersetzt.
func (w *Wahl) Ersetzen(schluessel string, bisher, neu []byte) error {
	primaer, _ := w.orten(schluessel)
	return primaer.fehl(primaer.ziel.Ersetzen(schluessel, bisher, neu))
}

// Entfernen löscht das Segment im Ziel des Mandanten und eine ältere Fassung im gemeinsamen Ziel.
func (w *Wahl) Entfernen(schluessel string) error {
	primaer, historisch := w.orten(schluessel)
	if err := primaer.entfernen(schluessel); err != nil {
		return err
	}
	if historisch.ziel == nil {
		return nil
	}
	return historisch.entfernen(schluessel)
}

// Liste liefert die Schlüssel unter prefix.
// Belegung, Instanz, Vorbereitung und Annahme kommen nur aus dem gemeinsamen Ziel.
func (w *Wahl) Liste(prefix string) ([]string, error) {
	gesehen := map[string]struct{}{}
	var out []string
	for _, ort := range w.orte(prefix) {
		keys, err := ort.ziel.Liste(prefix)
		if err != nil {
			return nil, ort.fehl(err)
		}
		for _, key := range keys {
			if _, ok := gesehen[key]; ok {
				continue
			}
			gesehen[key] = struct{}{}
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (w *Wahl) orten(schluessel string) (primaer, historisch speicherOrt) {
	mandant, _, _, _, err := protocol.ParseObjektSchluessel(schluessel)
	if err != nil {
		return w.gemeinsam, speicherOrt{}
	}
	ort, ok := w.mandant[mandant]
	if !ok {
		return w.gemeinsam, speicherOrt{}
	}
	return ort, w.gemeinsam
}

func (w *Wahl) orte(prefix string) []speicherOrt {
	if operational(prefix) {
		return []speicherOrt{w.gemeinsam}
	}
	if id, ok := mandantPraefix(prefix); ok {
		if ort, da := w.mandant[id]; da {
			return []speicherOrt{w.gemeinsam, ort}
		}
		return []speicherOrt{w.gemeinsam}
	}
	ids := make([]protocol.ID, 0, len(w.mandant))
	for id := range w.mandant {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Hex() < ids[j].Hex() })
	out := make([]speicherOrt, 0, 1+len(ids))
	out = append(out, w.gemeinsam)
	for _, id := range ids {
		out = append(out, w.mandant[id])
	}
	return out
}

func (w *Wahl) gleich(ort speicherOrt, schluessel string, inhalt []byte) (bool, error) {
	alt, ok, err := ort.ziel.Lesen(schluessel)
	if err != nil {
		return false, ort.fehl(err)
	}
	if !ok {
		return false, nil
	}
	if bytes.Equal(alt, inhalt) {
		return true, nil
	}
	return false, ort.fehl(abschluss.ErrObjekt)
}

func (o speicherOrt) fehl(err error) error {
	if err == nil {
		return nil
	}
	return artFehler{art: o.art, err: err}
}

func (o speicherOrt) entfernen(schluessel string) error {
	weg, ok := o.ziel.(Entfernen)
	if !ok {
		return o.fehl(protocol.ErrLength)
	}
	return o.fehl(weg.Entfernen(schluessel))
}

func operational(prefix string) bool {
	for _, name := range []string{"belegt", "instanz", "vorbereitung", "annahme"} {
		if prefix == name || strings.HasPrefix(prefix, name+"/") {
			return true
		}
	}
	return false
}

func mandantPraefix(prefix string) (protocol.ID, bool) {
	teil := prefix
	if i := strings.IndexByte(prefix, '/'); i >= 0 {
		teil = prefix[:i]
	}
	if len(teil) != protocol.IDLen*2 {
		return protocol.ID{}, false
	}
	id, err := protocol.ParseID(teil)
	if err != nil || id.Hex() != teil {
		return protocol.ID{}, false
	}
	return id, true
}

func gleichesZiel(a, b Ziel) bool {
	switch x := a.(type) {
	case *S3:
		y, ok := b.(*S3)
		return ok && x.bucket == y.bucket && x.endpunkt.Scheme == y.endpunkt.Scheme && x.endpunkt.Host == y.endpunkt.Host
	case *Platte:
		y, ok := b.(*Platte)
		return ok && x.wurzel == y.wurzel
	default:
		return false
	}
}

// zieleAus liest je Mandant die optionale Datei ziel.
// Fehlt sie überall, bleibt das gemeinsame Ziel unverändert.
func zieleAus(wurzel string, gemeinsam Ziel, art string) (Ziel, error) {
	eintraege, err := os.ReadDir(wurzel)
	if err != nil {
		return nil, konfigFehler("mandanten")
	}
	mandanten := map[protocol.ID]Ziel{}
	arten := map[protocol.ID]string{}
	for _, ein := range eintraege {
		if !ein.IsDir() {
			return nil, konfigFehler("mandanten")
		}
		id, err := protocol.ParseID(ein.Name())
		if err != nil || id.Hex() != ein.Name() || id == (protocol.ID{}) {
			return nil, konfigFehler("mandanten")
		}
		pfad := filepath.Join(wurzel, ein.Name(), "ziel")
		if _, err := os.Stat(pfad); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, konfigFehler("ziel")
		}
		if id == protocol.PlattformMandant() {
			return nil, konfigFehler("mandanten")
		}
		ziel, zart, err := mandantZielAus(filepath.Join(wurzel, ein.Name()), gemeinsam)
		if err != nil {
			return nil, err
		}
		mandanten[id] = ziel
		arten[id] = zart
	}
	if len(mandanten) == 0 {
		return gemeinsam, nil
	}
	wahl, err := NeueWahl(gemeinsam, art, mandanten, arten)
	if err != nil {
		return nil, konfigFehler("ziel")
	}
	return wahl, nil
}

func mandantZielAus(dir string, gemeinsam Ziel) (Ziel, string, error) {
	werte, err := liesWerte(filepath.Join(dir, "ziel"), mandantZielFelder, 1<<16)
	if err != nil {
		return nil, "", err
	}
	switch werte["ziel"] {
	case "platte":
		if werte["endpunkt"] != "" || werte["bucket"] != "" || werte["region"] != "" || werte["zugang"] != "" || werte["geheimnis"] != "" {
			return nil, "", konfigFehler("ziel")
		}
		wurzel, err := pflichtPfad(dir, werte, "wurzel")
		if err != nil {
			return nil, "", err
		}
		platte, err := OeffnenPlatte(wurzel)
		if err != nil {
			return nil, "", konfigFehler("wurzel")
		}
		if gleichesZiel(gemeinsam, platte) {
			return nil, "", konfigFehler("ziel")
		}
		return platte, "platte", nil
	case "s3":
		if werte["wurzel"] != "" {
			return nil, "", konfigFehler("ziel")
		}
		if werte["bucket"] == "plattform" {
			return nil, "", konfigFehler("bucket")
		}
		zugang, err := liesText(pflichtPfadWert(dir, werte, "zugang"), 4<<10)
		if err != nil {
			return nil, "", konfigFehler("zugang")
		}
		geheim, err := liesText(pflichtPfadWert(dir, werte, "geheimnis"), 4<<10)
		if err != nil {
			return nil, "", konfigFehler("geheimnis")
		}
		s3, err := OeffnenS3(S3Konfig{
			Endpunkt: werte["endpunkt"], Bucket: werte["bucket"], Region: werte["region"],
			Zugang: strings.TrimSpace(zugang), Geheimnis: strings.TrimSpace(geheim),
		})
		if err != nil {
			return nil, "", konfigFehler("s3")
		}
		if gleichesZiel(gemeinsam, s3) {
			return nil, "", konfigFehler("ziel")
		}
		return s3, "s3", nil
	default:
		return nil, "", konfigFehler("ziel")
	}
}
