package fenster

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"cryptlog/protocol"
	"cryptlog/schluessel"
)

// ZielArt ist S3 oder die Platte. Die Passphrase gehört nicht dazu.
type ZielArt int

const (
	// ZielS3 nennt Endpunkt und Bucket.
	ZielS3 ZielArt = iota + 1
	// ZielPlatte nennt den Pfad des Ziels.
	ZielPlatte
)

// Verbindung ist das, was das Werkzeug lokal ablegen darf:
// Endpunkt und Bucket oder der Pfad der Platte, die mandant_id,
// die Katalogablage und die Pfade der Schlüsseldateien.
// Eine Passphrase und eine PIN haben hier kein Feld.
type Verbindung struct {
	Ziel         ZielArt
	Endpunkt     string
	Bucket       string
	Pfad         string
	Mandant      protocol.ID
	Zone         protocol.ID
	Katalog      protocol.ID
	KEK          string
	Zertifikat   string
	Aufruf       string
	Bestaetigung string
	Plattform    bool
}

var verboten = map[string]struct{}{
	"passphrase": {},
	"passwort":   {},
	"password":   {},
	"pin":        {},
	"secret":     {},
	"privat":     {},
	"klartext":   {},
}

var erlaubt = map[string]struct{}{
	"ziel": {}, "endpunkt": {}, "bucket": {}, "pfad": {},
	"mandant": {}, "zone": {}, "katalog": {}, "kek": {}, "zertifikat": {},
	"aufruf": {}, "bestaetigung": {}, "plattform": {},
}

// Parsen liest eine abgelegte Verbindung. Ein Feld für die Passphrase lehnt es ab.
func Parsen(b []byte) (Verbindung, error) {
	if len(b) > 1<<16 {
		return Verbindung{}, ErrVerbindung
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	var v Verbindung
	gesehen := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		zeile := strings.TrimSpace(sc.Text())
		if zeile == "" || strings.HasPrefix(zeile, "#") {
			continue
		}
		schluessel, wert, ok := strings.Cut(zeile, "=")
		if !ok {
			return Verbindung{}, ErrVerbindung
		}
		schluessel = strings.ToLower(strings.TrimSpace(schluessel))
		wert = strings.TrimSpace(wert)
		if _, nein := verboten[schluessel]; nein {
			return Verbindung{}, ErrVerbindung
		}
		if _, ja := erlaubt[schluessel]; !ja {
			return Verbindung{}, ErrVerbindung
		}
		if _, doppelt := gesehen[schluessel]; doppelt || strings.ContainsAny(wert, "\r\n\x00") {
			return Verbindung{}, ErrVerbindung
		}
		gesehen[schluessel] = struct{}{}
		switch schluessel {
		case "ziel":
			switch wert {
			case "s3":
				v.Ziel = ZielS3
			case "platte":
				v.Ziel = ZielPlatte
			default:
				return Verbindung{}, ErrVerbindung
			}
		case "endpunkt":
			v.Endpunkt = wert
		case "bucket":
			v.Bucket = wert
		case "pfad":
			v.Pfad = wert
		case "mandant":
			id, err := protocol.ParseID(wert)
			if err != nil {
				return Verbindung{}, ErrVerbindung
			}
			v.Mandant = id
		case "zone":
			id, err := protocol.ParseID(wert)
			if err != nil {
				return Verbindung{}, ErrVerbindung
			}
			v.Zone = id
		case "katalog":
			id, err := protocol.ParseID(wert)
			if err != nil {
				return Verbindung{}, ErrVerbindung
			}
			v.Katalog = id
		case "kek":
			v.KEK = wert
		case "zertifikat":
			v.Zertifikat = wert
		case "aufruf":
			v.Aufruf = wert
		case "bestaetigung":
			v.Bestaetigung = wert
		case "plattform":
			switch wert {
			case "0":
				v.Plattform = false
			case "1":
				v.Plattform = true
			default:
				return Verbindung{}, ErrVerbindung
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Verbindung{}, ErrVerbindung
	}
	if err := v.vollstaendig(); err != nil {
		return Verbindung{}, err
	}
	return v, nil
}

// Format schreibt die Verbindung. Die Passphrase kommt darin nicht vor.
func Format(v Verbindung) ([]byte, error) {
	if err := v.vollstaendig(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	ziel := "s3"
	if v.Ziel == ZielPlatte {
		ziel = "platte"
	}
	plattform := "0"
	if v.Plattform {
		plattform = "1"
	}
	zeilen := [][2]string{
		{"ziel", ziel},
		{"endpunkt", v.Endpunkt},
		{"bucket", v.Bucket},
		{"pfad", v.Pfad},
		{"mandant", v.Mandant.Hex()},
		{"zone", v.Zone.Hex()},
		{"katalog", v.Katalog.Hex()},
		{"kek", v.KEK},
		{"zertifikat", v.Zertifikat},
		{"aufruf", v.Aufruf},
		{"bestaetigung", v.Bestaetigung},
		{"plattform", plattform},
	}
	for _, z := range zeilen {
		b.WriteString(z[0])
		b.WriteByte('=')
		b.WriteString(z[1])
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// Ablegen schreibt die Verbindung mit Rechten nur für den Empfänger.
func Ablegen(pfad string, v Verbindung) error {
	b, err := Format(v)
	if err != nil {
		return err
	}
	return os.WriteFile(pfad, b, 0o600)
}

// Lesen lädt eine abgelegte Verbindung und öffnet keine Prüfung.
func Lesen(pfad string) (Verbindung, error) {
	b, err := os.ReadFile(pfad)
	if err != nil || len(b) > 1<<16 {
		return Verbindung{}, ErrVerbindung
	}
	return Parsen(b)
}

func (v Verbindung) vollstaendig() error {
	var leer protocol.ID
	if v.Mandant == leer || v.Zone == leer || v.Katalog == leer || v.Zertifikat == "" {
		return ErrVerbindung
	}
	switch v.Ziel {
	case ZielS3:
		if v.Endpunkt == "" || v.Bucket == "" || v.Pfad != "" {
			return ErrVerbindung
		}
	case ZielPlatte:
		if v.Pfad == "" || v.Endpunkt != "" || v.Bucket != "" {
			return ErrVerbindung
		}
	default:
		return ErrVerbindung
	}
	return nil
}

func (v Verbindung) zumModus(modus schluessel.Modus) error {
	if err := v.vollstaendig(); err != nil {
		return err
	}
	switch modus {
	case schluessel.ModusEinfach:
		if v.KEK == "" {
			return ErrVerbindung
		}
	case schluessel.ModusSicher:
		if v.KEK != "" {
			return ErrModus
		}
	default:
		return ErrModus
	}
	if v.Plattform && v.Mandant != protocol.PlattformMandant() {
		return ErrVerbindung
	}
	return nil
}
