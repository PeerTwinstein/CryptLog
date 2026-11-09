package oberflaeche

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cryptlog/fenster"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/werkzeug"
)

func statusVon(s string) (werkzeug.Status, error) {
	switch s {
	case "aktuell":
		return werkzeug.StatusAktuell, nil
	case "abgeloest":
		return werkzeug.StatusAbgeloest, nil
	case "abgelaufen":
		return werkzeug.StatusAbgelaufen, nil
	case "kompromittiert":
		return werkzeug.StatusKompromittiert, nil
	case "verloren":
		return werkzeug.StatusVerloren, nil
	default:
		return 0, ErrAngabe
	}
}

func statusWort(s werkzeug.Status, ende time.Time, jetzt time.Time) string {
	if s == werkzeug.StatusAktuell && !ende.IsZero() && !jetzt.Before(ende) {
		s = werkzeug.StatusAbgelaufen
	}
	switch s {
	case werkzeug.StatusAktuell:
		return "aktuell"
	case werkzeug.StatusAbgeloest:
		return "abgelöst"
	case werkzeug.StatusAbgelaufen:
		return "abgelaufen"
	case werkzeug.StatusKompromittiert:
		return "kompromittiert"
	case werkzeug.StatusVerloren:
		return "verloren"
	default:
		return ""
	}
}

func modusWort(m schluessel.Modus) string {
	switch m {
	case schluessel.ModusEinfach:
		return "einfach"
	case schluessel.ModusSicher:
		return "sicher"
	default:
		return ""
	}
}

func artSchluessel(a fenster.Art) string {
	switch a {
	case fenster.ArtGruppe:
		return "gruppe"
	case fenster.ArtGezielt:
		return "gezielt"
	case fenster.ArtAuffang:
		return "auffang"
	case fenster.ArtPlattform:
		return "plattform"
	default:
		return ""
	}
}

func artVon(s string) (fenster.Art, bool) {
	switch s {
	case "gruppe":
		return fenster.ArtGruppe, true
	case "gezielt":
		return fenster.ArtGezielt, true
	case "auffang":
		return fenster.ArtAuffang, true
	case "plattform":
		return fenster.ArtPlattform, true
	default:
		return 0, false
	}
}

func artWort(a fenster.Art) string {
	switch a {
	case fenster.ArtGruppe:
		return "Gruppe"
	case fenster.ArtGezielt:
		return "Gezielt"
	case fenster.ArtAuffang:
		return "Auffang"
	case fenster.ArtPlattform:
		return "Plattform-Auffang"
	default:
		return ""
	}
}

func rolleWort(r protocol.StromRolle) string {
	switch r {
	case protocol.RolleGruppe:
		return "Gruppe"
	case protocol.RolleEinzel:
		return "Einzeln"
	case protocol.RolleAuffang:
		return "Auffang"
	case protocol.RolleVerzeichnis:
		return "Verzeichnis"
	case protocol.RolleVorgang:
		return "Vorgang"
	case protocol.RolleKatalog:
		return "Katalog"
	case protocol.RolleVerzeichnisSumme:
		return "Verzeichnis-Summe"
	case protocol.RolleVorgangSumme:
		return "Vorgang-Summe"
	default:
		return ""
	}
}

func grundWort(g protocol.Grund) string {
	switch g {
	case protocol.GrundUnbekannt:
		return "unbekannt"
	case protocol.GrundAussageUngueltig:
		return "aussage_ungueltig"
	case protocol.GrundZielFehlt:
		return "ziel_fehlt"
	case protocol.GrundOhneBezug:
		return "ohne_bezug"
	case protocol.GrundKEKFehlt:
		return "kek_fehlt"
	case protocol.GrundMandantUnbekannt:
		return "mandant_unbekannt"
	default:
		return ""
	}
}

func fingerText(h protocol.Hash) string {
	s := hex.EncodeToString(h[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

func zahl(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, ErrAngabe
	}
	return n, nil
}

func tagSpanne(vonText, bisText string, leerErlaubt bool) (time.Time, time.Time, error) {
	vonText = strings.TrimSpace(vonText)
	bisText = strings.TrimSpace(bisText)
	if vonText == "" && bisText == "" {
		if leerErlaubt {
			return time.Time{}, time.Time{}, nil
		}
		return time.Time{}, time.Time{}, ErrAngabe
	}
	von, err := time.ParseInLocation("2006-01-02", vonText, time.UTC)
	if err != nil {
		return time.Time{}, time.Time{}, ErrAngabe
	}
	bis, err := time.ParseInLocation("2006-01-02", bisText, time.UTC)
	if err != nil {
		return time.Time{}, time.Time{}, ErrAngabe
	}
	return von, bis.Add(24 * time.Hour), nil
}

func monatVon(s string) (time.Time, error) {
	t, err := time.ParseInLocation("2006-01", strings.TrimSpace(s), time.UTC)
	if err != nil || t.Day() != 1 {
		return time.Time{}, ErrAngabe
	}
	return t, nil
}

func befundZeile(b fenster.Befund) string {
	teile := []string{b.Epoch.String(), rolleWort(b.Rolle)}
	if b.Name != "" {
		teile = append(teile, b.Name)
	}
	teile = append(teile, "Ablage "+b.Ablage.Hex())
	if b.Luecke {
		teile = append(teile, "Lücke")
	}
	if b.Verzweigung {
		teile = append(teile, "Verzweigung")
	}
	if b.VorgaengerBruch {
		teile = append(teile, "Bruch zum Vorgänger")
	}
	if b.Geloescht {
		teile = append(teile, "gelöscht")
	}
	if b.Kompromittiert {
		teile = append(teile, "kompromittiert")
	}
	if b.Verloren {
		teile = append(teile, "verloren")
	}
	if b.Vertraulich {
		teile = append(teile, "vertraulich")
	}
	return strings.Join(teile, " · ")
}

func eintragZeile(z fenster.Zeile) string {
	teile := []string{zeitText(z.Zeit), "seq " + strconv.FormatUint(z.Seq, 10)}
	if namen := personenText(z.Personen); namen != "" {
		teile = append(teile, namen)
	}
	if len(z.Vorgang) > 0 {
		teile = append(teile, klartext(z.Vorgang))
	}
	if len(z.Text) > 0 {
		teile = append(teile, klartext(z.Text))
	}
	if z.Unzugeordnet {
		teile = append(teile, "unzugeordnet")
		if g := grundWort(z.Grund); g != "" {
			teile = append(teile, g)
		}
	}
	if len(z.Angabe) > 0 {
		teile = append(teile, klartext(z.Angabe))
	}
	if z.NachRaster {
		teile = append(teile, "nach dem Raster")
	}
	if !z.Gueltig {
		teile = append(teile, "Aussage ungültig")
	}
	return strings.Join(teile, " · ")
}

func personenText(liste [][]byte) string {
	var namen []string
	for _, b := range liste {
		if len(b) > 0 {
			namen = append(namen, klartext(b))
		}
	}
	return strings.Join(namen, ", ")
}

func klartext(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return hex.EncodeToString(b)
}

func zeitText(ms uint64) string {
	return time.UnixMilli(int64(ms)).UTC().Format("2006-01-02 15:04:05")
}
