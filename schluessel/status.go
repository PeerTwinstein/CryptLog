package schluessel

// Status ist die Lage eines Schlüssels im Schlüsselspeicher.
// Aktuell ist genau ein Zertifikat, oder keines.
// Abgelöst, verloren und kompromittiert sind nicht aktuell.
type Status uint8

const (
	// StatusAktuell ist der eine Schlüssel, mit dem neue Epochen gewickelt werden.
	StatusAktuell Status = iota
	// StatusAbgeloest wickelt keine neue Epoche. Abgeschlossene Epochen bleiben lesbar.
	StatusAbgeloest
	// StatusVerloren verwirft den Klartext-DEK einer offenen Epoche.
	StatusVerloren
	// StatusKompromittiert hebt die Vertraulichkeitsaussage dieses Fingerabdrucks auf.
	StatusKompromittiert
)

// String ist der Wortlaut aus dem Konzept.
func (s Status) String() string {
	switch s {
	case StatusAktuell:
		return "aktuell"
	case StatusAbgeloest:
		return "abgeloest"
	case StatusVerloren:
		return "verloren"
	case StatusKompromittiert:
		return "kompromittiert"
	default:
		return ""
	}
}

// Gueltig sagt, ob der Wert einer der vier Lagen ist.
func (s Status) Gueltig() bool {
	return s == StatusAktuell || s == StatusAbgeloest || s == StatusVerloren || s == StatusKompromittiert
}

// Art unterscheidet, was ein Protokolleintrag festhält.
type Art uint8

const (
	// ArtKEK hält ein Schlüsselzertifikat fest.
	ArtKEK Art = 1
	// ArtPruef hält den Prüfschlüssel der Zugehörigkeitsaussage fest.
	ArtPruef Art = 2
	// ArtCRL hält eine Sperrliste fest.
	ArtCRL Art = 3
	// ArtStand hält eine Auffrischung fest, ohne den Schlüssel zu wechseln.
	ArtStand Art = 4
)

// Modus ist die Eigenschaft des Mandanten.
// Einfach legt in ein Verzeichnis, sicher veröffentlicht signiert.
type Modus uint8

const (
	// ModusEinfach legt den verschlüsselten privaten Schlüssel in das Verzeichnis.
	ModusEinfach Modus = 1
	// ModusSicher veröffentlicht nur den öffentlichen Schlüssel.
	ModusSicher Modus = 2
)

func (a Art) gueltig() bool {
	return a == ArtKEK || a == ArtPruef || a == ArtCRL || a == ArtStand
}
