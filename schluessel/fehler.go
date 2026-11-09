package schluessel

import "errors"

var (
	// ErrQuelle heißt, der Schlüsselspeicher antwortet nicht.
	ErrQuelle = errors.New("schluessel: Speicher antwortet nicht")
	// ErrSignatur heißt, die Veröffentlichung prüft unter dem Vertrauensanker nicht.
	ErrSignatur = errors.New("schluessel: Signatur prüft nicht")
	// ErrNummer heißt, die laufende Nummer nimmt nicht zu.
	ErrNummer = errors.New("schluessel: laufende Nummer nimmt nicht zu")
	// ErrZeit heißt, der Zeitpunkt liegt außerhalb des Höchstalters.
	ErrZeit = errors.New("schluessel: Zeitpunkt liegt außerhalb des Höchstalters")
	// ErrZertifikat heißt, das Zertifikat prüft nicht.
	ErrZertifikat = errors.New("schluessel: Zertifikat prüft nicht")
	// ErrStatus heißt, der verlangte Status passt nicht zur Lage.
	ErrStatus = errors.New("schluessel: Status passt nicht")
	// ErrQuittung heißt, der Fingerabdruck ist nicht quittiert.
	ErrQuittung = errors.New("schluessel: Fingerabdruck ist nicht quittiert")
	// ErrPrivat heißt, der private Schlüssel des einfachen Modus ist nicht verschlüsselt.
	ErrPrivat = errors.New("schluessel: privater Schlüssel ist nicht verschlüsselt")
	// ErrModus heißt, die Handlung passt nicht zum Modus des Mandanten.
	ErrModus = errors.New("schluessel: Modus passt nicht")
	// ErrMandant heißt, die Mandantenkennung fehlt.
	ErrMandant = errors.New("schluessel: Mandant fehlt")
	// ErrEntwurf heißt, es liegt kein Entwurf zum Quittieren.
	ErrEntwurf = errors.New("schluessel: Entwurf fehlt")
	// ErrAnker heißt, der Vertrauensanker fehlt oder ist kein CA-Zertifikat.
	ErrAnker = errors.New("schluessel: Vertrauensanker fehlt")
	// ErrFormat heißt, die Fassung des Speichers oder des Cache passt nicht.
	ErrFormat = errors.New("schluessel: Fassung passt nicht")
	// ErrAktuell heißt, der aktuelle Schlüssel passt nicht zur verlangten Lage.
	ErrAktuell = errors.New("schluessel: aktueller Schlüssel passt nicht")
	// ErrGeheimnis heißt, der Cache-Schlüssel fehlt.
	ErrGeheimnis = errors.New("schluessel: Cache-Schlüssel fehlt")
)
