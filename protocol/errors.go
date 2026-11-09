package protocol

import "errors"

var (
	// ErrLength heißt, eine Länge oder ein Feld liegt außerhalb der festgelegten Größe.
	ErrLength = errors.New("protocol: ungültige Länge")
	// ErrRaster heißt, der Rasterbeginn ist keine zulässige UTC-Zeit.
	ErrRaster = errors.New("protocol: Rasterzeit ungültig")
	// ErrSlotCount heißt, die Platzzahl ist keine Zweierpotenz ab 8.
	ErrSlotCount = errors.New("protocol: slot_count ist keine zulässige Zweierpotenz ab 8")
	// ErrArt heißt, die Art eines Rahmens oder Sequenzeintrags ist unbekannt.
	ErrArt = errors.New("protocol: ungültige Art")
	// ErrEvent heißt, die event_id passt nicht zur Art.
	ErrEvent = errors.New("protocol: event_id passt nicht zur Art")
	// ErrSeq heißt, die Sequenznummer ist 0 oder fällt.
	ErrSeq = errors.New("protocol: Sequenznummer ungültig")
	// ErrNonce heißt, die Nonce ist nicht epoch_prefix und Sequenznummer.
	ErrNonce = errors.New("protocol: Nonce passt nicht zur Sequenz")
	// ErrChain heißt, die Hash-Kette ist nicht geöffnet.
	ErrChain = errors.New("protocol: Kette ist nicht geöffnet")
	// ErrUTF8 heißt, ein Textfeld ist kein UTF-8.
	ErrUTF8 = errors.New("protocol: Text ist kein UTF-8")
	// ErrDomain heißt, die Domänenkennung am Anfang der Bytefolge fehlt.
	ErrDomain = errors.New("protocol: Domänenkennung fehlt")
	// ErrRahmen heißt, die Rahmenfolge eines Segments passt nicht.
	ErrRahmen = errors.New("protocol: Rahmenfolge ungültig")
	// ErrBelegung heißt, Generation, Lage oder Hash der Belegung passen nicht.
	ErrBelegung = errors.New("protocol: Belegung passt nicht")
	// ErrRolle heißt, die Stromrolle oder Personenrolle ist unbekannt.
	ErrRolle = errors.New("protocol: Rolle ungültig")
	// ErrGrund heißt, der Grund eines Auffang-Eintrags ist unbekannt.
	ErrGrund = errors.New("protocol: Grund ungültig")
	// ErrMerkmal heißt, das Ablagemerkmal einer Person ist unbekannt.
	ErrMerkmal = errors.New("protocol: Ablagemerkmal ungültig")
)
