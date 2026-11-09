package suchen

import "errors"

var (
	// ErrGeheimnis heißt, der private Index-Schlüssel fehlt oder ist unlesbar.
	ErrGeheimnis = errors.New("suchen: privater Index-Schlüssel fehlt")
	// ErrKonfig heißt, Zone, Register oder Protokollpfad fehlen.
	ErrKonfig = errors.New("suchen: Konfiguration passt nicht")
	// ErrBeenden heißt, der Prozess nimmt nichts mehr an.
	ErrBeenden = errors.New("suchen: Prozess nimmt nichts mehr an")
	// ErrAnfrage heißt, Signatur, Aussage oder Mandant autorisieren die Anfrage nicht.
	ErrAnfrage = errors.New("suchen: Anfrage nicht autorisiert")
	// ErrWiederholt heißt, dieselbe Signatur gilt in diesem Fenster schon als verwendet.
	ErrWiederholt = errors.New("suchen: Anfrage schon verwendet")
	// ErrFormat heißt, der Körper ist keine vollständige Anfrage.
	ErrFormat = errors.New("suchen: Anfrage unlesbar")
	// ErrBestand heißt, der Indexstrom des Mandanten fehlt.
	ErrBestand = errors.New("suchen: Indexstrom fehlt")
	// ErrZiel heißt, die gelesene Ablage passt nicht zur Anfrage.
	ErrZiel = errors.New("suchen: Ablage passt nicht")
	// ErrProtokoll heißt, die gesehene Signatur wurde nicht festgehalten.
	ErrProtokoll = errors.New("suchen: Protokoll nicht geschrieben")
	// ErrSumme heißt, die Vorgangssumme lässt sich nicht schreiben.
	ErrSumme = errors.New("suchen: Summe lässt sich nicht schreiben")
)
