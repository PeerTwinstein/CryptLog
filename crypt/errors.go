package crypt

import "errors"

var (
	// ErrAlgorithm heißt, der Schlüssel ist weder RSA ab 3072 Bit noch P-256.
	ErrAlgorithm = errors.New("crypt: Algorithmus nicht zulässig")
	// ErrKey heißt, der Schlüssel fehlt oder passt nicht zum Verfahren.
	ErrKey = errors.New("crypt: Schlüssel ungültig")
	// ErrPlaintext heißt, der Klartext ist leer oder für diesen Schlüssel zu lang.
	ErrPlaintext = errors.New("crypt: Klartextlänge für diesen Schlüssel nicht zulässig")
	// ErrContext heißt, der Wrap-Kontext fehlt.
	ErrContext = errors.New("crypt: Kontext fehlt")
	// ErrOpen heißt, Unwrap findet keinen Klartext.
	ErrOpen = errors.New("crypt: Öffnen fehlgeschlagen")
	// ErrTag heißt, der GCM-Tag hat nicht 16 Byte.
	ErrTag = errors.New("crypt: Tag hat nicht 16 Byte")
)
