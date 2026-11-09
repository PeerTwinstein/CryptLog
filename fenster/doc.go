// Package fenster ist das Werkzeug auf dem Rechner des Empfängers.
// Es ist kein Dienst und startet keine Prüfung aus einer Konfiguration.
// Pruefen, Zeitraum, Suche, Index, KatalogLesen, Loeschen und VerzeichnisSumme
// bleiben Bibliotheksfunktionen. Das Fenster entsperrt, zählt, zeigt die
// Befunde, signiert die eine Anfrage an den Suchprozess, bestätigt Epochen
// und schreibt die Verzeichnis-Summenepoche.
// Der Klartext der Auswahl bleibt in diesem Fenster und wird mit dem Ende
// der Prüfung verworfen. Eine Passphrase wird nicht abgelegt.
package fenster
