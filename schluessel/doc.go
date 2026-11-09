// Package schluessel hält die Schlüssel eines Mandanten außerhalb der Logströme.
// Der einfache Modus schreibt in ein Verzeichnis. Der sichere Modus veröffentlicht
// signiert. Die Verwaltung legt ab und setzt den Status. Der Cache des
// Schreibprozesses liest nur die öffentlichen Schlüssel.
package schluessel
