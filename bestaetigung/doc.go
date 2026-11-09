// Package bestaetigung ist der Bestätigungsspeicher beim Empfänger.
// Er liegt außerhalb des Schreibpfads und außerhalb des Log-Buckets.
// Ein Eintrag wird angehängt und bleibt stehen.
// Je Epoche und je Vorgänger bleibt eine Fassung der Abschluss.
// Eine weitere Fassung mit gültiger HSM-Signatur bleibt als Verzweigung.
// Die Signatur des Empfängers und der Löschvermerk hängen daneben.
package bestaetigung
