// Package suchen ist der Suchprozess und damit die Sicherheitszone des Vorgangsindex.
// Eine Replica hält den privaten Index-Schlüssel. Die signierte Anfrage nennt diese
// Zone. Er liest die Zugehörigkeitsaussage aus dem Register und öffnet danach nur
// den Index dieser einen Anfrage.
// Eine vom Aufrufer vorgelegte Abschrift ersetzt das Register nicht.
// Der Prozess startet keine Shell und hat keine Administrationsschnittstelle.
// Index-Epochen, Summenepochen und der Klartext eines DEK gehen nicht an den Aufrufer.
// Das Protokoll bleibt in der Zone und steht nicht im technischen Log.
package suchen
