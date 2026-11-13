# CryptLog — Aufbau des Programms

Stand: 12. November 2026

Teil des [Konzepts Audit-Log-Verschlüsselung](README.md). Dieses Dokument sagt, welches Paket welchen Teil des Konzepts ausführt. Die Festlegungen selbst stehen in [Protokoll](protokoll.md), [Ablage und Lesen](ablage-und-lesen.md), [Schlüssel](schluessel.md) und [Betrieb](betrieb.md). Die Namen der Ablage stehen im [Glossar](glossar.md).

Das Modul heißt `cryptlog`. `go doc` an einem Paket zeigt die öffentlichen Namen in dem Wortlaut, den der Quelltext darüber setzt.

## Befehl

`cmd/cryptlog` startet den Schreibprozess:

```
cryptlog schreiben <datei>
```

`schreiben.OeffnenDienst` liest die Datei. Geheimnisse stehen in den dort genannten Dateien. `Dienst.Dienen` spricht `POST /ereignis` und den Metrikport, bis das Signal zum Beenden kommt. Danach schreibt der Prozess die offenen Abschlüsse zu Ende.

`cryptlog werkzeug` öffnet das Fenster über `fenster.Neu`. Der Suchprozess startet über `suchen.Start` und bleibt eine Bibliothek. Die Unit, das Image und das Chart aus dem [Betrieb](betrieb.md) liegen in `deploy/systemd`, im `Dockerfile` und in `deploy/cryptlog`.

`cmd/testumgebung` legt eine lokale Umgebung mit Schlüsseln und drei Mandanten an. Die Schritte stehen in der [Testumgebung](testumgebung.md).

## Pakete

Die Abhängigkeit läuft von den Bytefolgen nach außen. `protocol` kennt kein anderes Paket dieses Moduls. `crypt` kennt `protocol`. Darüber bauen Epoche, Strom, Abschluss, Schlüssel, Werkzeug, Schreibprozess, Suchprozess und Fenster.

| Paket | Auftrag |
|---|---|
| `protocol` | Festgelegte Bytefolgen: Kennungen, Hash-Kette, Rahmen, Segmente, Annahme, Bindung, Belegung, Inhalte, Ereignisschnittstelle |
| `crypt` | DEK, AES-256-GCM, Wrap mit RSA-OAEP oder HPKE, Bindungsblob, ECDSA P-256, Zertifikatsfingerabdruck |
| `epoch` | Eine offene Epoche als Segmentfolge. Volle Segmente haben die Klasse, das letzte die kleinste passende Klasse, der Rest sind Füllrahmen |
| `strom` | Ordnet ein Ereignis den Strömen zu und schreibt Log, Verzeichnis und Vorgangsindex in bereits geöffnete Epochen |
| `abschluss` | Baut Belegung, Vorbereitung und Annahme, legt sie ab, hält den Spool und setzt einen Abschluss fort |
| `bestaetigung` | Bestätigungsspeicher beim Empfänger. Eine Fassung je Epoche und Vorgänger, weitere Fassungen bleiben Verzweigungen |
| `schluessel` | Schlüsselspeicher, Veröffentlichung, Verwaltung, Cache und lokale CA |
| `schreiben` | Schreibprozess: Annahme, Spool, S3 oder Platte, Katalog, Löschlauf, Ereignisport, Metrik |
| `suchen` | Sicherheitszone des Vorgangsindex |
| `werkzeug` | Prüfung, Zeitraum, Verzeichnis, Vorgangsindex, Katalog, Summen, Löschen. Öffnet nur die Auswahl |
| `fenster` | Sitzung auf dem Rechner des Empfängers |

## Schreibpfad

`POST /ereignis` ohne Query trägt die Bytefolge aus `protocol.EreignisBytes`. `Prozess.Ereignisport` liest sie und ruft `Prozess.Ereignis`. Die Antwort geht erst hinaus, wenn die Annahme am Ziel liegt. Dieselbe `event_id` mit demselben `event_hash` bestätigt die vorhandene Annahme und schreibt keine zweite Fassung. Ein anderer Hash unter derselben Kennung wird abgelehnt.

`strom.Zuordnen` entscheidet die Ziele. Ist mindestens eine Person einzeln geführt, entstehen nur deren Einzelströme. Bleibt kein beschreibbares Ziel, entsteht genau ein Auffang-Eintrag. Fehlt der Mandant oder der KEK, wickelt `WrapPlattform`. Sonst wickelt `WrapMandant` Log und Verzeichnis; der Vorgangsindex bleibt am Index-Schlüssel.

`strom.Schreiben` hängt die Rahmen an die offenen Epochen aus `epoch`. Der Klartext-DEK lebt in dieser Epoche. `crypt.Seal` verschlüsselt einen Rahmen, `crypt.WrapDEK` wickelt `dek || bind_id` einmal pro Epoche.

Der Puffer geht bei Größe oder Wartezeit in den Spool, Ausgang 1 MiB oder 100 Millisekunden. Der Fsync des Spools ist die lokale Folge, nicht die Annahme. Ist der Spool an der Obergrenze, nimmt der Prozess nichts weiteres an.

Am Ziel schreibt `abschluss.Ablegen` in dieser Reihenfolge: offene Belegung, Vorbereitung, Segmente, erneute Lesung der offenen Belegung, Annahme, bedingter Tausch der Belegung auf angenommen. Dieselben Bytes unter demselben Schlüssel gelten als wiederholtes Schreiben. Ein anderer Inhalt wird nicht ersetzt. `S3.Ersetzen` bindet den Tausch an den vorliegenden Inhalt. `Platte` schließt jedes Schreiben mit Fsync; die Sperre gilt innerhalb dieses Prozesses. `Wahl` leitet einen Segmentsschlüssel an das Ziel aus der Datei `ziel` dieses Mandanten. Fehlt die Datei, bleibt der Schlüssel im gemeinsamen Ziel. `belegt/`, `instanz/`, `vorbereitung/` und `annahme/` bleiben dort. Eine ältere Fassung im gemeinsamen Ziel wird gelesen und gelöscht und nicht kopiert.

Nach der Annahme reicht der Prozess das vom Integritätsschlüssel signierte Manifest beim Empfänger ein, wenn `Konfig.Einreichen` gesetzt ist. Der Löschlauf in `schreiben` ruft `werkzeug.Loeschen`, sobald `loesch` größer als null ist, und legt den Vermerk über `Vermerke` ab.

## Wiederanlauf

`abschluss.Spool` hält die Folgen auf der Platte der Instanz. `Fortsetzen` schreibt einen eigenen Abschluss mit denselben Bytes. `Erkennen` unterscheidet eine leere Stelle, eine vollständige Annahme und eine Annahme, deren Segmenthash abweicht. `FremdeAnnahme` ergänzt die Annahme einer anderen Instanz, wenn Vorbereitung und Segmente passen und die Instanzfrist samt der in `protocol.UhrSchiefe` festgelegten fünf Sekunden abgelaufen ist. Ein abweichender `event_hash` ist `BefundKonflikt`. Eine Belegung derselben Kennung unter anderer Instanz oder anderem Abschluss ist `BefundVerfallen`.

## Schlüssel

`schluessel.Verzeichnis` ist der Speicher des einfachen Modus. `schluessel.Server` veröffentlicht im sicheren Modus und prüft die Signatur unter dem Vertrauensanker. `HTTPQuelle` liest diese Veröffentlichung. `Verwaltung` legt ab und setzt den Status. `Cache` hält die öffentlichen Schlüssel; die Fassung auf der Platte ist mit dem Cache-Schlüssel verschlüsselt. `schreiben.AusCache` legt KEK, Prüfschlüssel und Status über die übrige Lage des Mandanten.

## Suche

`suchen.Start` liest den privaten Index-Schlüssel aus der genannten Datei. `Prozess.Suche` nimmt `POST /suche` an. `Anfrage` prüft die Signatur gegen das Register, merkt sie für das Fenster dieser Replica und ruft danach `werkzeug.Index` nur für diese eine Anfrage auf. Zurück gehen die Treffer. Index-Epochen, Summenepochen und der Klartext eines DEK gehen nicht an den Aufrufer. Das Protokoll der gesehenen Signaturen bleibt in der Zone.

## Werkzeug und Fenster

`werkzeug.Pruefen` gilt eine Epoche. `Zeitraum` gilt die Epochen eines Stroms, deren Raster den Zeitraum schneidet. `Suche` liest das Verzeichnis, für einen abgeschlossenen Monat zuerst die Summenepoche. `Index` beantwortet die Frage des Vorgangsindex. `KatalogLesen` löst einen Namen in die `ablage_id` auf. `Loeschen` setzt den Löschtag, entfernt die Segmente und lässt Annahmen fallen, sobald jede von ihnen genannte Epoche weg ist. Kette, HSM-Signatur und Epochenbestätigung brauchen den DEK nicht.

`fenster.Neu` legt die Sitzung an und entsperrt nichts. `Einfach` nimmt die Passphrase für diese Sitzung, `Sicher` den Träger. `Zaehlen` nennt die Zahl der Epochen, bevor `Pruefung` die Auswahl öffnet. `Ende` überschreibt den Klartext. `Bestaetigen` hängt die Signatur des Empfängers an. `VerzeichnisSumme` schreibt die Summenepoche des Verzeichnisses. `Frage` signiert die eine Anfrage an den Suchprozess. Was das Werkzeug lokal ablegen darf, ist die `Verbindung`: Endpunkt oder Pfad, Mandant, Katalogablage und die Pfade der Schlüsseldateien.
