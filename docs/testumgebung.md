# CryptLog — Testumgebung

Stand: 12. November 2026

Anleitung zum Ausprobieren. Die Festlegung bleibt in den übrigen Dokumenten, beginnend bei [README.md](README.md). Namen wie Epoche und KEK stehen im [Glossar](glossar.md). Der Befehl liegt in `cmd/testumgebung`. Er legt Schlüssel, drei Mandanten und die Verbindung des Werkzeugs lokal an. Das Verzeichnis `testumgebung/` ist von der Versionsverwaltung ausgenommen.

Die angelegte Umgebung schreibt auf die Platte. Einen S3-Speicher stellt man selbst und stellt das Ziel danach um. Das steht unter [Eigenes S3](#eigenes-s3).

## Anlegen

Im Modulverzeichnis:

```
go run ./cmd/testumgebung -aus testumgebung -pruefen
```

Das Modul verlangt Go 1.26. `-aus` nennt das Verzeichnis. Ohne die Angabe entsteht `testumgebung` im Arbeitsverzeichnis. Liegt dort schon etwas, bricht der Befehl ab. `-ersetzen` löscht es und legt es neu an, sobald darin eine Datei `konfig` liegt.

`-pruefen` nimmt nach dem Anlegen je eine Probe an und beendet den Schreibprozess wieder. Die Proben liegen danach unter `ziel/`. Die Adressen `127.0.0.1:8787` und `127.0.0.1:8788` hört dieser Lauf nicht ab. Er spricht die Schnittstelle im Prozess.

Der Befehl druckt die Passphrase, den Startaufruf und je Probe Mandant, Person und Vorgang. Dieselbe Passphrase steht in der Datei `passphrase`, eine Zeile, und in `stand`. Sie öffnet den KEK, den Bestätigungsschlüssel und den Aufrufschlüssel. Die Argon2id-Kosten dieser Umgebung sind ein Durchgang, 8 KiB und ein Thread, damit das Öffnen hier leicht bleibt.

`-ergaenzen` zieht an einer schon liegenden Umgebung die öffentlichen Schlüssel und den Bestätigungsspeicher nach. Ein frisch angelegtes Verzeichnis hat diese Dateien bereits.

## Was liegt wo

| Pfad | Inhalt |
|---|---|
| `stand` | Passphrase, Adressen, Instanz, Zone, Fingerabdrücke, je Mandant die Kennungen und die Personen |
| `passphrase` | dieselbe Passphrase, eine Zeile |
| `konfig` | Aufruf des Schreibprozesses. Pfade darin gelten ab diesem Verzeichnis |
| `schluessel/ca.pem` | Zertifikat der lokalen CA `CryptLog-Test`, zehn Jahre gültig |
| `schluessel/<Name>/pruef.pem` | privater Prüfschlüssel des Mandanten |
| `geheim/plattform.pem` | Zertifikat des Plattform-KEK |
| `geheim/index.pem` | Zertifikat des Index-Schlüssels |
| `geheim/index-privat.pem` | privater Index-Schlüssel. `schreiben` bindet ihn nicht ein |
| `geheim/signatur.pem` | privater Integritätsschlüssel, unverschlüsseltes PKCS#8, P-256 |
| `geheim/hsm.pem` | dazu der öffentliche Schlüssel |
| `mandanten/<id>/` | öffentlicher KEK, Prüfzertifikat, `lage`, `katalog`, `personen`. Daraus liest der Schreibprozess |
| `empfaenger/<Name>/` | verschlüsselte private Schlüssel und die Datei `verbindung` |
| `ziel/` | Ablage auf der Platte, sobald geschrieben wurde |
| `spool/` | lokaler Spool der Instanz, sobald `schreiben` läuft |
| `bestaetigung/` | Bestätigungsspeicher. `konfig` nennt ihn als `vermerke` |

Drei Mandanten, dazu der Empfänger der Plattform. Der Modus ist der einfache: der private KEK liegt verschlüsselt neben dem Zertifikat der lokalen CA.

| Mandant | Personen |
|---|---|
| Nordlicht | Ada und Bea in der Kohorte Nord, Cleo als Datenschützerin |
| Suedwerk | Dora in der Kohorte Sued, Emil einzeln, Frieda als Datenschützerin |
| Osthafen | Gerd in der Kohorte Ost, Hilde als Datenschützerin |

Die Kennungen stehen in `stand`. Die Datenschützerin trägt den Aufrufschlüssel. Seine Datei heißt `empfaenger/<Name>/aufruf.pk8`.

`-pruefen` nimmt diese Ereignisse an. Der Logtext ist `Probe`.

| Mandant | Person | Vorgang |
|---|---|---|
| Nordlicht | Ada | V-Ada |
| Suedwerk | Dora | V-Dora |
| Suedwerk | Emil | V-Emil |
| Osthafen | Gerd | V-Gerd |

## Schreibprozess

```
go run ./cmd/cryptlog schreiben testumgebung/konfig
```

Der Prozess hört `127.0.0.1:8787` für `POST /ereignis` und `127.0.0.1:8788` für `/live`, `/ready` und `/metrics`. Der Körper von `/ereignis` ist die Bytefolge aus `protocol.EreignisBytes`. Die Antwort kommt, wenn die Annahme am Ziel liegt.

Die Schwellen in `konfig` liegen unter den Ausgangswerten des Betriebs: Spool 16 MiB, Instanzfrist 15 Minuten, Pufferwarte 20 Millisekunden, Segment und Klasse 256 KiB, Segmentwarte 10 Sekunden. Gruppen-, Einzel- und sonstige Epochen bleiben bei 60 Minuten, 8 Stunden und 60 Minuten. Ein Strg+C beendet den Prozess geordnet und schreibt die offenen Abschlüsse zu Ende.

## Werkzeug

Für Nordlicht, im zweiten Fenster:

```
go run ./cmd/cryptlog werkzeug testumgebung/empfaenger/Nordlicht/verbindung
```

Dieselbe Datei liegt für Suedwerk, Osthafen und `plattform`. Die Datei entsperrt nichts. Im Fenster stehen Mandant, Ziel, Modus und der Fingerabdruck. Der Status bleibt `aktuell`. Prüfschlüssel, öffentlicher HSM-Schlüssel und der öffentliche Bestätigungsschlüssel sind aus dem Verzeichnis des Zertifikats gefüllt. Der Bestätigungsspeicher steht auf `bestaetigung` neben `ziel`.

Die Passphrase aus `passphrase` eintragen und **Entsperren**. Danach:

1. Art **Gruppe**, Kohorte `Nord`, der voreingestellte Zeitraum umfasst den heutigen Tag.
2. **Zählen**, dann **Prüfen**. Die Probe von Ada liegt in dieser Kohorte, Vorgang `V-Ada`, Text `Probe`.
3. Dieselbe Passphrase unter **Bestätigen**, dann **Epochen bestätigen**. Die Prüfung danach erneut öffnen. Die Bestätigung liegt in `bestaetigung/`.
4. **Prüfung beenden** verwirft den Klartext. **Sitzung schließen** gibt die Schlüssel frei.

Suedwerk liest Dora über die Kohorte `Sued` und Emil über den Einzelstrom. Osthafen liest Gerd über die Kohorte `Ost`. Der Plattform-Empfänger öffnet den Plattform-Auffang. Die drei Proben der Mandanten liegen dort nicht.

Die Summenepoche schreibt das Fenster für einen abgeschlossenen Monat. Dafür steht vor dem Entsperren die Instanz aus `stand` im Feld **Instanz**. Die Handlung verlangt außerdem die Datei `geheim/signatur.pem`. Ein Lauf vom selben Tag hat Epochen im laufenden Monat. Der Vormonat, den das Feld **Monat** anbietet, enthält dann noch keine.

Die Frage an den Suchprozess steht im selben Fenster. Diesen Prozess startet `cryptlog` in diesem Baum nicht. `suchen.Start` bleibt eine Bibliothek. Die Suchadresse trägt man vor dem Entsperren ein. Den Aufrufschlüssel entsperrt die Datenschützerin mit derselben Passphrase: Cleo, Frieda oder Hilde.

## Eigenes S3

Der Befehl legt keinen Bucket an. Der Speicher ist ein S3-kompatibler Endpunkt, den man selbst betreibt. Ein Schreibprozess hat ein Ziel. Die drei Mandanten und der Plattform-Auffang liegen in demselben Bucket. Der Objektschlüssel beginnt mit der Mandantenkennung.

Der Endpunkt ist `http` oder `https`, mit Host und ohne Pfad. Der Zugriff läuft im Pfadstil: der Bucket steht im Pfad, nicht im Host. Der Bucketname enthält keinen Schrägstrich.

Zugang und Geheimnis stehen in zwei Dateien, nicht in `konfig`. Eine Zeile je Datei, abgelegt zum Beispiel als `geheim/zugang` und `geheim/geheimnis`, Rechte nur für den Aufrufer.

In `konfig` fällt die Zeile `wurzel`. Dafür stehen:

```
ziel = s3
endpunkt = https://s3.example
bucket = cryptlog-probe
region = eu-central-1
zugang = geheim/zugang
geheimnis = geheim/geheimnis
```

Die übrigen Zeilen bleiben. `vermerke` bleibt das lokale Verzeichnis `bestaetigung`. Der Bestätigungsspeicher liegt nicht im Bucket.

In jeder Datei `empfaenger/<Name>/verbindung` wird das Ziel umgestellt. `mandant`, `zone`, `katalog` und die Schlüsselpfade bleiben. `pfad` bleibt leer.

```
ziel=s3
endpunkt=https://s3.example
bucket=cryptlog-probe
pfad=
```

Region, Zugang und Geheimnis trägt man im Fenster ein, vor dem Entsperren. Die Verbindung speichert sie nicht. Das Geheimnis bleibt in der Sitzung. Den Bestätigungsspeicher füllt das Fenster bei einem S3-Ziel nicht von selbst. Dort steht der Pfad des Verzeichnisses `bestaetigung` dieser Umgebung.

Die Proben aus `-pruefen` liegen im Verzeichnis `ziel`, weil der Befehl sie gegen die gerade geschriebene Plattenkonfiguration annimmt. Im Bucket liegen sie damit nicht. Für den Bucket `konfig` und die Verbindungen umstellen, `schreiben` starten und die Ereignisse an `POST /ereignis` senden.

## Eigenes Ziel eines Mandanten

Die Datei `ziel` im Verzeichnis des Mandanten nennt ein abweichendes Ziel. Fehlt sie, bleibt der Mandant im Ziel aus `konfig`.

```
ziel = s3
endpunkt = https://s3.mandant.example
bucket = mandant-logs
region = eu-central-1
zugang = zugang
geheimnis = geheimnis
```

`zugang` und `geheimnis` liegen im Mandantenverzeichnis. Der Bucketname `plattform` ist ausgeschlossen. Endpunkt und Bucket des gemeinsamen Ziels lehnt der Start ab. `ziel = platte` nennt stattdessen `wurzel`.

Die Verbindung des Empfängers nennt dieses Ziel. Segmente, die schon im gemeinsamen Ziel liegen, bleiben dort, bis ihre Epoche gelöscht wird. Dieselben Bytes schreibt der Prozess nicht ein zweites Mal. Belegung, Instanzobjekt, Vorbereitung und Annahme bleiben im gemeinsamen Ziel.
