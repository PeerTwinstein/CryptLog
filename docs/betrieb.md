# CryptLog — Betrieb

Stand: 12. November 2026

Teil des [Konzepts Audit-Log-Verschlüsselung](README.md). Dieselbe Fassung des Programms als Betriebssystemdienst, als Container und als Helm-Chart. Bereitschaft, Beenden und die Metriken für Prometheus.

## Programm

Das Programm heißt `cryptlog`. Es hat drei Aufrufe.

| Aufruf | Prozess | Laufzeit |
|---|---|---|
| `schreiben` | Schreibprozess | Dienst, Container, Chart |
| `suchen` | Suchprozess | Dienst, Container, Chart |
| `werkzeug` | Fenster des Empfängers | auf dem Rechner des Empfängers |

`schreiben` und `suchen` sind getrennte Prozesse. Sie teilen sich keinen Adressraum, keinen Spool und kein Secret. Das Werkzeug hält den privaten Schlüssel des Empfängers. Es läuft nicht als Dienst der Plattform, nicht im Image der Plattform und nicht im Chart. Seine Bedienung ist das Fenster unter [Oberfläche des Werkzeugs](ablage-und-lesen.md#oberfläche-des-werkzeugs). Die Sicherheitszone des Suchprozesses steht unter [Suche](ablage-und-lesen.md#suche). Die Grenze der Zusicherung steht unter [Kontrolle des Schreibprozesses](schluessel.md#kontrolle-des-schreibprozesses).

Dienst, Container und Chart starten `schreiben` und `suchen` mit derselben Konfiguration. `werkzeug` starten sie nicht. Schwellen, die der Dienst ablehnt, lehnen auch Container und Chart ab. Die Grenzen stehen bei [Annahme](ablage-und-lesen.md#annahme), [S3](ablage-und-lesen.md#s3) und [Epochen](protokoll.md#epochen).

## Vertrag des Prozesses

Der Prozess forkt nicht. Ein Fork und ein wiederhergestelltes Prozessabbild beginnen eine neue Epoche; ein Abbild, das den bisherigen DEK noch enthält, würde Nonces wiederholen. Das ist unter [Epochen](protokoll.md#epochen) festgelegt. Checkpoint, Restore und ein zweiter Prozess im selben Adressraum sind deshalb keine Betriebsformen. Auf dem Spool einer Instanz schreibt nur diese Instanz.

Geheimnisse kommen als Dateien auf einem tmpfs. Das sind der öffentliche Plattform-KEK, der Cache-Schlüssel des Schreibprozesses, der öffentliche Index-Schlüssel und, nur beim Suchprozess, der private Index-Schlüssel. Der private Schlüssel eines KEK liegt in keiner dieser Dateien. Die Bytes stehen nicht in der Kommandozeile, nicht in der Umgebung und nicht im Image. Ohne lesbaren Plattform-KEK startet `schreiben` nicht. Ohne lesbaren privaten Index-Schlüssel startet `suchen` nicht.

Das geordnete Beenden ist das Signal des Betriebs, das SIGTERM entspricht. Der Schreibprozess schreibt die offenen Abschlüsse zu Ende, schließt die offenen Epochen und beendet sich danach. Neue Ereignisse nimmt er ab diesem Signal nicht mehr an. Er verwirft sie nicht; der Aufrufer behält sie. Ein Absturz, ein OOM-Kill und das Entziehen des Prozesses sind kein geordnetes Beenden. Was noch nicht im Spool stand, bleibt beim Aufrufer. Die nächste Instanz beginnt neue Epochen.

Die Uhr ist UTC. Die Ereignisschnittstelle und die Suchschnittstelle bleiben die des übrigen Konzepts. `schreiben` nimmt Ereignisse als `POST /ereignis` ohne Query an. Der Körper und die Antwort stehen unter [Inhalte](protokoll.md#inhalte). `suchen` nimmt Anfragen als `POST /suche` an. Metriken und Bereitschaft liegen auf einem eigenen Port und nehmen weder Ereignisse noch Suchanfragen an. Der Ereignisport nimmt `/live`, `/ready` und `/metrics` nicht an.

## Konfiguration

`cryptlog schreiben <datei>` startet den Schreibprozess aus einer Datei von Schlüsseln und Werten. Ein Wert mit Leerzeichen am Rand wird abgeschnitten. Zeilen ohne Text und Zeilen, die mit `#` beginnen, bleiben aus. Ein unbekannter Schlüssel oder ein zweiter Wert desselben Schlüssels lehnt den Start ab.

Geheimnisse stehen nicht in dieser Datei. `plattform`, `index` und `signatur` nennen Dateien, ebenso `zugang` und `geheimnis`, wenn das Ziel S3 ist. `plattform` und `index` sind Zertifikate. Der Fingerabdruck, mit dem der Prozess wickelt, ist SHA-256 über das Zertifikat. `signatur` ist der private Integritätsschlüssel als unverschlüsseltes PKCS#8, P-256. Er steht für das HSM. Der private Schlüssel eines KEK liegt in keiner dieser Dateien.

`ziel` ist `platte` oder `s3`. Bei `platte` nennt `wurzel` das Verzeichnis. Bei `s3` nennen `endpunkt`, `bucket` und `region` das Ziel. `ereignis` und `metrik` sind die beiden Adressen und verschieden. `spool` ist das Verzeichnis der Instanz. `instanz` ist ihre Kennung. `mandanten` ist das Verzeichnis der Mandanten. Darunter trägt jeder Mandant seinen Namen als 32 Hexzeichen und darin `lage`, `katalog` und `personen`. Die Datei `ziel` liegt nur, wenn der Mandant vom gemeinsamen Ziel abweicht. `ziel = s3` nennt `endpunkt`, `bucket`, `region`, `zugang` und `geheimnis`. `ziel = platte` nennt `wurzel`. Die Pfade gelten ab dem Mandantenverzeichnis. Der Bucketname `plattform` ist ausgeschlossen. Dasselbe Ziel wie das gemeinsame lehnt der Start ab. Das Chart lässt diese Datei im Anspruch der Mandanten und legt Zugang und Geheimnis nicht in das Secret des Prozesses. `lage` nennt Name, Rahmen, die Ablagen, den KEK, den Prüfschlüssel, `deck` und `cache_seit`. `katalog` nennt je Zeile Rolle, Ablage, Bindung, Kohorte oder `-` und `an` oder `aus`. Eine Person nennt Merkmal, Ablage, Bindung, Kohorte, Gültigkeit und die 64 Byte der Signatur in Hex.

`spool_grenze` und `frist` haben keine Vorgabe. Die übrigen Schwellen beginnen bei den Ausgangswerten und lassen sich mit `puffer`, `puffer_warte`, `segment`, `segment_warte`, `klasse`, `gruppe`, `einzel` und `sonstige` setzen. Eine Schwelle außerhalb der Grenzen lehnt den Start ab. `loesch` ist der Abstand der Löschläufe. `0` lässt sie aus. Ist er größer, nennen `aufbewahrung` die Frist als Vielfaches von 24 Stunden und `vermerke` das Verzeichnis des Bestätigungsspeichers. `version` und `digest` erscheinen nur gemeinsam in `cryptlog_build_info`.

## Bereitschaft

Der Metrikport spricht HTTP. `/live` antwortet, solange der Prozess läuft und das Beenden noch nicht begonnen hat. `/ready` antwortet nur, solange der Prozess Arbeit annehmen kann. Sonst antwortet er mit einem Fehler und einem der Gründe `secret`, `spool` oder `beenden`. Der Grund nennt keinen Mandanten, keine Person und kein Ereignis.

`schreiben` ist bereit, wenn der Plattform-KEK lesbar ist, der Spool beschreibbar und unter seiner Obergrenze ist und kein Beenden läuft. Ein unerreichbares Ziel macht den Prozess nicht unbereit, solange der Spool die Abschlüsse noch aufnimmt. Ist der Spool an der Obergrenze, ist der Prozess nicht bereit und nimmt keine weiteren Ereignisse an. `/live` bleibt in diesem Fall erfolgreich. Ein Neustart wegen eines stehenden Ziels würde den noch nicht festgehaltenen Puffer verwerfen und neue Epochen beginnen, ohne das Ziel zu erreichen.

`suchen` ist bereit, wenn der private Index-Schlüssel lesbar ist und kein Beenden läuft. Eine abgelehnte Anfrage ändert die Bereitschaft nicht.

## Dienst

Der Betriebssystemdienst ist eine Unit unter systemd oder ein Windows-Dienst. Es gibt zwei Units, `cryptlog-schreiben` und `cryptlog-suchen`. Jede Unit startet genau einen Prozess unter einem eigenen Konto. Das Konto hat kein Anmelderecht und keine Administratorrechte. Die Such-Unit und die Schreib-Unit sind nicht dasselbe Konto.

Die Unit übergibt die Pfade der Secret-Dateien und der Konfiguration. Den Spool bindet sie als Verzeichnis, das nur dieses Konto beschreibt. Ein zweiter Start auf denselben Spool unterbleibt, solange der erste Prozess läuft. Nach Prozessende startet die Unit neu. Den Spool löscht sie dabei nicht. Ein Neustart auf demselben Knoten ist dieselbe Instanz und führt angenommene Arbeit im Spool zu Ende, wie unter [Wiederanlauf](ablage-und-lesen.md#wiederanlauf) beschrieben.

Das Stopp-Signal ist das geordnete Beenden. Die Wartezeit der Unit ist mindestens die konfigurierte Segment-Wartezeit plus 30 Sekunden. Kürzer lehnt die Unit den Start ab. Die Standardausgabe ist das technische Log. Personenkennungen, Vorgangsnummern und Ereignisinhalt stehen dort nicht, mit der unter [Freigabe](protokoll.md#freigabe) genannten Ausnahme des Mandantennamens beim Grund `kek_fehlt`.

## Container

Das Image ist ein OCI-Image. Es enthält das Programm und keine Shell, kein Paketverwaltungswerkzeug und kein Secret. Der Prozess läuft mit einer numerischen Benutzerkennung, ohne Anmelderecht, und bindet nur unprivilegierte Ports. Sämtliche Capabilities sind entzogen. Das Wurzeldateisystem ist nur lesbar. Beschreibbar sind der Spool und das tmpfs der Secrets.

Der Spool ist lokal zum Knoten. Er ist nicht das Speicherziel und nicht ein Band, das eine andere Instanz weiterbeschreibt. Ein neuer Pod ist eine neue Instanz. Ereignisse ohne Annahme bleiben beim Aufrufer. Ein Neustart desselben Pods auf demselben Knoten behält den Spool und ist dieselbe Instanz.

Das Image öffnet keinen zweiten Prozess und teilt seinen Adressraum nicht. Der Container spricht die Ereignis- oder die Suchschnittstelle und den Metrikport. `schreiben` und `suchen` sind zwei Images aus demselben Build oder zwei Aufrufe desselben Image. Sie werden nicht als derselbe Container betrieben.

Das Stopp-Signal des Laufzeitsystems ist SIGTERM. Die Frist entspricht der des Dienstes: mindestens die Segment-Wartezeit plus 30 Sekunden.

## Helm-Chart

Das Chart heißt `cryptlog` und rollt die Container aus. Es hat zwei Komponenten, `schreiben` und `suchen`. Jede ist einzeln einschaltbar. Jede Komponente hat ein eigenes Dienstkonto, ein eigenes Deployment und eigene Secrets. Die Komponente `schreiben` bindet den privaten Index-Schlüssel nicht ein. Die Komponente `suchen` bindet den Plattform-KEK und den Cache-Schlüssel nicht ein.

Kubernetes-Secrets liegen am Pod als Dateien im Speicher. Das Chart trägt die Bytes nicht in den Werten und nicht im Image-Tag. Das Image wird über den Digest gebunden. Ein Tag ohne Digest erfüllt die Bindung an Programmcode und Deployment nicht.

Die Pods laufen ohne erweiterte Rechte, ohne Host-Netz, ohne Host-PID und ohne gemeinsamen Prozessnamensraum. Ein flüchtiger Debug-Container und ein zusätzlicher Container im Prozessnamensraum des Pods sind eine Änderung der Laufzeitumgebung. Für jede Epoche, die dabei offen war, gilt die Vertraulichkeitsaussage nicht. Dieselbe Folge hat ein Wechsel des Digest, solange die Epoche offen ist. Ein rollierender Neustart beendet den bisherigen Prozess geordnet; die neue Instanz beginnt neue Epochen.

Die Netzrichtlinie lässt zur Komponente `schreiben` nur die Ereignisschnittstelle von den vorgesehenen Aufrufern zu und den Metrikport nur aus dem genannten Überwachungsnamensraum. Zur Komponente `suchen` lässt sie die Suchschnittstelle nur auf dem vorgesehenen Weg zu und den Metrikport ebenso nur aus diesem Namensraum. Weitere Eingänge hat der Pod nicht.

`suchen` läuft als eine Replica. Sie hält den privaten Index-Schlüssel und ist die Sicherheitszone. Das Suchprotokoll auf ihrer lokalen Platte ist die gemerkte Menge der Signaturen für das Fenster von fünf Minuten. Ein Neustart desselben Pods lädt sie. Ein neuer Pod ist eine neue Zone und hat diese Menge nicht. Eine zweite Replica würde den privaten Index-Schlüssel ein weiteres Mal im Speicher halten. Die signierte Anfrage nennt die Zone; eine Anfrage für die eine ist an der anderen ungültig. Einen gemeinsamen Speicher für das Fenster gibt es nicht. Die Schreib-Replicas sind unabhängige Instanzen mit eigenen Epochen.

Das Speicherlimit liegt über dem Puffer bis zum Fsync und über dem Segmentpuffer. Ein OOM-Kill ist ein Absturz. Die Beendigungsfrist des Pods ist mindestens die Segment-Wartezeit plus 30 Sekunden. Einen kleineren Wert weist das Chart zurück. Die Schwellen aus der Konfiguration prüft das Chart gegen dieselben Unter- und Obergrenzen wie der Prozess.

## Metriken

Der Metrikport gibt unter `/metrics` die Textexposition von Prometheus in der Fassung 0.0.4 aus. Der Prozess schiebt keine Metriken. Zur Exposition gehören die Prozess- und Laufzeitmetriken des Programms. Deren Namen beginnen mit `process_` und `go_`. Sie tragen keine Felder eines Ereignisses.

`cryptlog_build_info` ist ein Gauge mit dem Wert 1. Seine Label sind `version` und `digest`. Weitere Label hat er nicht.

Eine Metrik nennt keine Person, keine Vorgangsnummer, keinen Kohortennamen, keine `event_id`, keine `bind_id`, keinen Ereigniszeitpunkt und keinen Klartext. Ein Label, das ein einzelnes Ereignis setzt, gibt es nicht. Gründe, die nur im Ciphertext stehen, sind keine Label. Das sind `unbekannt`, `aussage_ungueltig`, `ziel_fehlt` und `ohne_bezug`. Das Suchprotokoll steht nicht in den Metriken. Es bleibt in der Sicherheitszone und außerhalb des technischen Logs.

Die Metriken sind eine eigene Freigabe an den Betrieb. Sie erweitern die [sichtbaren Metadaten](protokoll.md#sichtbare-metadaten) der Ablage nicht um die dort ausgeschlossenen Merkmale. Wer den Port lesen kann, sieht die folgenden Reihen und sonst nichts aus dem Prozess.

### Schreibprozess

| Name | Art | Label | Bedeutung |
|---|---|---|---|
| `cryptlog_ready` | Gauge | — | 1, solange `/ready` erfolgreich ist, sonst 0 |
| `cryptlog_events_unaccepted_total` | Zähler | `grund` | Nicht angenommene Ereignisse. `grund` ist `mandant_unbekannt`, `spool` oder `belegung` |
| `cryptlog_kek_fehlt_total` | Zähler | `mandant_id` | Ereignisse, die in die Dead Letter Box gingen, weil kein aktueller Mandanten-KEK lesbar ist. Die Kennung, nicht der Name |
| `cryptlog_target_errors_total` | Zähler | `ziel` | Fehlgeschlagene Schreibversuche am Ziel. `ziel` ist `s3` oder `platte` und nennt den Speicher, der den Fehler gemeldet hat. Ein Mandantenziel zählt mit seiner Art |
| `cryptlog_spool_bytes` | Gauge | — | Belegte Bytes des Spools |
| `cryptlog_spool_limit_bytes` | Gauge | — | Konfigurierte Obergrenze |
| `cryptlog_cache_age_seconds` | Gauge | `mandant_id` | Alter des Cache-Eintrags dieses Mandanten |
| `cryptlog_instance_lease_seconds` | Gauge | — | Verbleibende Frist des Instanzobjekts |
| `cryptlog_accept_seconds` | Histogramm | `ziel` | Dauer von der Entgegennahme bis zur Annahme. `ziel` bleibt die Art des gemeinsamen Ziels |
| `cryptlog_segment_seconds` | Histogramm | `ziel` | Dauer des Segment-Schreibens |
| `cryptlog_events_accepted_total` | Zähler | `mandant_id`, `rolle` | Angenommene Ereignisse |
| `cryptlog_epochs_open` | Gauge | `mandant_id`, `rolle` | Offene Epochen, als Anzahl |

`rolle` ist `gruppe`, `einzel`, `auffang`, `verzeichnis`, `vorgang` oder `katalog`. Die Anzahl offener Einzel-Epochen nennt keine `bind_id`.

`cryptlog_events_accepted_total` und `cryptlog_epochs_open` führt der Prozess für einen Mandanten nur, solange dessen Deckverkehr aus ist. Ist der Deckverkehr an, fehlen beide Reihen dieses Mandanten. Eine Summe über alle Mandanten gibt es daneben nicht. Die Differenz würde die ausgelassene Menge wiederherstellen und den Deckverkehr aufheben. Die Schreibarbeit dieses Mandanten bleibt an den Objekten in den Größenklassen sichtbar, wie unter [Deckverkehr](protokoll.md#deckverkehr) beschrieben. Fehler, Spool, Cache-Alter und Latenzen bleiben auch dann stehen. Sie tragen keine Ereignismenge.

`kek_fehlt` und `mandant_unbekannt` stehen hier, weil das technische Log sie bereits nennt. Der Name des Mandanten bleibt im technischen Log und wird kein Label.

### Suchprozess

| Name | Art | Label | Bedeutung |
|---|---|---|---|
| `cryptlog_ready` | Gauge | — | 1, solange `/ready` erfolgreich ist, sonst 0 |
| `cryptlog_search_requests_total` | Zähler | `ergebnis` | `autorisiert`, `abgelehnt` oder `wiederholt` |
| `cryptlog_search_seconds` | Histogramm | — | Dauer der Anfrage, nachdem sie angenommen wurde |

`abgelehnt` fasst jede fehlende Autorisierung zusammen. `wiederholt` ist eine Signatur, die in ihrem Zeitfenster schon einmal galt. Der Zähler nennt weder Mandant noch Person noch Vorgangsnummer noch die Größe der Antwort. Eine Trefferzahl gibt der Port nicht heraus.
