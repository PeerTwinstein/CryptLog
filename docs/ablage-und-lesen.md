# CryptLog — Ablage und Lesen

Stand: 12. November 2026

Teil des [Konzepts Audit-Log-Verschlüsselung](README.md). Speicherziel, Wiederanlauf, Löschen, Suche, Prüfung, Verzeichnis, Vorgangsindex, Summenindex, Entschlüsselung und die Oberfläche des Werkzeugs. Die kurzen Namen stehen im [Glossar](glossar.md).

## Speicherziel

Verschlüsselte Ströme liegen vorrangig in einem S3-kompatiblen Objektspeicher. Dieselbe Ablage kann stattdessen auf der Platte liegen. Das gemeinsame Ziel gilt für jeden Mandanten, dessen Lage kein eigenes Ziel nennt. Voreinstellung ist S3. Was Bucketname und `mandant_id` sichtbar machen, steht unter [Sichtbare Metadaten](protokoll.md#sichtbare-metadaten). Der Bucket `plattform` ist reserviert und gehört zu keinem Mandanten. Ein Mandantenziel trägt diesen Namen nicht.

Ein eigenes Ziel steht in der Datei `ziel` der Lage. Bei S3 nennt sie Endpunkt, Bucket, Region, Zugang und Geheimnis. Bei der Platte nennt sie die Wurzel. Zugang und Geheimnis sind Dateien und stehen nicht in der Lage. Dasselbe Ziel wie das gemeinsame lehnt der Start ab.

Segmente dieses Mandanten liegen in seinem Ziel. Dazu gehört die Dead Letter Box bei fehlendem Mandanten-KEK, gewrappt mit dem Plattform-KEK. Der Objektschlüssel bleibt `{mandant_id}/{ablage_id}/{epoch_id}/{segment_nr}`. Belegung, Instanzobjekt, Vorbereitung und Annahme bleiben im gemeinsamen Ziel. Ein Abschluss kann Segmente mehrerer Mandanten nennen. Diese Objekte gehören zur Instanz.

Ein Segment, das vor dem eigenen Ziel schon im gemeinsamen Ziel liegt, bleibt dort. Derselbe Inhalt unter demselben Schlüssel ist ein wiederholtes Schreiben und wird nicht kopiert. Ein anderer Inhalt wird nicht ersetzt. Lesen und Löschen suchen das Segment im eigenen Ziel und danach im gemeinsamen Ziel. Das Werkzeug nennt in der Verbindung das Ziel, dessen Segmente es öffnet. Der Suchprozess liest und schreibt die Indexsegmente über dieselbe Verteilung.

Der Dienst verschlüsselt jeden Eintrag, bevor er ihn weitergibt. Im Puffer, im Spool und in den Segmenten steht nur Ciphertext. Belegung, Vorbereitung und Annahme nennen keine Person, keine Vorgangsnummer und keinen Logtext. Die Schreibschwellen verlängern den Klartext-DEK nicht. Er bleibt an die Epoche gebunden und wird mit ihrem Ende verworfen.

### Annahme

Der Dienst bestätigt ein Ereignis erst, wenn dessen Belegung am Ziel auf angenommen steht. Die Annahme ist ein einzelnes Objekt je Gruppenabschluss. Sie nennt jede `event_id` dieses Abschlusses und dazu die Stelle des Logeintrags, die Stellen der Verzeichnisverweise und die Stellen der Vorgangsindexeinträge. S3 schreibt ein Objekt atomar und bietet keine Transaktion über mehrere Objekte. Mehrere Dateien auf der Platte sind ebenfalls keine gemeinsame Transaktion. Das Annahmeobjekt wird zuerst geschrieben. Die Entscheidung für eine `event_id` ist danach der bedingte Tausch ihrer Belegung von offen auf angenommen. Vor diesem Tausch ist das Ereignis nicht angenommen, auch wenn Log, Verzeichnis, Vorgangsindex oder das Annahmeobjekt schon am Ziel liegen. Die Antwort an den Aufrufer geht erst nach dem Tausch hinaus. Schlägt er fehl, bleibt das Ereignis beim Aufrufer.

Bis dahin bleiben drei Stufen auseinander.

**Im Speicher.** Der verschlüsselte Eintrag, seine Verweise und die Indexeinträge liegen nur im Speicher der Instanz. Ein Absturz verliert sie. Der Aufrufer behält das Ereignis.

**Lokal festgehalten.** Der Abschluss hängt die noch offenen Ereignisse an den lokalen Spool und schließt diesen Schreibvorgang mit einem Fsync ab. Danach kann dieselbe Instanz den Abschluss nach einem Prozessabsturz auf diesem Knoten fortsetzen. Der Seitencache ohne Fsync gilt nicht als lokal festgehalten. Der Fsync ist die lokale Persistenz des Knotens. Er ist nicht die Annahme. Der Verlust des Knotens nimmt den Spool mit. Eine Antwort an den Aufrufer gibt es an dieser Stelle nicht.

**Angenommen.** Die Instanz schreibt die Bestandteile am Ziel, prüft ihre Hashes und schreibt danach das Annahmeobjekt. Erst wenn dieses Objekt am Ziel dauerhaft ist, gelten die darin genannten Ereignisse als angenommen, und erst dann antwortet der Dienst dem Aufrufer. Das Ziel überdauert den schreibenden Knoten. Im gemeinsamen S3-Ziel ist das der Bucket der Annahme. Segmente eines eigenen Mandantenziels überdauern in diesem Ziel. Auf der Platte ist das ein Speicher außerhalb der lokalen Platte des Schreibprozesses. Ein Fsync auf dieser lokalen Platte bleibt der Spool.

Der Abschluss tritt ein, sobald der noch nicht abgeschlossene Puffer eine Grenze erreicht:

| Schwelle | Ausgang | Untergrenze | Obergrenze |
|---|---|---|---|
| Datengröße | 1 MiB | 64 KiB | 8 MiB |
| Wartezeit | 100 Millisekunden | 10 Millisekunden | 1 Sekunde |

Werte außerhalb dieser Grenzen lehnt der Dienst ab. Ein Abschluss umfasst Logeintrag, Verzeichnis und Vorgangsindex. Viele offene Ströme teilen sich diesen einen Abschluss. Ein Fsync je Datei und ein Fsync je Eintrag finden dabei nicht statt. Ein Ereignis ohne Person und ohne Vorgangsnummer hat keine Verweise und keinen Indexeintrag; die Annahme nennt dann nur den Logeintrag. Fehlt ein erforderlicher Bestandteil, entsteht für dieses Ereignis keine Annahme.

Ein Abschluss ist eine Einheit. Die Annahme nennt jedes in ihn aufgenommene Ereignis mit allen erforderlichen Bestandteilen. Ein Ereignis, dessen Belegung schon eine andere Annahme oder einen anderen `event_hash` zeigt, kommt nicht hinein. Die übrigen Ereignisse des Puffers können abgeschlossen werden.

Ein Absturz vor dem Fsync verliert den Puffer. Diese Ereignisse waren nicht angenommen, der Aufrufer behält sie. Nach dem Fsync steht der Abschluss im Spool, bis die Annahme am Ziel dauerhaft ist. Kommt die Antwort danach nicht an, sendet der Aufrufer dieselbe `event_id` erneut. Der Dienst bestätigt die vorhandene Annahme und schreibt keine zweite Fassung in die Kette.

Der Spool ist der Wiederanlaufpuffer vor dem Segment. Sein Anteil wird gelöscht, sobald das Annahmeobjekt dieses Abschlusses am Ziel dauerhaft ist. Die Hashes der Annahmen behält die Instanz, bis das HSM-signierte Manifest, das sie einschließt, am Ziel dauerhaft ist. Wächst der Spool über seine konfigurierte Obergrenze, weil das Ziel nicht nachkommt, nimmt der Dienst keine weiteren Ereignisse an. Einträge werden nicht still verworfen.

Beide Ziele verwenden dieselben Segmente. Ein Segment ist eine unveränderliche Folge bereits verschlüsselter Rahmen einer Epoche. Kopf, Manifest, Füllung und Objektschlüssel stehen unter [Sichtbare Metadaten](protokoll.md#sichtbare-metadaten). Der Epochenkopf nennt den Fingerabdruck des KEK im Klartext, sodass das Werkzeug Epochen des Mandanten-KEK und Epochen des Plattform-KEK unterscheidet, ohne Einträge zu öffnen.

Ein geschriebenes Segment wird nicht ersetzt. Ein wiederholtes Schreiben derselben Bytes unter demselben Schlüssel lässt das Objekt unverändert. Ein anderer Inhalt unter demselben Schlüssel wird abgelehnt. Das Werkzeug liest die von der Annahme genannten Segmente nach Segmentnummer, setzt die Hash-Kette darüber und prüft sie gegen das Manifest und die Epochenbestätigung des Empfängers. Eine Lücke in der angenommenen Segmentnummer ist dieselbe Feststellung wie ein fehlendes Glied der Kette. Ein Objekt, das keine Annahme nennt, ist unvollständiger Rest und keine Lücke. Eine Epoche mit Löschvermerk oder ab ihrem Zugriffsschnitt ist gelöscht, auch wenn einzelne Segmente noch vorliegen. Die Epochenbestätigung bleibt. Fehlen einzelne Segmente vor dem Zugriffsschnitt und ohne Löschvermerk, ist das eine Lücke. Beides steht unter [Löschen](#löschen).

### S3

Ein Eintrag wird nicht als eigenes Objekt geschrieben. Angenommen ist er mit dem Annahmeobjekt im gemeinsamen Ziel. Das Segment liegt im Ziel des Mandanten. Aus dem Spool wird ein Segment hochgeladen, sobald eine der Bedingungen eintritt:

- die konfigurierte Datengröße der noch nicht hochgeladenen Einträge ist erreicht
- die konfigurierte Wartezeit seit dem ältesten noch nicht hochgeladenen Eintrag ist abgelaufen
- die Epoche endet, einschließlich Rest und Epochenmanifest
- der Schreibprozess wird geordnet beendet

| Schwelle | Ausgang | Untergrenze | Obergrenze |
|---|---|---|---|
| Datengröße | 4 MiB | 256 KiB | 32 MiB |
| Wartezeit | 60 Sekunden | 10 Sekunden | 5 Minuten |

Werte außerhalb dieser Grenzen lehnt der Dienst ab.

Schlägt das PUT fehl, wiederholt der Dienst dieselben Bytes unter demselben Schlüssel. Ein Segment ohne zugehöriges Annahmeobjekt ist unvollständiger Rest und kein Glied der Kette. Der Spool-Anteil wird gelöscht, sobald die Annahme dieses Abschlusses dauerhaft ist. Der Spool ist Übertragungsspeicher des S3-Ziels, kein zweites Archiv. Das erfolgreiche PUT eines Segments ist nicht die Annahme.

### Platte

Ist das Ziel die Platte, bleiben die Segmente im Ordner des Stroms. Es gibt keinen Upload. Angenommen ist ein Ereignis mit demselben Annahmeobjekt wie beim S3-Ziel. Die Schwellen für den Upload gelten hier für den Schnitt des Segments: Datengröße, Wartezeit, Epochenende und das geordnete Beenden. Der Dienst schreibt die Segmente und schließt jede Datei mit Fsync ab, schreibt danach das Annahmeobjekt und schließt auch dieses mit Fsync ab. Dieser letzte Fsync ist die Annahme, sofern der Zielspeicher den schreibenden Knoten überdauert. Der Fsync des lokalen Spools bleibt davon getrennt. Schlägt das Schreiben fehl, bleibt der Anteil im Spool. Neue Ereignisse nimmt der Dienst nicht an, sobald der Spool seine Obergrenze erreicht. Ein bereits angenommenes Ereignis wird dadurch nicht zurückgenommen.

## Wiederanlauf

S3 schreibt ein Objekt atomar und führt keine Transaktion über Log, Verzeichnis und Vorgangsindex. Dieselbe Grenze gilt für mehrere Dateien auf der Platte. Ein Gruppenabschluss bleibt deshalb eine Vorbereitung, bis das Annahmeobjekt die Entscheidung festhält. Der Wiederanlauf setzt Teilfehler fort und erkennt, was unvollständig geblieben ist.

### Ereignis-ID

Jedes Audit-Ereignis trägt eine `event_id` von 16 Byte. Der Aufrufer erzeugt sie zufällig und sendet bei jeder Wiederholung dieselben Bytes. Sie wird nicht aus der Personenkennung und nicht aus der Vorgangsnummer abgeleitet. Dieselbe `event_id` steht im Klartext des Logeintrags, jedes Verzeichnisverweises und jedes Vorgangsindexeintrags.

`event_hash` bindet diese Kennung an den Aufruf:

```
event_hash = SHA-256(
    L("event") || "event" ||
    mandant_id ||
    event_id ||
    L(aufruf) || aufruf)
```

Ist kein Mandant ermittelt, steht als `mandant_id` die Kennung der Plattform. `aufruf` ist unter [Inhalte](protokoll.md#inhalte) festgelegt. Die Klartexte von Log, Verzeichnis und Index tragen dieselbe `event_id` und gehen nicht in diesen Hash ein. Dieselben Aufrufbytes ergeben denselben `event_hash`. Ein zweites Senden mit derselben `event_id` und einem anderen Aufruf wird abgelehnt. Es entsteht kein weiterer Eintrag. Der Aufbau der Rahmen steht unter [Rahmen und Größenklassen](protokoll.md#rahmen-und-größenklassen).

### Belegung

Bevor Nutzbytes eines Abschlusses am Ziel entstehen, belegt der Dienst jede `event_id` dieses Abschlusses. Die Belegung ist das eine Objekt, an dem die Annahme einer `event_id` entschieden wird. Es nennt `event_id`, `instanz_id`, `batch_id`, die Generation, die Lage und den `event_hash`. Es nennt keine Person, keine Vorgangsnummer und keinen Logtext. Der Schlüssel ist `belegt/{event_id}`. `event_id` steht dort als 32 Hexzeichen in Kleinbuchstaben. Die Generation ist eine vorzeichenlose 64-Bit-Zahl und beginnt bei 1. Die Lage ist ein Byte: `offen` = 1, `angenommen` = 2.

```
belegung =
    L("belegung") || "belegung" ||
    event_id ||
    instanz_id ||
    batch_id ||
    generation ||
    lage ||
    event_hash
```

Die Belegung entsteht nur, wenn für diese `event_id` noch keine vorliegt. Das Anlegen gelingt nur, wenn der Schlüssel fehlt. Liegt sie vor und der `event_hash` stimmt überein, führt der Dienst eine offene Generation derselben Instanz weiter oder antwortet, wenn die Lage `angenommen` ist und die Annahme dieser Generation vorliegt. Liegt sie vor und der `event_hash` weicht ab, lehnt er das Senden ab und schreibt nichts. Eine Generation mit der Lage `angenommen` wird nicht ersetzt und nicht erhöht.

Jedes Ziel muss dafür zwei bedingte Schreibzugriffe bieten. Anlegen gelingt nur, wenn das Objekt fehlt. Ersetzen gelingt nur über die Bytes, die der Schreiber gerade gelesen hat. Im S3-Ziel ist das `If-None-Match: *` und `If-Match` auf das ETag dieser Bytes. Auf der Platte hält jeder Schreiber für die Dauer von Lesen und Schreiben eine exklusive Sperre der Zieldatei `.sperre`, über Prozessgrenzen. Die Sperre innerhalb eines Prozesses allein erfüllt das nicht. Ein Schreiber, der diese Zugriffe nicht verwendet, ist kein Ziel.

Jede schreibende Instanz erneuert ein Objekt `instanz/{instanz_hex}` mit einer Frist, solange sie läuft. `instanz_hex` sind die 32 Hexzeichen der `instanz_id`. Die Frist ist länger als die Segment-Wartezeit, damit ein lebender Schreiber die offene Generation nicht verliert, während ein Segment entsteht.

```
instanz =
    L("instanz") || "instanz" ||
    instanz_id ||
    frist
```

`frist` ist die Unix-Zeit in Millisekunden, zu der die Frist endet. Die Uhren der Instanzen liegen höchstens fünf Sekunden auseinander; sie laufen über NTP. Die Inhaberin führt eine passende offene Belegung unter derselben Generation weiter und schreibt die Frist neu. Sie setzt die Generation dabei nicht hoch. Eine andere Instanz setzt die Generation nur hoch, wenn die Lage `offen` ist und das Instanzobjekt fehlt oder `jetzt` mindestens `frist` plus fünf Sekunden erreicht. Der Tausch ersetzt die vorliegenden offenen Bytes. `event_id` und `event_hash` bleiben, die neue Lage ist `offen`. Eine angenommene Generation hat keinen Nachfolger. Ein Stillstand, der länger dauert als die Frist samt dieser Schiefe, ist ein Ausfall: die übernehmende Instanz gewinnt den Tausch, die zurückkehrende bestätigt diese Generation nicht mehr.

### Vorbereitung und Annahme

Ein Gruppenabschluss erhält eine `batch_id` von 16 Byte und eine `batch_seq`. Beides steht im Spool, bevor etwas ans Ziel geht. `batch_seq` beginnt bei 1 und steigt je Abschluss dieser Instanz um 1. Sie wird nicht erneut vergeben und nicht übersprungen.

Die Vorbereitung ist das Objekt `vorbereitung/{instanz_hex}/{batch_seq}`. Die Annahme ist das Objekt `annahme/{instanz_hex}/{batch_seq}`. `instanz_hex` sind die 32 Hexzeichen der `instanz_id`. `batch_seq` steht dezimal ohne führende Nullen.

Die Kodierung folgt der [Verkettung](protokoll.md#verkettung). `batch_id` ist 16 Byte und hat kein Längenfeld. Die erste Annahme einer Instanz setzt `previous_annahme_hash` auf

```
annahme_genesis = SHA-256(
    L("annahme-genesis") || "annahme-genesis" ||
    instanz_id)
```

Jede folgende Annahme setzt ihn auf den `annahme_hash` der vorigen `batch_seq`.

```
annahme_payload =
    L("annahme") || "annahme" ||
    batch_id ||
    instanz_id ||
    batch_seq ||
    previous_annahme_hash ||
    slot_count ||
    slot … ||
    segment_count ||
    segment_ref … ||
    blob_count ||
    blob …

annahme_hash = SHA-256(
    L("annahme-hash") || "annahme-hash" ||
    annahme_payload)
```

`slot_count`, `segment_count` und `blob_count` sind vorzeichenlose 64-Bit-Zahlen. `slot` steht `slot_count`-mal. `segment_ref` steht `segment_count`-mal. `blob` steht `blob_count`-mal. `slot_count` ist die unter [Sichtbare Metadaten](protokoll.md#sichtbare-metadaten) festgelegte Zweierpotenz.

```
slot = event_id || event_hash

segment_ref =
    L(objekt_schluessel) || objekt_schluessel ||
    segment_hash

blob = mandant_id
    || L(wrapped_schluessel) || wrapped_schluessel
    || bindung_nonce
    || L(bindung_ciphertext) || bindung_ciphertext
    || bindung_tag
```

`segment_hash` ist SHA-256 über die vollständigen Segmentbytes. `bindung_nonce` ist 12 Byte, `bindung_tag` ist 16 Byte. Beide haben kein Längenfeld.

`wrapped_schluessel` entsteht mit denselben Algorithmen wie der DEK-Wrap. Der Klartext sind die 48 Byte `bindungsschluessel || batch_id`. Der Kontext ist `bindung_ctx`. Der Bindungsschlüssel ist 32 Byte aus einem kryptografischen Zufallszahlengenerator. Er verschlüsselt den Klartext `bindung` einmal mit AES-256-GCM. Die Nonce dieses einen Aufrufs ist `bindung_nonce`. Die Zusatzdaten sind `bindung_aad`. Danach steht der Schlüssel nur noch gewrappt im Blob. Der Klartext wird nicht persistiert, nicht geloggt und nicht für einen zweiten Klartext verwendet. Ein wiederholtes Schreiben sendet dieselben Bytes.

```
bindung_ctx = L("annahme-bindung") || "annahme-bindung"
           || mandant_id
           || batch_id
           || kek_fingerabdruck

bindung_aad = L("bindung-aad") || "bindung-aad"
           || mandant_id
           || batch_id
           || kek_fingerabdruck

bindung =
    L("bindung") || "bindung" ||
    batch_id ||
    seq_count ||
    seq_eintrag …

seq_eintrag = seq || art || event_id
```

`art` ist ein Byte: `ereignis` = 1, `fortsetzung` = 2, `fuellung` = 3. `event_id` ist bei `ereignis` die des Ereignisses und sonst 16 Nullbytes. `seq_count` ist eine vorzeichenlose 64-Bit-Zahl. Ein Blob gehört zu dem Schlüssel, der die Epochen dieses Anteils wrappt. Ein Abschluss, der Anteile unter dem Mandanten-KEK und unter dem Plattform-KEK enthält, trägt zwei Blobs. Die Vorbereitung trägt dieselbe Nutzlast unter der Domänenkennung `vorbereitung` und ohne `previous_annahme_hash`.

Das Werkzeug öffnet `wrapped_schluessel` und prüft, dass die 16 Byte hinter dem Bindungsschlüssel die `batch_id` der Annahme sind. Es öffnet `bindung` mit `bindung_nonce`, `bindung_tag` und `bindung_aad`. Die `batch_id` im Klartext ist dieselbe. Sequenz, Art und `event_id` stehen nur dort.

Die Instanz schreibt zuerst die offenen Belegungen, dann die Vorbereitung, dann die Segmente. Sie prüft, dass jedes genannte Segment vorhanden ist und denselben Hash trägt und dass jede Belegung noch die offenen Bytes dieser Generation trägt. Dann schreibt sie das Annahmeobjekt. Danach tauscht sie jede Belegung bedingt von diesen offenen Bytes auf `angenommen`. Ein fehlgeschlagenes Schreiben wird mit denselben Bytes unter demselben Schlüssel wiederholt. Ein Objekt, das schon mit demselben Hash vorliegt, gilt als geschrieben. Ein Objekt mit demselben Schlüssel und einem anderen Hash wird nicht ersetzt. Der Tausch auf `angenommen` ist die Entscheidung. Liegt die angenommene Fassung dieser Generation schon vor, bleibt sie stehen.

Die Antwort an den Aufrufer verlässt den Dienst erst nach diesem Tausch. Kommt sie nicht an, sendet der Aufrufer dieselbe `event_id` erneut. Ist die Lage `angenommen` und liegt die Annahme dieser Generation vor, bestätigt der Dienst sie und schreibt keine zweite Fassung.

### Teilfehler

Kommt der Logeintrag an, kommt das Verzeichnis an und schlägt der Vorgangsindex fehl, fehlt die Annahme. Das Ereignis ist nicht angenommen. Der Aufrufer behält es. Log und Verzeichnis sind unvollständiger Rest. Der Wiederanlauf schreibt den fehlenden Bestandteil mit denselben Bytes nach, prüft alle Hashes und schreibt dann die Annahme. Bis dahin wertet keine Prüfung den Rest als Logeintrag, Verweis oder Indexeintrag.

Dieselbe Regel gilt, wenn ein anderer Bestandteil fehlt oder die Annahme selbst nicht ankommt. Eine Annahme ohne vorher geprüfte Segmente schreibt der Dienst nicht. Liegt die Annahme vor und ein darin genanntes Segment fehlt oder trägt einen anderen Hash, ist die Annahme beschädigt. Der Dienst schreibt sie nicht neu und ersetzt das Segment nicht.

### Knotenverlust

Der Fsync des Spools bindet den Abschluss an diesen Knoten. Fällt der Knoten danach aus, ist der Spool weg. War die Annahme noch nicht am Ziel, hat der Aufrufer keine Bestätigung erhalten. Er sendet dasselbe Ereignis mit derselben `event_id` erneut.

Liegen Vorbereitung und alle Segmente mit passenden Hashes schon am Ziel, schreibt die übernehmende Instanz nach Ablauf der Instanzfrist samt der fünf Sekunden Schiefe die fehlende Annahme und tauscht die noch offene Belegung auf `angenommen`. Liegen die Bytes nicht mehr vor, setzt sie eine neue offene Generation, wenn die vorliegende Lage `offen` ist. Die alte Vorbereitung kann keine Annahme mehr werden. Der neue Abschluss verschlüsselt das Ereignis in einer Epoche der übernehmenden Instanz. Eine zweite angenommene Fassung derselben `event_id` entsteht dabei nicht.

Angenommene Ereignisse stehen im Ziel. Der Verlust des Knotens löscht sie nicht, weil das Ziel den Knoten überdauert. Für S3 ist das der Bucket. Für die Platte ist es ein Speicher außerhalb der lokalen Platte des Schreibprozesses. Liegen Ziel und Knoten auf derselben Maschine, nimmt der Verlust dieser Maschine die dort angenommenen Ereignisse mit. Diese Anordnung erfüllt die Annahme einer verteilten Plattform nicht.

### Erkennung

Der Dienst prüft beim Start und wiederkehrend Belegung, Vorbereitung, Segmente und Annahme.

| Befund | Bedeutung |
|---|---|
| Annahme vorhanden, jedes genannte Segment vorhanden, Hashes gleich | angenommen |
| Vorbereitung oder Segmente ohne Annahme | unvollständig, nicht angenommen |
| Belegung ohne Annahme | offen, nicht angenommen |
| Annahme, genanntes Segment fehlt oder Hash weicht ab | beschädigte Annahme |
| eine `event_id` in zwei Annahmen oder mit zwei `event_hash` | Konflikt |

Unvollständiger Rest gehört nicht zur Hash-Kette, nicht zum Epochenmanifest und nicht zur Suche. Eine Lücke ist eine Annahme oder ein Manifest, dessen Segment fehlt, eine unterbrochene Folge der `batch_seq` oder eine unterbrochene Folge der angenommenen Segmentnummern. Ein zusätzliches Objekt ohne Annahme ist keine Lücke und kein Glied. Ab dem Zugriffsschnitt oder mit einem Löschvermerk ist das Fehlen der Segmente einer bestätigten Epoche eine Löschung. Eine Annahme, die ein Segment dieser Epoche nennt, ist keine beschädigte Annahme. Das steht unter [Löschen](#löschen).

Nach einem Neustart setzt die Instanz eigene Abschlüsse aus dem Spool fort, solange die Belegung ihre Generation nennt. Eine fremde Epoche schließt der Dienst nur über die angenommenen Segmente ab, signiert dieses Manifest und schreibt in dieser Epoche keine neuen Einträge. Den unvollständigen Rest nimmt das Manifest nicht auf.

Der Spool eines Abschlusses ist diese Bytefolge. Der Knoten schreibt sie und schließt den Schreibvorgang mit einem Fsync ab.

```
spool =
    L("spool") || "spool" ||
    instanz_id ||
    batch_seq ||
    L(annahme) || annahme ||
    L(vorbereitung) || vorbereitung ||
    belegung_count ||
    (L(belegung) || belegung) … ||
    segment_count ||
    (L(objekt_schluessel) || objekt_schluessel || L(segment) || segment) …
```

Ein Füllplatz hat keine Belegung. Nennt die Belegung die Generation dieser Folge nicht mehr, schreibt der Wiederanlauf sie nicht weiter. Die Obergrenze zählt diese Folgen. Ist sie erreicht, nimmt der Dienst keinen weiteren Abschluss in den Spool. Einträge werden nicht verworfen.

Liegt die Annahme am Ziel und passen die Segmente, löscht der Dienst diese Folge. Den `annahme_hash` behält er, bis ein Manifest dieser Instanz am Ziel liegt, dessen `annahme_first` und `annahme_last` die `batch_seq` einschließen.

Die übernehmende Instanz bildet die fehlende Annahme aus der Vorbereitung. `previous_annahme_hash` ist bei `batch_seq` 1 die `annahme_genesis` und sonst der `annahme_hash` der vorigen `batch_seq`. Fehlt die vorige Annahme, ist das eine Lücke, und die Annahme wird nicht geschrieben. Eine Belegung eines Platzes muss dieselbe `instanz_id`, dieselbe `batch_id` und denselben `event_hash` tragen. Ein Segment mit anderem Hash wird nicht ersetzt.

Für das Manifest nach dem Neustart gelten die angenommenen Segmente in der Reihenfolge ihrer Nummer, beginnend bei 1, ohne Lücke. Ein Segment, das keine Annahme nennt, beendet diese Folge. Ein späteres angenommenes Segment ist eine Lücke. Die Kette wird über diese Segmente neu gesetzt. Der Klartext-DEK wird dafür nicht gebraucht. Der Rest bleibt außerhalb des Manifests.

## Löschen

Gelöscht wird eine Epoche, nicht ein Eintrag, nicht eine Person und nicht ein Vorgang. Mit der Epoche fallen alle ihre Segmente, einschließlich Kopf und Epochenmanifest im Segment. Ein einzelnes Segment wird nicht für sich gelöscht. Die Epochenbestätigung des Empfängers bleibt. Sie liegt außerhalb des Log-Buckets. Das Werkzeug erkennt die Löschung an der bestätigten Epoche, sobald ihr Zugriffsschnitt erreicht ist oder ein Löschvermerk vorliegt. Die Manifestkette bleibt über diese Epochenbestätigung prüfbar. Fehlt eine Epoche vor ihrem Zugriffsschnitt, fehlt eine Epochenbestätigung, oder setzt ein folgendes Manifest nicht auf dem bestätigten Hash auf, bleibt das eine Lücke. Fehlen nur einzelne Segmente vor dem Zugriffsschnitt und ohne Löschvermerk, ist das ebenfalls eine Lücke und keine Löschung.

Die Frist wird pro Mandant festgelegt und kann verlängert werden. Für den Bucket `plattform` gilt eine eigene Frist. Sie gilt für alle Ströme des Ziels: Gruppen, Einzelpersonen, Auffang, Verzeichnis, Vorgangsindex und die Summenindizes. Jede dieser Epochen trägt ihr eigenes Raster und erreicht den Zugriffsschnitt für sich. Ein Indexeintrag und ein Verzeichnisverweis können auf eine Log-Epoche zeigen, deren Zugriff geendet hat oder die schon entfernt ist, bis ihre eigene Epoche die Frist erreicht. Die Suche nennt die Person dann mit dem Hinweis, dass die Epoche gelöscht ist.

### Datenschutz

Dass nur ganze Epochen gelöscht werden, begrenzt die Löschung personenbezogener Daten. Das ist eine bewusste Entscheidung der Architektur.

In einem Gruppenstrom teilen die Personen der Kohorte die Epoche und denselben DEK. Eine einzelne Person aus diesem Strom zu entfernen hieße, die Epoche ohne sie neu zu verschlüsseln: neuer DEK, neue Ciphertexte, neues Manifest. Dafür liegt der Klartext nach dem Abschluss nicht mehr vor. Der Klartext-DEK ist verworfen, der private Schlüssel liegt nicht in der Plattform. Eine Umschlüsselung findet nicht statt. Der Eintrag bleibt in der Gruppenepoche, bis diese Epoche als Ganzes gelöscht wird. Das Merkmal `einzeln`, ein Mandantenwechsel und ein auf diese Person beschränkter Löschwunsch ändern die abgeschlossene Epoche nicht.

Dieselbe Entscheidung gilt, wo die Person sonst noch steht. Verzeichnis, Vorgangsindex und Summenindex nennen Person, Vorgangsnummer, Zeitpunkt und bei einer Gruppe den Kohortennamen. Der Auffangstrom nennt die Bezüge im Ciphertext. Die Löschung der Log-Epoche nimmt diese Einträge nicht mit. Die Person bleibt darüber auffindbar, bis die Epochen gelöscht sind, die sie enthalten. Diese Epochen haben eigene Raster. Sie erreichen die Frist nicht gemeinsam mit der Log-Epoche.

Im Einzelstrom enthält die Epoche nur die Ereignisse dieser Person. Gelöscht wird auch dort die ganze Epoche, nicht ein einzelnes Ereignis.

Innerhalb der Frist bleibt die Person damit im Bestand, soweit eine Epoche sie noch enthält. Eine Verlängerung schiebt die Löschung jeder noch vollständig vorhandenen Epoche ohne Löschvermerk hinaus und mit ihr die Löschung jeder Person, die darin genannt ist.

### Eine Frist je Epoche

Die Frist ist eine Eigenschaft der Epoche. Alle Segmente teilen denselben Löschtag. Kein Segment verschwindet vor diesem Tag. Am Löschtag entfernt der Dienst die Epoche. Ein Rest bleibt danach nicht im Ziel.

Den Löschtag setzt der Beginn des Rasters in der Epochenkennung in Gang, gezählt in UTC. Er steht im Objektschlüssel und ist ohne Entschlüsselung sichtbar. Das Alter eines Segments, der Zeitpunkt seines PUT und die Uhrzeit einer Datei setzen ihn nicht in Gang. Dieselbe Rechnung gilt für Gruppe, Einzelperson, Auffang, Verzeichnis, Vorgangsindex und die Summenindizes. Das Raster einer Summenepoche ist der Monatsbeginn. Für den Bucket `plattform` gilt die Frist der Plattform.

Der Löschtag ist der UTC-Tag, in den der Rasterbeginn plus die aktuelle Frist fällt. Der Zugriff endet mit Beginn des vorherigen UTC-Tages. Werkzeug und Suche öffnen die Epoche von diesem Zeitpunkt an nicht mehr. Die Segmente liegen an diesem Tag noch im Ziel. Der Zugriffsschnitt entfernt nichts. Eine Epoche, deren Segmente an diesem Tag schon fehlen, führt das Werkzeug ebenfalls als gelöscht.

Eine Verlängerung ändert die aktuelle Frist, bevor gelöscht wird. Löschtag und Zugriffsschnitt entstehen daraus und aus dem Rasterbeginn neu. Das gilt für jede Epoche, die noch vollständig vorliegt und keinen Löschvermerk trägt. Ein Löschdatum am Objekt gibt es nicht. Bereits entfernte Segmente stellt die Verlängerung nicht wieder her. Eine Verlängerung, die nur einen Teil der Segmente erreicht, ist keine Verlängerung dieser Epoche.

Auf der Platte und im S3-Ziel löscht derselbe Vorgang des Dienstes. Er rechnet mit der aktuellen Frist und dem Rasterbeginn. Ist der Löschtag erreicht und liegt die Epoche noch vollständig und ohne Löschvermerk vor, reicht der Dienst den Löschvermerk beim Empfänger ein und entfernt danach alle Segmente. Auf der Platte geschieht das in einem Schritt. Im S3-Ziel entfernt derselbe Vorgang die Segmente unter dem Präfix der Epoche. Ein eigenes Ziel gibt die Segmente dort heraus. Liegen noch Segmente derselben Epoche im gemeinsamen Ziel, entfernt derselbe Vorgang sie dort. In welcher Reihenfolge sie an diesem Tag wegfallen, bleibt unsichtbar, weil der Zugriff am Vortag geendet hat. Eine ältere Datei oder ein älteres Objekt derselben Epoche entfernt er nicht voraus.

Der Löschvermerk liegt neben der Epochenbestätigung, außerhalb des Log-Buckets. Der Speicher hängt ihn an. Er ersetzt die Bestätigung nicht und löscht sie nicht. Der Vermerk nennt den Löschtag. Kommt der Vorgang nach dem Vermerk nicht zu Ende, setzt der nächste Lauf bei dieser Epoche fort und entfernt die restlichen Segmente. Eine Verlängerung nach dem Vermerk stellt die Epoche nicht wieder her. Das Werkzeug öffnet sie nicht mehr.

Ab dem Zugriffsschnitt führt das Werkzeug eine bestätigte Epoche als gelöscht. Dieselbe Epoche mit fehlenden Segmenten vor dem Zugriffsschnitt und ohne Löschvermerk bleibt eine Lücke. Eine Annahme, die ein Segment einer so gelöschten Epoche nennt, ist keine beschädigte Annahme.

Der Bucket trägt keine Regel, die Segmente, Annahmen, Vorbereitungen oder Belegungen nach dem Alter des Objekts entfernt. Die Segmente einer Epoche entstehen über die Laufzeit der Epoche, und ein verzögerter Abschluss schreibt das letzte Segment erst, wenn das Ziel wieder annimmt. Das Manifest liegt in diesem letzten Segment. Eine Regel auf das Alter des einzelnen Objekts würde die früheren Segmente entfernen, während das Manifest noch da ist.

### Abschlüsse neben der Epoche

Annahmen, Vorbereitungen und Belegungen gehören zum Abschluss, nicht zur Epoche. Ein Abschluss kann Segmente mehrerer Epochen nennen. Der Löschvorgang der Epoche entfernt diese Objekte nicht.

Eine Annahme und ihre Vorbereitung fallen, sobald jede Epoche gelöscht ist, deren Manifest die `batch_seq` dieser Annahme einschließt. Die Belegung bleibt und sperrt die `event_id` gegen eine zweite Fassung. Sie nennt keinen Logtext, keine Person und keine Vorgangsnummer.

## Suche

Die Suchen sind verschieden.

**Epoche eines Stroms.** Das Werkzeug löst den Namen über den Stromkatalog in die `ablage_id` auf und listet `{mandant_id}/{ablage_id}/`. Die Epochenkennung beginnt mit dem Raster, deshalb trifft der Zeitraum die Epochen, ohne dass ein Eintrag geöffnet wird. Personenkennung, Vorgangsnummer und der Zeitpunkt des Ereignisses stehen auf diesem Weg nicht.

**Welche Personen an einem Vorgang gearbeitet haben.** Ein Datenschützer fragt den Suchprozess nach einer Vorgangsnummer. In der anderen Richtung nennt dieselbe Abfrage die Vorgänge einer Person. Der Prozess öffnet den Vorgangsindex erst nach der Autorisierung in der Sicherheitszone, und nur den Index des Mandanten der Anfrage: je abgeschlossenem Monat die Summenepoche, im laufenden Monat die Epochen, deren Zeitfenster den Zeitraum schneiden. Eine Epoche ab ihrem Zugriffsschnitt oder mit Löschvermerk öffnet er nicht. Die Kohorte steht am Eintrag, sie ist nicht die Ablage des Index. Personen aus mehreren Kohorten, aus Einzelströmen und aus dem Auffang dieses Mandanten erscheinen in derselben Antwort. Den Logtext öffnet diese Suche nicht. Zurück gehen nur die Treffer dieser Anfrage. Eine Vorgangsnummer, die bei weiteren Mandanten vorkommt, bleibt dort unsichtbar. Ein Ergebnis über alle Mandanten entsteht, wenn die Datenschützer dieser Mandanten ihre Antworten zusammenführen. Der Suchprozess führt sie nicht zusammen.

**Person oder Vorgangsnummer im Werkzeug des Mandanten.** Dieselben Merkmale stehen im Ciphertext des Verzeichnisses. Wer den Bucket listen kann, sieht sie nicht. Das Werkzeug öffnet mit dem privaten Schlüssel des Mandanten je abgeschlossenem Monat die Summenepoche des Verzeichnisses und im laufenden Monat die Verzeichnis-Epochen des Zeitraums, liest die Verweise auf `bind_id`, Epoche und erste Sequenz und entschlüsselt die verwiesenen Logeinträge. Eine Epoche ab ihrem Zugriffsschnitt oder mit Löschvermerk öffnet es nicht. Ein unverschlüsseltes Verzeichnis würde dieselben Merkmale jedem mit Leserecht auf den Bucket zeigen.

Epochen, deren Kopf den Plattform-KEK nennt, öffnet das Werkzeug des Mandanten nicht. Sie liegen unter der `ablage_id` der Rolle `auffang`, die Verweise unter der Rolle `verzeichnis`. Geöffnet werden sie mit dem privaten Schlüssel der Plattform.

### Sicherheitszone

Der Suchprozess ist eine eigene Sicherheitszone. Ihm wird der private Index-Schlüssel übergeben. Damit kann er sämtliche Einträge des Vorgangsindex entschlüsseln. Der Index enthält keinen Logtext. Er enthält Personenkennungen, Vorgangsnummern, Zeitpunkte und die Zuordnung zu Strömen. Das ist ein eigener schützenswerter Bestand.

Die Zone hat keine allgemeine Administrationsschnittstelle und keine interaktive Shell. Sie exportiert keine beliebigen Indexdaten. Eine Index-Epoche, eine Summenepoche und der Klartext des Index-DEK gehen nicht an den Aufrufer hinaus. Das Erzeugen einer Summenepoche bleibt in der Zone. Der Metrikport ist keine Administrationsschnittstelle. Er nimmt keine Suchanfrage an und gibt das Suchprotokoll nicht heraus. Sein Umfang steht unter [Metriken](betrieb.md#metriken).

Ohne authentisierten Aufrufer wird keine Index-Epoche geöffnet. Der Prozess autorisiert jede Anfrage einzeln. Die Autorisierung gilt für diese Anfrage: Mandant, Vorgangsnummer oder Person, Zeitraum. Sie ist keine Freigabe, den Index zu durchsuchen oder auszulesen.

Die Autorisierung liest die Zugehörigkeitsaussage aus dem Register des Mandanten der Anfrage, für den Bucket `plattform` aus dem Register der Plattform. Die Rolle ist Datenschützer, die Signatur der Aussage passt zum Prüfschlüssel des Mandanten, der Zeitpunkt der Anfrage liegt in der Gültigkeit, und der Mandant der Aussage ist der Mandant der Anfrage. Die Person signiert diese Anfrage mit ihrem privaten Aufrufschlüssel. Die Signatur deckt Mandant, die Zone des Suchprozesses, Person, Anfrage, Zeitraum und Zeitpunkt. Die Passphrase, die den Schlüssel lokal öffnet, geht nicht mit. Der Prozess prüft die Signatur gegen den öffentlichen Schlüssel des Eintrags. Dessen Fingerabdruck ist der Fingerabdruck in der Aussage. Eine gültige Aussage ohne diese Signatur autorisiert den Aufruf nicht. Die Signatur einer anderen Anfrage autorisiert diese nicht. Eine Anfrage für eine andere Zone ist an diesem Prozess ungültig. Der Zeitpunkt darf höchstens fünf Minuten von der Uhr des Prozesses abweichen. Das ist die Lebensdauer der signierten Anfrage und nicht die Schiefe der Instanzfrist. Dieselbe Signatur nimmt der Prozess in diesem Fenster nur einmal an. Die gemerkte Menge steht im Suchprotokoll auf der lokalen Platte dieser Replica und wird beim Start derselben Replica geladen. Ein neuer Pod hat ein leeres Protokoll; eine mitgeschnittene Signatur kann dort noch einmal gelten, bis ihr Zeitpunkt außerhalb der fünf Minuten liegt. Einen gemeinsamen Speicher für dieses Fenster gibt es nicht. Danach öffnet er den Index nur für diese Anfrage.

Jeder Suchvorgang wird protokolliert. Das Protokoll nennt die Person, deren Aufrufschlüssel die Anfrage verifiziert hat, den Fingerabdruck, den Mandanten, die Anfrage, den Zeitraum und den Zeitpunkt. Es enthält keinen Logtext, ist kein Export des Index und steht nicht im technischen Log. Dieselbe Zone und dieselbe Bindung gelten für die Abfrage des Index im Bucket `plattform`.

## Prüfung

Der Datenschutzbeauftragte prüft auf zwei Arten. Das Werkzeug entschlüsselt in beiden Fällen nur die Auswahl. Andere Ströme, andere Zeiten und nicht ausgewählte Einträge bleiben Ciphertext. Die Epochen des Zeitraums bestimmt es über den Präfix, bevor es einen DEK öffnet. Eine Epoche ab ihrem Zugriffsschnitt oder mit Löschvermerk lädt es nicht zum Entschlüsseln. Sie gilt als gelöscht, wie unter [Löschen](#löschen) beschrieben.

**Gruppe über einen Zeitraum.** Anlasslose Prüfung. Das Werkzeug lädt die Epochen des Gruppenstroms, deren Zeitfenster den Zeitraum schneiden, öffnet deren DEKs und entschlüsselt die Einträge dieser Epochen. Inhalt der Prüfung ist die Gruppe in diesem Zeitraum. Das Verzeichnis wird dafür nicht gebraucht.

**Person und/oder Vorgangsnummer.** Gezielte Suche. Das Werkzeug ermittelt die Treffer über das Verzeichnis und entschlüsselt nur die verwiesenen Logeinträge. Eine Vorgangsnummer kann auf Einträge mehrerer Personen und mehrerer Ströme zeigen, auch auf Einträge, die noch in einem Gruppenstrom liegen, weil die Person erst später als `einzeln` geführt wurde. Verweise in den Auffangstrom gehören zu den Treffern. Das Werkzeug zeigt sie mit dem dort vermerkten Grund und stellt sie als unzugeordnet dar.

**Auffangstrom über einen Zeitraum.** Prüfung der Ereignisse ohne Zuordnung innerhalb eines Mandanten. Das Werkzeug lädt die Epochen des Auffangstroms, deren Zeitfenster den Zeitraum schneiden, öffnet deren DEKs und entschlüsselt die Einträge dieser Epochen. Zu jedem Eintrag zeigt es den Grund. Einträge ohne gültige Aussage bleiben sichtbar; der fehlende Bezug ist der Befund. Einträge mit dem Grund `ziel_fehlt` prüft das Werkzeug an der mitgeführten Aussage wie jeden anderen geöffneten Eintrag. Die Prüfung einer Gruppe schließt den Auffangstrom nicht ein. Das Verzeichnis wird für diese Prüfung nicht gebraucht.

**Plattform-Auffang über einen Zeitraum.** Prüfung der Ereignisse ohne Mandant und der Epochen mit Grund `kek_fehlt`. Sie steht nur dem Datenschutzbeauftragten der Plattform offen. Das Werkzeug löst die Rolle `auffang` über den Stromkatalog in die `ablage_id` auf und listet diese Ablage im Bucket `plattform` und in den Buckets der Mandanten. Epochen, deren Kopf den Plattform-KEK nennt, sind die mit Grund `kek_fehlt`. Die gezielte Suche läuft über das jeweilige Verzeichnis und zeigt die Treffer mit dem Grund. Eine Gruppenprüfung schließt diese Epochen nicht ein.

An jedem geöffneten Eintrag eines Gruppen- oder Einzelstroms prüft das Werkzeug die Zugehörigkeit. Die Signatur der Aussage passt zum Prüfschlüssel des Mandanten. Die Person in der Aussage ist die Person im Eintrag. Der Mandant in der Aussage ist der Mandant, dessen `mandant_id` in den Zusatzdaten steht. Das Werkzeug löst den Namen über den Stromkatalog auf. Die `bind_id` im Klartext des Eintrags ist die `bind_id` im geöffneten DEK. Der Zeitpunkt des Eintrags liegt in der Gültigkeit. Das Werkzeug liest ihn aus dem Klartext und stellt ihn neben das Raster der Epoche. Liegt er nach dem Ende dieses Rasters, ist das ein Befund. Eine Aussage, die daran scheitert, fällt aus dieser Prüfung. Das bestätigte Epochenmanifest belegt daneben Reihenfolge und Vollständigkeit der Ciphertexte und das Aufsetzen auf dem vorherigen Abschluss dieser Instanz. Eine zweite vom HSM signierte Fassung derselben Epoche ist eine Verzweigung. Dieselbe Prüfung gilt für die Epochen des Auffangstroms.

## Verzeichnis

Das Verzeichnis zeigt von einer Person und von einer Vorgangsnummer auf die Logeinträge, bevor diese geöffnet werden. Es wird mit demselben KEK gewrappt wie die Logs und führt eigene DEK-Epochen. Dieselben Grenzen gelten: 15 Minuten bis 8 Stunden, Ausgangswert 60 Minuten. Die Plattform schreibt das Verzeichnis und liest es nicht.

Person und Vorgangsnummer stehen nur im Ciphertext des Verzeichnisses. Sie erscheinen nicht im Objektschlüssel und nicht in den authentisierten Zusatzdaten. Dadurch bleibt die gezielte Suche an den privaten Schlüssel gebunden. Das Listen der Epochen ersetzt sie nicht.

Zu jedem Logeintrag entstehen Verweise: einer je genannter Person, und einer zur Vorgangsnummer, sofern das Ereignis eine trägt. Die Bytefolge steht unter [Inhalte](protokoll.md#inhalte). Liegt der Eintrag im Auffangstrom, entsteht ein Verweis je dort genannter Person, auch wenn die Zuordnung gescheitert ist, und einer zur Vorgangsnummer, sofern vorhanden. Ein Verweis nennt im Klartext `mandant_id`, `bind_id`, die Epoche und die erste Sequenz des Eintrags. Er wird in derselben Annahme geschrieben wie der Logeintrag. Das Ereignis gilt erst als angenommen, wenn diese Annahme am Ziel den Logeintrag, die Verweise und, soweit eine Vorgangsnummer genannt ist, die Einträge im Vorgangsindex nennt. Fehlt ein Verweis oder ein solcher Indexeintrag, entsteht keine Annahme; das Ereignis bleibt beim Aufrufer. Ein Auffang-Ereignis ohne Person und ohne Vorgangsnummer hat keinen Verweis; die Annahme nennt dann nur den Eintrag im Auffangstrom.

Das Verzeichnis ist ein Strom des Mandanten mit der Rolle `verzeichnis` und eigener `ablage_id`, im selben Segmentformat wie die Logs, mit eigener Hash-Kette, eigener HSM-Signatur und eigener Epochenbestätigung. Das Werkzeug prüft Kette, Signatur und Epochenbestätigung, bevor es Verweise verwendet. Ein entfernter oder ersetzter Verweis ist damit erkennbar. Der Logeintrag liegt zusätzlich im Strom. Die Prüfung einer Gruppe über einen Zeitraum findet ihn auch ohne Verzeichnis.

Ablauf der gezielten Suche:

1. Das Werkzeug öffnet je abgeschlossenem Monat im gewählten Zeitraum die Summenepoche des Verzeichnisses und im laufenden Monat die Verzeichnis-Epochen, deren Zeitfenster den Zeitraum schneiden. Ohne Zeitraum öffnet es jede Summenepoche des Mandanten und die Verzeichnis-Epochen des laufenden Monats. Fehlt eine Summenepoche oder passt einer der darin genannten Manifest-Hashes nicht, öffnet es für diesen Monat die Verzeichnis-Epochen.
2. Es liest die Treffer zur Person, zur Vorgangsnummer oder zu beiden, wenn beide angegeben sind.
3. Es öffnet nur die Epochen, auf die diese Treffer zeigen, und entschlüsselt nur die verwiesenen Einträge.

Die übrigen Einträge einer so geöffneten Epoche werden nicht entschlüsselt. Der DEK dieser Epoche liegt dabei im Speicher des Werkzeugs und könnte sie öffnen. Dass sie verschlossen bleiben, sichert das Werkzeug zu.

## Vorgangsindex

Der Vorgangsindex beantwortet, welche Personen an einem Vorgang gearbeitet haben. Die Personen können in verschiedenen Kohorten liegen, einzeln geführt sein oder im Auffang stehen. Ein Index pro Kohorte beantwortet das nicht, weil die Suche dann jede Kohorte öffnen müsste und Personen außerhalb der Kohorte fehlen würden.

Der Index ist ein Strom des Mandanten mit der Rolle `vorgang` und eigener `ablage_id`. Er ist nicht nach Kohorte geteilt. Die Kohorte steht im Klartext des Eintrags. Ereignisse ohne Mandant liegen im Index des Buckets `plattform`.

Zu jedem Logeintrag mit Vorgangsnummer entsteht ein Indexeintrag je genannter Person. Er nennt Vorgangsnummer, Person, die Rolle der Ablage, bei einer Gruppe den Kohortennamen, die Epoche, die erste Sequenz und den Zeitstempel des Logeintrags. Der Logtext steht dort nicht. Eine Vorgangsnummer ohne genannte Person erzeugt keinen Personeneintrag. Ein Ereignis ohne Vorgangsnummer erzeugt keinen Indexeintrag.

„Gearbeitet“ heißt hier: die Person ist an einem Audit-Ereignis dieser Vorgangsnummer genannt. Eine Rolle darüber hinaus enthält der Index nicht.

Der Schreibprozess verschlüsselt den Index mit dem öffentlichen Index-Schlüssel. Dieselben Epochengrenzen gelten, Ausgangswert 60 Minuten, eigene Hash-Kette und eigene HSM-Signatur. Der Index-Schlüssel wrappt keine Log-Epoche und nicht den Plattform-KEK. Der Suchprozess erhält den privaten Index-Schlüssel als eigenes tmpfs-Secret. Er ist die Sicherheitszone unter [Suche](#suche) und exportiert den Index nicht. Er öffnet den Index nur des Mandanten der autorisierten Anfrage, im gewählten Zeitraum oder über die vorhandene Frist: je abgeschlossenem Monat die Summenepoche, im laufenden Monat die Epochen. Eine Epoche ab ihrem Zugriffsschnitt oder mit Löschvermerk öffnet er nicht. Er filtert auf die Vorgangsnummer und gibt die verschiedenen Personen mit ihren Strömen zurück. Dieselbe Abfrage in der anderen Richtung nennt die Vorgänge einer Person in diesem Mandanten. Fehlt eine Summenepoche oder passt einer der darin genannten Manifest-Hashes nicht, liest er diesen Monat über die Epochen. Log-DEKs wickelt er nicht aus. Den Index im Bucket `plattform` fragt eine Person aus dem Register der Plattform ab, kein Datenschützer eines Mandanten. Der Aufrufer weist sich mit der Signatur seines Aufrufschlüssels aus, wie unter [Suche](#suche) beschrieben.

Das Ereignis gilt erst als angenommen, wenn die Annahme am Ziel neben Logeintrag und Verzeichnisverweisen auch die zugehörigen Indexeinträge nennt. Fehlt der Index-Schlüssel, nimmt der Schreibprozess das Ereignis nicht an.

Der Datenschutzbeauftragte des Mandanten kann den Logtext über das Verzeichnis öffnen. Die Frage nach den Personen eines Vorgangs stellt ein Datenschützer dieses Mandanten an den Suchprozess. Die Antwort nennt die Personen und ihre Ströme, ohne den Logtext.

## Summenindex

Der Summenindex fasst einen abgeschlossenen Monat von Verzeichnis oder Vorgangsindex in eine Epoche. Die Suche öffnet damit je Monat einen DEK statt einer Epoche pro Stunde. Der laufende Monat bleibt in den Epochen des Stroms, Ausgangswert 60 Minuten. Eine weitere Stufe pro Tag gibt es nicht.

Zwei Ströme, je Mandant und im Bucket `plattform`, mit den Rollen `verzeichnis-summe` und `vorgang-summe` und je eigener `ablage_id`. Der Objektschlüssel folgt dem der übrigen Ströme. Das Rasterfeld der Epochenkennung ist der Monatsbeginn in UTC, sodass ein List die Monate in zeitlicher Ordnung liefert. Person und Vorgangsnummer stehen nur im Ciphertext.

`verzeichnis-summe` trägt dieselben Verweise wie das Verzeichnis dieses Monats, geordnet nach Person und nach Vorgangsnummer, und wird mit demselben Schlüssel gewrappt wie das Verzeichnis. `vorgang-summe` nennt je Vorgangsnummer die verschiedenen Personen mit Strom sowie erstem und letztem Zeitstempel, und je Person die Vorgangsnummern. Der Logtext steht dort nicht. Gewrappt wird mit dem Index-Schlüssel.

Erzeugt wird er, sobald der Monat geschlossen ist, von dem, der den zugrunde liegenden Strom öffnen darf. Den Strom `vorgang` fasst der Suchprozess zusammen, den Strom `verzeichnis` das Werkzeug. Das Zusammenfassen von `vorgang` bleibt in der Sicherheitszone. Die Summenepoche wird nicht an den Aufrufer herausgegeben. Der Schreibprozess hält dafür keinen DEK über den Monat. Der DEK des Summenindex existiert nur für das Erzeugen und wird danach verworfen. Die Epochen des Monats bleiben die Belege. Die Annahme eines Ereignisses hängt am Summenindex nicht.

Der Summenindex nennt die Epochen und die Hashes ihrer bestätigten Manifeste. Vor der Verwendung werden diese Hashes gegen die Epochenbestätigungen geprüft. Fehlt er oder weicht ein Hash ab, wird dieser Monat über die Epochen gelesen. Eigene Hash-Kette und eigene HSM-Signatur entsprechen den übrigen Strömen. Die Frist des Ziels gilt auch für ihn.

## Entschlüsselung

Das Werkzeug läuft beim Datenschutzbeauftragten, in der [Oberfläche](#oberfläche-des-werkzeugs).

Im einfachen Modus gibt er dort die Passphrase ein. Das Werkzeug wickelt den gespeicherten privaten Schlüssel lokal aus, öffnet damit die DEKs der benötigten Epochen und entschlüsselt nur die Einträge der Auswahl.

Im sicheren Modus verwendet das Werkzeug den Schlüssel am HSM oder auf der Smartcard. Der private Schlüssel verlässt diesen Träger nicht.

Das Werkzeug prüft je Epoche den Zertifikatsfingerabdruck, die Hash-Kette und das Epochenmanifest gegen die Epochenbestätigung des Mandanten, einschließlich des Aufsetzens auf dem vorherigen Abschluss derselben Instanz. Es prüft, dass jede Nonce der Epoche einmal vorkommt und dass ihre letzten 8 Byte gleich der `seq` des Eintrags sind. Eine davon abweichende, ebenfalls gültig signierte Fassung zeigt es als Verzweigung. Beim Plattform-Auffang prüft es gegen die Epochenbestätigung des Datenschutzbeauftragten der Plattform. An jedem geöffneten Eintrag eines Gruppen- oder Einzelstroms prüft es die Zugehörigkeitsaussage gegen den Prüfschlüssel des Mandanten. Im Auffangstrom zeigt es den Grund; eine mitgeführte Aussage bei `ziel_fehlt` prüft es auf dieselbe Weise. Dieselbe Ketten- und Signaturprüfung gilt für die Epochen des Verzeichnisses, des Summenindex, des Auffangstroms und des Plattform-Auffangs. Den Status des Fingerabdrucks liest es mit. Bei `abgeloest` und bei einem abgelaufenen Zertifikat bleibt der bisherige private Schlüssel der Schlüssel dieser Epoche, solange er unverletzt beim Empfänger liegt. Bei `kompromittiert` öffnet das Werkzeug die Auswahl und weist die Epoche ohne Vertraulichkeitszusicherung aus. Bei `verloren` öffnet es den Inhalt nicht mehr. Eine Prüfung, deren DEK bereits geöffnet ist, darf zu Ende gehen. Danach prüft es Kette, Signatur und Epochenbestätigung ohne den DEK.

## Oberfläche des Werkzeugs

Das Werkzeug ist ein Fenster auf dem Rechner des Empfängers. Der Datenschutzbeauftragte prüft darin. Eine Konfigurationsdatei ist nicht die Bedienung. `schreiben` und `suchen` starten aus der Konfiguration des Betriebs. `werkzeug` tut das nicht.

Die Verbindung zum Speicherziel darf das Werkzeug lokal ablegen: Endpunkt und Bucket oder den Pfad der Platte, die `mandant_id`, die Zone des Suchprozesses und die Pfade der Schlüsseldateien. Die Passphrase steht dort nicht. Sie wird nicht gespeichert, nicht geloggt und nicht an die Plattform übertragen. Dieselbe Grenze gilt für die PIN eines Trägers. Ein Start, der eine Prüfung ohne diese Eingabe öffnet, findet nicht statt.

Vor dem Öffnen nennt das Fenster den Fingerabdruck des KEK und seinen Status. Im einfachen Modus gibt der Empfänger die Passphrase ein. Das Werkzeug wickelt den privaten Schlüssel lokal aus. Im sicheren Modus verwendet es den Schlüssel am HSM oder auf der Smartcard. Der private Schlüssel verlässt den Träger nicht. Der Aufrufschlüssel ist eine zweite Entsperrung und nur für die Anfrage an den Suchprozess nötig. Seine Passphrase öffnet keinen DEK.

Die Prüfung ist eine der vier unter [Prüfung](#prüfung) genannten Arten. Das Fenster verlangt die Art und, wo die Art einen Zeitraum hat, den Zeitraum. Es zeigt vorher, wie viele Epochen die Auswahl trifft. Eine Handlung, die den Bucket entschlüsselt, gibt es nicht. Die Gruppe über einen Zeitraum öffnet die Einträge dieser Epochen. Die gezielte Suche öffnet nur die verwiesenen Einträge. Der Auffangstrom und der Plattform-Auffang sind eigene Prüfungen. Den Plattform-Auffang bietet das Fenster nur an, wenn der entsperrte Schlüssel der Plattform-KEK ist.

Namen kommen aus dem Stromkatalog. Die `ablage_id` bleibt prüfbar und ist nicht die Beschriftung. Zu jedem geöffneten Eintrag zeigt das Fenster den Befund: die Zugehörigkeit, einen unzugeordneten Eintrag mit seinem Grund, einen Zeitpunkt nach dem Raster, und an der Epoche Lücke, Verzweigung, Bruch zum Vorgänger, Löschung, `kompromittiert` und `verloren`. Bei `verloren` bleibt der Inhalt zu. Bei `kompromittiert` bleibt die Auswahl lesbar und ist ohne Vertraulichkeitszusicherung gekennzeichnet. Eine gelöschte Epoche wird nicht geladen.

Die Frage, welche Personen an einem Vorgang gearbeitet haben, geht an den Suchprozess. Das Fenster signiert diese eine Anfrage mit dem Aufrufschlüssel und zeigt die Treffer. Einen Export des Index gibt es nicht. Dieselbe Anfrage in der anderen Richtung nennt die Vorgänge einer Person.

Kette, HSM-Signatur und Epochenbestätigung prüft das Fenster auch, ohne die Einträge zu öffnen. Die Epochenbestätigung signiert der Empfänger in demselben Fenster mit dem Bestätigungsschlüssel. Das Fenster signiert eine Epoche erst, nachdem diese Prüfung gehalten hat. Eine Lücke, eine Verzweigung und ein Bruch zum Vorgänger werden nicht bestätigt. Mehrere so geprüfte Epochen können in einer Handlung bestätigt werden. Jede Epoche erhält ihre eigene Signatur. Die Passphrase dieses Schlüssels wird nicht abgelegt.

Ist ein Monat geschlossen, schreibt das Werkzeug die Summenepoche des Verzeichnisses. Das ist eine Handlung des Fensters. Den Vorgangsindex fasst es nicht zusammen. Das bleibt in der Sicherheitszone des Suchprozesses.

Das Fenster zeigt den Klartext der Auswahl für die Dauer dieser Prüfung. Es schreibt ihn nicht in eine Datei und nicht in ein Protokoll. Mit dem Ende der Prüfung verwirft das Werkzeug den Klartext-DEK, und der Klartext ist aus dem Fenster.

Das Fenster läuft nicht im Image der Plattform, nicht im Chart und nicht als Dienst. Es ist nicht die [Verwaltung](schluessel.md#verwaltung). Die Verwaltung nimmt keine Passphrase an und öffnet keine Logs.
