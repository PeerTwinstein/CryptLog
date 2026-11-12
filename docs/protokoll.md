# CryptLog — Protokoll

Stand: 12. November 2026

Teil des [Konzepts Audit-Log-Verschlüsselung](README.md). Hüllenverschlüsselung, Ablage, Auffangstrom, Verkettung und sichtbare Metadaten.

## Hüllenverschlüsselung

Ein Schreibprozess erzeugt den DEK selbst und hält den Klartext nur im eigenen Speicher. Der DEK wird nicht an andere Instanzen verteilt, nicht persistiert, nicht geloggt und nicht in Backups geschrieben.

Der DEK ist 32 Byte aus einem kryptografischen Zufallszahlengenerator. Er verschlüsselt jeden Eintrag mit AES-256-GCM. Nonce und Tag sind 12 und 16 Byte, die Zusatzdaten sind die in der [Verkettung](#verkettung) festgelegten Bytes. Die Nonce ist `epoch_prefix || seq`: 4 Byte Zufall, einmal beim Erzeugen dieses DEK, und die 8 Byte der Sequenznummer. Aufbau und Vergabe stehen in der [Verkettung](#verkettung).

Den DEK verschlüsselt der öffentliche Schlüssel des Empfängers. Dieselbe Festlegung gilt für den KEK des Mandanten, den Plattform-KEK und den Index-Schlüssel. AES-GCM nimmt einen symmetrischen Schlüssel. Der öffentliche Schlüssel liefert ihn bei den Kurven über HPKE. Bei RSA verschlüsselt RSA-OAEP die 48 Byte `dek || bind_id` direkt. Dieselbe Klartextfolge wickeln die HPKE-Varianten ein. `bind_id` ist die Bindungskennung aus dem Abschnitt [Sichtbare Metadaten](#sichtbare-metadaten).

Der Kontext des Wraps ist:

```
wrap_ctx = L("dek-wrap") || "dek-wrap"
        || mandant_id
        || ablage_id
        || epoch_id
        || kek_fingerabdruck
```

`L` und die Feldlängen sind dieselben wie in der [Verkettung](#verkettung). `kek_fingerabdruck` ist der Fingerabdruck des Zertifikats, mit dem dieser DEK gewrappt wird.

- RSA ab 3072 Bit: RSA-OAEP nach RFC 8017 mit SHA-256, MGF1-SHA-256 und `wrap_ctx` als Label. `wrapped_dek` ist das Chiffrat.
- P-256: HPKE nach RFC 9180 im Basismodus, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. `info` und `aad` sind `wrap_ctx`.

Bei HPKE ist `wrapped_dek` die Aneinanderreihung `enc || ct` aus RFC 9180. AES-256-GCM verschlüsselt darin die 48 Byte `dek || bind_id`. Der Schlüssel dafür entsteht aus dem ECDH mit dem öffentlichen Schlüssel und verlässt den Wrap nicht. Die Nonce dieses einen Aufrufs ist die aus RFC 9180. Sie ist nicht die Nonce der Einträge.

Der Bindungsschlüssel einer Annahme ist ebenfalls 32 Byte. Gewrappt werden die 48 Byte `bindungsschluessel || batch_id`, mit demselben öffentlichen Schlüssel und denselben Algorithmen. Der Kontext dafür ist `bindung_ctx`. Den Klartext `bindung` verschlüsselt dieser Schlüssel einmal mit AES-256-GCM. Diese Nonce ist `bindung_nonce`. Sie ist nicht die Nonce der Einträge und nicht die Nonce aus RFC 9180. Aufbau und Zusatzdaten stehen unter [Vorbereitung und Annahme](ablage-und-lesen.md#vorbereitung-und-annahme).

Der gewrappte DEK steht einmal pro Epoche im Logstrom, als Kopf dieser Epoche. Jeder Eintrag verweist über eine `dek_id` auf diesen Kopf. Ein exportierter Logbestand bleibt damit für sich lesbar, sobald der Datenschutzbeauftragte seinen privaten Schlüssel einsetzt.

Jeder Eintrag enthält Nonce, Ciphertext und Tag. In die authentisierten Zusatzdaten gehören `mandant_id`, `ablage_id`, `epoch_id`, `dek_id` und die Sequenznummer. Die Bytes stehen in der [Verkettung](#verkettung). Die Zusatzdaten sind authentisiert und nicht verschlüsselt. Sie binden den Eintrag an Mandantenkennung, Ablage und Epoche. Ein Zeitstempel, ein Kohortenname, eine Personenkennung, eine Vorgangsnummer und eine `bind_id` stehen dort nicht. Im Klartext des Eintrags stehen die `event_id`, der Zeitpunkt, die `bind_id` und der übrige Ereignisinhalt. Dieselbe `event_id` steht im Klartext der zugehörigen Verzeichnisverweise und Vorgangsindexeinträge.

### Epochen

Das Rotationsintervall ist pro logischem Strom einstellbar und hart auf 15 Minuten bis 8 Stunden begrenzt. Kürzere und längere Intervalle lehnt der Dienst ab. Zulässig ist ein Intervall, das 24 Stunden teilt, gezählt von Mitternacht UTC. Die Epoche gehört zum Raster, in das der Schreibzeitpunkt fällt. Die Epochenkennung nennt den Beginn dieses Rasters.

Ausgangswerte:

- Gruppenstrom: 60 Minuten
- Einzelstrom: 8 Stunden

Nach Ablauf der Epoche wird der Klartext-DEK im Speicher verworfen. Die nächste Epoche beginnt mit einem neuen DEK. Ein Neustart des Schreibprozesses, ein Absturz, ein Fork und ein wiederhergestelltes Prozessabbild beginnen für neue Ereignisse ebenfalls eine neue Epoche. Ein im Spool bereits verschlüsselter Abschluss wird davor noch zu Ende geschrieben. Der Zähler der Nonce steht nur neben dem DEK im Speicher. Ein wiederhergestelltes Abbild, das den bisherigen DEK noch enthält, würde bereits vergebene Nonces wiederholen. Ein Klartext-DEK wird nie aus einem Speicher zurückgeholt.

Pro schreibender Instanz und logischem Strom gibt es höchstens eine offene Epoche. Der logische Strom einer Einzelperson ist ihre `bind_id`. Schreiben mehrere Instanzen in dieselbe Ablage, führen sie nebeneinander eigene Epochen. Abgeschlossene Epochen bleiben, weil ältere Einträge sonst nicht mehr zu öffnen sind.

Läuft das Zertifikat ab oder wird der KEK getauscht, gilt der neue Schlüssel nur für neue Epochen. Bestehende Epochen bleiben an den bisherigen Zertifikatsfingerabdruck gebunden. Der bisherige private Schlüssel bleibt beim Datenschutzbeauftragten und bleibt für diese Epochen vertrauenswürdig. Der Fingerabdruck steht in jeder Epoche und ist ein Glied der Hash-Kette. Ein stiller Tausch des Empfängerschlüssels fällt im Werkzeug auf, weil sich die Epoche mit dem bekannten Zertifikat nicht mehr öffnen lässt. Ein neues Zertifikat über denselben öffentlichen Schlüssel ist kein Tausch. Verlust und Kompromittierung des privaten Schlüssels sind andere Lagen. Sie stehen unter [Wechsel, Verlust und Kompromittierung](schluessel.md#wechsel-verlust-und-kompromittierung).

## Ablage: Gruppe und Einzelperson

Die Trennung betrifft die Ablage und den DEK, nicht den Empfänger. Gruppen- und Einzelströme werden mit demselben KEK des Mandanten gewrappt. Wer eine Gruppe öffnet, sieht nur diese Gruppe.

Jede betroffene Person trägt ein Ablagemerkmal.

**Gruppe.** Das Ereignis läuft in den Strom einer konfigurierten Kohorte im Mandanten, etwa eine Organisationseinheit oder ein benannter Sammelbereich. Alle gruppierbaren Personen dieser Kohorte teilen sich die laufende DEK-Epoche der schreibenden Instanz. Das Register vergibt die `ablage_id`. Der Name der Kohorte steht im Register und im Stromkatalog.

**Einzeln.** Die Person hat einen eigenen DEK und eigene Epochen. Ihre Ereignisse erscheinen in keinem Gruppen-Ciphertext. Die `bind_id` ist ein undurchsichtiges Kennzeichen aus dem Register und ist nicht die Personenkennung. Die Segmente liegen unter der gemeinsamen `ablage_id` des Einzelpräfixes dieses Mandanten. Die Manifestkette dieser Instanz führt über den Präfix, in der Abschlussreihenfolge der Epochen, über Personen hinweg.

Das Merkmal `einzeln` ist verbindlich. Es stammt aus dem Personenregister. Der schreibende Dienst kann es nicht übersteuern. Es gilt ab der nächsten Schreiboperation. Ereignisse, die bereits in einer Gruppenepoche liegen, bleiben dort: ohne den privaten Schlüssel kann die Plattform sie nicht umschlüsseln. Dieselbe Grenze gilt für die Löschung und ist unter [Löschen](ablage-und-lesen.md#löschen) beschrieben.

Gehört ein Ereignis zu mehreren Personen und ist mindestens eine davon als `einzeln` markiert, wird das Ereignis ausschließlich in die Einzelströme der so markierten Personen geschrieben. Je Strom entsteht ein eigener Ciphertext unter dem DEK dieses Stroms. In den Gruppenstrom wird das Ereignis dann nicht geschrieben.

## Auffangstrom

Der Auffangstrom ist die Dead Letter Box eines Mandanten. Er nimmt ein Audit-Ereignis auf, das der Dienst keinem Gruppenstrom und keinem Einzelstrom zuordnen kann, und ein Ereignis, dessen Mandanten-KEK fehlt. Das Ereignis bleibt erhalten. Epochen mit dem KEK des Mandanten liest der Datenschutzbeauftragte dieses Mandanten. Epochen mit dem Grund `kek_fehlt` liest der Datenschutzbeauftragte der Plattform. Der Auffangstrom erscheint in keinem Gruppen-Ciphertext und in keinem Einzelstrom.

Der Dienst schreibt das Ereignis genau einmal in den Auffangstrom, wenn nach der Auflösung im Mandanten des Ereignisses kein beschreibbares Ziel bleibt:

| Grund | Lage |
|---|---|
| `unbekannt` | Keine genannte Person hat einen Eintrag im Personenregister dieses Mandanten. |
| `aussage_ungueltig` | Zur Person liegt keine Aussage vor, die Signatur passt nicht zum Prüfschlüssel, oder der Zeitpunkt des Ereignisses liegt außerhalb der Gültigkeit. |
| `ziel_fehlt` | Die Aussage ist gültig, das Ablagemerkmal verweist aber auf keine vorhandene Gruppe und auf keinen Einzelstrom. |
| `ohne_bezug` | Das Ereignis nennt weder eine Person noch eine Gruppe. |
| `kek_fehlt` | Der Mandant ist ermittelt, ein aktueller KEK dieses Mandanten ist nicht lesbar. Der DEK dieser Epoche wird mit dem Plattform-KEK gewrappt. |

Trägt das Ereignis mehrere Personen und lässt sich mindestens eine davon einem Gruppen- oder Einzelstrom zuordnen, gilt der bisherige Ablageweg nur für die zuordenbaren Personen. Die übrigen Bezüge stehen im Klartext dieser Einträge. Eine zweite Kopie im Auffangstrom entsteht dann nicht.

Die Rolle heißt `auffang`. Die `ablage_id` vergibt das Register. Solange ein aktueller KEK des Mandanten lesbar ist, wird der Strom mit diesem KEK gewrappt. Fehlt er, wird die Epoche mit dem Plattform-KEK gewrappt. Dieselben Grenzen gelten: 15 Minuten bis 8 Stunden, Ausgangswert 60 Minuten. Segmentformat, Hash-Kette und HSM-Signatur entsprechen den übrigen Strömen. Pro schreibender Instanz und Wrap-Schlüssel gibt es höchstens eine offene Epoche. Person, Vorgangsnummer und Grund stehen nur im Ciphertext. Der Objektschlüssel nennt `mandant_id`, `ablage_id` und die Epoche.

Im Klartext stehen das Ereignis, der Grund und die genannten Bezüge. Bei `ziel_fehlt` steht dort zusätzlich die gültige Zugehörigkeitsaussage. In den übrigen Fällen liegt keine gültige Aussage vor; der Grund hält das fest. Der Dienst bildet keine Ersatzaussage und ändert das Merkmal `einzeln` nicht.

Nennt das Ereignis Personen oder eine Vorgangsnummer, entstehen im Verzeichnis Verweise auf die Stelle im Auffangstrom: einer je genannter Person, und einer zur Vorgangsnummer, sofern vorhanden. Die Verweise werden mit demselben Schlüssel gewrappt wie der Logeintrag. Bei `kek_fehlt` ist das der Plattform-KEK. Ein Ereignis ohne Person und ohne Vorgangsnummer hat keinen Verweis. Es ist über die Prüfung des Auffangstroms im Zeitraum erreichbar. Das Ereignis gilt erst als angenommen, wenn die Annahme am Ziel den Eintrag im Auffangstrom, die vorhandenen Verweise und, soweit eine Vorgangsnummer genannt ist, die Einträge im Vorgangsindex nennt.

Ein Ausfall des Spools lässt das Ereignis unangenommen. Der Dienst verwirft es nicht; der Aufrufer behält es. Ein Ausfall des Ziels lässt den Abschluss im Spool, solange die Annahme fehlt. Der Auffangstrom eines Mandanten sammelt Ereignisse, deren Zuordnung scheitert, und Ereignisse, deren Mandanten-KEK fehlt.

### Kein Mandant

Der Mandant steht am Ereignis. Der Dienst ermittelt ihn dort. Er sucht ihn nicht, indem er Personenregister anderer Mandanten durchgeht. Fehlt die Angabe, nennt sie keinen registrierten Mandanten oder ist sie mehrdeutig, ist kein Mandant ermittelt.

Für diesen Fall und für `kek_fehlt` hält der Dienst einen eigenen KEK, den Plattform-KEK. Das ist der öffentliche Schlüssel des Datenschutzbeauftragten der Plattform, gebunden an ein Zertifikat. Der Dienst wickelt damit DEKs ein. Er wickelt sie nicht aus. Den privaten Schlüssel liest der Schreibpfad nicht.

Der Plattform-KEK wird dem Schreibprozess als Secret über ein tmpfs übergeben. Er liegt damit im Speicher des Prozesses und nicht auf einer persistenten Platte des Knotens. Er wird nicht in das Image übernommen und nicht in den Schlüsselspeicher eines Mandanten geschrieben. Das Secret enthält den öffentlichen Schlüssel, nicht den privaten. Algorithmen, Key Usage und die Ablehnung eines CA-Zertifikats entsprechen dem KEK eines Mandanten. Subjekt des Zertifikats ist die Plattform plus ihr Datenschutzbeauftragter. Es gibt genau einen Empfänger und genau einen privaten Schlüssel. Im sicheren Modus liegt dieser Schlüssel auf zwei Trägern beim Datenschutzbeauftragten, zum Beispiel zwei Smartcards oder ein HSM mit Backup. Die Träger werden getrennt aufbewahrt. Die Plattform erhält keinen von beiden. Im einfachen Modus liegt zusätzlich die verschlüsselte Kopie außerhalb des Schreibpfads; die Passphrase bleibt beim Datenschutzbeauftragten. Ohne lesbares Secret startet der Schreibprozess nicht.

Der Plattform-Auffang hat die Rolle `auffang` im reservierten Bucket `plattform`. Dieser Bucket ist kein Mandant. `mandant_id` ist dort die unter [Sichtbare Metadaten](#sichtbare-metadaten) festgelegte Kennung der Plattform. Der Objektschlüssel folgt der gemeinsamen Form. Person, Vorgangsnummer und der im Ereignis genannte Mandantenwert stehen nur im Ciphertext.

Der Strom führt eigene DEK-Epochen. Dieselben Grenzen gelten: 15 Minuten bis 8 Stunden, Ausgangswert 60 Minuten. Segmentformat, Hash-Kette und HSM-Signatur entsprechen den übrigen Strömen. Die Epochenbestätigung liegt beim Datenschutzbeauftragten der Plattform. Pro schreibender Instanz gibt es höchstens eine offene Epoche. Im Klartext stehen das Ereignis, der Grund `mandant_unbekannt` und die genannten Bezüge. Eine Zugehörigkeitsaussage fügt der Dienst nicht hinzu.

Nennt das Ereignis Personen oder eine Vorgangsnummer, entstehen Verweise im Verzeichnis der Plattform. Dieses Verzeichnis hat die Rolle `verzeichnis` im Bucket `plattform`, eigene `ablage_id`, gewrappt mit dem Plattform-KEK, mit eigenen DEK-Epochen, eigener Hash-Kette und eigener HSM-Signatur. Ein Ereignis ohne Person und ohne Vorgangsnummer hat keinen Verweis. Das Ereignis gilt erst als angenommen, wenn die Annahme am Ziel den Eintrag, die vorhandenen Verweise und, soweit eine Vorgangsnummer genannt ist, die Einträge im Vorgangsindex des Buckets `plattform` nennt. Die Antwort an den Aufrufer nennt das Ziel `plattform/auffang`. Diese Ablage gilt nicht als Ablage bei einem Mandanten.

Der Strom kann Ereignisse enthalten, die sachlich zu verschiedenen Mandanten gehören. Öffnen kann ihn nur der Datenschutzbeauftragte der Plattform, in demselben Werkzeug und nur im Umfang der Auswahl. Ein Mandant erhält den Plattform-KEK nicht. Der Plattform-KEK öffnet keine Gruppen- und keine Einzel-Epoche. In der Dead Letter Box eines Mandanten öffnet er nur die Epochen mit dem Grund `kek_fehlt`. Der Dienst verschiebt einen abgelegten Eintrag später nicht in einen Gruppen- oder Einzelstrom und schreibt ihn nicht um.

Das technische Log nennt Zeitpunkt, erzeugenden Dienst, den Grund `mandant_unbekannt` und das Ziel `plattform/auffang`. Inhalt, Personenkennungen und Vorgangsnummern stehen dort nicht.

Ist der Plattform-KEK nicht aus dem tmpfs lesbar, läuft der Schreibprozess nicht. Ein bereits laufender Prozess nimmt keine weiteren Ereignisse an, sobald das Secret verschwindet. Er verwirft sie nicht. Der öffentliche Schlüssel lässt sich aus einem verbliebenen Träger wieder herstellen und erneut als Secret übergeben. Schon abgelegte Epochen bleiben dabei lesbar, solange ein Träger des zugehörigen privaten Schlüssels existiert.

Ist der Mandant ermittelt und kein aktueller KEK von ihm lesbar, entsteht die Epoche in seiner Dead Letter Box mit dem Grund `kek_fehlt`. Das Lesen steht unter [Cache des Schreibprozesses](schluessel.md#cache-des-schreibprozesses). Das technische Log nennt den Mandantennamen und diesen Grund, ohne Inhalt, Personenkennung oder Vorgangsnummer. Der Name an dieser Stelle ist die betriebliche Ausnahme der sichtbaren Metadaten. Eine Gruppen-, Einzel- oder Verzeichnis-Epoche unter dem fehlenden Mandanten-KEK beginnt nicht. Der Datenschutzbeauftragte des Mandanten sieht diese Epoche am Präfix, öffnen kann er sie nicht. Das Werkzeug des Plattform-Schlüssels öffnet sie.

### Verlust und Wechsel des Plattform-Schlüssels

Im sicheren Modus liegt derselbe private Schlüssel auf zwei Trägern. Fällt ein Träger aus und ist der Schlüssel nicht entwendet, öffnet der andere dieselben Epochen. Neue Epochen wickelt der öffentliche Schlüssel im tmpfs. Ablauf, planmäßiger Wechsel, Verlust und Kompromittierung folgen dem Abschnitt [Wechsel, Verlust und Kompromittierung](schluessel.md#wechsel-verlust-und-kompromittierung). Eine Epoche, die dieser Schlüssel gewrappt hat, wird nicht an einen Mandanten-KEK umgewickelt. Über ihm gibt es keine weitere Hülle.

## Verkettung

Jeder Strom, ob Gruppe, gemeinsamer Einzelpräfix, Auffangstrom, Plattform-Auffang, Verzeichnis, Vorgangsindex, Summenindex oder Stromkatalog, führt je Epoche eine Hash-Kette über die Ciphertexte. Der Klartext geht nicht in den Hash ein. Jede Epoche beginnt eine neue Hash-Kette. Diese Kette belegt Reihenfolge und Vollständigkeit der Einträge dieser Epoche.

Die Epochen einer Ablage hängen zusätzlich über Epochenmanifeste zusammen. Pro Ablage und schreibender Instanz gibt es eine Manifestkette. Am Einzelpräfix ist die Ablage der Präfix: die Epochen aller Personen dieser Instanz hängen an derselben Kette, in der Abschlussreihenfolge. Schreiben mehrere Instanzen in dieselbe Ablage, führen sie diese Ketten nebeneinander. Die Historie der Ablage ist die Gesamtheit dieser Ketten. Die Manifestkette folgt der Abschlussreihenfolge dieser Instanz. Ein List über die Ablage bleibt nach dem Beginn der Epochenkennung geordnet. Ein Wechsel des KEK beginnt keine neue Manifestkette.

### Bildung der Kette

Die Hashfunktion ist SHA-256. Die Integritätssignatur ist ECDSA auf der Kurve P-256 mit SHA-256. Die Signatur steht als `r || s`, jede Koordinate eine vorzeichenlose 32-Byte-Zahl in Big-Endian.

`L(x)` ist die Bytezahl von `x` als vorzeichenlose 32-Bit-Zahl in Big-Endian. Ein Feld variabler Länge steht als `L(x) || x`. Texte stehen in UTF-8. Hashwerte und der Zertifikatsfingerabdruck sind 32 Byte und haben kein Längenfeld. `seq` und `entry_count` sind vorzeichenlose 64-Bit-Zahlen in Big-Endian. Die Nonce ist 12 Byte, das GCM-Tag 16 Byte. Der Zeitstempel ist die Unix-Zeit in Millisekunden als vorzeichenlose 64-Bit-Zahl in Big-Endian und steht im Klartext des Eintrags. `mandant_id`, `ablage_id`, `bind_id`, `dek_id` und `instanz_id` sind 16 Byte ohne Längenfeld. `epoch_id` ist 36 Byte ohne Längenfeld: 16 Byte ASCII `YYYYMMDDThhmmssZ` für den Beginn des Rasters, danach `instanz_id`, danach `epoch_prefix`. Jede Hash- und Signatur-Eingabe beginnt mit einer Domänenkennung. Die Domänenkennung ist ASCII und wird wie ein Textfeld geschrieben. Gehasht werden nur die hier genannten Felder. Die Segmenthülle geht nicht ein.

Der Zertifikatsfingerabdruck ist SHA-256 über die DER-Kodierung des Zertifikats. Das ist der Wert, den der Epochenkopf im Klartext nennt.

Die Nonce ist 12 Byte und hat die Form `epoch_prefix || seq`. `epoch_prefix` sind 4 Byte aus dem kryptografischen Zufallszahlengenerator, gezogen einmal beim Erzeugen des DEK dieser Epoche. `seq` sind dieselben 8 Byte wie im Eintrag und in den Zusatzdaten, vorzeichenlos und Big-Endian. Unter demselben DEK kommt jede Nonce einmal vor.

Der erste Eintrag trägt `seq` 1. Jeder weitere Eintrag der Epoche trägt den um 1 höheren Wert. Der Zähler läuft nicht modulo. Passt der nächste Wert nicht mehr in 64 Bit, verschlüsselt der Dienst den Eintrag nicht, schließt die Epoche und beginnt die nächste mit einem neuen DEK.

`seq` wird vergeben, bevor der Eintrag verschlüsselt wird. Unter einem DEK gibt es einen Zähler. Vergeben mehrere Schreibstränge Einträge derselben Epoche, geschieht das unter gegenseitigem Ausschluss. Ein angenommener Eintrag behält die beim Verschlüsseln entstandenen Bytes. Ein zweites Verschlüsseln derselben `seq` mit anderem Klartext findet nicht statt. Schlägt das Verschlüsseln fehl, wird diese `seq` nicht erneut vergeben; die Epoche endet, und die folgende beginnt mit einem neuen DEK. Schlägt das Schreiben am Ziel fehl, wiederholt der Dienst dieselben Bytes. Die `seq` bleibt, und die Epoche endet deshalb nicht. In die Hash-Kette gehen die Datensätze der angenommenen Segmente ein, einschließlich Fortsetzung und Füllung. Jeder dieser Datensätze ist ein Rahmen der unter [Sichtbare Metadaten](#sichtbare-metadaten) festgelegten Größe. Der Klartext eines solchen Rahmens beginnt mit der Art als einem Byte: `ereignis` = 1, `fortsetzung` = 2, `fuellung` = 3. Dieselben Werte gelten im Bindungsblob. Aufbau des Ereignisses und der Rahmen steht unter [Rahmen und Größenklassen](#rahmen-und-größenklassen).

`head_n` ist das Glied des Eintrags mit dieser `seq`. `entry_count` ist die Anzahl der Rahmen in der Kette und zählt Epochenkopf und Manifest nicht mit. Fortsetzung und Füllung zählen mit. `dek_id` ist in Kopf, Zusatzdaten und Einträgen dieselbe 16-Byte-Folge.

Die authentisierten Zusatzdaten sind genau diese Bytes, und dieselben Bytes gehen in die Kette ein:

```
aad = mandant_id
   || ablage_id
   || epoch_id
   || dek_id
   || seq
```

```
genesis = SHA-256(
    L("genesis") || "genesis" ||
    ablage_id ||
    instanz_id)

head_0 = SHA-256(
    L("epoch-head") || "epoch-head" ||
    ablage_id ||
    kek_fingerabdruck ||
    epoch_id ||
    dek_id ||
    L(wrapped_dek) || wrapped_dek)

head_n = SHA-256(
    L("entry") || "entry" ||
    head_{n-1} ||
    dek_id ||
    seq ||
    nonce ||
    L(ciphertext) || ciphertext ||
    tag ||
    L(aad) || aad)
```

`wrapped_dek` ist die Bytefolge des gewrappten DEK, wie sie im Epochenkopf steht. Damit hängt der Datenschlüssel an derselben Kette wie die Einträge. `chain_head` ist `head_entry_count`. Hat die Epoche keine Einträge, ist `chain_head` gleich `head_0`.

`epoch_id` ist die Epochenkennung. Die erste Epoche einer Instanz in dieser Ablage setzt `previous_epoch_hash` auf `genesis`. Jede folgende Epoche setzt `previous_epoch_hash` auf den `epoch_hash` des letzten von dieser Instanz signierten Manifests in dieser Ablage. Die Kennung der Instanz in der Epochenkennung ist dieselbe `instanz_id` wie in `genesis`. Der neue KEK-Fingerabdruck steht in `head_0` der neuen Epoche.

```
manifest_payload =
    L("manifest") || "manifest" ||
    epoch_id ||
    previous_epoch_hash ||
    chain_head ||
    entry_count ||
    annahme_first ||
    annahme_last ||
    annahme_head

signature = ECDSA-P256-SHA-256(manifest_payload)

epoch_hash = SHA-256(
    L("epoch-hash") || "epoch-hash" ||
    manifest_payload ||
    L(signature) || signature)
```

Der Integritätsschlüssel im HSM signiert `manifest_payload`. Die Signatur öffnet keinen Inhalt. Das Manifest aus `epoch_id`, `previous_epoch_hash`, `chain_head`, `entry_count`, `annahme_first`, `annahme_last`, `annahme_head` und `signature` steht im letzten Segment.

`annahme_first` und `annahme_last` sind die `batch_seq` der ersten und der letzten Annahme dieser Instanz, die einen Eintrag dieser Epoche nennt. `annahme_head` ist der `annahme_hash` von `annahme_last`. Hat die Epoche keine Einträge, sind `annahme_first` und `annahme_last` 0 und `annahme_head` 32 Nullbytes. `batch_seq`, `annahme_first` und `annahme_last` sind vorzeichenlose 64-Bit-Zahlen in Big-Endian. Die Annahme und ihr Hash sind im [Wiederanlauf](ablage-und-lesen.md#wiederanlauf) beschrieben. Das Manifest bindet die Epoche an genau diese Annahmen.

Eine laufende Epoche hat noch kein Manifest. Die Instanz bildet es beim Abschließen. Die folgende Epoche übernimmt den dabei entstandenen `epoch_hash`. Nach einem Neustart schreibt die Instanz einen im Spool bereits verschlüsselten Abschluss zu Ende und schließt die offene Epoche danach nur über die angenommenen Ciphertexte. Den unvollständigen Rest signiert sie nicht in das Manifest. Neue Ereignisse beginnen eine neue Epoche. Der Klartext-DEK wird dafür nicht gebraucht.

### Abschluss

Die HSM-Signatur belegt, dass das HSM dieses Manifest signiert hat. Den Abschluss der Epoche bildet die Epochenbestätigung dieses `epoch_hash` durch den Empfänger.

Der Empfänger signiert mit seinem Bestätigungsschlüssel:

```
confirmation_payload =
    L("confirm") || "confirm" ||
    epoch_hash

confirmation = ECDSA-P256-SHA-256(confirmation_payload)
```

Der private Bestätigungsschlüssel bleibt beim Empfänger. Der Schreibpfad hat ihn nicht. Im Schlüsselspeicher liegt der öffentliche Schlüssel, Key Usage `digitalSignature`. An der Epochenbestätigung steht der Fingerabdruck dieses Schlüssels, SHA-256 über das SubjectPublicKeyInfo in DER. Ein abgelöster öffentlicher Schlüssel bleibt prüfbar.

Für die Ströme eines Mandanten bestätigt der Mandant. Für den Plattform-Auffang und sein Verzeichnis bestätigt der Datenschutzbeauftragte der Plattform. Der Bestätigungsspeicher liegt beim Empfänger, außerhalb des Schreibpfads und außerhalb des Log-Buckets. Der Schreibpfad reicht das signierte Manifest ein. Ein Eintrag wird dort weder ersetzt noch gelöscht. Die Epochenbestätigung bleibt bestehen, wenn die Segmente nach Frist gelöscht werden. Der Löschvorgang reicht vor dem ersten entfernten Segment einen Löschvermerk ein. Der Speicher hängt ihn an. Er nennt den Löschtag. Das Verfahren steht unter [Löschen](ablage-und-lesen.md#löschen).

Der Speicher bestätigt je Strom und Instanz das erste Manifest, dessen HSM-Signatur gültig ist und dessen `previous_epoch_hash` die `genesis` oder der `epoch_hash` des bestätigten Vorgängers ist. Dieselbe `epoch_id` und derselbe `previous_epoch_hash` werden kein zweites Mal bestätigt. Ein weiteres Manifest mit gültiger HSM-Signatur wird behalten und als Verzweigung geführt. Es wird nicht der Abschluss.

Die Historie einer Instanz sind die bestätigten Manifeste. Das Manifest im Segment muss denselben `epoch_hash` tragen wie die Epochenbestätigung. Eine Abweichung ist eine Verzweigung, auch wenn beide HSM-Signaturen gültig sind. Ein Nachfolger, dessen `previous_epoch_hash` nicht der bestätigte `epoch_hash` ist, setzt die Historie nicht fort. Fehlt die Epochenbestätigung zu einer noch vorhandenen Epoche, ist das eine Lücke.

Neue Ereignisse werden mit der Annahme ihres Gruppenabschlusses am Ziel angenommen. Die Epochenbestätigung läuft daneben. Die Instanz reicht das Manifest beim Abschließen ein und setzt die nächste Epoche auf den `epoch_hash` dieser Fassung.

Das Werkzeug setzt die Hash-Kette neu und vergleicht sie mit `chain_head` und `entry_count`. Es prüft, dass jede Nonce der Epoche einmal vorkommt und dass ihre letzten 8 Byte gleich der `seq` des Eintrags sind. Es prüft, dass die `ablage_id` der Zusatzdaten die des Objektschlüssels ist. Den DEK braucht diese Prüfung nicht. Es prüft die HSM-Signatur über `manifest_payload`, die Epochenbestätigung über `confirmation_payload` und das Aufsetzen auf dem bestätigten Vorgänger. Es geht die Annahmen von `annahme_first` bis `annahme_last`, prüft `annahme_head` und die Previous-Kette und öffnet den Bindungsblob. Darin kommt jede `seq` der Epoche genau einmal vor. Ein Objekt ohne Annahme ist kein Glied. Kette, Segment-Hashes und Epochenbestätigung bleiben ohne den Blob prüfbar. Über die Epochenbestätigungen lässt sich die Kette bis zur `genesis` prüfen, ohne die Segmente zu öffnen.

## Sichtbare Metadaten

Wer Objektspeicher, Platte oder ein Backup liest, sieht Objektschlüssel, Objektgrößen, Zusatzdaten, Epochenköpfe, Manifeste und den Klartext der Annahmen. Personenkennung, Vorgangsnummer, Kohortenname und der Zeitpunkt eines Ereignisses stehen dort nicht. Sie stehen im Ciphertext. Dieser Abschnitt ist die Freigabe dessen, was ohne privaten Schlüssel sichtbar bleibt, und die Festlegung, wie die Ablage es begrenzt.

### Kennungen

`mandant_id` und `ablage_id` sind je 16 Byte aus dem kryptografischen Zufallszahlengenerator. Die `mandant_id` entsteht mit dem Mandanten und liegt im Schlüsselspeicher. Die `ablage_id` ist die Stromkennung eines Gruppenstroms, des Auffangstroms, des Verzeichnisses, des Vorgangsindex, eines Summenindex, des Stromkatalogs oder des gemeinsamen Einzelpräfixes. Das Register vergibt sie. Der Name einer Kohorte ist keine Stromkennung.

`bind_id` ist 16 Byte. Bei einem Gruppenstrom, beim Auffang, beim Verzeichnis, beim Index und beim Katalog ist sie gleich der `ablage_id`. Bei einer Einzelperson ist sie das undurchsichtige Kennzeichen aus dem Register und von der `ablage_id` des Einzelpräfixes verschieden. `dek_id` wird je DEK neu gezogen und nicht aus der `bind_id` abgeleitet. `instanz_id` ist 16 Byte.

`epoch_id` nennt den Beginn des Rasters, in dem geschrieben wurde. Ein Neustart im selben Raster trägt denselben Beginn und ein anderes `epoch_prefix`. Der Zeitpunkt des Ereignisses steht im Klartext des Eintrags.

Im Objektschlüssel stehen `mandant_id` und `ablage_id` als 32 Hexzeichen in Kleinbuchstaben. Die Epochenkennung steht als `{raster}-{instanz_hex}-{prefix_hex}`.

```
{mandant_id}/{ablage_id}/{epoch_id}/{segment_nr}
```

`segment_nr` beginnt bei 1 und steigt je Segment der Epoche um 1. Sie steht dezimal ohne führende Nullen. Das Werkzeug liest die Segmente nach dieser Nummer aus der Annahme.

Ein List über `{mandant_id}/{ablage_id}/` liefert die Epochen dieser Ablage in zeitlicher Ordnung. Ein List über das Raster-Präfix liefert die Epochen dieses Zeitfensters. Dafür wird nichts entschlüsselt.

Im Bucket `plattform` ist `mandant_id` die 16 Byte der ASCII-Zeichenfolge `plattform`, aufgefüllt mit Nullbytes. Der Bucketname `plattform` bleibt.

Ein eigener Bucket je Mandant trägt den Mandanten im Bucketnamen. Die Objektmenge und die Schreibzeitpunkte dieses Buckets sind die Aktivität dieses Mandanten. Ein gemeinsamer Bucket führt jeden Mandanten unter seiner `mandant_id`. Sichtbar ist die Aktivität dieser Kennung. Den Namen liefert der Schlüsselspeicher. Das eigene Ziel eines Mandanten ist dieser Bucket oder diese Wurzel. `belegt/`, `instanz/`, `vorbereitung/` und `annahme/` bleiben im gemeinsamen Ziel.

### Stromkatalog

Der Stromkatalog ist ein Strom des Mandanten mit eigener `ablage_id`, gewrappt mit dem KEK des Mandanten. Das Werkzeug erfährt `mandant_id` und diese `ablage_id` bei der Hinterlegung des Schlüssels. Ein Export der Logs umfasst den Katalogstrom. Der Schreibprozess liest das Register. Bevor er eine neue Kennung in einem Logstrom verwendet, schreibt er einen Stand in den Katalog.

Ein Stand nennt den Mandantennamen und jede bisher vergebene Kennung: die Rolle, `ablage_id`, `bind_id` und bei einer Gruppe den Kohortennamen. Abgeschaltete Kennungen bleiben im Stand. Person und Vorgangsnummer eines Ereignisses stehen im Katalog nicht. Der Katalog führt eigene Epochen, eine eigene Hash-Kette und eine eigene Epochenbestätigung. Im Bucket `plattform` liegt ein Katalog derselben Art, gewrappt mit dem Plattform-KEK, ohne Kohortennamen.

### Hülle

Die Hash-Kette über `genesis` und `head_0` bindet die `ablage_id`. Die `bind_id` einer Einzelperson geht dort nicht im Klartext ein. Sie steht in den 48 Byte des Wraps und im Klartext des Eintrags. Das Werkzeug prüft nach dem Öffnen des DEK, dass beide übereinstimmen und zum Katalog passen.

### Rahmen und Größenklassen

Jeder Datensatz der Kette ist genau ein Rahmen. Die Rahmengröße gilt je Mandant, Ausgang 1024 Byte, Grenzen 256 und 8192, Zweierpotenz. Nonce und Tag liegen im Rahmen, der übrige Raum ist Ciphertext. Die Nutzlänge ist die Rahmengröße minus 28. Passt ein Ereignis nicht in einen Rahmen, setzen die folgenden Sequenznummern es als `fortsetzung` fort. Füllung trägt keinen Ereignisinhalt.

Der Klartext eines Ereignisses wird vor der Aufteilung auf Rahmen gefasst. Der `event_hash` deckt nicht diesen Klartext, sondern den Aufruf unter [Inhalte](#inhalte).

```
klartext =
    event_id ||
    zeitstempel ||
    bind_id ||
    L(inhalt) || inhalt
```

`event_id` und `bind_id` sind 16 Byte. Der Zeitstempel ist die Unix-Zeit in Millisekunden. `inhalt` ist der übrige Ereignisinhalt. Bei einem Logeintrag liegt darin die Zugehörigkeitsaussage, soweit der Eintrag sie mitführt. Verzeichnis, Index und Katalog verwenden dieselbe Hülle und ihren eigenen Inhalt. Die Bytefolgen stehen unter [Inhalte](#inhalte).

Der Klartext eines Rahmens der Kette ist genau die Nutzlänge. Er beginnt mit der Art. Dahinter liegt das Stück des Ereignisses. Nur der letzte Rahmen eines Ereignisses endet mit Zufallsbytes. Jeder vorausgehende Rahmen ist nach der Art voll. Der Zufall kommt aus dem kryptografischen Zufallszahlengenerator.

```
ereignis     = art || gesamt || stück || zufall
fortsetzung  = art || stück || zufall
fuellung     = art || zufall
```

`gesamt` ist die Bytezahl des gesamten Klartexts als vorzeichenlose 64-Bit-Zahl und steht nur im ersten Rahmen. Eine Fortsetzung setzt das Stück in der Reihenfolge der Sequenz fort. Das Werkzeug setzt die Stücke zusammen und prüft die Länge an `gesamt`.

Ein Segmentobjekt hat eine der Größen 256 KiB, 1 MiB, 4 MiB, 16 MiB oder 32 MiB. Ein Segment, das nicht das letzte der Epoche ist, hat genau die konfigurierte Segmentgröße. Fehlen an diesem Schnitt Rahmen, sind es Füllrahmen. Das letzte Segment hat die kleinste Klasse, die seinen Inhalt fasst. Zum Inhalt gehören der Epochenkopf, soweit er in diesem Segment liegt, die Rahmen der Ereignisse und das Manifest. Fehlen vor dem Manifest Rahmen, sind es Füllrahmen. Der Epochenkopf ist nicht verschlüsselt und zählt nicht als Rahmen der Kette. Er belegt die ersten ganzen Rahmen des ersten Segments:

```
kopf = kek_fingerabdruck || dek_id || L(wrapped_dek) || wrapped_dek
```

Reicht ein Rahmen nicht, setzt der nächste Kopfrahmen die Bytefolge fort. Der angebrochene letzte Kopfrahmen endet mit Zufallsbytes. Die Länge des gewrappten DEK folgt aus dem KEK. Das Manifest belegt den letzten Rahmen des letzten Segments, unverschlüsselt. Es zählt nicht als Rahmen der Kette.

```
manifest_rahmen = manifest_payload || signature || zufall
```

`manifest_payload` hat die feste Länge der Manifestfelder. `signature` ist die 64 Byte der HSM-Signatur ohne Längenfeld. Dazwischen, in den Rahmen der Kette, liegen Ereignis, Fortsetzung und Füllung. Fülleinträge stehen in der Hash-Kette. `entry_count` zählt sie mit. Die Zahl der Ereignisse ist das nicht.

### Inhalte

`inhalt` ist je Strom festgelegt. Texte sind UTF-8 und stehen als `L(s) || s`. `text` ist die vom Aufrufer gelieferte Bytefolge und unterliegt dieser Prüfung nicht. Personen und Vorgangsnummern stehen in der Reihenfolge des Aufrufs. Eine leere Personenkennung wird abgelehnt, dieselbe Person zweimal ebenfalls.

Der `event_hash` deckt den Aufruf. Ist keine Vorgangsnummer genannt, ist ihre Länge 0. `anzahl` ist eine vorzeichenlose 32-Bit-Zahl. Jede Person steht als `L(person) || person`.

```
aufruf =
    L("aufruf") || "aufruf" ||
    zeitstempel ||
    L(vorgang) || vorgang ||
    anzahl || personen ||
    L(text) || text
```

Die Rollen der Ströme sind ein Byte: `gruppe` = 1, `einzel` = 2, `auffang` = 3, `verzeichnis` = 4, `vorgang` = 5, `katalog` = 6, `verzeichnis-summe` = 7, `vorgang-summe` = 8.

Die Rolle einer Person in der Aussage ist ein Byte: `person` = 1, `datenschuetzer` = 2. Das Ablagemerkmal ist ein Byte und steht nicht in der Aussage: `gruppe` = 1, `einzeln` = 2.

Die Gründe des Auffangstroms sind ein Byte: `unbekannt` = 1, `aussage_ungueltig` = 2, `ziel_fehlt` = 3, `ohne_bezug` = 4, `kek_fehlt` = 5, `mandant_unbekannt` = 6.

Die Zugehörigkeitsaussage ist die signierte Nutzlast. `gueltig_von` und `gueltig_bis` sind die Unix-Zeit in Millisekunden. Der Zeitpunkt liegt in der Gültigkeit, wenn er größer oder gleich `gueltig_von` und kleiner oder gleich `gueltig_bis` ist. Der Fingerabdruck ist 32 Byte. Bei der Rolle `person` ist er 32 Nullbytes. Bei `datenschuetzer` ist er der Fingerabdruck des Aufrufschlüssels und nicht null. Die Signatur ist die 64 Byte `r || s` von ECDSA P-256. Prüfschlüssel, Aufrufschlüssel, Integritätsschlüssel und Bestätigungsschlüssel sind dieser Algorithmus. Die Verwaltung legt keinen anderen für sie ab. Die signierte Nutzlast ist dieselbe.

```
aussage =
    L("aussage") || "aussage" ||
    mandant_id ||
    L(person) || person ||
    rolle ||
    gueltig_von ||
    gueltig_bis ||
    fingerabdruck
```

Im Log steht dazu `L(aussage) || aussage || L(signatur) || signatur`.

Ein Gruppen- oder Einzeleintrag trägt die Aussagen der Personen, deren Strom dieser Eintrag ist, in der Reihenfolge des Aufrufs. Die Bezüge nennen jede Person des Aufrufs, ebenfalls in dieser Reihenfolge. Ist mindestens eine Person `einzeln`, entstehen nur die Einzelströme dieser Personen. Die übrigen Personen stehen in den Bezügen und erhalten keinen eigenen Eintrag. Lässt sich daneben eine Person nicht zuordnen, entsteht keine zweite Kopie im Auffangstrom.

```
log =
    L("log") || "log" ||
    L(text) || text ||
    L(vorgang) || vorgang ||
    anzahl_aussagen || aussagen ||
    anzahl_bezuege || bezuege
```

Der Auffang trägt `angabe` nur bei `mandant_unbekannt`. Das ist der im Ereignis genannte Mandantenwert. Aussagen stehen nur bei `ziel_fehlt`, eine je genannter Person, und die Person in der Aussage ist die Person an derselben Stelle. In den übrigen Gründen ist die Zahl der Aussagen 0. `ohne_bezug` nennt keine Person.

```
auffang =
    L("auffang") || "auffang" ||
    grund ||
    L(text) || text ||
    L(vorgang) || vorgang ||
    L(angabe) || angabe ||
    anzahl_aussagen || aussagen ||
    anzahl_personen || personen
```

Lässt sich keine Person einem Gruppen- oder Einzelstrom zuordnen, gilt die erste passende Lage. Keine Person ergibt `ohne_bezug`. Eine ungültige Aussage ergibt `aussage_ungueltig`. Eine unbekannte Person ergibt `unbekannt`. Sonst ist der Grund `ziel_fehlt`. `kek_fehlt` und `mandant_unbekannt` gelten vor dieser Reihe und tragen keine Aussage.

Ein Verzeichnisverweis zeigt auf einen Logeintrag. `art` ist `person` = 1 oder `vorgang` = 2. `schluessel` ist die Person oder die Vorgangsnummer. `bind_id`, `epoch_id` und `seq` bezeichnen den Logeintrag. `mandant_id` ist der Mandant dieses Eintrags. Die `bind_id` in der Hülle des Verweises ist die der Verzeichnisablage. Zu jedem Logeintrag entsteht ein Personenverweis je genannter Person und, wenn eine Vorgangsnummer genannt ist, ein Verweis auf diese Nummer. Alle zeigen auf diesen Logeintrag.

```
verweis =
    L("verweis") || "verweis" ||
    art ||
    L(schluessel) || schluessel ||
    mandant_id ||
    bind_id ||
    epoch_id ||
    seq
```

Ein Vorgangsindexeintrag nennt die Rolle der Ablage des Logeintrags. Die Kohorte steht nur bei `gruppe`, sonst ist ihre Länge 0. Zu jedem Logeintrag mit Vorgangsnummer entsteht ein Eintrag je genannter Person. Eine Vorgangsnummer ohne genannte Person erzeugt keinen Eintrag. Der Zeitstempel ist der des Logeintrags. Die `bind_id` in der Hülle ist die der Indexablage.

```
vorgang =
    L("vorgang") || "vorgang" ||
    L(nummer) || nummer ||
    L(person) || person ||
    rolle ||
    L(kohorte) || kohorte ||
    epoch_id ||
    seq ||
    zeitstempel
```

Ein Katalogstand nennt den Mandantennamen und jede vergebene Kennung in der Reihenfolge der Vergabe. `aktiv` ist 0 oder 1. Abgeschaltete Kennungen bleiben. Die Kohorte ist nur bei `gruppe` gefüllt. Bei `einzel` ist `bind_id` von der `ablage_id` des Präfixes verschieden. Bei den übrigen Rollen sind beide gleich.

```
katalog =
    L("katalog") || "katalog" ||
    L(name) || name ||
    anzahl || kennungen

kennung =
    rolle ||
    ablage_id ||
    bind_id ||
    L(kohorte) || kohorte ||
    aktiv
```

Ein Beleg nennt eine Epoche des zugrunde liegenden Stroms und den Hash ihres bestätigten Manifests. Das ist der `epoch_hash`. Die Summe eines Monats nennt jede Epoche dieses Monats genau einmal, in der Abschlussreihenfolge.

```
beleg =
    L("beleg") || "beleg" ||
    epoch_id ||
    epoch_hash
```

`verzeichnis-summe` trägt danach dieselben Verweise wie das Verzeichnis dieses Monats. Zuerst die Personenverweise, geordnet nach Person, Epoche und Sequenz, danach die Verweise auf Vorgangsnummern in derselben Ordnung.

`vorgang-summe` trägt danach je Vorgangsnummer die verschiedenen Personen und je Person die Vorgangsnummern. Ein Strom ist die Rolle und, bei einer Gruppe, der Kohortenname. `erster` und `letzter` sind die Unix-Zeit in Millisekunden. Dieselbe Person in demselben Strom steht je Vorgangsnummer nur einmal.

```
vorgang-summe =
    L("vorgang-summe") || "vorgang-summe" ||
    L(nummer) || nummer ||
    anzahl || personen

person =
    L(person) || person ||
    rolle ||
    L(kohorte) || kohorte ||
    erster ||
    letzter

person-summe =
    L("person-summe") || "person-summe" ||
    L(person) || person ||
    anzahl || nummern

nummer =
    L(nummer) || nummer ||
    rolle ||
    L(kohorte) || kohorte ||
    erster ||
    letzter
```

Die Personen einer Vorgangsnummer stehen nach Person, Rolle und Kohorte. Die Nummern einer Person stehen nach Nummer, Rolle und Kohorte. `anzahl` ist mindestens 1. `letzter` ist nicht kleiner als `erster`.

Die Anfrage an den Suchprozess ist die signierte Nutzlast. `zone` ist die Instanzkennung dieses Suchprozesses. `art` ist `vorgang` = 1 oder `person` = 2. `schluessel` ist die Vorgangsnummer oder die Person. `von` und `bis` sind die Unix-Zeit in Millisekunden, `bis` ist größer als `von`. `zeitpunkt` ist der Zeitpunkt der Anfrage.

```
anfrage =
    L("anfrage") || "anfrage" ||
    mandant_id ||
    zone ||
    L(person) || person ||
    art ||
    L(schluessel) || schluessel ||
    von ||
    bis ||
    zeitpunkt
```

Die Ereignisschnittstelle nimmt diese Bytefolge. `aufruf` ist die oben festgelegte Folge, vollständig und mit ihrer Domänenkennung. Ist ein Mandant ermittelt, ist `angabe` leer. Fehlt der Mandant, steht in `angabe` der genannte Mandantenwert und `mandant_id` ist 16 Nullbytes.

```
ereignis =
    L("ereignis") || "ereignis" ||
    event_id ||
    mandant_id ||
    L(angabe) || angabe ||
    L(aufruf) || aufruf
```

Die Antwort verlässt den Dienst erst nach der Annahme.

```
bestaetigt =
    L("bestaetigt") || "bestaetigt" ||
    event_id ||
    annahme_hash ||
    batch_seq ||
    L(annahme_schluessel) || annahme_schluessel
```

### Annahmen

Die Annahme bleibt für den Schreibprozess lesbar. Im Klartext stehen die Plätze `event_id || event_hash` und die Segmentreferenzen. Die Zuordnung, welcher Platz ein Ereignis ist und welche Sequenzen der Abschluss geschrieben hat, steht im Klartext des Bindungsblobs. Den Bindungsschlüssel wrappt derselbe Schlüssel, der die Epochen dieses Anteils wrappt. Der Klartext nennt jede Sequenz dieses Abschlusses in Log, Verzeichnis und Vorgangsindex, einschließlich Fortsetzung und Füllung, und markiert die Art. Plätze ohne Ereignis tragen eine zufällige `event_id` und einen zufälligen `event_hash`. Die Zahl der Plätze ist die nächste Zweierpotenz der Zahl der Ereignisse, mindestens 8. Liegt kein Ereignis vor, ist die Zahl der Plätze ebenfalls 8. Die Plätze der Ereignisse stehen vorn, in der Reihenfolge des Abschlusses. Die Plätze ohne Ereignis folgen dahinter.

Der Schreibprozess findet eine wiederholte `event_id` im Klartext und prüft den `event_hash`, ohne den Blob zu öffnen. Die Bytes des Blobs stehen in der Vorbereitung. Der Wiederanlauf übernimmt sie, ohne sie zu öffnen.

### Deckverkehr

Deckverkehr ist je Mandant `aus` oder `an`. Ausgang ist `aus`.

Bei `aus` entsteht eine Epoche nur, wenn in ihrem Raster Ereignisse geschrieben wurden. Bei `an` schreibt die Instanz für jeden Gruppenstrom, für den Auffangstrom und für den Einzelpräfix in jedem Raster eine Epoche. Liegen keine Ereignisse vor, besteht sie aus Fülleinträgen und einem Segment der kleinsten Größenklasse. Die Annahme dazu hat acht Plätze, und der Blob nennt nur Füllsequenzen. Am Einzelpräfix stehen die Epochen der Personen daneben. Wie viele es sind, bleibt sichtbar.

### Freigabe

Ohne den privaten Schlüssel bleibt sichtbar:

- die `mandant_id`, ihre Objektmenge und die Schreibzeitpunkte ihrer Objekte; bei einem eigenen Bucket zusätzlich der Bucketname
- je Gruppenstrom die `ablage_id` und die Raster, in denen eine Epoche liegt; ohne Deckverkehr auch das Fehlen eines Rasters
- am Einzelpräfix die Zahl der Epochen je Raster und die Größenklasse jeder Epoche
- die Zweierpotenz der Plätze einer Annahme und die Segmentreferenzen darin, also welche Ablage und welche Epoche der Abschluss berührt hat
- Sequenznummern einschließlich Füllung und Fortsetzung, `entry_count`, Rahmengröße und Größenklasse
- der Fingerabdruck des KEK und die Art des Schlüssels an der Länge des gewrappten DEK und des gewrappten Bindungsschlüssels
- am Bindungsblob die Nonce und die Länge des Ciphertexts; Sequenz, Art und `event_id` stehen darin nicht im Klartext
- Instanz, `batch_seq`, Manifestkette und die Signaturen
- Belegung: `event_id`, `instanz_id`, `batch_id`, Generation, Lage und `event_hash`; dazu die Frist im Instanzobjekt
- im technischen Log der Mandantenname beim Grund `kek_fehlt`

Die Betriebsmetriken sind eine eigene Freigabe an den Betrieb und gehören nicht zu dieser Liste. Ihr Umfang steht unter [Metriken](betrieb.md#metriken). Sie nennen keine Person, keine Vorgangsnummer, keinen Kohortennamen und keinen Ereignisinhalt.

Eine Verkehrsanalyse kann bei wenigen gleichzeitig aktiven Einzelpersonen Epochen aufeinanderfolgender Raster an Größe und Abstand wiedererkennen. Sie liefert keine `bind_id` und keinen Namen.

Ein Auslesen des Speichers der schreibenden Instanz sieht zusätzlich den Klartext der offenen Epoche, ihre DEKs und die Auflösung der Kennungen, die sie gerade verwendet. Abgeschlossene Epochen liegen dort nicht mehr im Klartext. Die dann noch sichtbaren Merkmale der Ablage sind die dieser Freigabe.
