# CryptLog — Schlüssel und Zugehörigkeit

Stand: 8. November 2026

Teil des [Konzepts Audit-Log-Verschlüsselung](README.md). Schlüssel, Schlüsselspeicher, Verteilung, Verwaltung, Cache, Hinterlegen des KEK, Zugehörigkeit, Wechsel, Verlust, Kompromittierung und die Grenze der Zusicherung.

## Schlüssel

Pro Mandant gibt es einen Schlüsselverschlüsselungsschlüssel (KEK). Das ist der öffentliche Schlüssel des Datenschutzbeauftragten, gebunden an ein Zertifikat. Mit ihm werden der DEK seiner Ströme und der Bindungsschlüssel der zugehörigen Annahmenteile gewrappt. Den Logtext verschlüsselt er nicht, und den Vorgangsindex wrappt er nicht.

| Schlüssel | Art | Lebensdauer | Ablage |
|---|---|---|---|
| KEK | öffentlich, im Zertifikat | Gültigkeit des Zertifikats | Schlüsselspeicher des Mandanten, getrennt von den Logströmen |
| Plattform-KEK | öffentlich, im Zertifikat | Gültigkeit des Zertifikats | Secret auf tmpfs, nur im Speicher des Schreibprozesses; wrappt den Plattform-Auffang und, wenn der KEK des Mandanten fehlt, die Dead Letter Box dieses Mandanten |
| Index-Schlüssel | öffentlich im Schreibprozess, privat nur im Suchprozess | Gültigkeit des Zertifikats | je ein tmpfs-Secret; wrappt den Vorgangsindex und den Bindungsschlüssel seines Anteils |
| privater Schlüssel | Gegenstück zum KEK | beim Datenschutzbeauftragten, bis die letzte damit gewrappte Epoche gelöscht ist | im sicheren Modus nur bei ihm, der Plattform-Schlüssel auf zwei Trägern; im einfachen Modus zusätzlich die verschlüsselte Kopie im Schlüsselspeicher |
| Signaturschlüssel der Zugehörigkeit | ECDSA P-256, SHA-256, Signatur des Mandanten | beim Mandanten | öffentlich im Schlüsselspeicher; privat nur beim Mandanten |
| Aufrufschlüssel | ECDSA P-256, SHA-256, Signatur der Suchanfrage | Gültigkeit der Aussage | öffentlich im Personenregister; privat bei der Person |
| DEK | symmetrisch, AES-256-GCM | 15 Minuten bis 8 Stunden | Klartext nur im Speicher der schreibenden Instanz; im Log nur gewrappt |
| Bindungsschlüssel | symmetrisch, AES-256-GCM | ein Abschluss, ein Klartext | Klartext nur im Speicher, solange der Blob entsteht; in der Annahme nur gewrappt |
| Integritätsschlüssel | ECDSA P-256, SHA-256, im HSM der Plattform | betreibergesteuert, nicht exportierbar | HSM; unabhängig vom KEK |
| Bestätigungsschlüssel | ECDSA P-256, SHA-256, Abschluss der Epoche | beim Empfänger | öffentlich im Schlüsselspeicher; privat beim Mandanten bzw. beim Datenschutzbeauftragten der Plattform |

Die Plattform wickelt DEKs der Logs und die zugehörigen Bindungsschlüssel ein. Sie wickelt sie nicht aus und bietet dafür keine API. Den Vorgangsindex öffnet allein der Suchprozess, mit dem privaten Index-Schlüssel, und nur diesen Strom, einschließlich des Bindungsschlüssels seines Anteils. Dieser Prozess ist die Sicherheitszone unter [Suche](ablage-und-lesen.md#suche).

## Schlüsselspeicher

Die Mandanten sind voneinander unabhängig. Das Schlüsselmaterial eines Mandanten liegt in einem eigenen Speicher, getrennt von seinen Logströmen. Das Personenregister ist ein weiterer eigener Speicher und unter [Zugehörigkeit](#zugehörigkeit) beschrieben. Objektspeicher und Platte der Segmente enthalten keines von beiden. Ein Backup der Logs enthält damit weder das Zertifikat, noch den verschlüsselten privaten Schlüssel, noch den Prüfschlüssel der Zugehörigkeit.

Der Schreibpfad hat auf diesen Speicher nur lesenden Zugriff, und nur auf die öffentlichen Schlüssel des Mandanten: den KEK und den Prüfschlüssel der Zugehörigkeit. Im einfachen Modus liegt der Speicher in einem Verzeichnis, im sicheren Modus an einem Server. Beides steht unter [Verteilung](#verteilung). Anlegen, Ersetzen und Löschen laufen über die [Verwaltung](#verwaltung). Der Betrieb der Plattform hat diesen Zugang nicht. Der Zugriff eines Mandanten erreicht den Schlüssel eines anderen Mandanten nicht.

Ist kein aktueller KEK des Mandanten lesbar, beginnt der Dienst keine Gruppen-, Einzel- oder Verzeichnis-Epoche unter einem Mandantenschlüssel. Lesbar heißt ein Cache-Eintrag innerhalb seines Höchstalters, im sicheren Modus aus einer übernommenen Veröffentlichung. Das Lesen steht unter [Cache des Schreibprozesses](#cache-des-schreibprozesses). Aktuell ist genau ein Zertifikat. Es ist gültig, nicht gesperrt und trägt keinen der Status `abgeloest`, `verloren` und `kompromittiert`. Die drei Status stehen unter [Wechsel, Verlust und Kompromittierung](#wechsel-verlust-und-kompromittierung). Das Ereignis wird nicht verworfen. Es geht in die Dead Letter Box des Mandanten und wird mit dem Plattform-KEK gewrappt. Der Dienst legt selbst keinen Mandanten-KEK an.

Der verschlüsselte private Schlüssel des einfachen Modus liegt im selben Speicher. Der Schreibpfad liest ihn nicht und übernimmt ihn nicht in den Cache. Der gewrappte DEK bleibt im Epochenkopf. Der Integritätsschlüssel bleibt im HSM der Plattform.

## Verteilung

Die Verteilung bringt dem Schreibprozess die öffentlichen Schlüssel und ihren Status. Den privaten Schlüssel eines Mandanten enthält sie nicht. Plattform-KEK und Index-Schlüssel bleiben eigene Secrets auf tmpfs und laufen nicht über diese Verteilung.

### Verzeichnis im einfachen Modus

Der Speicher eines Mandanten ist ein Verzeichnis. Der Schreibpfad bindet es nur lesend ein, als lokale Einbindung oder über NFS, und kann es nicht beschreiben. Die Verwaltung schreibt auf der Seite, die das Verzeichnis bereitstellt. Eine Änderung darin sieht der Schreibprozess spätestens mit dem Höchstalter des Cache-Eintrags.

### Server im sicheren Modus

Der Speicher liegt an einem Server. Der Schreibprozess liest über dessen Schnittstelle eine Veröffentlichung. Sie nennt die Mandantenkennung, die laufende Nummer, die Uhrzeit in UTC, die Zertifikate des Mandanten mit Fingerabdruck und Status und den öffentlichen Prüfschlüssel der Zugehörigkeit. Genau ein Zertifikat ist der aktuelle KEK. Die laufende Nummer beginnt bei 1 und steigt mit jeder Änderung um eins.

Signiert ist die Veröffentlichung mit dem privaten Schlüssel des Vertrauensankers des Mandanten. Der Anker ist derselbe, gegen den die Zertifikatskette geprüft wird. Die erlaubten Algorithmen sind dieselben wie beim KEK, der Hash ist SHA-256. Den privaten Schlüssel des Ankers hält der Mandant. Der Server verwahrt die Signatur und liefert sie mit der Veröffentlichung aus.

Der öffentliche Anker wird bei der Anlage des Mandanten hinterlegt. Der Datenschutzbeauftragte quittiert seinen Fingerabdruck. Der Schreibprozess führt diesen Anker getrennt von der Veröffentlichung. Eine Veröffentlichung unter einem anderen Anker übernimmt er nicht. Eine Veröffentlichung ohne gültige Signatur ist kein aktueller KEK.

Jede Änderung hängt der Server an sein Protokoll. Der Eintrag nennt den Mandanten, den bisherigen Fingerabdruck, den neuen Fingerabdruck, den Status, die handelnde Person, den Zeitpunkt und die laufende Nummer. Betrifft die Änderung den Prüfschlüssel der Zugehörigkeit, nennt der Eintrag dessen Fingerabdrücke. Ein Eintrag wird dort weder ersetzt noch gelöscht. Die Veröffentlichung wird erst mit diesem Eintrag die aktuelle. Die handelnde Person ist der in der Verwaltung authentisierte Datenschutzbeauftragte.

Unterdrückt der Server eine neuere Veröffentlichung, endet die Übernahme mit dem Höchstalter der letzten gültig signierten Fassung. Danach ist kein aktueller KEK lesbar.

## Verwaltung

Beide Modi nutzen dieselbe Oberfläche. Sie ist ein eigener Prozess, getrennt vom Schreibpfad, vom Suchprozess und vom [Werkzeug](ablage-und-lesen.md#oberfläche-des-werkzeugs). Das Werkzeug öffnet die Logs. Diese Oberfläche tut das nicht. Der Modus ist eine Eigenschaft des Mandanten und entscheidet, welche Ablage die Oberfläche anbietet. Angemeldet ist der Datenschutzbeauftragte dieses Mandanten. Der Betrieb der Plattform hat diesen Zugang nicht. Ein Mandant erreicht den Speicher eines anderen Mandanten nicht.

Im einfachen Modus schreibt die Oberfläche in das Verzeichnis des Mandanten. Neben dem Verzeichnis führt sie ein Protokoll mit demselben Inhalt wie der Server des sicheren Modus. Wirksam für den Schreibpfad ist der Inhalt des Verzeichnisses. Im sicheren Modus legt sie die signierte Veröffentlichung ab. Der Mandant signiert sie mit dem privaten Schlüssel des Vertrauensankers.

Im einfachen Modus nimmt die Oberfläche den öffentlichen Schlüssel und den bereits verschlüsselten privaten Schlüssel entgegen. Ein Feld für die Passphrase gibt es nicht. Die Oberfläche erzeugt kein Schlüsselpaar. Im sicheren Modus nimmt sie nur ein Zertifikat an. Der private Schlüssel entsteht beim Mandanten und wird nicht hochgeladen. Eine Erzeugung im Browser dieser Oberfläche findet nicht statt.

Bevor ein Schlüssel aktuell wird, zeigt die Oberfläche den Fingerabdruck. Der Datenschutzbeauftragte quittiert ihn. Den Status setzt er in derselben Oberfläche, als eigene Handlung. Die Oberfläche nennt die Folge. Bei `abgeloest` wickelt der Nachfolger die neuen Epochen; der bisherige Schlüssel bleibt vertrauenswürdig, und die vorhandenen Epochen bleiben lesbar. Bei `verloren` werden die vorhandenen Epochen dieses Fingerabdrucks unlesbar. Bei `kompromittiert` bleiben sie öffnenbar, und die Vertraulichkeit dieses Fingerabdrucks endet.

## Cache des Schreibprozesses

Beim Start liest der Schreibprozess die öffentlichen Schlüssel und ihren Status und hält sie im Speicher. Gewrappt wird aus diesem Cache. Die verschlüsselte private Kopie des einfachen Modus liegt nicht darin. Plattform-KEK und Index-Schlüssel bleiben ihre eigenen Secrets.

Ein Eintrag gilt höchstens für das Höchstalter, Ausgangswert 60 Sekunden. Solange er jünger ist, wickelt der Prozess daraus. Danach liest er den Speicher neu, bevor er eine Epoche beginnt und bevor er einen weiteren Eintrag der offenen Epoche verschlüsselt. Schlägt diese Lesung fehl oder ist danach kein aktueller KEK erkennbar, beginnt er keine Epoche unter einem Mandantenschlüssel. Das Ereignis geht in die Dead Letter Box, Grund `kek_fehlt`, gewrappt mit dem Plattform-KEK.

Der Cache kann auf der Platte des Knotens liegen. Diese Fassung ist mit AES-256-GCM verschlüsselt. Der Schlüssel dafür ist 32 Byte und liegt nur als Secret auf tmpfs im Speicher des Schreibprozesses. Es ist nicht der Plattform-KEK und nicht ein Schlüssel eines Mandanten. Er wird nicht in das Image übernommen. Ohne dieses Secret liest der Prozess keine persistente Fassung und schreibt keine. Eine Fassung, deren Authentisierung scheitert, verwendet er nicht. Beim Start liest er den Speicher. Die persistente Fassung überbrückt einen Start, in dem der Speicher nicht antwortet, unter denselben Prüfungen.

Im sicheren Modus prüft er an der geöffneten Fassung die Signatur unter dem hinterlegten Vertrauensanker. Er übernimmt eine Veröffentlichung nur, wenn die Signatur prüft, die Zertifikatsprüfung aus [Sicherer Modus](#sicherer-modus) besteht, die Uhrzeit der Signatur innerhalb des Höchstalters liegt und die laufende Nummer größer ist als die zuletzt für diesen Mandanten übernommene. Dieselbe Nummer übernimmt er nur bei gleichen Bytes. Eine kleinere Nummer übernimmt er nicht. Die zuletzt übernommene Nummer steht in der verschlüsselten Fassung. Beim ersten Start dieses Prozesses übernimmt er die Veröffentlichung, deren Signatur prüft und deren Uhrzeit innerhalb des Höchstalters liegt.

Eine Datei, die ohne den Cache-Schlüssel neu geschrieben wird, öffnet der Prozess nicht. Kennt jemand diesen Schlüssel aus dem Prozessspeicher, kann er eine neue verschlüsselte Fassung schreiben. Ohne die Signatur des Ankers übernimmt der Prozess sie nicht. Nach einem Neustart kann eine ältere Veröffentlichung wieder zur übernommenen werden, wenn ihre Signatur prüft, ihre Uhrzeit noch innerhalb des Höchstalters liegt und ihre Nummer die höchste in der geladenen Fassung ist. Das Fenster dieses Rücksprungs ist das Höchstalter.

## Hinterlegen des KEK

Beide Modi enden mit demselben Ergebnis: ein geprüftes Zertifikat mit dem öffentlichen Schlüssel, an den alle neuen DEKs gewrappt werden. Entschlüsselt wird in beiden Fällen im Werkzeug des Datenschutzbeauftragten.

### Einfacher Modus

Der Datenschutzbeauftragte hinterlegt über die [Verwaltung](#verwaltung) den öffentlichen Schlüssel und den privaten Schlüssel. Der private Schlüssel kommt bereits verschlüsselt an (PKCS#8, Passphrase nur ihm bekannt, abgeleitet mit Argon2id). Die Passphrase wird nicht gespeichert, nicht geloggt und nicht an die Plattform übertragen. Die Verwaltung erzeugt das Schlüsselpaar nicht.

Die lokale CA stellt aus dem öffentlichen Schlüssel ein Zertifikat aus:

- Subjekt ist Mandant plus Datenschutzbeauftragter
- Key Usage ist `keyEncipherment` beziehungsweise `keyAgreement`
- die Laufzeit ist begrenzt

Der Fingerabdruck des Zertifikats wird angezeigt und quittiert.

Dieselbe Aussage wie im sicheren Modus gilt hier nur, solange die Passphrase ausschließlich beim Datenschutzbeauftragten bleibt. Der verschlüsselte private Schlüssel liegt in diesem Modus im Schlüsselspeicher des Mandanten.

### Sicherer Modus

Hinterlegt wird über die [Verwaltung](#verwaltung) nur ein Zertifikat. Der private Schlüssel entsteht beim Mandanten und bleibt dort, zum Beispiel auf einer Smartcard oder in einem HSM. Er wird nie hochgeladen. Die Verwaltung erzeugt kein Schlüsselpaar. Mit der Hinterlegung signiert der Mandant die Veröffentlichung mit dem privaten Schlüssel des Vertrauensankers.

Die Prüfung des Zertifikats umfasst:

- die Kette gegen den hinterlegten Vertrauensanker des Mandanten
- die Gültigkeit
- den Sperrstatus
- die Key Usage
- die erlaubten Algorithmen des KEK: RSA ab 3072 Bit oder P-256
- die Bindung des Subjekts an den registrierten Datenschutzbeauftragten

Ein Zertifikat, das selbst eine CA ist, wird abgelehnt.

Pro Mandant gibt es genau einen Empfänger für Gruppenstrom, Einzelstrom und das Verzeichnis. Diese Epochen werden nicht zusätzlich an den Plattform-KEK gewrappt. Der Plattform-KEK wrappt den Plattform-Auffang und die Epochen der Dead Letter Box, die entstehen, während der KEK des Mandanten fehlt.

## Zugehörigkeit

Die Zugehörigkeit ist das Paar aus Mandant und Person. Dieselbe Personenkennung bei einem anderen Mandanten ist eine andere Person. Die Personen eines Mandanten teilen seinen Empfängerschlüssel.

Die Bindung steht in einem Personenregister, getrennt von den Logströmen. Ein Eintrag nennt Mandant, Person, das Ablagemerkmal, die Rolle und die Gültigkeit. Zur Rolle Datenschützer nennt er zusätzlich den öffentlichen Aufrufschlüssel dieser Person. Die Rolle wird an einzelne Personen gebunden, nicht an eine Gruppe und nicht an den Suchprozess. Der Schreibpfad darf das Register nur lesen und liest den Aufrufschlüssel nicht. Der Suchprozess liest das Register des Mandanten der Anfrage und für den Bucket `plattform` das Register der Plattform. Er schreibt es nicht. Anlegen und Ändern bleiben beim Mandanten, über einen Zugang, den der Betrieb nicht hat. Der Zugriff eines Mandanten erreicht das Register eines anderen Mandanten nicht.

Zu jedem Eintrag signiert der Mandant eine Zugehörigkeitsaussage: Mandant, Person, Rolle, Gültig-von, Gültig-bis. Die Aussage zur Rolle Datenschützer nennt zusätzlich den Fingerabdruck des Aufrufschlüssels. Der private Signaturschlüssel bleibt beim Mandanten. Im Schlüsselspeicher liegt der öffentliche Prüfschlüssel. Key Usage ist `digitalSignature`. Der Algorithmus ist ECDSA P-256 mit SHA-256, die Signatur `r || s`. Die Verwaltung legt RSA und P-384 dafür nicht ab.

Der Aufrufschlüssel gehört der Person. Der private Schlüssel bleibt bei ihr. Liegt er in einer Datei, ist diese PKCS#8 und mit einer Passphrase gewrappt, abgeleitet mit Argon2id. Die Passphrase wird nicht gespeichert, nicht geloggt und nicht an die Plattform übertragen. Auf einer Smartcard oder in einem HSM der Person verlässt er diese nicht. Die Plattform erhält den öffentlichen Schlüssel. Key Usage ist `digitalSignature`. Der Algorithmus ist derselbe wie beim Signaturschlüssel der Zugehörigkeit, ECDSA P-256. Der Fingerabdruck ist SHA-256 über das SubjectPublicKeyInfo in DER.

Der Aufrufschlüssel wickelt keine DEKs. Der KEK bleibt einer pro Mandant, mit Key Usage `keyEncipherment` beziehungsweise `keyAgreement`. Seine Passphrase autorisiert keine Suche. Der Signaturschlüssel der Zugehörigkeit signiert die Aussage und bleibt beim Mandanten. Das Werkzeug öffnet den Logtext mit dem privaten KEK und braucht den Aufrufschlüssel nicht.

Wechselt der Aufrufschlüssel, hinterlegt der Mandant den neuen öffentlichen Schlüssel an diesem Eintrag und signiert eine neue Aussage. Der Suchprozess verwendet die Aussage, die im Register steht. Eine vom Aufrufer vorgelegte Abschrift ersetzt sie nicht. Damit endet der bisherige Schlüssel für neue Anfragen. Verlust oder Bekanntwerden des privaten Aufrufschlüssels lässt den KEK unberührt. Bis der Mandant den Eintrag ersetzt, gilt eine Signatur mit diesem Schlüssel als diese Person. Das Protokoll der Suche nennt sie.

Für den Bucket `plattform` gilt dieselbe Bindung in einem eigenen Register. Die Aussage nennt die Plattform, die Person, die Rolle Datenschützer, die Gültigkeit und den Fingerabdruck. Der private Signaturschlüssel bleibt außerhalb von Suchprozess und Schreibprozess. Der Prüfschlüssel liegt beim Suchprozess. Eine Aussage der Plattform öffnet nur den Index dieses Buckets. Eine Aussage eines Mandanten öffnet ihn nicht.

Vor dem Verschlüsseln löst der Dienst die Person nur im Mandanten des Ereignisses auf. Liegt eine Aussage vor, passt die Signatur zum hinterlegten Prüfschlüssel und liegt der Zeitpunkt des Ereignisses in der Gültigkeit, übernimmt er das Ablagemerkmal aus diesem Eintrag. Lässt sich das Ereignis danach keinem Gruppenstrom und keinem Einzelstrom zuordnen, schreibt er es in den Auffangstrom. Lässt sich kein Mandant ermitteln, schreibt er es in den Plattform-Auffang. Fehlt bei ermitteltem Mandanten der aktuelle KEK, schreibt er es ebenfalls in den Auffangstrom dieses Mandanten, gewrappt mit dem Plattform-KEK.

Die signierte Aussage wird Teil des Klartexts jedes zugeordneten Logeintrags. Im Auffangstrom steht sie nur beim Grund `ziel_fehlt`. Sie erscheint nicht im Objektschlüssel und nicht in den authentisierten Zusatzdaten. Das Register kann sich danach ändern. Die Epoche trägt die Aussage, die beim Schreiben galt.

Wechselt eine Person den Mandanten, gilt die neue Aussage für neue Ereignisse. Bestehende Epochen bleiben bei der bisherigen Aussage und beim bisherigen Mandanten.

Die Aussage belegt, dass der Mandant die genannte Person für den Zeitpunkt des Ereignisses als zugehörig signiert hat. Zur Rolle Datenschützer bindet sie zugleich den Fingerabdruck des Aufrufschlüssels. Dass der Aufrufer diesen Schlüssel besitzt, prüft der Suchprozess an der Signatur der Anfrage, unter [Suche](ablage-und-lesen.md#suche). Den Inhalt des Ereignisses schreibt der Dienst, bevor er verschlüsselt.

## Wechsel, Verlust und Kompromittierung

Ablauf eines Zertifikats, Verlust des privaten Schlüssels und Kompromittierung des privaten Schlüssels sind drei Lagen. Ein neues Zertifikat über denselben öffentlichen Schlüssel lässt alle drei unverändert. Der Nachfolger ist in jeder Lage ein neues Schlüsselpaar. Er wickelt nur neue Epochen. Bestehende Epochen bleiben an ihrem Fingerabdruck. Die Manifestkette läuft weiter. Der Dienst schreibt keine Epoche um und wickelt keinen DEK auf einen anderen Schlüssel um.

| Lage | Privater Schlüssel | Neue Epochen | Alte Epochen |
|---|---|---|---|
| Ablauf oder planmäßiger Wechsel | bleibt beim Empfänger und bleibt vertrauenswürdig | Nachfolger | bisheriger Schlüssel, weiter lesbar |
| Verlust | keine brauchbare Kopie mehr | Nachfolger, sobald hinterlegt | unlesbar |
| Kompromittierung | unbefugt bekannt, oder das ist anzunehmen | Nachfolger; der bisherige Schlüssel wickelt sofort nicht mehr | weiter öffnenbar, ohne Vertraulichkeitszusicherung |

In demselben Schritt wird der Nachfolger der aktuelle KEK, und der bisherige Schlüssel erhält seinen Status. Danach ist genau ein Schlüssel aktuell, oder keiner. Fehlt der Nachfolger, wickelt bis zu seiner Hinterlegung kein Mandanten-KEK.

Betroffen ist jede Epoche, deren Kopf den Fingerabdruck des betroffenen Zertifikats nennt. Der Fingerabdruck steht im Klartext des Kopfes. Die Menge ist ohne Entschlüsselung feststellbar. Eine kleinere Menge ist aus dem Log nicht bestimmbar. Das Öffnen hinterlässt im Log keine Spur. Der Zeitpunkt der Erklärung ist keine Grenze dieser Menge. Er ist der Zeitpunkt, ab dem dieser Schlüssel keine neue Epoche mehr wickelt. Abgeschlossene Epochen gehören dazu. Jede Kopie, die den gewrappten DEK noch enthält, gehört dazu: Objektspeicher, Platte, Backup und Export. Ein Backup der Logs enthält den privaten Schlüssel nicht. Mit dem Schlüssel lässt sich die Kopie lesen.

Beim Mandanten-KEK sind das die Gruppenströme, die Einzelströme, der Auffangstrom soweit dieser KEK ihn wrappt, das Verzeichnis, der Strom `verzeichnis-summe`, der Stromkatalog und die Bindungsschlüssel der Annahmenteile, die dieser Schlüssel wrappt. Beim Plattform-KEK sind das der Plattform-Auffang, sein Verzeichnis, sein Strom `verzeichnis-summe`, sein Katalog, jede Epoche mit dem Grund `kek_fehlt`, deren Kopf diesen Fingerabdruck nennt, und die Bindungsschlüssel der Annahmenteile, die dieser Schlüssel wrappt. Der Vorgangsindex, der Strom `vorgang-summe` und der Bindungsschlüssel ihres Anteils hängen am Index-Schlüssel und gehören nicht dazu.

Bei Ablauf und beim Status `abgeloest` läuft die offene Epoche bis zu ihrer Grenze zu Ende. Der Klartext-DEK bleibt bis dahin im Speicher, und der bisherige Schlüssel bleibt vertrauenswürdig. Bei `kompromittiert` ist die offene Epoche betroffen, sobald ihr Kopf mit dem gewrappten DEK am Ziel liegt. Bei `verloren` und bei `kompromittiert` verwirft der Schreibprozess den Klartext-DEK, sobald der Status lesbar ist, auch mitten in der Epoche. Das Rotationsintervall hält das nicht auf. Den Abschluss über bereits angenommene Ciphertexte schreibt er noch. Dafür wird der Klartext-DEK nicht gebraucht. Weitere Annahmen unter diesem DEK schreibt er nicht. Liegt der Nachfolger vor, beginnt die folgende Epoche mit ihm und einem neuen DEK, auch innerhalb desselben Rasters. Der Aufrufer behält, was noch nicht angenommen ist. Liegt der Kopf schon am Ziel, bleibt ein Rest daneben für den Inhaber des privaten Schlüssels lesbar. Dieser Rest bleibt unvollständig und ist kein Glied der Kette.

Der kompromittierte Schlüssel öffnet die vorhandenen Wraps weiter. Sperrung und Ablauf des Zertifikats lassen dieses Öffnen bestehen. Die Sperrung nimmt ihn aus dem Wickelpfad für neue Epochen. Den Status `kompromittiert` setzt die Erklärung des Empfängers, dass das Geheimnis nicht mehr ausschließlich bei ihm liegt. Von dieser Erklärung an ist der Schlüssel keine Grenze der Vertraulichkeit mehr. Ein zweiter Empfänger entsteht nicht. Es bleibt dieser eine Wrap. Die Kopie beim Empfänger bleibt, bis die letzte Epoche dieses Fingerabdrucks gelöscht ist, und dient der Prüfung. Eine weitere Kopie bleibt davon unabhängig brauchbar. Vernichten der Kopie des Empfängers nimmt ihm den Inhalt und lässt die weitere Kopie unberührt. Das Werkzeug führt den Fingerabdruck als `kompromittiert`.

`verloren` wird gesetzt, wenn keine Kopie des privaten Schlüssels mehr brauchbar ist. Die verschlüsselte Kopie des einfachen Modus ist brauchbar, solange die Passphrase ausschließlich beim Empfänger liegt. Ist die Passphrase bekannt oder muss das angenommen werden, ist der Schlüssel `kompromittiert`, auch wenn die Kopie verschlüsselt im Schlüsselspeicher liegt.

Die Plattform hält keinen entschlüsselten DEK einer abgeschlossenen Epoche. Ein Klartext-DEK im Schreibprozess, den der Status `verloren` oder `kompromittiert` verwirft, wird nicht wiederhergestellt und nicht auf einen neuen DEK umgesetzt. Die Einträge bleiben unter ihrem DEK. Das Werkzeug legt einen geöffneten DEK nicht ab und hält ihn über die laufende Prüfung hinaus nicht vor. Bei `kompromittiert` verwirft es ihn mit dem Ende der Prüfung. Ein späteres Öffnen benutzt die beim Empfänger verbliebene Kopie des privaten Schlüssels. Bei `verloren` darf die schon begonnene Prüfung zu Ende gehen, weil ein erneutes Öffnen danach unmöglich ist. Danach wird dieser Klartext-DEK verworfen. Ein Vorrat entschlüsselter DEKs entsteht nicht. Eine Kopie eines DEK außerhalb von Schreibprozess und Werkzeug bleibt für diese Epoche lesbar. Der neue KEK erreicht sie nicht. Das Löschen des Klartext-DEK im Schreibprozess stellt die Vertraulichkeit einer Epoche nicht wieder her, deren gewrappter DEK bereits vorliegt.

Beim Mandanten liegt der Status im Schlüsselspeicher neben dem Zertifikat, außerhalb der Logströme. Werte sind `abgeloest`, `verloren` und `kompromittiert`. Den Status setzt der Mandant in der [Verwaltung](#verwaltung). Der Betrieb hat diesen Zugang nicht. Der Schreibpfad liest den Status aus dem [Cache](#cache-des-schreibprozesses), bevor er eine neue Epoche beginnt und bevor er einen weiteren Eintrag der offenen Epoche verschlüsselt. Liegt der Eintrag innerhalb seines Höchstalters, genügt der Cache. Danach liest er den Speicher neu. Er setzt den Status nicht. In den Epochenkopf wird der Status nicht geschrieben. Bis ein aktueller Nachfolger lesbar ist, gehen neue Ereignisse des Mandanten in die Dead Letter Box, Grund `kek_fehlt`, gewrappt mit dem Plattform-KEK. Diese Epochen sieht der Datenschutzbeauftragte des Mandanten am Präfix. Öffnen kann sie der Datenschutzbeauftragte der Plattform. Nach dem Nachfolger liegen neue Ereignisse wieder in den Strömen des Mandanten.

Der Nachfolger wird hinterlegt wie jeder KEK. Im sicheren Modus entsteht das Schlüsselpaar beim Empfänger. Im einfachen Modus kommt der private Schlüssel bereits verschlüsselt an. Die Prüfung des Zertifikats bleibt dieselbe. Der bisherige Fingerabdruck bleibt den bisherigen Epochen zugeordnet.

Hash-Kette, HSM-Signatur und Epochenbestätigung hängen nicht am Geheimnis des KEK. Der Inhaber des privaten Schlüssels liest den Klartext. Eine zweite Fassung setzt er damit nicht in die Kette, und eine HSM-Signatur erzeugt er damit nicht. Reihenfolge, Vollständigkeit und Abschluss bleiben prüfbar. Die Epochenbestätigung belegt den `epoch_hash`. Sie belegt nicht die Vertraulichkeit. Eine betroffene Epoche ist keine Lücke und keine Verzweigung. Die belegbare Aussage, dass ein Plattformadministrator den Klartext abgeschlossener Epochen nicht erzeugen kann, gilt für diesen Fingerabdruck nicht, sobald der private Schlüssel ihm bekannt ist oder das angenommen werden muss. Dieselbe Grenze gilt für jeden anderen Inhaber einer Kopie des Schlüssels. Aus dem Ciphertext ist die Kompromittierung nicht erkennbar. Erkennbar ist sie an der Erklärung zum Fingerabdruck.

Bestätigungsschlüssel und Integritätsschlüssel sind andere Schlüssel. Ein Wechsel des KEK löst sie nicht ab. Ihre Signaturen bleiben gültig. Liegen der private KEK und der Bestätigungsschlüssel auf demselben Träger und ist dieser Träger kompromittiert, wird der Bestätigungsschlüssel an seinem eigenen Fingerabdruck als `kompromittiert` geführt. Der Index-Schlüssel bleibt davon unberührt.

Beim Plattform-KEK ist die Kompromittierung eines Trägers die Kompromittierung des Schlüssels. Beide Träger halten denselben privaten Schlüssel. Der zweite Träger öffnet dieselben Epochen. Vertrauenswürdig wird der Schlüssel dadurch nicht wieder. Neue Epochen wickelt nur der öffentliche Schlüssel, der im tmpfs liegt. Der Nachfolger ersetzt dieses Secret. Bis das Secret den Nachfolger nennt, nimmt der Schreibprozess keine Ereignisse an und verwirft sie nicht. Der Status eines abgelösten Plattform-KEK liegt beim Datenschutzbeauftragten der Plattform, neben dem privaten Schlüssel. Dieser private Schlüssel bleibt dort, bis die Aufbewahrungsfrist der letzten damit gewrappten Epoche abgelaufen ist. Betroffen sind der Plattform-Auffang, sein Verzeichnis, sein Katalog, sein Strom `verzeichnis-summe` und jede Epoche mit dem Grund `kek_fehlt` unter diesem Fingerabdruck. Diese Epochen haben keinen zweiten Empfänger. Bei einem Verlust ohne verbliebene brauchbare Kopie bleibt ihr Inhalt unlesbar. Im einfachen Modus stellt die verschlüsselte Kopie den Schlüssel wieder her, solange die Passphrase ausschließlich beim Datenschutzbeauftragten geblieben ist.

Eine Kompromittierung wird erklärt, sobald sie nicht ausgeschlossen werden kann. Der Umfang der Epochen ist derselbe wie nach einer festgestellten Entwendung.

## Grenze der Zusicherung im sicheren Modus

Im Bedrohungsmodell des sicheren Modus darf der Plattformadministrator Objektspeicher, Platte, Backups und den Speicher des Schreibprozesses lesen. Programmcode, Deployment und Laufzeitumgebung des Schreibprozesses darf er nicht ändern. Die Aussage über abgeschlossene Epochen steht unter dieser Trennung.

### Auslesen von Speicher und Ablage

Die laufende Epoche liegt im Speicher des schreibenden Prozesses. Ein Administrator, der diesen Speicher auslesen kann, erhält den Klartext-DEK dieser Epoche und kann sie entschlüsseln. Die Länge des Fensters ist das konfigurierte Rotationsintervall, höchstens 8 Stunden, bei Gruppenströmen voreingestellt 60 Minuten. Mit dem Abschluss wird der Klartext-DEK verworfen. Ein späteres Auslesen des Speichers trifft ihn nicht mehr.

Für abgeschlossene Log-Epochen und für jeden Zugriff auf Objektspeicher, Platte und Backup gilt dann, solange der private Schlüssel ihres Fingerabdrucks nicht kompromittiert ist: der Logtext lässt sich aus dem dort liegenden Material nicht erzeugen. Sichtbar bleiben die unter [Sichtbare Metadaten](protokoll.md#sichtbare-metadaten) freigegebenen Merkmale. Der private Schlüssel des Mandanten ist nicht vorhanden, der DEK liegt nur gewrappt vor. Ein Administrator, der den Prozess erst nach dem Abschluss verändert, holt den verworfenen DEK dadurch nicht zurück. Für die Gruppen-, Einzel- und Verzeichnis-Epochen eines Mandanten existiert kein zweiter Empfänger. Für den Plattform-Auffang ist der einzige Empfänger der Datenschutzbeauftragte der Plattform. Im sicheren Modus trägt er denselben privaten Schlüssel auf zwei Trägern. Gehen beide verloren, bleiben der Plattform-Auffang, sein Verzeichnis und die Epochen mit Grund `kek_fehlt` unlesbar. Der Vorgangsindex hat einen anderen Empfänger, den Suchprozess. Er enthält keinen Logtext. Personenkennungen, Vorgangsnummern, Zeitpunkte und die Zuordnung zu Strömen liegen diesem Prozess vor, weil er den privaten Index-Schlüssel hält. Deshalb ist er die Sicherheitszone unter [Suche](ablage-und-lesen.md#suche). Wer diese Zone ändert oder ihren Speicher liest, kann diesen Bestand abgreifen. Den Logtext der Epochen gewinnt er daraus nicht.

### Austausch des öffentlichen Schlüssels

Die persistente Fassung des Caches liegt auf der Platte des Knotens. Wer diese Datei schreiben kann und das tmpfs-Secret des Cache-Schlüssels nicht hat, erzeugt keine Fassung, die der Schreibprozess öffnet. Wer den Prozessspeicher gelesen hat, kennt den Cache-Schlüssel und kann eine neue verschlüsselte Fassung mit einem anderen öffentlichen Schlüssel schreiben. Diese Fassung trägt die Signatur des Vertrauensankers nicht. Der Prozess übernimmt sie nicht. Neue Epochen wickeln an die signierte Veröffentlichung. Das Protokoll des Servers ist der Beleg dieser Änderung. Nach einem Neustart begrenzt das Höchstalter, wie weit eine ältere, noch innerhalb dieser Frist signierte Veröffentlichung an die Stelle einer neueren treten kann. Das Verfahren steht unter [Cache des Schreibprozesses](#cache-des-schreibprozesses).

### Kompromittierter privater Schlüssel

Ist der private Schlüssel eines KEK kompromittiert, kann jeder Inhaber einer Kopie aus Objektspeicher, Platte und Backup den Klartext jeder Epoche erzeugen, deren Kopf diesen Fingerabdruck nennt. Der Abschluss verwirft den DEK im Schreibprozess und lässt den gewrappten DEK liegen. Die Aussage über abgeschlossene Epochen gilt für diesen Fingerabdruck nicht. Ablauf und Wechsel des Zertifikats sind diese Lage nicht. Das Verfahren steht unter [Wechsel, Verlust und Kompromittierung](#wechsel-verlust-und-kompromittierung).

### Kontrolle des Schreibprozesses

Ein Administrator, der Programmcode, Deployment oder die Laufzeitumgebung des Schreibprozesses ändern kann, kann das Verhalten des Prozesses ändern, solange eine Epoche offen ist: den Klartext abgreifen, bevor er verschlüsselt wird, den DEK exportieren oder zusätzlich an einen anderen Schlüssel wrappen, Ereignisse verändern und zusätzliche Ereignisse erzeugen. Deployment und Laufzeitumgebung sind auch der Dienst, der Container und das Helm-Chart unter [Betrieb](betrieb.md). Ein anderer Image-Digest, ein gemeinsamer Prozessnamensraum und ein zusätzlicher Container in diesem Namensraum sind eine solche Änderung.

Für jede Epoche, die unter einem so veränderten Prozess offen war, gilt die Vertraulichkeitsaussage nicht. Das bleibt auch nach dem Abschluss so. Ein exportierter DEK oder ein abgegriffener Klartext liegt dann außerhalb der Plattform. Das Verwerfen des DEK im Prozess macht das nicht rückgängig.

Dieselbe Kontrolle betrifft den Inhalt. Hash-Kette und HSM-Signatur belegen, was dieser Prozess dem HSM vorgelegt hat. Ein veränderter Prozess kann andere oder zusätzliche Ereignisse vorlegen. Löschen, Umordnen und Ersetzen nach dem Schreiben bleibt an der Kette erkennbar. Was vor dem Verschlüsseln verändert oder hinzugefügt wurde, erkennt sie nicht.
