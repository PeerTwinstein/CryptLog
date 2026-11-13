# Glossar

Stand: 13. November 2026

Kurze Fassungen der Namen. Was gilt, steht in den verlinkten Abschnitten, nicht hier. Einstieg ist das [Konzept](README.md).

## Ablage

Ein Strom unter einer `ablage_id`: Gruppe, Einzelpräfix, Auffang, Verzeichnis, Vorgang, Katalog oder eine der Summen. Die `ablage_id` ist 16 Byte aus dem Zufall, kein Kohortenname.

## Annahme

Ein Ereignis ist angenommen, wenn das Annahmeobjekt am Ziel dauerhaft ist und die Belegung danach von offen auf angenommen getauscht wurde. Darin stehen Logeintrag, Verzeichnisverweise und Vorgangsindexeinträge gemeinsam. Der Fsync des Spools auf dem schreibenden Knoten ist eine Stufe davor. Kommt die Antwort nicht an, bestätigt dieselbe `event_id` diese Annahme und schreibt keine zweite Fassung.

[Annahme](ablage-und-lesen.md#annahme)

## Aufrufschlüssel

Schlüssel einer Person mit der Rolle Datenschützer. ECDSA P-256. Damit signiert sie eine Suchanfrage. Er wickelt keine DEKs ein und öffnet keinen Logtext. Die Passphrase bleibt bei der Person.

[Zugehörigkeit](schluessel.md#zugehörigkeit)

## Auffangstrom

Die Dead Letter Box eines Mandanten, Rolle `auffang`. Dahin geht ein Audit-Ereignis genau einmal, wenn es nach der Auflösung keinen Gruppen- und keinen Einzelstrom hat. Oder wenn der Mandant feststeht und sein KEK fehlt. Im zweiten Fall, Grund `kek_fehlt`, wrappt der Plattform-KEK. Den Inhalt liest dann der Datenschutzbeauftragte der Plattform. Die übrigen Gründe öffnet der Mandant.

Das ist nicht der Plattform-Auffang.

[Auffangstrom](protokoll.md#auffangstrom)

## Belegung

Das Objekt `belegt/{event_id}`. Daran hängt, ob diese Kennung noch offen oder schon angenommen ist. Kein Logtext, keine Person, keine Vorgangsnummer. Eine angenommene Belegung bleibt nach dem Löschen der Epoche liegen und sperrt die `event_id` gegen eine zweite Fassung.

[Belegung](ablage-und-lesen.md#belegung)

## Bestätigungsschlüssel

Privater Schlüssel des Empfängers. Er signiert den `epoch_hash`. Damit ist die Epoche abgeschlossen. Der Schlüssel öffnet nichts. Die Bestätigung liegt außerhalb des Log-Buckets und bleibt, wenn die Segmente gelöscht werden. Eine weitere gültig signierte Fassung derselben Epoche ist eine Verzweigung und ersetzt diesen Abschluss nicht.

[Abschluss](protokoll.md#abschluss)

## Bindungsschlüssel

32 Byte, einmal pro Anteil einer Annahme. Er verschlüsselt, welcher Platz welche Sequenz ist, einschließlich Fortsetzung und Füllung. Gewrappt wird er wie ein DEK, mit demselben öffentlichen Schlüssel: die 48 Byte `bindungsschluessel || batch_id`. Im Klartext der Annahme steht diese Zuordnung nicht.

[Vorbereitung und Annahme](ablage-und-lesen.md#vorbereitung-und-annahme)

## bind_id

16 Byte. Bei Gruppe, Auffang, Verzeichnis, Index und Katalog gleich der `ablage_id`. Bei einer Einzelperson ein undurchsichtiges Kennzeichen aus dem Register, nicht die Personenkennung. Sie steckt im Wrap des DEK und im Klartext des Eintrags, nicht im Objektschlüssel.

[Kennungen](protokoll.md#kennungen)

## Ciphertext

Was ohne den privaten Schlüssel nicht lesbar sein soll. Personenkennung, Vorgangsnummer, Kohortenname, Zeitpunkt des Ereignisses, Logtext. Im Objektschlüssel und in den Zusatzdaten stehen diese Felder nicht.

[Sichtbare Metadaten](protokoll.md#sichtbare-metadaten)

## Deckverkehr

Je Mandant an oder aus. Ausgang ist aus. Bei an schreibt die Instanz in jedem Raster eine Epoche, auch wenn nichts passiert ist. Sonst zeigt ein fehlendes Raster die Stille. Solange er an ist, fehlen die Mengenzähler dieses Mandanten in den Metriken. Eine Summe über alle Mandanten gibt es daneben nicht, die würde die Lücke wieder füllen.

[Deckverkehr](protokoll.md#deckverkehr)

## DEK

Datenschlüssel. 32 Byte, AES-256-GCM, einer pro Epoche und Strom auf einer schreibenden Instanz. Den Klartext hält nur der Speicher dieser Instanz. Mit dem Ende der Epoche ist er weg. Neustart, Absturz, Fork und ein wiederhergestelltes Prozessabbild beginnen eine neue Epoche. Einen DEK aus dem Speicher zurückholen gibt es nicht.

Die Einträge verweisen über `dek_id` auf den Kopf. Dort steht er einmal, gewrappt, zusammen mit der `bind_id`. Die Nonce eines Eintrags ist `epoch_prefix || seq`: 4 Byte Zufall, einmal beim Erzeugen dieses DEK, und die 8 Byte der Sequenz. Unter demselben DEK kommt jede Nonce einmal vor.

Gruppe voreingestellt 60 Minuten, Einzelperson 8 Stunden. Zulässig sind 15 Minuten bis 8 Stunden, und das Intervall muss 24 Stunden teilen.

[Hüllenverschlüsselung](protokoll.md#hüllenverschlüsselung)

## Einfacher Modus

Der Mandant hinterlegt den öffentlichen Schlüssel und den privaten Schlüssel schon verschlüsselt, PKCS#8, abgeleitet mit Argon2id. Die Passphrase geht nicht an die Plattform. Die lokale CA stellt das Zertifikat aus. Die Oberfläche erzeugt kein Schlüsselpaar.

Dieselbe Zusicherung wie im sicheren Modus gilt hier nur, solange die Passphrase beim Datenschutzbeauftragten bleibt.

[Einfacher Modus](schluessel.md#einfacher-modus)

## Einzelstrom

Eigene Epochen und ein eigener DEK für eine Person, die im Register als `einzeln` geführt ist. Ihre Ereignisse stehen in keinem Gruppen-Ciphertext. Die Segmente liegen trotzdem unter der gemeinsamen `ablage_id` des Einzelpräfixes. Empfänger bleibt der Datenschutzbeauftragte des Mandanten. Schon geschriebene Gruppeneinträge werden nicht umgeschlüsselt.

[Ablage: Gruppe und Einzelperson](protokoll.md#ablage-gruppe-und-einzelperson)

## Epoche

Das Zeitfenster eines Stroms auf einer schreibenden Instanz, mit genau einem DEK. Die Kennung beginnt mit dem Raster in UTC, danach Instanz und das `epoch_prefix`. Mehrere Instanzen in derselben Ablage führen nebeneinander eigene Epochen. Abgeschlossene Epochen bleiben liegen, sonst ließen sich die älteren Einträge nicht mehr öffnen.

Gelöscht wird eine ganze Epoche nach der Frist des Mandanten, nicht ein einzelner Eintrag. Eine Person aus einer Gruppenepoche zu nehmen hieße, die Epoche neu zu verschlüsseln. Dafür liegt der Klartext nach dem Abschluss nicht mehr vor.

[Epochen](protokoll.md#epochen), [Löschen](ablage-und-lesen.md#löschen)

## Epochenbestätigung

Die Signatur des Empfängers über den `epoch_hash`. Je Strom und Instanz wird das erste Manifest bestätigt, das gültig auf den Vorgänger oder auf die Genesis aufsetzt. Dieselbe Epoche wird kein zweites Mal bestätigt.

[Abschluss](protokoll.md#abschluss)

## event_id

16 Byte, vom Aufrufer zufällig gewählt. Dieselben Bytes beim erneuten Senden. Sie steht im Klartext von Logeintrag, Verzeichnisverweis und Vorgangsindex. Der `event_hash` deckt den Aufruf. Ein anderer Aufruf unter derselben Kennung wird abgelehnt.

[Ereignis-ID](ablage-und-lesen.md#ereignis-id)

## Fingerabdruck

Beim KEK ist das SHA-256 über das Zertifikat in DER. Er steht im Epochenkopf im Klartext. Daran hängt, welcher private Schlüssel die Epoche öffnet, und welche Epochen ein Wechsel, ein Verlust oder eine Kompromittierung trifft. Beim Aufrufschlüssel und beim Bestätigungsschlüssel ist es SHA-256 über das SubjectPublicKeyInfo.

[Wechsel, Verlust und Kompromittierung](schluessel.md#wechsel-verlust-und-kompromittierung)

## Gruppenstrom

Ereignisse einer Kohorte. Die Personen dieser Kohorte, soweit sie nicht `einzeln` sind, teilen sich die laufende DEK-Epoche der schreibenden Instanz. Der Name der Kohorte steht im Register und im Stromkatalog.

[Ablage: Gruppe und Einzelperson](protokoll.md#ablage-gruppe-und-einzelperson)

## Hash-Kette

SHA-256 über die Ciphertexte einer Epoche, nicht über den Klartext. Fortsetzung und Füllung zählen mit. Sie belegt Reihenfolge und Vollständigkeit dieser Epoche. Den DEK braucht die Prüfung nicht. Die Epochen einer Instanz hängen zusätzlich über die Manifeste zusammen. Die erste setzt auf den Genesis-Hash aus Ablage und Instanz auf. Ein KEK-Wechsel beginnt keine neue Kette.

[Verkettung](protokoll.md#verkettung)

## HSM

Das Modul mit dem Integritätsschlüssel. Es signiert das Manifest, ECDSA P-256. Die Signatur belegt, dass dieses Manifest vorgelegt wurde. Sie öffnet keinen Inhalt. In der Testumgebung liegt der Schlüssel als Datei, unverschlüsseltes PKCS#8.

[Abschluss](protokoll.md#abschluss)

## Index-Schlüssel

Öffentlich im Schreibprozess, privat nur im Suchprozess. Beide als Secret auf tmpfs. Er wrappt den Vorgangsindex und `vorgang-summe`. Keinen Logtext, und keine Log-DEKs. Der Suchprozess ist deshalb eine eigene Zone.

[Schlüssel](schluessel.md#schlüssel), [Suche](ablage-und-lesen.md#suche)

## Integritätsschlüssel

ECDSA P-256, im HSM, nicht exportierbar. Unabhängig vom KEK. Ein Wechsel des KEK löst ihn nicht ab.

[Schlüssel](schluessel.md#schlüssel)

## KEK

Schlüsselverschlüsselungsschlüssel. Der öffentliche Schlüssel des Datenschutzbeauftragten, gebunden an ein Zertifikat. Pro Mandant einer. Er wrappt die DEKs von Log, Verzeichnis, Katalog und vom Auffang dieses Mandanten, und die zugehörigen Bindungsschlüssel. Den Logtext verschlüsselt er nicht selbst. Den Vorgangsindex wrappt er nicht.

Aktuell ist genau ein Zertifikat. Die Status `abgeloest`, `verloren` und `kompromittiert` sind nicht aktuell. Fehlt ein aktueller KEK, beginnt keine Gruppen-, Einzel- oder Verzeichnis-Epoche unter einem Mandantenschlüssel. Das Ereignis geht in die Dead Letter Box, gewrappt mit dem Plattform-KEK.

RSA ab 3072 Bit mit RSA-OAEP und SHA-256, oder P-256 mit HPKE und AES-256-GCM.

[Schlüssel](schluessel.md#schlüssel)

## Kohorte

Eine benannte Gruppe im Mandanten. Organisationseinheit, Sammelbereich, was das Register so nennt. Personen mit dem Merkmal Gruppe teilen ihren Strom. Der Name steht nicht im Objektschlüssel.

## Manifest

Der Abschluss einer Epoche im letzten Segment. Es nennt den Kopf der Hash-Kette, die Zahl der Rahmen und die Annahmen, die Einträge dieser Epoche enthalten. Signiert vom Integritätsschlüssel. Die folgende Epoche derselben Instanz setzt auf den dabei entstandenen `epoch_hash` auf.

[Verkettung](protokoll.md#verkettung)

## Mandant

Eigener KEK, eigener Schlüsselspeicher, eigene Ströme. Dieselbe Personenkennung bei einem anderen Mandanten ist eine andere Person. Ein eigenes Speicherziel ist möglich. Fehlt es, liegen die Segmente im gemeinsamen Ziel. Belegung, Vorbereitung und Annahme bleiben dort, weil ein Abschluss mehrere Mandanten umfassen kann.

[Speicherziel](ablage-und-lesen.md#speicherziel)

## Nonce

12 Byte für AES-256-GCM. Bei den Einträgen `epoch_prefix || seq`. Die Nonce des Wraps ist eine andere, die aus HPKE. Die Nonce des Bindungsblobs auch. Der Zähler der Sequenz läuft nicht modulo.

[Hüllenverschlüsselung](protokoll.md#hüllenverschlüsselung)

## Plattform-Auffang

Rolle `auffang` im Bucket `plattform`. Der Bucket ist kein Mandant. Hier landen Ereignisse, deren Mandant sich nicht ermitteln lässt. Öffnen kann sie nur der Datenschutzbeauftragte der Plattform. Der Plattform-KEK öffnet keine Gruppen- und keine Einzel-Epoche eines gültigen Mandanten-KEK.

[Kein Mandant](protokoll.md#kein-mandant)

## Plattform-KEK

Öffentlicher Schlüssel dieses Datenschutzbeauftragten. Secret auf tmpfs, nur der öffentliche Teil. Ohne ihn startet der Schreibprozess nicht. Er wrappt den Plattform-Auffang und die Epochen mit Grund `kek_fehlt`. Im sicheren Modus liegt derselbe private Schlüssel auf zwei Trägern. Ist einer kompromittiert, ist der Schlüssel kompromittiert. Der andere Träger öffnet dieselben Epochen.

[Kein Mandant](protokoll.md#kein-mandant)

## Rahmen

Ein Datensatz der Kette, feste Größe je Mandant. Ausgang 1024 Byte, Zweierpotenz zwischen 256 und 8192. Passt ein Ereignis nicht hinein, setzen die folgenden Sequenznummern es als Fortsetzung fort. Füllung trägt keinen Ereignisinhalt und steht trotzdem in der Kette.

[Rahmen und Größenklassen](protokoll.md#rahmen-und-größenklassen)

## Raster

Der UTC-Beginn des Fensters, in das der Schreibzeitpunkt fällt. Steht vorn in der Epochenkennung. Der Löschtag rechnet ab diesem Beginn plus die Frist des Mandanten, nicht ab dem Alter der Datei. Am UTC-Tag davor endet der Zugriff. Am Löschtag entfernt der Dienst die Segmente.

[Löschen](ablage-und-lesen.md#löschen)

## Segment

Eine unveränderliche Folge schon verschlüsselter Rahmen einer Epoche. Schlüssel `{mandant_id}/{ablage_id}/{epoch_id}/{segment_nr}`. Dieselben Bytes unter demselben Schlüssel sind ein wiederholtes Schreiben. Ein anderer Inhalt wird nicht ersetzt. Ein Segment ohne Annahme ist Rest, kein Glied der Kette.

[Speicherziel](ablage-und-lesen.md#speicherziel)

## Sicherer Modus

Hinterlegt wird nur ein geprüftes Zertifikat. Der private Schlüssel entsteht beim Mandanten, auf einer Smartcard oder in einem HSM, und wird nicht hochgeladen. Die Veröffentlichung ist unter dem Vertrauensanker signiert. Abgeschlossene Epochen bleiben für einen Administrator unlesbar, der Speicher und Ablage lesen darf, solange der Schreibprozess unverändert war und der Schlüssel nicht kompromittiert ist. Die offene Epoche liegt in diesem Fenster noch im Speicher.

[Sicherer Modus](schluessel.md#sicherer-modus), [Grenze der Zusicherung](schluessel.md#grenze-der-zusicherung-im-sicheren-modus)

## Spool

Lokaler Puffer auf dem schreibenden Knoten, vor dem Segment. Der Fsync hält den Abschluss auf diesem Knoten fest. Fällt der Knoten weg, bevor die Annahme am Ziel steht, ist der Spool weg. Der Aufrufer hat dann keine Bestätigung und sendet das Ereignis erneut. Ist der Spool voll, weil das Ziel nicht nachkommt, nimmt der Dienst nichts weiteres an. Verworfen wird dabei nichts.

[Annahme](ablage-und-lesen.md#annahme)

## Strom

Siehe Ablage. Zusätzlich die Rolle, ein Byte: Gruppe, Einzel, Auffang, Verzeichnis, Vorgang, Katalog, und die beiden Summen.

## Stromkatalog

Stand der vergebenen Kennungen, gewrappt mit dem KEK. Das Werkzeug löst darüber einen Namen in die `ablage_id` auf. Bei einer Gruppe steht hier der Kohortenname. Person und Vorgangsnummer eines Ereignisses nicht.

[Stromkatalog](protokoll.md#stromkatalog)

## Summenindex

Eine Epoche je abgeschlossenem Monat, einmal für das Verzeichnis und einmal für den Vorgangsindex. Die Suche öffnet damit einen DEK pro Monat statt einer Epoche pro Stunde. Der laufende Monat bleibt in den kurzen Epochen. Eine Stufe pro Tag gibt es nicht. Der DEK des Summenindex lebt nur für das Erzeugen.

[Summenindex](ablage-und-lesen.md#summenindex)

## tmpfs

Dateisystem im Speicher des Knotens. Dort liegen der öffentliche Plattform-KEK, der Cache-Schlüssel und die Index-Schlüssel. Nicht im Image, nicht in der Konfigurationsdatei, nicht auf der Platte.

[Betrieb](betrieb.md#vertrag-des-prozesses)

## Verzeichnis

Verweise von Person und Vorgangsnummer auf Strom, Epoche und erste Sequenz. Eigener DEK, derselbe KEK wie die Logs. Person und Vorgangsnummer stehen nur im Ciphertext. Die gezielte Suche im Werkzeug läuft darüber und öffnet nur die verwiesenen Einträge.

[Verzeichnis](ablage-und-lesen.md#verzeichnis)

## Vertrauensanker

Öffentlicher Schlüssel des Mandanten. Dagegen werden im sicheren Modus die Zertifikatskette und die Veröffentlichung geprüft. Den privaten Schlüssel hält der Mandant. Eine Veröffentlichung unter einem anderen Anker übernimmt der Schreibprozess nicht.

[Verteilung](schluessel.md#verteilung)

## Vorgangsindex

Ein Strom pro Mandant, nicht pro Kohorte. Er nennt, welche Personen an einem Vorgang stehen, in welcher Rolle, und bei einer Gruppe den Kohortennamen. Dazu Epoche, Sequenz und Zeitpunkt. Keinen Logtext. Ihn öffnet nur der Suchprozess, nach einer einzeln autorisierten Anfrage.

[Vorgangsindex](ablage-und-lesen.md#vorgangsindex)

## Wrap

Der öffentliche Schlüssel verschlüsselt den DEK, nicht den Logeintrag. Im Text auch wickeln oder einwickeln. Auswickeln tut die Plattform nicht, und sie bietet dafür keine Schnittstelle. Das tut das Werkzeug beim Empfänger, und für den Vorgangsindex der Suchprozess.

[Hüllenverschlüsselung](protokoll.md#hüllenverschlüsselung)

## Zugriffsschnitt

Beginn des UTC-Tages vor dem Löschtag. Ab dann öffnen Werkzeug und Suche die Epoche nicht mehr. Die Segmente liegen an diesem Tag noch. Entfernt wird am Löschtag.

[Löschen](ablage-und-lesen.md#löschen)

## Zugehörigkeit

Das Paar aus Mandant und Person. Der Mandant signiert die Aussage: Person, Rolle, Gültigkeit, und bei einem Datenschützer den Fingerabdruck des Aufrufschlüssels. Dieselbe Personenkennung bei einem anderen Mandanten ist eine andere Person. Die Aussage wird Teil des Klartexts des Logeintrags. Im Auffang steht sie nur, wenn sie gültig war und allein das Ablageziel fehlt.

[Zugehörigkeit](schluessel.md#zugehörigkeit)
