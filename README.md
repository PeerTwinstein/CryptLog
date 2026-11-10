# CryptLog

CryptLog legt die Audit-Logs einer Plattform verschlüsselt ab. Im Objektspeicher, auf der Platte und in Backups steht der Logtext nur als Ciphertext. Technische Logs bleiben ein eigener Strom. Sie beschreiben den Betrieb und enthalten keinen Personenbezug.

Den Logtext eines Mandanten öffnet genau ein Empfänger: der Datenschutzbeauftragte dieses Mandanten, mit seinem privaten Schlüssel. Das Werkzeug läuft auf seinem Rechner. Die Plattform wickelt den Schlüssel der Einträge ein. Ereignisse ohne ermittelten Mandanten liest der Datenschutzbeauftragte der Plattform.

Ohne diesen Schlüssel bleiben Mandant, Ablage und das Raster der Epoche sichtbar. Personenkennung, Vorgangsnummer, Kohortenname und der Inhalt liegen im Ciphertext. Eine Hash-Kette macht Löschen, Umordnen und eine zweite Fassung einer Epoche erkennbar, auch ohne den Klartext. Was sich nicht zuordnen lässt oder wofür der Schlüssel des Mandanten fehlt, bleibt erhalten und liegt verschlüsselt im Auffang.

Angenommen ist ein Ereignis erst, wenn Logeintrag, Verzeichnis und Vorgangsindex gemeinsam am Ziel stehen, das den schreibenden Knoten überdauert. Der Vorgangsindex ist ein eigener Bestand. Er nennt Personen und Vorgänge, keinen Logtext, und nur der Suchprozess öffnet ihn.

Im sicheren Modus bleibt der private Schlüssel beim Mandanten. Abgeschlossene Epochen bleiben für einen Administrator unlesbar, der Speicher und Ablage lesen darf, solange der Schreibprozess unverändert war und der Schlüssel nicht kompromittiert ist. Die gerade offene Epoche liegt in diesem Fenster noch im Speicher des Prozesses.

## Ausprobieren

Schlüssel, drei Mandanten und das Werkzeug legt die [Testumgebung](docs/testumgebung.md) lokal an. Die Ablage liegt auf der Platte. Einen S3-Speicher stellt man selbst.

## Zuerst die Folien

Der Steckbrief in 13 Folien: [docs/steckbrief.md](docs/steckbrief.md). Im Browser: [docs/steckbrief.html](docs/steckbrief.html).

## Das Konzept

Die Festlegung, Stand 8. November 2026, beginnt bei [docs/README.md](docs/README.md).

- [Schlüssel](docs/schluessel.md) — Modus, Zugehörigkeit, Wechsel
- [Protokoll](docs/protokoll.md) — Hülle, Ströme, Kette
- [Ablage und Lesen](docs/ablage-und-lesen.md) — Annahme, Suche, Löschen, Werkzeug
- [Betrieb](docs/betrieb.md) — Dienst, Container, Chart
- [Aufbau](docs/aufbau.md) — Pakete und Schreibpfad
