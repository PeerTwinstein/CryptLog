# CryptLog

CryptLog legt Audit-Logs verschlüsselt ab. Im Objektspeicher, auf der Platte und in Backups steht der Logtext als Ciphertext.

Den Text eines Mandanten öffnet der Datenschutzbeauftragte, mit seinem privaten Schlüssel. Das Werkzeug läuft auf seinem Rechner. Die Plattform hat den öffentlichen Schlüssel und wickelt damit die Datenschlüssel der Einträge ein. Ohne ermittelten Mandanten liest der Datenschutzbeauftragte der Plattform.

Technische Logs sind ein eigener Strom. Die beschreiben den Betrieb und haben keinen Personenbezug.

Ohne den privaten Schlüssel bleiben Mandant, Ablage und das Raster einer Epoche sichtbar. Person, Vorgang, Kohortenname und der Inhalt nicht. Ob gelöscht, umgeordnet oder ein zweites Mal signiert wurde, zeigt die Hash-Kette, auch ohne den Klartext.

Die Namen, Epoche, DEK, KEK und der Rest, stehen im [Glossar](docs/glossar.md).

## Ausprobieren

Schlüssel, drei Mandanten und das Werkzeug legt die [Testumgebung](docs/testumgebung.md) lokal an. Die Ablage liegt auf der Platte. Einen S3-Speicher stellt man selbst.

## Steckbrief

13 Folien: [docs/steckbrief.md](docs/steckbrief.md). Im Browser: [docs/steckbrief.html](docs/steckbrief.html).

## Festlegung

Der Überblick ist [docs/README.md](docs/README.md). Die Dokumente tragen ihren eigenen Stand.

- [Glossar](docs/glossar.md)
- [Schlüssel](docs/schluessel.md) — Modus, Zugehörigkeit, Wechsel
- [Protokoll](docs/protokoll.md) — Hülle, Ströme, Kette
- [Ablage und Lesen](docs/ablage-und-lesen.md) — Annahme, Suche, Löschen, Werkzeug
- [Betrieb](docs/betrieb.md) — Dienst, Container, Chart
- [Aufbau](docs/aufbau.md) — Pakete und Schreibpfad
