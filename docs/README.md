# CryptLog — Konzept Audit-Log-Verschlüsselung

Überblick, 13. November 2026. Die Festlegungen darunter haben ihren eigenen Stand.

Die [Testumgebung](testumgebung.md) ist die Anleitung zum Ausprobieren. Sie legt nichts fest. Kurze Erklärungen der Namen stehen im [Glossar](glossar.md).

## Dokumente

- [Glossar](glossar.md) — Epoche, DEK, KEK und die übrigen Namen
- [Schlüssel und Zugehörigkeit](schluessel.md) — Speicher, Verteilung, Cache, Modus, Wechsel, Grenze der Zusicherung
- [Protokoll](protokoll.md) — Hülle, Ströme, Kette, was ohne privaten Schlüssel sichtbar bleibt
- [Ablage und Lesen](ablage-und-lesen.md) — Ziel, Annahme, Löschen, Suche, Werkzeug
- [Betrieb](betrieb.md) — Dienst, Container, Chart, Metriken
- [Aufbau des Programms](aufbau.md) — Pakete und Schreibpfad

## Worum es geht

Die Plattform schreibt zwei Sorten Logs.

Technische Logs beschreiben den Betrieb. Kein Personenbezug, eigener Strom. Hier tauchen sie nur auf, wenn eine Ablage ohne Mandant oder ohne aktuellen KEK sichtbar wird, und dann ohne den Inhalt des Ereignisses.

Audit-Logs enthalten personenbezogene Daten. Die liegen verschlüsselt. Den Logtext eines Mandanten liest der Datenschutzbeauftragte dieses Mandanten, im Werkzeug auf seinem Rechner. Ereignisse ohne Mandant liest der Datenschutzbeauftragte der Plattform.

Angenommen ist ein Ereignis erst am Ziel, das den schreibenden Knoten überdauert. Logeintrag, Verzeichnis und Vorgangsindex gemeinsam. Der Vorgangsindex ist ein eigener Bestand: Personen und Vorgänge, kein Logtext, und nur der Suchprozess öffnet ihn.

Was ohne den privaten Schlüssel sichtbar bleiben darf, steht unter [Sichtbare Metadaten](protokoll.md#sichtbare-metadaten). Die Zusicherung im sicheren Modus und der Umgang mit Verlust und Kompromittierung stehen unter [Schlüssel](schluessel.md). Löschen, Suche und das Fenster unter [Ablage und Lesen](ablage-und-lesen.md).
