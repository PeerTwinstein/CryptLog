---
marp: true
theme: default
paginate: true
html: true
size: 16:9
title: CryptLog — Steckbrief
footer: CryptLog · Steckbrief der Audit-Log-Verschlüsselung
style: |
  section {
    font-family: "Segoe UI", sans-serif;
    background: #f3efe6;
    color: #1c1915;
    font-size: 22px;
    line-height: 1.35;
    padding: 42px 52px 46px;
  }
  section::after {
    color: #8a8175;
    font-size: 13px;
  }
  footer {
    color: #8a8175;
    font-size: 13px;
    letter-spacing: 0.01em;
  }
  h1, h2, h3 {
    font-family: "Segoe UI", sans-serif;
    font-weight: 650;
    letter-spacing: -0.02em;
    color: #1c3d3b;
  }
  section h1 { font-size: 40px; margin: 0 0 0.3em; }
  section h2 { font-size: 28px; margin: 0 0 14px; }
  section h3 { font-size: 17px; margin: 0 0 4px; }
  strong { color: #0f6b66; font-weight: 650; }
  code {
    font-family: Consolas, "Cascadia Code", monospace;
    font-size: 0.86em;
    background: #efe8dc;
    color: #1c3d3b;
    padding: 0.05em 0.35em;
    border-radius: 4px;
  }
  .kicker {
    margin: 0 0 10px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #0f6b66;
  }
  .grid2, .grid3 { display: grid; gap: 12px; }
  .grid2 { grid-template-columns: 1fr 1fr; }
  .grid3 { grid-template-columns: 1fr 1fr 1fr; }
  .card {
    background: #fffcf7;
    border: 1px solid #ddd4c6;
    border-left: 4px solid #0f6b66;
    border-radius: 12px;
    padding: 12px 14px 11px;
    height: 100%;
    box-sizing: border-box;
  }
  .card p, .card li { margin: 0; font-size: 15.5px; line-height: 1.35; color: #1c1915; }
  .card.copper { border-left-color: #8d4b2b; }
  .card.ink { border-left-color: #1c3d3b; }
  .card h3.copper { color: #8d4b2b; }
  .note, .note-copper {
    margin-top: 12px;
    border-radius: 10px;
    padding: 10px 14px;
    font-size: 15px;
    line-height: 1.35;
  }
  .note { background: #1c3d3b; color: #f3efe6; }
  .note strong { color: #e6c2a4; }
  .note-copper { background: #f6ece4; color: #1c1915; border: 1px solid #ead8c8; }
  .muted { color: #5e6a66; font-size: 14px; margin: 8px 0 0; }
  ul.clean { margin: 4px 0 0; padding-left: 1.05em; }
  ul.clean li { margin: 0.18em 0; font-size: 16px; }
  section table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14.5px;
    line-height: 1.3;
    margin: 0;
  }
  section table th {
    background: #1c3d3b;
    color: #f3efe6;
    font-weight: 600;
    text-align: left;
    padding: 6px 9px;
    border: none;
  }
  section table td {
    background: #fffcf7;
    color: #1c1915;
    padding: 5px 9px;
    border: none;
    border-bottom: 1px solid #eadfce;
    vertical-align: top;
  }
  section.lead {
    background: #1c3d3b;
    color: #f3efe6;
    padding: 68px 76px;
  }
  section.lead .kicker { color: #e6c2a4; }
  section.lead h1 {
    color: #f3efe6;
    font-size: 76px;
    margin: 0 0 8px;
    border-bottom: 4px solid #e6c2a4;
    display: inline-block;
    padding-bottom: 4px;
    line-height: 1;
  }
  section.lead .sub {
    margin: 18px 0 22px;
    font-size: 28px;
    color: #d7e4e1;
  }
  section.lead .leadtext {
    max-width: 980px;
    margin: 0;
    font-size: 22px;
    line-height: 1.45;
    color: #f3efe6;
  }
  section.lead .pills {
    display: flex;
    gap: 10px;
    margin-top: 36px;
    flex-wrap: wrap;
  }
  section.lead .pills span {
    border: 1px solid #3e6b68;
    background: #143330;
    color: #e6c2a4;
    border-radius: 999px;
    padding: 8px 14px;
    font-size: 15px;
  }
  section.lead footer, section.lead::after { color: #8fb3ae; }
  .docs { display: flex; flex-direction: column; gap: 8px; }
  .docs a {
    display: grid;
    grid-template-columns: 250px 1fr;
    gap: 16px;
    background: #fffcf7;
    border: 1px solid #ddd4c6;
    border-radius: 10px;
    padding: 11px 16px;
    text-decoration: none;
    color: #1c1915;
    font-size: 17px;
  }
  .docs a b { color: #0f6b66; font-weight: 700; }
  svg text { font-family: "Segoe UI", sans-serif; }
---

<!-- _class: lead -->
<!-- _paginate: false -->
<!-- _footer: "" -->

<p class="kicker">Konzept · Stand 8. November 2026</p>
<h1>CryptLog</h1>
<p class="sub">Steckbrief der Audit-Log-Verschlüsselung</p>
<p class="leadtext">Audit-Logs mit Personenbezug werden so abgelegt, dass die Plattform den Logtext einwickelt und nicht ausliest. Öffnen kann ihn der Datenschutzbeauftragte, mit seinem privaten Schlüssel, in einem Werkzeug außerhalb der Plattform.</p>
<div class="pills">
<span>Ein Empfänger für den Logtext</span>
<span>Vertraulich im Ruhezustand</span>
<span>Prüfbar ohne Klartext</span>
</div>

---

## Zwei Bestände

<div class="grid2">
<div class="card">
<h3>Technische Logs</h3>
<p>Beschreiben den Betrieb. Sie laufen über einen eigenen Strom und enthalten keinen Personenbezug. Das Konzept berührt sie nur dort, wo eine Ablage ohne Mandant oder ein fehlender Schlüssel sichtbar wird, jeweils ohne den Inhalt des Ereignisses.</p>
</div>
<div class="card copper">
<h3 class="copper">Audit-Logs</h3>
<p>Enthalten personenbezogene Daten und werden verschlüsselt abgelegt. Den Logtext eines Mandanten liest der Datenschutzbeauftragte dieses Mandanten. Ereignisse ohne ermittelten Mandanten liest ausschließlich der Datenschutzbeauftragte der Plattform.</p>
</div>
</div>
<div class="note">Der <strong>Vorgangsindex</strong> ist ein eigener Bestand. Er nennt Person, Vorgang und Strom, keinen Logtext. Ihn öffnet nur der Suchprozess.</div>

---

## Was zugesichert wird

<div class="grid3">
<div class="card">
<h3>Ruhezustand</h3>
<p>Objektspeicher, Platte und Backups enthalten den Logtext nur verschlüsselt.</p>
</div>
<div class="card">
<h3>Ein Empfänger</h3>
<p>Den Logtext eines Mandanten öffnet sein Datenschutzbeauftragter. Einen zweiten Wrap gibt es nicht.</p>
</div>
<div class="card">
<h3>Kleine Freigabe</h3>
<p>Objektschlüssel und Zusatzdaten nennen keine Person, keinen Vorgang, keinen Kohortennamen und keinen Ereigniszeitpunkt.</p>
</div>
<div class="card">
<h3>Erhalt</h3>
<p>Der Dienst verwirft kein Ereignis. Ohne Mandant oder ohne Schlüssel liegt es verschlüsselt im Auffang, sonst bleibt es beim Aufrufer.</p>
</div>
<div class="card">
<h3>Eine Annahme</h3>
<p>Logeintrag, Verzeichnis und Index gelten gemeinsam, am Ziel, das den schreibenden Knoten überdauert.</p>
</div>
<div class="card">
<h3>Erkennbar</h3>
<p>Löschen, Umordnen, Ersetzen, eine Lücke und eine zweite signierte Fassung sind ohne den Inhalt sichtbar.</p>
</div>
</div>

---

## Wo die Teile liegen

<svg viewBox="0 0 1120 400" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Schreibprozess, Ziel, Werkzeug, Suchprozess und Bestätigung">
<defs>
<marker id="pfeil" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#1c3d3b"/></marker>
</defs>
<rect x="30" y="36" width="229" height="132" rx="14" fill="#e7e4de" stroke="#8a8175" stroke-width="1.5"/>
<text x="46" y="66" fill="#5e6a66" font-size="12" font-weight="700" letter-spacing="1.1">AUFRUF</text>
<text x="46" y="90" fill="#1c1915" font-size="18" font-weight="700">Dienste</text>
<text x="46" y="114" fill="#1c1915" font-size="14">POST /ereignis</text>
<text x="46" y="134" fill="#1c1915" font-size="14">behält Unangenommenes</text>
<rect x="307" y="36" width="229" height="132" rx="14" fill="#e5f2f0" stroke="#0f6b66" stroke-width="1.5"/>
<text x="323" y="66" fill="#0f6b66" font-size="12" font-weight="700" letter-spacing="1.1">PLATTFORM</text>
<text x="323" y="90" fill="#1c1915" font-size="18" font-weight="700">Schreibprozess</text>
<text x="323" y="114" fill="#1c1915" font-size="14">verschlüsselt, wickelt ein</text>
<text x="323" y="134" fill="#1c1915" font-size="14">liest den Logtext nicht aus</text>
<rect x="584" y="36" width="229" height="132" rx="14" fill="#1c3d3b"/>
<text x="600" y="66" fill="#e6c2a4" font-size="12" font-weight="700" letter-spacing="1.1">ABLAGE</text>
<text x="600" y="90" fill="#f3efe6" font-size="18" font-weight="700">Ziel</text>
<text x="600" y="114" fill="#f3efe6" font-size="14">S3 oder Platte, Ciphertext</text>
<text x="600" y="134" fill="#f3efe6" font-size="14">überdauert den Knoten</text>
<rect x="861" y="36" width="229" height="132" rx="14" fill="#f6ece4" stroke="#8d4b2b" stroke-width="1.5"/>
<text x="877" y="66" fill="#8d4b2b" font-size="12" font-weight="700" letter-spacing="1.1">EMPFÄNGER</text>
<text x="877" y="90" fill="#1c1915" font-size="18" font-weight="700">Werkzeug</text>
<text x="877" y="114" fill="#1c1915" font-size="14">auf seinem Rechner</text>
<text x="877" y="134" fill="#1c1915" font-size="14">öffnet nur die Auswahl</text>
<rect x="307" y="248" width="229" height="120" rx="14" fill="#f6ece4" stroke="#8d4b2b" stroke-width="1.5"/>
<text x="323" y="276" fill="#8d4b2b" font-size="12" font-weight="700" letter-spacing="1.1">EMPFÄNGER</text>
<text x="323" y="300" fill="#1c1915" font-size="18" font-weight="700">Bestätigung</text>
<text x="323" y="324" fill="#1c1915" font-size="14">außerhalb des Buckets</text>
<text x="323" y="344" fill="#1c1915" font-size="14">bleibt nach dem Löschen</text>
<rect x="584" y="248" width="229" height="120" rx="14" fill="#e5f2f0" stroke="#0f6b66" stroke-width="1.5"/>
<text x="600" y="276" fill="#0f6b66" font-size="12" font-weight="700" letter-spacing="1.1">ZONE</text>
<text x="600" y="300" fill="#1c1915" font-size="18" font-weight="700">Suchprozess</text>
<text x="600" y="324" fill="#1c1915" font-size="14">nur der Vorgangsindex</text>
<text x="600" y="344" fill="#1c1915" font-size="14">kein Logtext</text>
<line x1="264" y1="102" x2="302" y2="102" stroke="#1c3d3b" stroke-width="1.6" marker-end="url(#pfeil)"/>
<text x="283" y="92" text-anchor="middle" fill="#5e6a66" font-size="12">Ereignis</text>
<line x1="541" y1="102" x2="579" y2="102" stroke="#1c3d3b" stroke-width="1.6" marker-end="url(#pfeil)"/>
<text x="560" y="92" text-anchor="middle" fill="#5e6a66" font-size="12">Ciphertext</text>
<line x1="856" y1="102" x2="818" y2="102" stroke="#8d4b2b" stroke-width="1.6" marker-end="url(#pfeil)"/>
<text x="837" y="92" text-anchor="middle" fill="#8d4b2b" font-size="12">Auswahl</text>
<line x1="421" y1="172" x2="421" y2="242" stroke="#8d4b2b" stroke-width="1.6" marker-end="url(#pfeil)"/>
<text x="430" y="214" fill="#8d4b2b" font-size="12">Manifest</text>
<line x1="698" y1="244" x2="698" y2="174" stroke="#0f6b66" stroke-width="1.6" marker-end="url(#pfeil)"/>
<text x="708" y="214" fill="#0f6b66" font-size="12">Index</text>
</svg>
<p class="muted">Schreiben und Suchen teilen sich keinen Adressraum und kein Secret. Das Werkzeug läuft nicht als Dienst, nicht im Image und nicht im Chart.</p>

---

## Weg eines Ereignisses

<svg viewBox="0 0 1120 156" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Sechs Schritte von Ereignis bis Annahme">
<defs>
<marker id="pfeil2" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#1c3d3b"/></marker>
</defs>
<rect x="16" y="36" width="158" height="104" rx="12" fill="#fffcf7" stroke="#ddd4c6"/>
<circle cx="38" cy="60" r="12" fill="#1c3d3b"/><text x="38" y="64" text-anchor="middle" fill="#f3efe6" font-size="13" font-weight="700">1</text>
<text x="56" y="64" fill="#1c1915" font-size="15" font-weight="700">Ereignis</text>
<text x="32" y="96" fill="#1c1915" font-size="13">event_id, 16 Byte</text>
<text x="32" y="116" fill="#1c1915" font-size="13">vom Aufrufer</text>
<rect x="202" y="36" width="158" height="104" rx="12" fill="#fffcf7" stroke="#ddd4c6"/>
<circle cx="224" cy="60" r="12" fill="#1c3d3b"/><text x="224" y="64" text-anchor="middle" fill="#f3efe6" font-size="13" font-weight="700">2</text>
<text x="242" y="64" fill="#1c1915" font-size="15" font-weight="700">Auflösen</text>
<text x="218" y="96" fill="#1c1915" font-size="13">Mandant und</text>
<text x="218" y="116" fill="#1c1915" font-size="13">signierte Aussage</text>
<rect x="388" y="36" width="158" height="104" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<circle cx="410" cy="60" r="12" fill="#0f6b66"/><text x="410" y="64" text-anchor="middle" fill="#f3efe6" font-size="13" font-weight="700">3</text>
<text x="428" y="64" fill="#1c1915" font-size="15" font-weight="700">Strom</text>
<text x="404" y="96" fill="#1c1915" font-size="13">Gruppe, Einzeln</text>
<text x="404" y="116" fill="#1c1915" font-size="13">oder Auffang</text>
<rect x="574" y="36" width="158" height="104" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<circle cx="596" cy="60" r="12" fill="#0f6b66"/><text x="596" y="64" text-anchor="middle" fill="#f3efe6" font-size="13" font-weight="700">4</text>
<text x="614" y="64" fill="#1c1915" font-size="15" font-weight="700">Hülle</text>
<text x="590" y="96" fill="#1c1915" font-size="13">AES-256-GCM</text>
<text x="590" y="116" fill="#1c1915" font-size="13">unter dem DEK</text>
<rect x="760" y="36" width="158" height="104" rx="12" fill="#fffcf7" stroke="#ddd4c6"/>
<circle cx="782" cy="60" r="12" fill="#1c3d3b"/><text x="782" y="64" text-anchor="middle" fill="#f3efe6" font-size="13" font-weight="700">5</text>
<text x="800" y="64" fill="#1c1915" font-size="15" font-weight="700">Spool</text>
<text x="776" y="96" fill="#1c1915" font-size="13">Fsync auf dem Knoten</text>
<text x="776" y="116" fill="#1c1915" font-size="13">noch keine Annahme</text>
<rect x="946" y="36" width="158" height="104" rx="12" fill="#1c3d3b"/>
<circle cx="968" cy="60" r="12" fill="#e6c2a4"/><text x="968" y="64" text-anchor="middle" fill="#1c1915" font-size="13" font-weight="700">6</text>
<text x="986" y="64" fill="#f3efe6" font-size="15" font-weight="700">Annahme</text>
<text x="962" y="96" fill="#f3efe6" font-size="13">Tausch am Ziel</text>
<text x="962" y="116" fill="#f3efe6" font-size="13">dann die Antwort</text>
<line x1="178" y1="88" x2="198" y2="88" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil2)"/>
<line x1="364" y1="88" x2="384" y2="88" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil2)"/>
<line x1="550" y1="88" x2="570" y2="88" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil2)"/>
<line x1="736" y1="88" x2="756" y2="88" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil2)"/>
<line x1="922" y1="88" x2="942" y2="88" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil2)"/>
</svg>
<div class="grid3">
<div class="card ink">
<h3>Kein Mandant</h3>
<p>Plattform-Auffang, gewrappt mit dem Plattform-KEK. Den Inhalt liest der Datenschutzbeauftragte der Plattform.</p>
</div>
<div class="card copper">
<h3 class="copper">Kein Mandanten-KEK</h3>
<p>Dead Letter Box im Bucket des Mandanten, Grund <code>kek_fehlt</code>. Sichtbar für ihn, zu öffnen nur mit dem Plattform-Schlüssel.</p>
</div>
<div class="card">
<h3>Mandant und KEK</h3>
<p>Gruppe oder Einzelstrom. Ist eine Person einzeln geführt, entstehen nur ihre Einzelströme. Ohne Zuordnung bleibt der Auffang des Mandanten.</p>
</div>
</div>
<div class="note">Angenommen ist das Ereignis erst, wenn die Belegung am Ziel auf angenommen steht. Dieselbe <strong>event_id</strong> bestätigt diese Annahme. Ein anderer Inhalt unter derselben Kennung wird abgelehnt.</div>

---

## Hülle einer Epoche

<div class="grid2">
<div>
<svg viewBox="0 0 520 418" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Aufbau einer Epoche aus Kopf, Rahmen und Manifest">
<rect x="4" y="4" width="512" height="410" rx="16" fill="#fffcf7" stroke="#ddd4c6"/>
<text x="24" y="32" fill="#1c3d3b" font-size="14" font-weight="700" letter-spacing="1.2">EPOCHE</text>
<rect x="20" y="48" width="480" height="108" rx="12" fill="#f6ece4" stroke="#8d4b2b"/>
<text x="36" y="74" fill="#8d4b2b" font-size="15" font-weight="700">Kopf, unverschlüsselt</text>
<text x="36" y="98" fill="#1c1915" font-size="14">Fingerabdruck des KEK und dek_id</text>
<text x="36" y="118" fill="#1c1915" font-size="14">Wrap von DEK und bind_id, einmal</text>
<text x="36" y="138" fill="#1c1915" font-size="14">RSA-OAEP ab 3072 Bit, oder HPKE auf P-256</text>
<rect x="20" y="168" width="480" height="128" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<text x="36" y="194" fill="#0f6b66" font-size="15" font-weight="700">Rahmen, AES-256-GCM</text>
<text x="36" y="218" fill="#1c1915" font-size="14">Nonce aus Präfix der Epoche und Sequenz</text>
<text x="36" y="238" fill="#1c1915" font-size="14">Zusatzdaten: Mandant, Ablage, Epoche, dek_id, seq</text>
<text x="36" y="258" fill="#1c1915" font-size="14">Klartext: event_id, Zeitpunkt, bind_id, Inhalt</text>
<text x="36" y="278" fill="#5e6a66" font-size="13">Füllung und Fortsetzung liegen in derselben Kette</text>
<rect x="20" y="308" width="480" height="86" rx="12" fill="#1c3d3b"/>
<text x="36" y="338" fill="#e6c2a4" font-size="15" font-weight="700">Manifest am Ende</text>
<text x="36" y="362" fill="#f3efe6" font-size="14">SHA-256 über die Ciphertexte, nicht über den Klartext</text>
<text x="36" y="382" fill="#f3efe6" font-size="14">ECDSA P-256, signiert im HSM</text>
</svg>
</div>
<div>
<div class="card">
<h3>Flüchtig</h3>
<p>Der DEK hat 32 Byte und liegt nur im Speicher der schreibenden Instanz. Gruppe 60 Minuten, Einzelperson 8 Stunden. Zulässig sind 15 Minuten bis 8 Stunden.</p>
</div>
<div class="card" style="margin-top:12px">
<h3>Neu nach jedem Bruch</h3>
<p>Neustart, Absturz, Fork und ein wiederhergestelltes Abbild beginnen eine neue Epoche. Ein DEK wird nicht aus dem Speicher zurückgeholt.</p>
</div>
<div class="card" style="margin-top:12px">
<h3>Ein Wrap</h3>
<p>Gruppenstrom, Einzelstrom und Verzeichnis eines Mandanten hängen an seinem KEK. Der Plattform-KEK wrappt diese Epochen nicht zusätzlich.</p>
</div>
<div class="card ink" style="margin-top:12px">
<h3>Ohne den DEK prüfbar</h3>
<p>Kette, HSM-Signatur und Epochenbestätigung brauchen den Schlüssel der Einträge nicht.</p>
</div>
</div>
</div>

---

## Ströme eines Mandanten

| Strom | Was darin liegt | Wer den Inhalt öffnet |
|---|---|---|
| Gruppe | Ereignisse einer Kohorte, gemeinsamer DEK der Instanz | Datenschutzbeauftragter des Mandanten |
| Einzeln | nur die Ereignisse dieser Person, eigener DEK | derselbe Empfänger |
| Auffang | ohne Zuordnung, oder der Mandanten-KEK fehlt | Mandant, bei fehlendem KEK die Plattform |
| Verzeichnis | Verweise von Person und Vorgang auf den Eintrag | Werkzeug, für die gezielte Suche |
| Vorgang | Personen eines Vorgangs, über Kohorten hinweg, ohne Logtext | Suchprozess |
| Katalog | Kennung, Rolle und bei Gruppen der Name | Werkzeug, zum Auflösen der Namen |

<p class="muted">Gruppe und Einzelperson haben denselben Empfänger. Getrennt sind Ablage und DEK. Der Name einer Kohorte steht im Katalog, nicht im Objektschlüssel. Der Schlüssel lautet <code>{mandant}/{ablage}/{epoche}/{segment}</code>.</p>

---

## Schlüssel

| Schlüssel | Wo er liegt | Was er bewirkt |
|---|---|---|
| KEK | öffentlich in der Plattform, privat beim Datenschutzbeauftragten | wrappt Log, Verzeichnis, Katalog und den Auffang des Mandanten |
| Plattform-KEK | öffentlich, Secret auf tmpfs | wrappt den Plattform-Auffang und Epochen ohne Mandanten-KEK |
| Index-Schlüssel | privat nur im Suchprozess | wrappt den Vorgangsindex, keinen Logtext |
| DEK | Speicher der Instanz, bis die Epoche endet | verschlüsselt die Einträge dieser Epoche |
| Integrität | HSM der Plattform, nicht exportierbar | signiert das Manifest, öffnet nichts |
| Bestätigung | privat beim Empfänger | bestätigt den Hash der Epoche, öffnet nichts |

<div class="grid2" style="margin-top:12px">
<div class="card">
<h3>Einfacher Modus</h3>
<p>Öffentlicher Schlüssel und bereits verschlüsselter privater Schlüssel, PKCS#8 mit Argon2id, dazu ein Zertifikat der lokalen CA. Die Passphrase bleibt beim Empfänger.</p>
</div>
<div class="card copper">
<h3 class="copper">Sicherer Modus</h3>
<p>Nur ein geprüftes Zertifikat. Der private Schlüssel entsteht beim Mandanten, auf Smartcard oder HSM, und wird nicht hochgeladen. Die Veröffentlichung ist unter dem Vertrauensanker signiert.</p>
</div>
</div>

---

## Prüfen, suchen, löschen

<div class="grid2">
<div class="card">
<h3>Gruppe über einen Zeitraum</h3>
<p>Anlasslose Prüfung. Die Epochen dieses Gruppenstroms im Fenster. Das Verzeichnis wird dafür nicht gebraucht.</p>
</div>
<div class="card">
<h3>Person oder Vorgangsnummer</h3>
<p>Gezielte Suche. Das Werkzeug liest die Verweise und entschlüsselt nur diese Einträge, auch im Auffang.</p>
</div>
<div class="card">
<h3>Auffang über einen Zeitraum</h3>
<p>Ereignisse ohne Zuordnung, jeweils mit Grund. Eine Gruppenprüfung schließt den Auffang nicht ein.</p>
</div>
<div class="card copper">
<h3 class="copper">Plattform-Auffang</h3>
<p>Ereignisse ohne Mandant und Epochen mit fehlendem Mandanten-KEK. Nur der Datenschutzbeauftragte der Plattform.</p>
</div>
</div>
<div class="note-copper"><strong>Suchprozess.</strong> Welche Personen an einem Vorgang gearbeitet haben, und in der anderen Richtung die Vorgänge einer Person. Die Anfrage signiert der Datenschützer mit seinem Aufrufschlüssel. Zurück gehen die Treffer dieses Mandanten, ohne Logtext.</div>
<div class="note">Gelöscht wird eine ganze Epoche nach der Frist des Mandanten. Eine Person aus einer Gruppenepoche zu lösen verlangte die Umschlüsselung; der Klartext liegt nach dem Abschluss nicht mehr vor. Die Bestätigung bleibt, damit die Löschung erkennbar ist.</div>

---

## Was ohne privaten Schlüssel sichtbar bleibt

<div class="grid2">
<div class="card">
<h3>Sichtbar</h3>
<ul class="clean">
<li>Mandant, Ablage, Raster, Größenklasse, Objektmenge</li>
<li>Fingerabdruck des KEK und die Art des Schlüssels an der Länge des Wraps</li>
<li>Manifestkette, HSM-Signatur, Epochenbestätigung</li>
<li>In der Annahme Kennung, Hash und Segmentreferenzen</li>
<li>Im technischen Log der Mandantenname, nur beim Grund <code>kek_fehlt</code></li>
</ul>
</div>
<div class="card copper">
<h3 class="copper">Im Ciphertext</h3>
<ul class="clean">
<li>Personenkennung, Vorgangsnummer, Kohortenname</li>
<li>Zeitpunkt des Ereignisses und der Logtext</li>
<li>Grund und Bezüge im Auffang</li>
<li>Namen im Stromkatalog</li>
</ul>
</div>
</div>
<svg viewBox="0 0 1120 108" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Manifestkette von der Genesis bis zur Bestätigung" style="margin-top:10px">
<defs>
<marker id="pfeil3" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#1c3d3b"/></marker>
</defs>
<rect x="16" y="22" width="176" height="70" rx="12" fill="#e7e4de" stroke="#8a8175"/>
<text x="104" y="50" text-anchor="middle" fill="#1c1915" font-size="15" font-weight="700">Genesis</text>
<text x="104" y="72" text-anchor="middle" fill="#5e6a66" font-size="13">Ablage und Instanz</text>
<rect x="240" y="22" width="176" height="70" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<text x="328" y="50" text-anchor="middle" fill="#1c1915" font-size="15" font-weight="700">Epoche</text>
<text x="328" y="72" text-anchor="middle" fill="#5e6a66" font-size="13">eigene Hash-Kette</text>
<rect x="464" y="22" width="176" height="70" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<text x="552" y="50" text-anchor="middle" fill="#1c1915" font-size="15" font-weight="700">Epoche</text>
<text x="552" y="72" text-anchor="middle" fill="#5e6a66" font-size="13">setzt auf die vorige</text>
<rect x="688" y="22" width="176" height="70" rx="12" fill="#e5f2f0" stroke="#0f6b66"/>
<text x="776" y="50" text-anchor="middle" fill="#1c1915" font-size="15" font-weight="700">Epoche</text>
<text x="776" y="72" text-anchor="middle" fill="#5e6a66" font-size="13">vom HSM signiert</text>
<rect x="912" y="22" width="192" height="70" rx="12" fill="#f6ece4" stroke="#8d4b2b"/>
<text x="1008" y="50" text-anchor="middle" fill="#1c1915" font-size="15" font-weight="700">Bestätigung</text>
<text x="1008" y="72" text-anchor="middle" fill="#8d4b2b" font-size="13">bleibt nach dem Löschen</text>
<line x1="196" y1="57" x2="234" y2="57" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil3)"/>
<line x1="420" y1="57" x2="458" y2="57" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil3)"/>
<line x1="644" y1="57" x2="682" y2="57" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil3)"/>
<line x1="868" y1="57" x2="906" y2="57" stroke="#1c3d3b" stroke-width="1.5" marker-end="url(#pfeil3)"/>
</svg>
<p class="muted">Eine zweite gültig signierte Fassung ist eine Verzweigung und ersetzt den Abschluss nicht. Deckverkehr ist je Mandant zuschaltbar, im Ausgang aus, und schreibt leere Epochen, damit ein fehlendes Raster die Stille nicht zeigt.</p>

---

## Dieselbe Fassung, drei Prozesse

<div class="grid3">
<div class="card">
<h3>cryptlog schreiben</h3>
<p>Dienst, Container oder Helm-Chart. Nimmt Ereignisse an, hält den Spool, schreibt das Ziel und reicht das Manifest ein. Secrets auf tmpfs: Plattform-KEK, Cache-Schlüssel, öffentlicher Index-Schlüssel.</p>
</div>
<div class="card">
<h3>cryptlog suchen</h3>
<p>Eigene Sicherheitszone, eine Replica. Keine Shell, kein Export des Index. Jede Anfrage wird einzeln autorisiert und protokolliert. Das Protokoll bleibt in der Zone.</p>
</div>
<div class="card copper">
<h3 class="copper">cryptlog werkzeug</h3>
<p>Fenster auf dem Rechner des Empfängers. Eine Konfigurationsdatei öffnet keine Prüfung. Die Passphrase wird nicht abgelegt. Der Klartext endet mit der Prüfung.</p>
</div>
</div>
<div class="note">Bereitschaft auf einem eigenen Port: <strong>/live</strong>, <strong>/ready</strong>, <strong>/metrics</strong>. Prometheus nennt keine Person, keine Vorgangsnummer und kein Suchprotokoll. Mengenzähler eines Mandanten gibt es nur bei ausgeschaltetem Deckverkehr. Ein Fork und ein wiederhergestelltes Prozessabbild sind keine Betriebsformen.</div>

---

## Grenze im sicheren Modus

<p class="muted" style="margin-top:0">Der Plattformadministrator darf Objektspeicher, Platte, Backups und den Speicher des Schreibprozesses lesen. Programmcode, Deployment und Laufzeitumgebung darf er nicht ändern.</p>
<div class="grid3" style="margin-top:12px">
<div class="card copper">
<h3 class="copper">Offene Epoche</h3>
<p>Im Prozessspeicher liegt der Klartext-DEK. Das Fenster ist das Rotationsintervall, höchstens 8 Stunden. Mit dem Abschluss ist er verworfen.</p>
</div>
<div class="card">
<h3>Abgeschlossene Epoche</h3>
<p>Aus Ablage und Backup entsteht der Logtext nicht. Der private Schlüssel dieses Fingerabdrucks liegt nicht in der Plattform und ist nicht kompromittiert.</p>
</div>
<div class="card ink">
<h3>Veränderter Prozess</h3>
<p>War Code, Deployment oder Laufzeit verändert, solange die Epoche offen war, trägt sie die Zusicherung auch nach dem Abschluss nicht. Ein anderer Image-Digest gehört dazu.</p>
</div>
</div>
<div class="note-copper" style="margin-top:12px"><strong>Kompromittierung</strong> trifft jede noch vorhandene Epoche dieses Fingerabdrucks, einschließlich Backup und Export. Das Öffnen hinterlässt keine Spur. <strong>Verlust</strong> lässt dieselben Epochen unlesbar. Der Nachfolger wickelt nur neue Epochen. Eine Umschlüsselung findet nicht statt.</div>
<div class="note">Der Vorgangsindex liegt außerhalb dieser Aussage. Wer die Zone des Suchprozesses liest, sieht Personen, Vorgänge und Zeitpunkte. Den Logtext sieht er daraus nicht.</div>

---

<!-- _class: lead -->
<!-- _paginate: false -->
<!-- _footer: "" -->

<p class="kicker">Weiterlesen</p>
<h1 style="font-size:48px">Wo es festgelegt ist</h1>
<p class="sub" style="font-size:22px;margin-top:12px">Die Folien sind der Steckbrief. Die Festlegung steht in den Dokumenten vom 8. November 2026.</p>
<div class="docs">
<a href="schluessel.md"><b>Schlüssel</b><span>Modus, Zugehörigkeit, Wechsel, Verlust, Grenze</span></a>
<a href="protokoll.md"><b>Protokoll</b><span>Hülle, Ströme, Kette, sichtbare Metadaten</span></a>
<a href="ablage-und-lesen.md"><b>Ablage und Lesen</b><span>Annahme, Suche, Löschen, Werkzeug</span></a>
<a href="betrieb.md"><b>Betrieb</b><span>Dienst, Container, Chart, Metriken</span></a>
<a href="aufbau.md"><b>Aufbau</b><span>Pakete, Schreibpfad, Wiederanlauf</span></a>
</div>
