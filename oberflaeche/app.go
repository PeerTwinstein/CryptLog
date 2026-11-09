package oberflaeche

import (
	"fmt"
	"image/color"
	"os"
	"strings"
	"time"

	"gioui.org/app"
	"gioui.org/font/opentype"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"cryptlog/crypt"
	"cryptlog/fenster"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/suchen"
	"cryptlog/werkzeug"
)

// Start öffnet das Fenster. pfad ist eine abgelegte Verbindung oder leer.
// Die Datei entsperrt nichts und startet keine Prüfung.
func Start(pfad string) {
	go func() {
		w := new(app.Window)
		w.Option(app.Title("CryptLog"), app.Size(unit.Dp(980), unit.Dp(760)))
		u := neueUI(w, pfad)
		code := u.schleife()
		os.Exit(code)
	}()
	app.Main()
}

type rueckgabe struct {
	text   string
	fehler bool
	danach func()
}

type ui struct {
	w         *app.Window
	th        *material.Theme
	liste     widget.List
	komm      chan rueckgabe
	arbeit    bool
	meldung   string
	fehler    bool
	startPfad string
	geladen   bool

	vorlage      *Vorlage
	finger       string
	certEnde     time.Time
	pruefPfad    string
	hsmPfad      string
	bestPfad     string
	status       widget.Enum
	person       widget.Editor
	suche        widget.Editor
	instanz      widget.Editor
	rahmen       widget.Editor
	intervall    widget.Editor
	frist        widget.Editor
	speicher     widget.Editor
	region       widget.Editor
	zugang       widget.Editor
	geheimnis    widget.Editor
	pass         widget.Editor
	oeffnen      widget.Clickable
	entsperren   widget.Clickable
	pruefWahl    widget.Clickable
	hsmWahl      widget.Clickable
	bestWahl     widget.Clickable
	speicherWahl widget.Clickable

	sitz        *Sitzung
	art         widget.Enum
	kohorte     widget.Editor
	von         widget.Editor
	bis         widget.Editor
	suchPerson  widget.Editor
	suchVorgang widget.Editor
	zaehlen     widget.Clickable
	pruefen     widget.Clickable
	ende        widget.Clickable
	erg         *fenster.Ergebnis

	bestPass    widget.Editor
	bestaetigen widget.Clickable
	monat       widget.Editor
	summeWahl   widget.Clickable

	frageArt       widget.Enum
	frageSchlussel widget.Editor
	frageVon       widget.Editor
	frageBis       widget.Editor
	aufrufPass     widget.Editor
	aufrufKnopf    widget.Clickable
	frageKnopf     widget.Clickable
	aufrufOffen    bool
	treffer        *suchen.Treffer
	trefferArt     protocol.AnfrageArt
	schliessen     widget.Clickable
}

func neueUI(w *app.Window, pfad string) *ui {
	u := &ui{
		w: w, th: thema(), komm: make(chan rueckgabe, 4), startPfad: pfad,
		liste: widget.List{List: layout.List{Axis: layout.Vertical}},
	}
	for _, ed := range []*widget.Editor{
		&u.person, &u.suche, &u.instanz, &u.rahmen, &u.intervall, &u.frist, &u.speicher,
		&u.region, &u.zugang, &u.kohorte, &u.von, &u.bis, &u.suchPerson, &u.suchVorgang,
		&u.monat, &u.frageSchlussel, &u.frageVon, &u.frageBis,
	} {
		*ed = widget.Editor{SingleLine: true, Submit: true}
	}
	for _, ed := range []*widget.Editor{&u.geheimnis, &u.pass, &u.bestPass, &u.aufrufPass} {
		*ed = widget.Editor{SingleLine: true, Submit: true, Mask: '•'}
	}
	u.rahmen.SetText("256")
	u.intervall.SetText("60")
	u.frist.SetText("30")
	u.status.Value = "aktuell"
	u.frageArt.Value = "vorgang"
	jetzt := time.Now().UTC()
	u.von.SetText(jetzt.AddDate(0, 0, -1).Format("2006-01-02"))
	u.bis.SetText(jetzt.Format("2006-01-02"))
	u.frageVon.SetText(u.von.Text())
	u.frageBis.SetText(u.bis.Text())
	u.monat.SetText(jetzt.AddDate(0, -1, 0).Format("2006-01"))
	return u
}

func (u *ui) schleife() int {
	var ops op.Ops
	for {
		switch e := u.w.Event().(type) {
		case app.DestroyEvent:
			u.sitzungZu()
			if e.Err != nil {
				return 1
			}
			return 0
		case app.FrameEvent:
			u.abholen()
			if !u.geladen {
				u.geladen = true
				if u.startPfad != "" {
					u.verbindungLaden(u.startPfad)
				}
			}
			gtx := app.NewContext(&ops, e)
			paint.Fill(gtx.Ops, u.th.Palette.Bg)
			u.rahmenLayout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func (u *ui) abholen() {
	for {
		select {
		case r := <-u.komm:
			u.arbeit = false
			u.meldung = r.text
			u.fehler = r.fehler
			if r.danach != nil {
				r.danach()
			}
		default:
			return
		}
	}
}

func (u *ui) lauf(fn func() rueckgabe) {
	if u.arbeit {
		return
	}
	u.arbeit = true
	u.meldung = "Die Handlung läuft."
	u.fehler = false
	go func() {
		u.komm <- fn()
		u.w.Invalidate()
	}()
}

func (u *ui) rahmenLayout(gtx layout.Context) layout.Dimensions {
	return material.List(u.th, &u.liste).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return layout.UniformInset(unit.Dp(20)).Layout(gtx, u.inhalt)
	})
}

func (u *ui) inhalt(gtx layout.Context) layout.Dimensions {
	var kinder []layout.FlexChild
	kinder = append(kinder, u.zeilen(u.titel("CryptLog"))...)
	kinder = append(kinder, abschnitt())
	if u.sitz == nil {
		kinder = append(kinder, u.verbindung()...)
	} else {
		kinder = append(kinder, u.pruefung()...)
	}
	if u.meldung != "" {
		kinder = append(kinder, abschnitt(), layout.Rigid(u.meldungsZeile()))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kinder...)
}

func (u *ui) verbindung() []layout.FlexChild {
	zeilen := []layout.Widget{
		u.text("Die Verbindung legt keine Passphrase ab. Eine Prüfung beginnt erst nach dem Entsperren."),
		u.knopf(&u.oeffnen, "Verbindung öffnen", u.verbindungWaehlen),
	}
	if u.vorlage == nil {
		return u.zeilen(zeilen...)
	}
	v := u.vorlage.Verbindung
	ziel := v.Pfad
	if v.Ziel == fenster.ZielS3 {
		ziel = v.Endpunkt + "  " + v.Bucket
	}
	zeilen = append(zeilen,
		u.text("Mandant "+v.Mandant.Hex()),
		u.text("Ziel "+ziel),
		u.text("Modus "+modusWort(u.vorlage.Modus)),
		u.text("Fingerabdruck"),
		u.text(u.finger),
		u.text("Status "+statusWort(u.statusGewaehlt(), u.certEnde, time.Now().UTC())),
		u.wahl(&u.status, "aktuell", "aktuell"),
		u.wahl(&u.status, "abgeloest", "abgelöst"),
		u.wahl(&u.status, "kompromittiert", "kompromittiert"),
		u.wahl(&u.status, "verloren", "verloren"),
		u.wahl(&u.status, "abgelaufen", "abgelaufen"),
		u.dateiZeile(&u.pruefWahl, "Prüfschlüssel", u.pruefPfad, func(p string) { u.pruefPfad = p }),
		u.dateiZeile(&u.hsmWahl, "HSM, öffentlich", u.hsmPfad, func(p string) { u.hsmPfad = p }),
		u.dateiZeile(&u.bestWahl, "Bestätigung, öffentlich", u.bestPfad, func(p string) { u.bestaetigungSetzen(p) }),
		u.eingabe(&u.speicher, "Bestätigungsspeicher"),
		u.knopf(&u.speicherWahl, "Ordner", u.speicherWaehlen),
		u.eingabe(&u.person, "Person des Aufrufs"),
		u.eingabe(&u.suche, "Suchadresse, vor dem Entsperren"),
		u.eingabe(&u.instanz, "Instanz, für die Summenepoche"),
		u.eingabe(&u.rahmen, "Rahmen in Byte"),
		u.eingabe(&u.intervall, "Intervall in Minuten"),
		u.eingabe(&u.frist, "Frist in Tagen"),
	)
	if v.Ziel == fenster.ZielS3 {
		zeilen = append(zeilen,
			u.eingabe(&u.region, "Region"),
			u.eingabe(&u.zugang, "Zugang"),
			u.eingabe(&u.geheimnis, "Geheimnis, bleibt in dieser Sitzung"),
		)
	}
	if u.vorlage.Modus == schluessel.ModusEinfach {
		zeilen = append(zeilen,
			u.eingabe(&u.pass, "Passphrase"),
			u.knopf(&u.entsperren, "Entsperren", u.entsperrenKlick),
		)
	} else {
		zeilen = append(zeilen, u.text("Sicherer Modus: der Schlüssel bleibt auf dem Träger. Dieser Bau hat keinen Trägeranschluss."))
	}
	return u.zeilen(zeilen...)
}

func (u *ui) pruefung() []layout.FlexChild {
	sicht := u.sitz.Fenster.Sicht()
	zeilen := []layout.Widget{
		u.text("Fingerabdruck " + fingerText(sicht.Finger)),
		u.text("Status " + statusWort(sicht.Status, time.Time{}, time.Now())),
		u.knopf(&u.schliessen, "Sitzung schließen", u.sitzungZu),
		u.text("Klartext bleibt in diesem Fenster und wird mit dem Ende der Prüfung verworfen."),
	}
	for _, art := range u.sitz.Fenster.Arten() {
		zeilen = append(zeilen, u.wahl(&u.art, artSchluessel(art), artWort(art)))
	}
	gew, _ := artVon(u.art.Value)
	switch gew {
	case fenster.ArtGruppe:
		zeilen = append(zeilen, u.eingabe(&u.kohorte, "Kohorte"))
	case fenster.ArtGezielt:
		zeilen = append(zeilen,
			u.eingabe(&u.suchPerson, "Person"),
			u.eingabe(&u.suchVorgang, "Vorgangsnummer"),
		)
	}
	zeilen = append(zeilen,
		u.eingabe(&u.von, "Von, JJJJ-MM-TT"),
		u.eingabe(&u.bis, "Bis, dieser Tag zählt mit"),
		reihe(u.knopf(&u.zaehlen, "Zählen", u.zaehlenKlick), u.knopf(&u.pruefen, "Prüfen", u.pruefenKlick), u.knopf(&u.ende, "Prüfung beenden", u.pruefungBeenden)),
		u.befunde(),
		u.titel("Bestätigen"),
		u.text("Bestätigt werden die Epochen dieser Prüfung, deren Kette hält. Eine Verzweigung und ein Bruch zum Vorgänger bleiben draußen. Danach die Prüfung erneut öffnen."),
		u.eingabe(&u.bestPass, "Passphrase der Bestätigung"),
		u.knopf(&u.bestaetigen, "Epochen bestätigen", u.bestaetigenKlick),
		u.titel("Verzeichnis-Summe"),
		u.eingabe(&u.monat, "Monat, JJJJ-MM"),
		u.knopf(&u.summeWahl, "Summenepoche schreiben", u.summeKlick),
		u.titel("Suchprozess"),
		u.wahl(&u.frageArt, "vorgang", "Personen eines Vorgangs"),
		u.wahl(&u.frageArt, "person", "Vorgänge einer Person"),
		u.eingabe(&u.frageSchlussel, "Vorgang oder Person"),
		u.eingabe(&u.frageVon, "Von, JJJJ-MM-TT"),
		u.eingabe(&u.frageBis, "Bis, dieser Tag zählt mit"),
		u.eingabe(&u.aufrufPass, "Passphrase des Aufrufschlüssels"),
		u.knopf(&u.aufrufKnopf, "Aufrufschlüssel entsperren", u.aufrufKlick),
		u.knopf(&u.frageKnopf, "Anfrage stellen", u.frageKlick),
		u.trefferZeilen(),
	)
	return u.zeilen(zeilen...)
}

func (u *ui) verbindungWaehlen() {
	pfad, ok := dateiWaehlen("Verbindung")
	if ok {
		u.verbindungLaden(pfad)
	}
}

func (u *ui) verbindungLaden(pfad string) {
	v, err := LesenVorlage(pfad)
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	finger, ende, err := fingerVon(v.Verbindung.Zertifikat)
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	u.vorlage = &v
	u.finger = finger
	u.certEnde = ende
	u.pruefPfad = v.Pruef
	u.hsmPfad = v.HSM
	u.bestPfad = v.Bestaetigung
	u.speicher.SetText(v.Speicher)
	u.meldung = ""
	u.fehler = false
}

func (u *ui) entsperrenKlick() {
	if u.vorlage == nil || u.vorlage.Modus != schluessel.ModusEinfach {
		return
	}
	angaben, pass, err := u.angaben()
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	u.lauf(func() rueckgabe {
		sitz, err := Oeffnen(angaben)
		if err != nil {
			crypt.Wipe(pass)
			return misslungen(err)
		}
		if err = sitz.Fenster.Einfach(pass); err != nil {
			sitz.Schliessen()
			return misslungen(err)
		}
		return rueckgabe{text: "Der Schlüssel ist offen.", danach: func() {
			u.sitz = sitz
			if arten := sitz.Fenster.Arten(); len(arten) > 0 {
				u.art.Value = artSchluessel(arten[0])
			}
		}}
	})
}

func (u *ui) angaben() (Angaben, []byte, error) {
	status, err := statusVon(u.status.Value)
	if err != nil {
		return Angaben{}, nil, err
	}
	rahmen, err := zahl(u.rahmen.Text())
	if err != nil {
		return Angaben{}, nil, err
	}
	minuten, err := zahl(u.intervall.Text())
	if err != nil {
		return Angaben{}, nil, err
	}
	tage, err := zahl(u.frist.Text())
	if err != nil {
		return Angaben{}, nil, err
	}
	var instanz protocol.ID
	if text := strings.TrimSpace(u.instanz.Text()); text != "" {
		instanz, err = protocol.ParseID(text)
		if err != nil {
			return Angaben{}, nil, ErrAngabe
		}
	}
	vorlage := *u.vorlage
	vorlage.Pruef = u.pruefPfad
	vorlage.HSM = u.hsmPfad
	vorlage.Bestaetigung = u.bestPfad
	vorlage.Speicher = strings.TrimSpace(u.speicher.Text())
	pass := bytesVon(&u.pass)
	geheim := bytesVon(&u.geheimnis)
	return Angaben{
		Vorlage: vorlage, Status: status, Person: u.person.Text(), Suche: u.suche.Text(),
		Instanz: instanz, Rahmen: rahmen, Intervall: time.Duration(minuten) * time.Minute,
		Frist: time.Duration(tage) * 24 * time.Hour, Region: strings.TrimSpace(u.region.Text()),
		Zugang: strings.TrimSpace(u.zugang.Text()), Geheimnis: geheim,
	}, pass, nil
}

func (u *ui) auswahl() (fenster.Auswahl, error) {
	art, ok := artVon(u.art.Value)
	if !ok {
		return fenster.Auswahl{}, fenster.ErrArt
	}
	von, bis, err := tagSpanne(u.von.Text(), u.bis.Text(), art == fenster.ArtGezielt)
	if err != nil {
		return fenster.Auswahl{}, err
	}
	return fenster.Auswahl{
		Art: art, Von: von, Bis: bis,
		Kohorte: strings.TrimSpace(u.kohorte.Text()),
		Person:  strings.TrimSpace(u.suchPerson.Text()),
		Vorgang: strings.TrimSpace(u.suchVorgang.Text()),
	}, nil
}

func (u *ui) zaehlenKlick() {
	aus, err := u.auswahl()
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	f := u.sitz.Fenster
	u.lauf(func() rueckgabe {
		n, err := f.Zaehlen(aus)
		if err != nil {
			return misslungen(err)
		}
		return rueckgabe{text: fmt.Sprintf("Die Auswahl trifft %d Epochen.", n)}
	})
}

func (u *ui) pruefenKlick() {
	aus, err := u.auswahl()
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	f := u.sitz.Fenster
	u.lauf(func() rueckgabe {
		erg, err := f.Pruefung(aus)
		if err != nil {
			return misslungen(err)
		}
		return rueckgabe{text: fmt.Sprintf("Die Prüfung hält %d Epochen.", erg.Epochen), danach: func() {
			ergebnisWeg(u.erg)
			u.erg = &erg
		}}
	})
}

func (u *ui) pruefungBeenden() {
	if u.sitz == nil {
		return
	}
	u.sitz.Fenster.Ende()
	ergebnisWeg(u.erg)
	u.erg = nil
	u.sagen("Der Klartext ist aus dem Fenster.", false)
}

func (u *ui) bestaetigenKlick() {
	gruppen := bestaetigenGruppen(u.erg)
	if len(gruppen) == 0 {
		u.sagen("Keine Epoche ist zu bestätigen.", true)
		return
	}
	pass := bytesVon(&u.bestPass)
	if len(pass) == 0 {
		u.sagen(fenster.ErrPassphrase.Error(), true)
		return
	}
	f := u.sitz.Fenster
	u.lauf(func() rueckgabe {
		defer crypt.Wipe(pass)
		var n int
		for _, g := range gruppen {
			kopie := append([]byte(nil), pass...)
			got, err := f.Bestaetigen(kopie, nil, g.ablage, g.rolle, g.epochen)
			if err != nil {
				return misslungen(err)
			}
			n += len(got)
		}
		return rueckgabe{text: fmt.Sprintf("%d Epochen bestätigt.", n)}
	})
}

func (u *ui) summeKlick() {
	monat, err := monatVon(u.monat.Text())
	if err != nil {
		u.sagen("Der Monat ist JJJJ-MM.", true)
		return
	}
	pfad, ok := dateiWaehlen("HSM-Signatur für diese Handlung")
	if !ok {
		return
	}
	key, err := PrivaterSchluessel(pfad)
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	if err = u.sitz.Signieren(key); err != nil {
		u.sagen(err.Error(), true)
		return
	}
	f := u.sitz.Fenster
	sitz := u.sitz
	u.lauf(func() rueckgabe {
		defer sitz.SignaturWeg()
		if err := f.VerzeichnisSumme(monat); err != nil {
			return misslungen(err)
		}
		return rueckgabe{text: "Die Summenepoche ist geschrieben."}
	})
}

func (u *ui) aufrufKlick() {
	pass := bytesVon(&u.aufrufPass)
	f := u.sitz.Fenster
	u.lauf(func() rueckgabe {
		if err := f.AufrufEinfach(pass); err != nil {
			return misslungen(err)
		}
		return rueckgabe{text: "Der Aufrufschlüssel ist offen.", danach: func() { u.aufrufOffen = true }}
	})
}

func (u *ui) frageKlick() {
	if !u.aufrufOffen {
		u.sagen(fenster.ErrAufruf.Error(), true)
		return
	}
	var art protocol.AnfrageArt
	switch u.frageArt.Value {
	case "vorgang":
		art = protocol.AnfrageVorgang
	case "person":
		art = protocol.AnfragePerson
	default:
		u.sagen(ErrAngabe.Error(), true)
		return
	}
	von, bis, err := tagSpanne(u.frageVon.Text(), u.frageBis.Text(), false)
	if err != nil {
		u.sagen(err.Error(), true)
		return
	}
	schlussel := strings.TrimSpace(u.frageSchlussel.Text())
	f := u.sitz.Fenster
	u.lauf(func() rueckgabe {
		treffer, err := f.Frage(art, schlussel, von, bis)
		if err != nil {
			return misslungen(err)
		}
		return rueckgabe{text: "Die Treffer sind da.", danach: func() {
			u.treffer = &treffer
			u.trefferArt = art
		}}
	})
}

func (u *ui) sitzungZu() {
	if u.sitz != nil {
		u.sitz.Schliessen()
	}
	ergebnisWeg(u.erg)
	u.erg = nil
	u.treffer = nil
	u.sitz = nil
	u.aufrufOffen = false
	u.pass.SetText("")
	u.bestPass.SetText("")
	u.aufrufPass.SetText("")
	u.geheimnis.SetText("")
	if u.meldung == "" || !u.fehler {
		u.meldung = "Die Sitzung ist zu. Der Klartext ist verworfen."
		u.fehler = false
	}
}

func (u *ui) speicherWaehlen() {
	pfad, ok := ordnerWaehlen("Bestätigungsspeicher")
	if ok {
		u.speicher.SetText(pfad)
	}
}

func (u *ui) bestaetigungSetzen(pfad string) { u.bestPfad = pfad }

func (u *ui) statusGewaehlt() werkzeug.Status {
	s, err := statusVon(u.status.Value)
	if err != nil {
		return werkzeug.StatusAktuell
	}
	return s
}

func (u *ui) sagen(text string, fehler bool) {
	u.meldung = text
	u.fehler = fehler
}

func (u *ui) dateiZeile(c *widget.Clickable, name, pfad string, setzen func(string)) layout.Widget {
	anzeige := pfad
	if anzeige == "" {
		anzeige = "nicht gewählt"
	}
	return func(gtx layout.Context) layout.Dimensions {
		return spalte(gtx,
			u.text(name+": "+anzeige),
			u.knopf(c, "Wählen", func() {
				neu, ok := dateiWaehlen(name)
				if ok {
					setzen(neu)
				}
			}),
		)
	}
}

func (u *ui) befunde() layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if u.erg == nil {
			return layout.Dimensions{}
		}
		ww := []layout.Widget{u.text("Eine Lücke, eine Verzweigung oder ein Bruch hält den Inhalt zu. Eine gelöschte Epoche wird nicht geladen.")}
		for _, b := range u.erg.Befunde {
			ww = append(ww, u.text(befundZeile(b)))
			if b.Kompromittiert && len(b.Eintraege) > 0 {
				ww = append(ww, u.text("Ohne Vertraulichkeitszusicherung."))
			}
			for _, z := range b.Eintraege {
				ww = append(ww, u.text(eintragZeile(z)))
			}
		}
		return spalte(gtx, ww...)
	}
}

func (u *ui) trefferZeilen() layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if u.treffer == nil {
			return layout.Dimensions{}
		}
		var ww []layout.Widget
		switch u.trefferArt {
		case protocol.AnfrageVorgang:
			for _, p := range u.treffer.Personen {
				ww = append(ww, u.text(p.Person+" · "+rolleWort(p.Rolle)+" · "+p.Kohorte+" · "+zeitText(p.Erster)+" – "+zeitText(p.Letzter)))
			}
		case protocol.AnfragePerson:
			for _, v := range u.treffer.Vorgaenge {
				ww = append(ww, u.text(v.Nummer+" · "+rolleWort(v.Rolle)+" · "+v.Kohorte+" · "+zeitText(v.Erster)+" – "+zeitText(v.Letzter)))
			}
		}
		if len(ww) == 0 {
			ww = append(ww, u.text("Keine Treffer."))
		}
		return spalte(gtx, ww...)
	}
}

func (u *ui) meldungsZeile() layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		l := material.Body1(u.th, u.meldung)
		if u.fehler {
			l.Color = color.NRGBA{R: 0x8C, G: 0x2F, B: 0x1B, A: 0xFF}
		}
		return l.Layout(gtx)
	}
}

func (u *ui) titel(s string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return material.H6(u.th, s).Layout(gtx)
	}
}

func (u *ui) text(s string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if s == "" {
			return layout.Dimensions{}
		}
		return material.Body1(u.th, s).Layout(gtx)
	}
}

func (u *ui) eingabe(ed *widget.Editor, hinweis string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return material.Editor(u.th, ed, hinweis).Layout(gtx)
	}
}

func (u *ui) wahl(group *widget.Enum, key, label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return material.RadioButton(u.th, group, key, label).Layout(gtx)
	}
}

func (u *ui) knopf(c *widget.Clickable, text string, fn func()) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		dims := material.Button(u.th, c, text).Layout(gtx)
		if c.Clicked(gtx) && !u.arbeit {
			fn()
		}
		return dims
	}
}

func (u *ui) zeilen(ww ...layout.Widget) []layout.FlexChild {
	out := make([]layout.FlexChild, 0, len(ww)*2)
	for i, w := range ww {
		if i > 0 {
			out = append(out, abstand())
		}
		out = append(out, layout.Rigid(w))
	}
	return out
}

func fingerVon(pfad string) (string, time.Time, error) {
	cert, err := zertifikatLesen(pfad)
	if err != nil {
		return "", time.Time{}, err
	}
	fp, err := crypt.FingerprintCertificate(cert)
	if err != nil {
		return "", time.Time{}, err
	}
	return fingerText(fp), cert.NotAfter, nil
}

func bytesVon(ed *widget.Editor) []byte {
	b := append([]byte(nil), ed.Text()...)
	ed.SetText("")
	return b
}

func misslungen(err error) rueckgabe {
	if err == nil {
		return rueckgabe{}
	}
	return rueckgabe{text: err.Error(), fehler: true}
}

func ergebnisWeg(e *fenster.Ergebnis) {
	if e == nil {
		return
	}
	for i := range e.Befunde {
		for j := range e.Befunde[i].Eintraege {
			z := &e.Befunde[i].Eintraege[j]
			crypt.Wipe(z.Text)
			crypt.Wipe(z.Vorgang)
			crypt.Wipe(z.Angabe)
			for k := range z.Personen {
				crypt.Wipe(z.Personen[k])
			}
		}
		e.Befunde[i].Eintraege = nil
	}
}

type bestGruppe struct {
	ablage  protocol.ID
	rolle   protocol.StromRolle
	epochen []protocol.EpochID
}

func bestaetigenGruppen(e *fenster.Ergebnis) []bestGruppe {
	if e == nil {
		return nil
	}
	type key struct {
		a protocol.ID
		r protocol.StromRolle
	}
	idx := map[key]int{}
	var out []bestGruppe
	for _, b := range e.Befunde {
		if b.Geloescht || b.Verzweigung || b.VorgaengerBruch || b.Verloren {
			continue
		}
		k := key{b.Ablage, b.Rolle}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, bestGruppe{ablage: b.Ablage, rolle: b.Rolle})
		}
		out[i].epochen = append(out[i].epochen, b.Epoch)
	}
	return out
}

func reihe(ww ...layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		kinder := make([]layout.FlexChild, 0, len(ww)*2)
		for i, w := range ww {
			if i > 0 {
				kinder = append(kinder, layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout))
			}
			kinder = append(kinder, layout.Rigid(w))
		}
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, kinder...)
	}
}

func spalte(gtx layout.Context, ww ...layout.Widget) layout.Dimensions {
	kinder := make([]layout.FlexChild, 0, len(ww)*2)
	for i, w := range ww {
		if i > 0 {
			kinder = append(kinder, abstand())
		}
		kinder = append(kinder, layout.Rigid(w))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kinder...)
}

func abstand() layout.FlexChild {
	return layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout)
}

func abschnitt() layout.FlexChild {
	return layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout)
}

func thema() *material.Theme {
	th := material.NewTheme()
	th.Palette = material.Palette{
		Fg:         color.NRGBA{R: 0x1C, G: 0x1C, B: 0x1C, A: 0xFF},
		Bg:         color.NRGBA{R: 0xF7, G: 0xF6, B: 0xF3, A: 0xFF},
		ContrastBg: color.NRGBA{R: 0x1F, G: 0x4E, B: 0x5F, A: 0xFF},
		ContrastFg: color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF},
	}
	th.TextSize = 14
	roh, err := os.ReadFile(`C:\Windows\Fonts\segoeui.ttf`)
	if err != nil {
		return th
	}
	faces, err := opentype.ParseCollection(roh)
	if err != nil || len(faces) == 0 {
		return th
	}
	th.Shaper = text.NewShaper(text.WithCollection(faces))
	th.Face = faces[0].Font.Typeface
	return th
}
