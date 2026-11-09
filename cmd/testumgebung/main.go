// Befehl testumgebung legt eine lokale Umgebung mit drei Mandanten an.
// Der Schreibprozess liest daraus nur die öffentlichen Schlüssel.
// Die privaten Schlüssel der Empfänger liegen verschlüsselt daneben.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cryptlog/bestaetigung"
	"cryptlog/crypt"
	"cryptlog/fenster"
	"cryptlog/protocol"
	"cryptlog/schluessel"
	"cryptlog/schreiben"
)

const (
	passphraseDatei = "passphrase"
	ereignisAdresse = "127.0.0.1:8787"
	metrikAdresse   = "127.0.0.1:8788"
)

// kosten sind die Argon2id-Parameter dieser Umgebung.
// Sie bleiben klein, damit das Öffnen hier nicht 64 MiB zieht.
var kosten = fenster.Kosten{Passes: 1, Memory: 8, Threads: 1}

type personVorlage struct {
	Name           string
	Merkmal        string
	Kohorte        string
	Datenschuetzer bool
}

type mandantVorlage struct {
	Name     string
	Personen []personVorlage
}

type probe struct {
	Mandant protocol.ID
	Person  string
	Vorgang string
}

var vorlagen = []mandantVorlage{
	{Name: "Nordlicht", Personen: []personVorlage{
		{Name: "Ada", Merkmal: "gruppe", Kohorte: "Nord"},
		{Name: "Bea", Merkmal: "gruppe", Kohorte: "Nord"},
		{Name: "Cleo", Merkmal: "gruppe", Kohorte: "Nord", Datenschuetzer: true},
	}},
	{Name: "Suedwerk", Personen: []personVorlage{
		{Name: "Dora", Merkmal: "gruppe", Kohorte: "Sued"},
		{Name: "Emil", Merkmal: "einzeln"},
		{Name: "Frieda", Merkmal: "gruppe", Kohorte: "Sued", Datenschuetzer: true},
	}},
	{Name: "Osthafen", Personen: []personVorlage{
		{Name: "Gerd", Merkmal: "gruppe", Kohorte: "Ost"},
		{Name: "Hilde", Merkmal: "gruppe", Kohorte: "Ost", Datenschuetzer: true},
	}},
}

func main() {
	aus := flag.String("aus", "testumgebung", "Verzeichnis der Umgebung")
	ersetzen := flag.Bool("ersetzen", false, "vorhandene Umgebung ersetzen")
	pruefen := flag.Bool("pruefen", false, "je Mandant ein Ereignis annehmen")
	nach := flag.Bool("ergaenzen", false, "öffentliche Schlüssel und den Bestätigungsspeicher nachziehen")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Aufruf: testumgebung [-aus verzeichnis] [-ersetzen] [-pruefen]")
		fmt.Fprintln(os.Stderr, "         testumgebung -ergaenzen [-aus verzeichnis]")
		os.Exit(2)
	}
	wurzel, err := filepath.Abs(*aus)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *nach {
		if *ersetzen || *pruefen {
			fmt.Fprintln(os.Stderr, "Aufruf: testumgebung -ergaenzen [-aus verzeichnis]")
			os.Exit(2)
		}
		if err = ergaenzen(wurzel); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Ergänzt: %s\n", wurzel)
		return
	}
	if err = vorbereiten(wurzel, *ersetzen); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	proben, pass, err := anlegen(wurzel)
	if err != nil {
		_ = os.RemoveAll(wurzel)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *pruefen {
		if err = annahmePruefen(filepath.Join(wurzel, "konfig"), proben); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Printf("Testumgebung: %s\n", wurzel)
	fmt.Printf("Passphrase: %s\n", pass)
	fmt.Printf("Start: cryptlog schreiben %s\n", filepath.Join(wurzel, "konfig"))
	for _, p := range proben {
		fmt.Printf("Mandant %s  Person %s  Vorgang %s\n", p.Mandant.Hex(), p.Person, p.Vorgang)
	}
}

func vorbereiten(wurzel string, ersetzen bool) error {
	st, err := os.Stat(wurzel)
	if os.IsNotExist(err) {
		return os.MkdirAll(wurzel, 0o700)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("testumgebung: %s ist kein Verzeichnis", wurzel)
	}
	eintraege, err := os.ReadDir(wurzel)
	if err != nil {
		return err
	}
	if len(eintraege) == 0 {
		return nil
	}
	if !ersetzen {
		return fmt.Errorf("testumgebung: %s ist nicht leer", wurzel)
	}
	if _, err = os.Stat(filepath.Join(wurzel, "konfig")); err != nil {
		return fmt.Errorf("testumgebung: ersetzen nur, wenn konfig schon liegt")
	}
	if err = os.RemoveAll(wurzel); err != nil {
		return err
	}
	return os.MkdirAll(wurzel, 0o700)
}

func anlegen(wurzel string) ([]probe, string, error) {
	jetzt := time.Now().UTC()
	bis := jetzt.AddDate(10, 0, 0)
	von := uint64(jetzt.Add(-time.Hour).UnixMilli())
	gueltigBis := uint64(bis.UnixMilli())
	pass, err := zufallsPassphrase()
	if err != nil {
		return nil, "", err
	}
	ca, err := schluessel.NeueCA("CryptLog-Test", jetzt, bis)
	if err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "schluessel", "ca.pem"), pemZertifikat(ca.Zertifikat())); err != nil {
		return nil, "", err
	}

	plattformKey, plattformCert, err := blatt(ca, protocol.PlattformMandant(), "Plattform", bis, jetzt, true)
	if err != nil {
		return nil, "", err
	}
	indexKey, indexCert, err := blatt(ca, protocol.PlattformMandant(), "Index", bis, jetzt, false)
	if err != nil {
		return nil, "", err
	}
	signier, err := neuerSchluessel()
	if err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "plattform.pem"), pemZertifikat(plattformCert)); err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "index.pem"), pemZertifikat(indexCert)); err != nil {
		return nil, "", err
	}
	signaturPEM, err := pemPrivat(signier)
	if err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "signatur.pem"), signaturPEM); err != nil {
		return nil, "", err
	}
	hsmPEM, err := pemOeffentlich(&signier.PublicKey)
	if err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "hsm.pem"), hsmPEM); err != nil {
		return nil, "", err
	}
	indexPEM, err := pemPrivat(indexKey)
	if err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "index-privat.pem"), indexPEM); err != nil {
		return nil, "", err
	}
	zone, err := neueID()
	if err != nil {
		return nil, "", err
	}
	if err = empfaenger(wurzel, "plattform", pass, plattformKey, plattformCert, nil, protocol.PlattformMandant(), zone, protocol.ID{}, true, &signier.PublicKey, nil); err != nil {
		return nil, "", err
	}

	var stand strings.Builder
	fmt.Fprintf(&stand, "passphrase = %s\n", pass)
	fmt.Fprintf(&stand, "ereignis = %s\n", ereignisAdresse)
	fmt.Fprintf(&stand, "metrik = %s\n", metrikAdresse)
	instanz, err := neueID()
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(&stand, "instanz = %s\n", instanz.Hex())
	fmt.Fprintf(&stand, "zone = %s\n", zone.Hex())
	platFinger, err := crypt.FingerprintCertificate(plattformCert)
	if err != nil {
		return nil, "", err
	}
	indexFinger, err := crypt.FingerprintCertificate(indexCert)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(&stand, "plattform = %s\n", hex.EncodeToString(platFinger[:]))
	fmt.Fprintf(&stand, "index = %s\n", hex.EncodeToString(indexFinger[:]))
	fmt.Fprintf(&stand, "argon2id = 1 Durchgang, 8 KiB, 1 Thread\n")

	var proben []probe
	for _, vorlage := range vorlagen {
		p, err := mandantAnlegen(wurzel, ca, vorlage, pass, zone, jetzt, bis, von, gueltigBis, &stand, &signier.PublicKey)
		if err != nil {
			return nil, "", err
		}
		proben = append(proben, p...)
	}
	if err = ablegen(filepath.Join(wurzel, "stand"), []byte(stand.String())); err != nil {
		return nil, "", err
	}
	if err = ablegen(filepath.Join(wurzel, passphraseDatei), []byte(pass+"\n")); err != nil {
		return nil, "", err
	}
	konfig := "" +
		"instanz = " + instanz.Hex() + "\n" +
		"spool = spool\n" +
		"ereignis = " + ereignisAdresse + "\n" +
		"metrik = " + metrikAdresse + "\n" +
		"ziel = platte\n" +
		"wurzel = ziel\n" +
		"plattform = geheim/plattform.pem\n" +
		"index = geheim/index.pem\n" +
		"signatur = geheim/signatur.pem\n" +
		"mandanten = mandanten\n" +
		"spool_grenze = 16777216\n" +
		"frist = 15m\n" +
		"puffer_warte = 20ms\n" +
		"segment = 262144\n" +
		"segment_warte = 10s\n" +
		"klasse = 262144\n" +
		"vermerke = bestaetigung\n"
	if err = ablegen(filepath.Join(wurzel, "konfig"), []byte(konfig)); err != nil {
		return nil, "", err
	}
	return proben, pass, nil
}

func mandantAnlegen(wurzel string, ca *schluessel.CA, vorlage mandantVorlage, pass string, zone protocol.ID, jetzt, bis time.Time, von, gueltigBis uint64, stand *strings.Builder, hsm *ecdsa.PublicKey) ([]probe, error) {
	id, err := neueID()
	if err != nil {
		return nil, err
	}
	kek, kekCert, err := blatt(ca, id, vorlage.Name, bis, jetzt, true)
	if err != nil {
		return nil, err
	}
	pruef, pruefCert, err := blatt(ca, id, "pruef", bis, jetzt, false)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(wurzel, "mandanten", id.Hex())
	if err = ablegen(filepath.Join(dir, "kek.pem"), pemZertifikat(kekCert)); err != nil {
		return nil, err
	}
	if err = ablegen(filepath.Join(dir, "pruef.pem"), pemZertifikat(pruefCert)); err != nil {
		return nil, err
	}
	pruefPEM, err := pemPrivat(pruef)
	if err != nil {
		return nil, err
	}
	if err = ablegen(filepath.Join(wurzel, "schluessel", vorlage.Name, "pruef.pem"), pruefPEM); err != nil {
		return nil, err
	}
	verzeichnis, err := neueID()
	if err != nil {
		return nil, err
	}
	vorgang, err := neueID()
	if err != nil {
		return nil, err
	}
	auffang, err := neueID()
	if err != nil {
		return nil, err
	}
	einzel, err := neueID()
	if err != nil {
		return nil, err
	}
	katalog, err := neueID()
	if err != nil {
		return nil, err
	}
	summeVerzeichnis, err := neueID()
	if err != nil {
		return nil, err
	}
	summeVorgang, err := neueID()
	if err != nil {
		return nil, err
	}
	gruppen := map[string]protocol.ID{}
	var katalogZeilen []string
	var personen []angelegtePerson
	var proben []probe
	for _, pv := range vorlage.Personen {
		ap, zeile, err := personAnlegen(dir, pruef, id, einzel, gruppen, pv, von, gueltigBis)
		if err != nil {
			return nil, err
		}
		personen = append(personen, ap)
		if zeile != "" {
			katalogZeilen = append(katalogZeilen, zeile)
		}
		if !pv.Datenschuetzer && (len(proben) == 0 || pv.Merkmal == "einzeln") {
			proben = append(proben, probe{Mandant: id, Person: pv.Name, Vorgang: "V-" + pv.Name})
		}
	}
	katalogZeilen = append(katalogZeilen,
		fmt.Sprintf("verzeichnis %s %s - an", verzeichnis.Hex(), verzeichnis.Hex()),
		fmt.Sprintf("vorgang %s %s - an", vorgang.Hex(), vorgang.Hex()),
		fmt.Sprintf("auffang %s %s - an", auffang.Hex(), auffang.Hex()),
		fmt.Sprintf("katalog %s %s - an", katalog.Hex(), katalog.Hex()),
		fmt.Sprintf("verzeichnis-summe %s %s - an", summeVerzeichnis.Hex(), summeVerzeichnis.Hex()),
		fmt.Sprintf("vorgang-summe %s %s - an", summeVorgang.Hex(), summeVorgang.Hex()),
	)
	lage := "" +
		"name = " + vorlage.Name + "\n" +
		"rahmen = 256\n" +
		"verzeichnis = " + verzeichnis.Hex() + "\n" +
		"vorgang = " + vorgang.Hex() + "\n" +
		"auffang = " + auffang.Hex() + "\n" +
		"einzel = " + einzel.Hex() + "\n" +
		"katalog = " + katalog.Hex() + "\n" +
		"kek = kek.pem\n" +
		"pruef = pruef.pem\n" +
		"deck = aus\n"
	if err = ablegen(filepath.Join(dir, "lage"), []byte(lage)); err != nil {
		return nil, err
	}
	if err = ablegen(filepath.Join(dir, "katalog"), []byte(strings.Join(katalogZeilen, "\n")+"\n")); err != nil {
		return nil, err
	}
	var aufruf *ecdsa.PrivateKey
	for _, ap := range personen {
		if ap.Aufruf != nil {
			aufruf = ap.Aufruf
		}
	}
	if err = empfaenger(wurzel, vorlage.Name, pass, kek, kekCert, aufruf, id, zone, katalog, false, hsm, pruefCert); err != nil {
		return nil, err
	}
	kekFinger, err := crypt.FingerprintCertificate(kekCert)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stand, "\nname = %s\n", vorlage.Name)
	fmt.Fprintf(stand, "id = %s\n", id.Hex())
	fmt.Fprintf(stand, "kek = %s\n", hex.EncodeToString(kekFinger[:]))
	fmt.Fprintf(stand, "katalog = %s\n", katalog.Hex())
	fmt.Fprintf(stand, "verzeichnis = %s\n", verzeichnis.Hex())
	fmt.Fprintf(stand, "vorgang = %s\n", vorgang.Hex())
	fmt.Fprintf(stand, "auffang = %s\n", auffang.Hex())
	fmt.Fprintf(stand, "einzel = %s\n", einzel.Hex())
	for _, ap := range personen {
		fmt.Fprintf(stand, "person = %s %s\n", ap.Name, ap.Zeile)
	}
	return proben, nil
}

type angelegtePerson struct {
	Name   string
	Zeile  string
	Aufruf *ecdsa.PrivateKey
}

func personAnlegen(dir string, pruef *ecdsa.PrivateKey, mandant, einzel protocol.ID, gruppen map[string]protocol.ID, pv personVorlage, von, bis uint64) (angelegtePerson, string, error) {
	var ablage, bind protocol.ID
	var katalogZeile string
	switch pv.Merkmal {
	case "gruppe":
		id, ok := gruppen[pv.Kohorte]
		if !ok {
			var err error
			id, err = neueID()
			if err != nil {
				return angelegtePerson{}, "", err
			}
			gruppen[pv.Kohorte] = id
			katalogZeile = fmt.Sprintf("gruppe %s %s %s an", id.Hex(), id.Hex(), pv.Kohorte)
		}
		ablage, bind = id, id
	case "einzeln":
		var err error
		bind, err = neueID()
		if err != nil {
			return angelegtePerson{}, "", err
		}
		ablage = einzel
		katalogZeile = fmt.Sprintf("einzel %s %s - an", ablage.Hex(), bind.Hex())
	default:
		return angelegtePerson{}, "", fmt.Errorf("testumgebung: merkmal %s", pv.Merkmal)
	}
	rolle := protocol.RollePerson
	rolleText := "person"
	var finger protocol.Hash
	var aufruf *ecdsa.PrivateKey
	if pv.Datenschuetzer {
		var err error
		aufruf, err = neuerSchluessel()
		if err != nil {
			return angelegtePerson{}, "", err
		}
		finger, err = crypt.FingerprintSPKI(&aufruf.PublicKey)
		if err != nil {
			return angelegtePerson{}, "", err
		}
		rolle = protocol.RolleDatenschuetzer
		rolleText = "datenschuetzer"
	}
	aussage := protocol.Aussage{
		Mandant: mandant, Person: pv.Name, Rolle: rolle, Von: von, Bis: bis, Finger: finger,
	}
	nutz, err := protocol.AussageBytes(aussage)
	if err != nil {
		return angelegtePerson{}, "", err
	}
	sig, err := crypt.SignP256(pruef, nutz)
	if err != nil {
		return angelegtePerson{}, "", err
	}
	inhalt := "" +
		"merkmal = " + pv.Merkmal + "\n" +
		"ablage = " + ablage.Hex() + "\n" +
		"bind = " + bind.Hex() + "\n"
	if pv.Kohorte != "" {
		inhalt += "kohorte = " + pv.Kohorte + "\n"
	}
	inhalt += "von = " + strconv.FormatUint(von, 10) + "\n" +
		"bis = " + strconv.FormatUint(bis, 10) + "\n" +
		"rolle = " + rolleText + "\n"
	if pv.Datenschuetzer {
		inhalt += "finger = " + hex.EncodeToString(finger[:]) + "\n"
	}
	inhalt += "signatur = " + hex.EncodeToString(sig[:]) + "\n"
	if err = ablegen(filepath.Join(dir, "personen", pv.Name), []byte(inhalt)); err != nil {
		return angelegtePerson{}, "", err
	}
	zeile := pv.Merkmal
	if pv.Kohorte != "" {
		zeile += " " + pv.Kohorte
	}
	zeile += " " + rolleText
	return angelegtePerson{Name: pv.Name, Zeile: zeile, Aufruf: aufruf}, katalogZeile, nil
}

func empfaenger(wurzel, name, pass string, kek *ecdsa.PrivateKey, cert *x509.Certificate, aufruf *ecdsa.PrivateKey, mandant, zone, katalog protocol.ID, plattform bool, hsm *ecdsa.PublicKey, pruef *x509.Certificate) error {
	dir := filepath.Join(wurzel, "empfaenger", name)
	kekRoh, err := fenster.Verschluesseln(rand.Reader, kek, []byte(pass), kosten)
	if err != nil {
		return err
	}
	if err = ablegen(filepath.Join(dir, "kek.pk8"), kekRoh); err != nil {
		return err
	}
	if err = ablegen(filepath.Join(dir, "kek.pem"), pemZertifikat(cert)); err != nil {
		return err
	}
	best, err := neuerSchluessel()
	if err != nil {
		return err
	}
	bestRoh, err := fenster.Verschluesseln(rand.Reader, best, []byte(pass), kosten)
	if err != nil {
		return err
	}
	if err = ablegen(filepath.Join(dir, "best.pk8"), bestRoh); err != nil {
		return err
	}
	bestPEM, err := pemOeffentlich(&best.PublicKey)
	if err != nil {
		return err
	}
	if err = ablegen(filepath.Join(dir, "best.pem"), bestPEM); err != nil {
		return err
	}
	hsmPEM, err := pemOeffentlich(hsm)
	if err != nil {
		return err
	}
	if err = ablegen(filepath.Join(dir, "hsm.pem"), hsmPEM); err != nil {
		return err
	}
	if pruef != nil {
		if err = ablegen(filepath.Join(dir, "pruef.pem"), pemZertifikat(pruef)); err != nil {
			return err
		}
	}
	v := fenster.Verbindung{
		Ziel:         fenster.ZielPlatte,
		Pfad:         filepath.Join(wurzel, "ziel"),
		Mandant:      mandant,
		Zone:         zone,
		Katalog:      katalog,
		KEK:          filepath.Join(dir, "kek.pk8"),
		Zertifikat:   filepath.Join(dir, "kek.pem"),
		Bestaetigung: filepath.Join(dir, "best.pk8"),
		Plattform:    plattform,
	}
	if aufruf != nil {
		roh, aerr := fenster.Verschluesseln(rand.Reader, aufruf, []byte(pass), kosten)
		if aerr != nil {
			return aerr
		}
		if err = ablegen(filepath.Join(dir, "aufruf.pk8"), roh); err != nil {
			return err
		}
		v.Aufruf = filepath.Join(dir, "aufruf.pk8")
	}
	if plattform {
		v.Katalog, err = neueID()
		if err != nil {
			return err
		}
	}
	return fenster.Ablegen(filepath.Join(dir, "verbindung"), v)
}

func annahmePruefen(konfig string, proben []probe) error {
	dienst, err := schreiben.OeffnenDienst(konfig)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = dienst.Prozess.Beenden(ctx)
	}()
	srv := httptest.NewServer(dienst.Prozess.Ereignisport())
	defer srv.Close()
	jetzt := uint64(time.Now().UnixMilli())
	for _, p := range proben {
		id, err := neueID()
		if err != nil {
			return err
		}
		roh, err := protocol.EreignisBytes(protocol.EreignisAufruf{
			ID: id, Mandant: p.Mandant, Zeit: jetzt, Vorgang: p.Vorgang,
			Personen: []string{p.Person}, Text: []byte("Probe"),
		})
		if err != nil {
			return err
		}
		res, err := http.Post(srv.URL+"/ereignis", "application/octet-stream", bytes.NewReader(roh))
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("testumgebung: %s %s %d %s", p.Mandant.Hex(), p.Person, res.StatusCode, body)
		}
		best, err := protocol.ParseBestaetigt(body)
		if err != nil || best.Event != id || best.Seq == 0 {
			return fmt.Errorf("testumgebung: annahme %s %v", p.Person, err)
		}
	}
	return nil
}

func blatt(ca *schluessel.CA, mandant protocol.ID, name string, bis, jetzt time.Time, kek bool) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := neuerSchluessel()
	if err != nil {
		return nil, nil, err
	}
	cert, err := ca.Ausstellen(&key.PublicKey, mandant, name, bis, jetzt, kek)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func neuerSchluessel() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func neueID() (protocol.ID, error) {
	var id protocol.ID
	for id == (protocol.ID{}) {
		if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
			return protocol.ID{}, err
		}
	}
	return id, nil
}

func zufallsPassphrase() (string, error) {
	var roh [16]byte
	if _, err := io.ReadFull(rand.Reader, roh[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(roh[:]), nil
}

func ergaenzen(wurzel string) error {
	roh, err := os.ReadFile(filepath.Join(wurzel, passphraseDatei))
	if err != nil {
		return err
	}
	pass := bytes.TrimSpace(roh)
	defer crypt.Wipe(pass)
	hsm, err := privaterAus(filepath.Join(wurzel, "geheim", "signatur.pem"))
	if err != nil {
		return err
	}
	defer privatWeg(hsm)
	hsmPEM, err := pemOeffentlich(&hsm.PublicKey)
	if err != nil {
		return err
	}
	if err = ablegen(filepath.Join(wurzel, "geheim", "hsm.pem"), hsmPEM); err != nil {
		return err
	}
	eintraege, err := os.ReadDir(filepath.Join(wurzel, "empfaenger"))
	if err != nil {
		return err
	}
	for _, eintrag := range eintraege {
		if !eintrag.IsDir() {
			continue
		}
		dir := filepath.Join(wurzel, "empfaenger", eintrag.Name())
		if err = oeffentlichNachziehen(dir, pass, hsmPEM); err != nil {
			return err
		}
	}
	if err = vermerkeErgaenzen(filepath.Join(wurzel, "konfig")); err != nil {
		return err
	}
	n, err := manifesteNachziehen(filepath.Join(wurzel, "ziel"), filepath.Join(wurzel, "bestaetigung"), &hsm.PublicKey)
	if err != nil {
		return err
	}
	fmt.Printf("Manifeste: %d\n", n)
	return nil
}

func manifesteNachziehen(ziel, speicher string, hsm *ecdsa.PublicKey) (int, error) {
	s, err := bestaetigung.Oeffnen(speicher)
	if err != nil {
		return 0, err
	}
	type schluessel struct {
		m, a protocol.ID
		e    protocol.EpochID
	}
	type fund struct {
		nr   uint64
		pfad string
	}
	letzt := map[schluessel]fund{}
	err = filepath.WalkDir(ziel, func(name string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || d.Name() == ".sperre" {
			return nil
		}
		rel, err := filepath.Rel(ziel, name)
		if err != nil {
			return err
		}
		m, a, e, nr, err := protocol.ParseObjektSchluessel(filepath.ToSlash(rel))
		if err != nil {
			return nil
		}
		k := schluessel{m, a, e}
		if alt, ok := letzt[k]; !ok || nr > alt.nr {
			letzt[k] = fund{nr, name}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for k, fund := range letzt {
		roh, err := os.ReadFile(fund.pfad)
		if err != nil {
			return n, err
		}
		_, _, manifest, err := protocol.Zerlegen(roh, 256, fund.nr == 1, true)
		if err != nil {
			continue
		}
		nutz, sig, err := protocol.ParseManifestRahmen(manifest)
		if err != nil {
			continue
		}
		if _, err = s.Einreichen(k.m, k.a, nutz, sig, hsm); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

func oeffentlichNachziehen(dir string, pass, hsmPEM []byte) error {
	if _, err := os.Stat(filepath.Join(dir, "best.pem")); err != nil {
		roh, err := os.ReadFile(filepath.Join(dir, "best.pk8"))
		if err != nil {
			return err
		}
		key, err := fenster.Entschluesseln(roh, pass)
		crypt.Wipe(roh)
		if err != nil {
			return err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("testumgebung: Bestätigung")
		}
		defer privatWeg(ec)
		oeffentlich, err := pemOeffentlich(&ec.PublicKey)
		if err != nil {
			return err
		}
		if err = ablegen(filepath.Join(dir, "best.pem"), oeffentlich); err != nil {
			return err
		}
	}
	if err := ablegen(filepath.Join(dir, "hsm.pem"), hsmPEM); err != nil {
		return err
	}
	v, err := fenster.Lesen(filepath.Join(dir, "verbindung"))
	if err != nil {
		return err
	}
	quelle := filepath.Join(filepath.Dir(filepath.Dir(dir)), "mandanten", v.Mandant.Hex(), "pruef.pem")
	pruef, err := os.ReadFile(quelle)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return ablegen(filepath.Join(dir, "pruef.pem"), pruef)
}

func vermerkeErgaenzen(pfad string) error {
	roh, err := os.ReadFile(pfad)
	if err != nil {
		return err
	}
	if strings.Contains(string(roh), "\nvermerke ") || strings.HasPrefix(string(roh), "vermerke ") {
		return nil
	}
	if len(roh) > 0 && roh[len(roh)-1] != '\n' {
		roh = append(roh, '\n')
	}
	roh = append(roh, []byte("vermerke = bestaetigung\n")...)
	return os.WriteFile(pfad, roh, 0o600)
}

func privaterAus(pfad string) (*ecdsa.PrivateKey, error) {
	roh, err := os.ReadFile(pfad)
	if err != nil {
		return nil, err
	}
	defer crypt.Wipe(roh)
	block, rest := pem.Decode(roh)
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("testumgebung: %s", pfad)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("testumgebung: %s", pfad)
	}
	return priv, nil
}

func privatWeg(key *ecdsa.PrivateKey) {
	if key == nil || key.D == nil {
		return
	}
	bits := key.D.Bits()
	for i := range bits {
		bits[i] = 0
	}
}

func pemOeffentlich(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func pemZertifikat(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func pemPrivat(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ablegen(pfad string, inhalt []byte) error {
	if len(inhalt) == 0 {
		return fmt.Errorf("testumgebung: leer %s", pfad)
	}
	if err := os.MkdirAll(filepath.Dir(pfad), 0o700); err != nil {
		return err
	}
	return os.WriteFile(pfad, inhalt, 0o600)
}
