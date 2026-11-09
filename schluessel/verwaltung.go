package schluessel

import (
	"bytes"
	"crypto/x509"
	"sort"
	"sync"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
)

// Material ist das, was der Datenschutzbeauftragte ablegt.
// Im einfachen Modus sind Oeffentlich der PKIX-Schlüssel und Privat das bereits
// verschlüsselte PKCS#8. Im sicheren Modus steht nur das Zertifikat hier.
// Eine Passphrase nimmt die Verwaltung nicht an.
type Material struct {
	Oeffentlich []byte
	Privat      []byte
	Zertifikat  []byte
	Bis         time.Time
}

// VerwKonfig öffnet die Verwaltung über einem Speicher.
// CA stellt im einfachen Modus aus. Jetzt nil ist time.Now.
type VerwKonfig struct {
	Speicher Speicher
	CA       *CA
	Jetzt    func() time.Time
}

// Verwaltung ist der eigene Prozess, in dem der Datenschutzbeauftragte
// Schlüssel ablegt und den Status setzt. Sie öffnet keine Logs.
type Verwaltung struct {
	sp    Speicher
	ca    *CA
	jetzt func() time.Time

	mu      sync.Mutex
	modus   map[protocol.ID]Modus
	name    map[protocol.ID]string
	anker   map[protocol.ID]*x509.Certificate
	ankerOK map[protocol.ID]bool
	entwurf map[protocol.ID]entwurf
}

type entwurf struct {
	raw          []byte
	eintrag      []byte
	finger       protocol.Hash
	person       string
	quittiert    bool
	privat       []byte
	privatFinger protocol.Hash
}

// NeueVerwaltung liest angelegte Mandanten aus dem Speicher.
func NeueVerwaltung(k VerwKonfig) (*Verwaltung, error) {
	if k.Speicher == nil {
		return nil, ErrMandant
	}
	jetzt := k.Jetzt
	if jetzt == nil {
		jetzt = func() time.Time { return time.Now().UTC() }
	}
	v := &Verwaltung{
		sp: k.Speicher, ca: k.CA, jetzt: jetzt,
		modus: map[protocol.ID]Modus{}, name: map[protocol.ID]string{},
		anker: map[protocol.ID]*x509.Certificate{}, ankerOK: map[protocol.ID]bool{},
		entwurf: map[protocol.ID]entwurf{},
	}
	if err := v.wiederherstellen(); err != nil {
		return nil, err
	}
	return v, nil
}

// Anlegen registriert den Mandanten. Der zurückgegebene Fingerabdruck ist der des Ankers.
func (v *Verwaltung) Anlegen(id protocol.ID, modus Modus, name string, anker *x509.Certificate) (protocol.Hash, error) {
	if id == (protocol.ID{}) || (modus != ModusEinfach && modus != ModusSicher) {
		return protocol.Hash{}, ErrMandant
	}
	if err := personOK(name); err != nil || anker == nil {
		if anker == nil {
			return protocol.Hash{}, ErrAnker
		}
		return protocol.Hash{}, err
	}
	if modus == ModusEinfach {
		if v.ca == nil || v.ca.Zertifikat() == nil || !bytes.Equal(anker.Raw, v.ca.Zertifikat().Raw) {
			return protocol.Hash{}, ErrAnker
		}
	} else if !anker.IsCA {
		return protocol.Hash{}, ErrAnker
	}
	finger, err := crypt.FingerprintCertificate(anker)
	if err != nil {
		return protocol.Hash{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.modus[id]; ok {
		return protocol.Hash{}, ErrMandant
	}
	if reg, ok := v.sp.(AnkerRegistrierung); ok && modus == ModusSicher {
		if err := reg.Anker(id, anker.Raw); err != nil {
			return protocol.Hash{}, err
		}
	}
	meta, err := metaBytes(modus, name, anker, protocol.Hash{}, "", false)
	if err != nil {
		return protocol.Hash{}, err
	}
	if err := v.sp.MetaSetzen(id, meta); err != nil {
		return protocol.Hash{}, err
	}
	v.modus[id] = modus
	v.name[id] = name
	v.anker[id] = anker
	return finger, nil
}

// AnkerQuittieren bestätigt den angezeigten Fingerabdruck des Ankers.
func (v *Verwaltung) AnkerQuittieren(id protocol.ID, person string, finger protocol.Hash) error {
	if err := personOK(person); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	anker := v.anker[id]
	if anker == nil {
		return ErrAnker
	}
	got, err := crypt.FingerprintCertificate(anker)
	if err != nil {
		return err
	}
	if got != finger {
		return ErrQuittung
	}
	meta, err := metaBytes(v.modus[id], v.name[id], anker, finger, person, true)
	if err != nil {
		return err
	}
	if err := v.sp.MetaSetzen(id, meta); err != nil {
		return err
	}
	v.ankerOK[id] = true
	return nil
}

// Hinterlegen prüft einen neuen KEK und legt einen Entwurf ab.
// Ist schon ein aktueller Schlüssel da, setzt den Nachfolger StatusSetzen.
// Zurück kommen der Fingerabdruck des Zertifikats und die Bytes der Veröffentlichung.
// Aktuell wird der Schlüssel erst nach Quittieren und Festschreiben.
func (v *Verwaltung) Hinterlegen(id protocol.ID, person string, m Material) (protocol.Hash, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.bereit(id, person); err != nil {
		return protocol.Hash{}, nil, err
	}
	basis, err := v.basis(id)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	if _, ok := aktuell(basis); ok {
		return protocol.Hash{}, nil, ErrAktuell
	}
	der, privat, finger, err := v.blatt(id, basis.CRL, m, true)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	basis.Zertifikate = append(basis.Zertifikate, Zertifikatseintrag{Status: StatusAktuell, DER: der})
	raw, ein, err := v.fassen(id, person, basis, Eintrag{
		Bisher: protocol.Hash{}, Neu: finger, Status: StatusAktuell, Art: ArtKEK,
	})
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	v.entwurf[id] = entwurf{raw: raw, eintrag: ein, finger: finger, person: person, privat: privat, privatFinger: finger}
	return finger, append([]byte(nil), raw...), nil
}

// StatusSetzen setzt den Status von bisher.
// nachfolger nil lässt keinen aktuellen KEK, wenn bisher der aktuelle war.
// Sonst wird der Nachfolger in demselben Schritt aktuell.
// Der Fingerabdruck gehört zum Nachfolger oder, ohne ihn, zum bisherigen Schlüssel.
func (v *Verwaltung) StatusSetzen(id protocol.ID, person string, bisher protocol.Hash, status Status, nachfolger *Material) (protocol.Hash, []byte, error) {
	if status != StatusAbgeloest && status != StatusVerloren && status != StatusKompromittiert {
		return protocol.Hash{}, nil, ErrStatus
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.bereit(id, person); err != nil {
		return protocol.Hash{}, nil, err
	}
	basis, err := v.basis(id)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	idx, ok := indexFinger(basis, bisher)
	if !ok {
		return protocol.Hash{}, nil, ErrStatus
	}
	var privat []byte
	var privatFinger, gezeigt protocol.Hash
	neu := protocol.Hash{}
	if nachfolger != nil {
		if basis.Zertifikate[idx].Status != StatusAktuell {
			return protocol.Hash{}, nil, ErrStatus
		}
		der, pk, finger, berr := v.blatt(id, basis.CRL, *nachfolger, true)
		if berr != nil {
			return protocol.Hash{}, nil, berr
		}
		basis.Zertifikate = append(basis.Zertifikate, Zertifikatseintrag{Status: StatusAktuell, DER: der})
		privat, privatFinger, neu, gezeigt = pk, finger, finger, finger
	} else {
		gezeigt = bisher
	}
	basis.Zertifikate[idx].Status = status
	raw, ein, err := v.fassen(id, person, basis, Eintrag{
		Bisher: bisher, Neu: neu, Status: status, Art: ArtKEK,
	})
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	v.entwurf[id] = entwurf{raw: raw, eintrag: ein, finger: gezeigt, person: person, privat: privat, privatFinger: privatFinger}
	return gezeigt, append([]byte(nil), raw...), nil
}

// PruefHinterlegen legt den öffentlichen Prüfschlüssel der Zugehörigkeit ab.
// Der Fingerabdruck ist SHA-256 über das SubjectPublicKeyInfo.
func (v *Verwaltung) PruefHinterlegen(id protocol.ID, person string, zertifikat []byte) (protocol.Hash, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.bereit(id, person); err != nil {
		return protocol.Hash{}, nil, err
	}
	basis, err := v.basis(id)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	cert, _, err := pruefeBlatt(zertifikat, v.anker[id], id, v.name[id], v.jetzt().UTC(), crlAus(basis.CRL), false)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	finger, err := crypt.FingerprintSPKI(cert.PublicKey)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	var bisher protocol.Hash
	if len(basis.Pruef) > 0 {
		alt, err := x509.ParsePKIXPublicKey(basis.Pruef)
		if err != nil {
			return protocol.Hash{}, nil, ErrFormat
		}
		bisher, err = crypt.FingerprintSPKI(alt)
		if err != nil {
			return protocol.Hash{}, nil, err
		}
	}
	basis.Pruef = spki
	raw, ein, err := v.fassen(id, person, basis, Eintrag{
		Bisher: bisher, Neu: finger, Status: StatusAktuell, Art: ArtPruef,
	})
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	v.entwurf[id] = entwurf{raw: raw, eintrag: ein, finger: finger, person: person}
	return finger, append([]byte(nil), raw...), nil
}

// Auffrischen setzt Zeit und laufende Nummer neu, ohne den Schlüssel zu wechseln.
// Im sicheren Modus hält das die Veröffentlichung innerhalb des Höchstalters.
// Der Fingerabdruck ist der der Bytes, die danach zu signieren sind.
func (v *Verwaltung) Auffrischen(id protocol.ID, person string) (protocol.Hash, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.bereit(id, person); err != nil {
		return protocol.Hash{}, nil, err
	}
	basis, err := v.basis(id)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	if basis.Nummer == 0 && len(basis.Zertifikate) == 0 {
		return protocol.Hash{}, nil, ErrEntwurf
	}
	var finger protocol.Hash
	if z, ok := aktuell(basis); ok {
		cert, err := x509.ParseCertificate(z.DER)
		if err != nil {
			return protocol.Hash{}, nil, ErrFormat
		}
		finger, err = crypt.FingerprintCertificate(cert)
		if err != nil {
			return protocol.Hash{}, nil, err
		}
	}
	raw, ein, err := v.fassen(id, person, basis, Eintrag{
		Bisher: finger, Neu: finger, Status: StatusAktuell, Art: ArtStand,
	})
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	summe := EntwurfFinger(raw)
	v.entwurf[id] = entwurf{raw: raw, eintrag: ein, finger: summe, person: person}
	return summe, append([]byte(nil), raw...), nil
}

// Sperrliste nimmt eine CRL auf, signiert vom Anker. Wirksam wird sie mit Festschreiben.
func (v *Verwaltung) Sperrliste(id protocol.ID, person string, crlDER []byte) (protocol.Hash, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.bereit(id, person); err != nil {
		return protocol.Hash{}, nil, err
	}
	list, err := parseCRL(crlDER)
	if err != nil || list == nil || list.CheckSignatureFrom(v.anker[id]) != nil {
		return protocol.Hash{}, nil, ErrZertifikat
	}
	basis, err := v.basis(id)
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	basis.CRL = append([]byte(nil), crlDER...)
	raw, ein, err := v.fassen(id, person, basis, Eintrag{
		Status: StatusAktuell, Art: ArtCRL,
	})
	if err != nil {
		return protocol.Hash{}, nil, err
	}
	summe := EntwurfFinger(raw)
	v.entwurf[id] = entwurf{raw: raw, eintrag: ein, finger: summe, person: person}
	return summe, append([]byte(nil), raw...), nil
}

// Quittieren bestätigt den angezeigten Fingerabdruck des Entwurfs.
func (v *Verwaltung) Quittieren(id protocol.ID, person string, finger protocol.Hash) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entwurf[id]
	if !ok || e.person != person || e.finger != finger {
		return ErrQuittung
	}
	e.quittiert = true
	v.entwurf[id] = e
	return nil
}

// Festschreiben macht den quittierten Entwurf zur Veröffentlichung.
// Im sicheren Modus muss sig über raw prüfen. Im einfachen Modus bleibt sig leer.
func (v *Verwaltung) Festschreiben(id protocol.ID, raw, sig []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entwurf[id]
	if !ok || !e.quittiert || !bytes.Equal(e.raw, raw) {
		return ErrEntwurf
	}
	modus := v.modus[id]
	if modus == ModusSicher {
		if !SignaturOK(v.anker[id].PublicKey, raw, sig) {
			return ErrSignatur
		}
	} else if len(sig) != 0 {
		return ErrModus
	}
	if len(e.privat) > 0 {
		if err := v.sp.Privat(id, e.privatFinger, e.privat); err != nil {
			return err
		}
	}
	if err := v.sp.Fest(id, raw, sig, e.eintrag); err != nil {
		return err
	}
	delete(v.entwurf, id)
	return nil
}

func (v *Verwaltung) bereit(id protocol.ID, person string) error {
	if err := personOK(person); err != nil {
		return err
	}
	if _, ok := v.modus[id]; !ok {
		return ErrMandant
	}
	if !v.ankerOK[id] {
		return ErrQuittung
	}
	return nil
}

func (v *Verwaltung) basis(id protocol.ID) (Veroeffentlichung, error) {
	st, err := v.sp.Stand(id)
	if err != nil {
		return Veroeffentlichung{}, err
	}
	if !st.Da {
		return Veroeffentlichung{Mandant: id, Name: v.name[id]}, nil
	}
	gefasst, err := ParseVeroeffentlichung(st.Pub)
	if err != nil || gefasst.Mandant != id {
		return Veroeffentlichung{}, ErrFormat
	}
	gefasst.Zertifikate = append([]Zertifikatseintrag(nil), gefasst.Zertifikate...)
	gefasst.CRL = append([]byte(nil), gefasst.CRL...)
	gefasst.Pruef = append([]byte(nil), gefasst.Pruef...)
	gefasst.Name = v.name[id]
	return gefasst, nil
}

func (v *Verwaltung) fassen(id protocol.ID, person string, basis Veroeffentlichung, ein Eintrag) ([]byte, []byte, error) {
	st, err := v.sp.Stand(id)
	if err != nil {
		return nil, nil, err
	}
	jetzt := v.jetzt().UTC()
	basis.Mandant = id
	basis.Name = v.name[id]
	basis.Nummer = st.Nummer + 1
	basis.Zeit = jetzt
	sort.Slice(basis.Zertifikate, func(i, j int) bool {
		return bytes.Compare(basis.Zertifikate[i].DER, basis.Zertifikate[j].DER) < 0
	})
	raw, err := basis.Bytes()
	if err != nil {
		return nil, nil, err
	}
	ein.Mandant = id
	ein.Zeit = jetzt
	ein.Nummer = basis.Nummer
	ein.Person = person
	encoded, err := ein.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return raw, encoded, nil
}

func (v *Verwaltung) blatt(id protocol.ID, crlDER []byte, m Material, kek bool) (der, privat []byte, finger protocol.Hash, err error) {
	anker := v.anker[id]
	jetzt := v.jetzt().UTC()
	list := crlAus(crlDER)
	if v.modus[id] == ModusEinfach {
		if len(m.Zertifikat) != 0 || len(m.Oeffentlich) == 0 || (kek && len(m.Privat) == 0) || (!kek && len(m.Privat) != 0) {
			return nil, nil, protocol.Hash{}, ErrModus
		}
		if kek {
			if err := verschluesseltPKCS8(m.Privat); err != nil {
				return nil, nil, protocol.Hash{}, err
			}
		}
		pub, err := x509.ParsePKIXPublicKey(m.Oeffentlich)
		if err != nil {
			return nil, nil, protocol.Hash{}, ErrZertifikat
		}
		cert, err := v.ca.Ausstellen(pub, id, v.name[id], m.Bis, jetzt, kek)
		if err != nil {
			return nil, nil, protocol.Hash{}, err
		}
		der = cert.Raw
		if kek {
			privat = append([]byte(nil), m.Privat...)
		}
	} else {
		if len(m.Oeffentlich) != 0 || len(m.Privat) != 0 || len(m.Zertifikat) == 0 {
			return nil, nil, protocol.Hash{}, ErrModus
		}
		der = append([]byte(nil), m.Zertifikat...)
	}
	_, finger, err = pruefeBlatt(der, anker, id, v.name[id], jetzt, list, kek)
	if err != nil {
		return nil, nil, protocol.Hash{}, err
	}
	return der, privat, finger, nil
}

func aktuell(v Veroeffentlichung) (Zertifikatseintrag, bool) {
	var gefunden Zertifikatseintrag
	n := 0
	for _, z := range v.Zertifikate {
		if z.Status == StatusAktuell {
			gefunden = z
			n++
		}
	}
	return gefunden, n == 1
}

func indexFinger(v Veroeffentlichung, finger protocol.Hash) (int, bool) {
	for i, z := range v.Zertifikate {
		cert, err := x509.ParseCertificate(z.DER)
		if err != nil {
			continue
		}
		got, err := crypt.FingerprintCertificate(cert)
		if err == nil && got == finger {
			return i, true
		}
	}
	return 0, false
}

func crlAus(der []byte) *x509.RevocationList {
	list, err := parseCRL(der)
	if err != nil {
		return nil
	}
	return list
}

func (v *Verwaltung) wiederherstellen() error {
	ids, err := v.sp.Mandanten()
	if err != nil {
		return err
	}
	for _, id := range ids {
		meta, ok, err := v.sp.Meta(id)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		modus, name, anker, finger, person, quittiert, err := parseMeta(meta)
		if err != nil {
			return err
		}
		if reg, ok := v.sp.(AnkerRegistrierung); ok && modus == ModusSicher {
			if err := reg.Anker(id, anker.Raw); err != nil {
				return err
			}
		}
		v.modus[id] = modus
		v.name[id] = name
		v.anker[id] = anker
		if quittiert {
			got, err := crypt.FingerprintCertificate(anker)
			if err != nil || got != finger || personOK(person) != nil {
				return ErrFormat
			}
			v.ankerOK[id] = true
		}
	}
	return nil
}

func metaBytes(modus Modus, name string, anker *x509.Certificate, finger protocol.Hash, person string, quittiert bool) ([]byte, error) {
	if anker == nil || len(anker.Raw) == 0 || personOK(name) != nil {
		return nil, ErrAnker
	}
	if quittiert && personOK(person) != nil {
		return nil, ErrQuittung
	}
	buf := append([]byte(nil), protocol.Domain("schluessel-mandant")...)
	buf = append(buf, byte(modus))
	if quittiert {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = protocol.AppendText(buf, name)
	var err error
	buf, err = appendLen(buf, anker.Raw)
	if err != nil {
		return nil, err
	}
	buf = append(buf, finger[:]...)
	buf = protocol.AppendText(buf, person)
	return buf, nil
}

func parseMeta(b []byte) (Modus, string, *x509.Certificate, protocol.Hash, string, bool, error) {
	dom := protocol.Domain("schluessel-mandant")
	if !bytes.HasPrefix(b, dom) || len(b) < len(dom)+2 {
		return 0, "", nil, protocol.Hash{}, "", false, ErrFormat
	}
	rest := b[len(dom):]
	modus := Modus(rest[0])
	quittiert := rest[1] == 1
	rest = rest[2:]
	if modus != ModusEinfach && modus != ModusSicher {
		return 0, "", nil, protocol.Hash{}, "", false, ErrFormat
	}
	name, rest, err := takeText(rest)
	if err != nil {
		return 0, "", nil, protocol.Hash{}, "", false, err
	}
	der, rest, err := takeLen(rest)
	if err != nil || len(rest) < protocol.HashLen {
		return 0, "", nil, protocol.Hash{}, "", false, ErrFormat
	}
	var finger protocol.Hash
	copy(finger[:], rest[:protocol.HashLen])
	rest = rest[protocol.HashLen:]
	person, rest, err := takePerson(rest)
	if err != nil || len(rest) != 0 {
		return 0, "", nil, protocol.Hash{}, "", false, ErrFormat
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, "", nil, protocol.Hash{}, "", false, ErrAnker
	}
	return modus, name, cert, finger, person, quittiert, nil
}

func takePerson(b []byte) (string, []byte, error) {
	raw, rest, err := takeLen(b)
	if err != nil {
		return "", nil, err
	}
	if len(raw) > 256 {
		return "", nil, ErrFormat
	}
	return string(raw), rest, nil
}
