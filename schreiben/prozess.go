// Package schreiben ist der Schreibprozess.
// Er nimmt Ereignisse an, schreibt den Puffer bei der Größen- oder Zeitgrenze
// in den Spool und antwortet dem Aufrufer erst nach der Annahme am Ziel.
// Am Ziel ist die Reihenfolge Belegung, Vorbereitung, Segmente, Annahme.
package schreiben

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"cryptlog/abschluss"
	"cryptlog/epoch"
	"cryptlog/protocol"
	"cryptlog/strom"
)

var (
	// ErrBeenden heißt, der Prozess nimmt nichts Neues mehr an.
	ErrBeenden = errors.New("schreiben: Prozess nimmt nichts mehr an")
	// ErrBelegung heißt, die Belegung lehnt das Ereignis ab.
	ErrBelegung = errors.New("schreiben: Belegung lehnt das Ereignis ab")
	// ErrGehalten heißt, eine andere Instanz hält die Frist dieser Belegung.
	ErrGehalten = errors.New("schreiben: Instanzfrist einer anderen Instanz läuft")
	// ErrGeheimnis heißt, der Plattform-KEK fehlt.
	ErrGeheimnis = errors.New("schreiben: Plattform-Schlüssel fehlt")
	// ErrIndex heißt, der öffentliche Index-Schlüssel fehlt.
	ErrIndex = errors.New("schreiben: Index-Schlüssel fehlt")
	// ErrKonflikt heißt, die event_id steht in mehr als einer Annahme.
	ErrKonflikt = errors.New("schreiben: Ereignis steht in mehr als einer Annahme")
	// ErrOffen heißt, der Abschluss dieser Instanz liegt nicht mehr im Spool.
	ErrOffen = errors.New("schreiben: Abschluss dieser Instanz liegt nicht mehr im Spool")
	// ErrSchluessel heißt, der Status verloren oder kompromittiert nimmt keine weiteren Einträge an.
	ErrSchluessel = errors.New("schreiben: Schlüsselstatus lässt keine weiteren Einträge zu")
)

// Schluessel ist ein öffentlicher Wrap-Schlüssel und der Fingerabdruck seines Zertifikats.
type Schluessel struct {
	Pub    crypto.PublicKey
	Finger protocol.Hash
}

// SchluesselStatus ist die Lage eines Fingerabdrucks, der nicht mehr der aktuelle KEK ist.
type SchluesselStatus uint8

const (
	// SchluesselAbgeloest wickelt keine neue Epoche mehr. Die offene Epoche bleibt.
	SchluesselAbgeloest SchluesselStatus = iota + 1
	// SchluesselVerloren verwirft den Klartext-DEK der offenen Epoche.
	SchluesselVerloren
	// SchluesselKompromittiert verwirft den Klartext-DEK der offenen Epoche.
	SchluesselKompromittiert
)

// Lage ist der Mandant, wie der Schreibprozess ihn zum Verschlüsseln braucht.
// Status nennt die Fingerabdrücke, die abgelöst, verloren oder kompromittiert sind.
// Der aktuelle KEK steht dort nicht.
type Lage struct {
	KEKVorhanden bool
	KEK          Schluessel
	Register     strom.Register
	Pruef        crypto.PublicKey
	Verzeichnis  protocol.ID
	Vorgang      protocol.ID
	Auffang      protocol.ID
	Einzel       protocol.ID
	Katalog      protocol.ID
	Stand        protocol.Stand
	Rahmen       int
	Status       map[protocol.Hash]SchluesselStatus
	CacheSeit    time.Time
	Deck         bool
}

// Bestand löst einen Mandanten auf. Die Nullkennung fragt der Prozess nicht ab;
// ohne Mandant verwendet er die Kennung der Plattform.
// Mandanten nennt die Kennungen, für die der Prozess Deckverkehr schreiben kann,
// auch ohne dass ein Ereignis eingetroffen ist.
type Bestand interface {
	Mandant(id protocol.ID) (Lage, error)
	Mandanten() ([]protocol.ID, error)
}

// Ziel ist das Speicherziel. Liste liefert die Schlüssel unter dem Präfix.
type Ziel interface {
	abschluss.Ziel
	Liste(prefix string) ([]string, error)
}

// Bestaetigung ist die Antwort nach der Annahme.
type Bestaetigung struct {
	Seq        uint64
	Hash       protocol.Hash
	Schluessel string
}

// Konfig startet eine schreibende Instanz.
// Jetzt nil ist time.Now in UTC. Rand nil zieht aus crypto/rand.
type Konfig struct {
	Instanz      protocol.ID
	Schwellen    Schwellen
	Spool        string
	Ziel         Ziel
	Plattform    Schluessel
	Index        Schluessel
	Bestand      Bestand
	Signatur     func([]byte) (protocol.Signature, error)
	Jetzt        func() time.Time
	Rand         io.Reader
	ZielArt      string
	Version      string
	Digest       string
	Loeschzeit   time.Duration
	Aufbewahrung time.Duration
	Vermerk      Vermerke
	// Einreichen reicht das vom HSM signierte Manifest beim Empfänger ein.
	// Derselbe Aufruf mit denselben Bytes ändert den Speicher nicht.
	Einreichen func(mandant, ablage protocol.ID, nutzlast []byte, sig protocol.Signature) error
}

type stromSchluss struct {
	mandant protocol.ID
	ablage  protocol.ID
	bind    protocol.ID
	finger  protocol.Hash
}

type ablageSchluss struct {
	mandant protocol.ID
	ablage  protocol.ID
}

type ergebnis struct {
	best Bestaetigung
	err  error
}

type job struct {
	ev  strom.Ereignis
	ctx context.Context
	ch  chan ergebnis
}

type warten struct {
	id             protocol.ID
	hash           protocol.Hash
	generation     uint64
	bytes          int
	chs            []chan ergebnis
	fertig         bool
	best           Bestaetigung
	err            error
	seit           time.Time
	rollen         []protocol.StromRolle
	zaehlen        bool
	kek            bool
	kekMandant     protocol.ID
	mandant        protocol.ID
	katalogMandant protocol.ID
	katalogRoh     []byte
}

type gespult struct {
	seq           uint64
	ein           abschluss.Eintrag
	hash          protocol.Hash
	zeit          time.Time
	groesse       int
	werte         []*warten
	fertig        bool
	gescheitert   bool
	abdeckenFirst uint64
	abdeckenLast  uint64
}

type stueck struct {
	lauf      *lauf
	mandant   protocol.ID
	finger    protocol.Hash
	pub       crypto.PublicKey
	eintraege []protocol.SeqEintrag
	segmente  []epoch.Segment
	manifest  bool
}

// Prozess nimmt Ereignisse an und schreibt sie über den Spool ans Ziel.
type Prozess struct {
	instanz   protocol.ID
	schwellen Schwellen
	spoolDir  string
	ziel      Ziel
	plattform Schluessel
	index     Schluessel
	bestand   Bestand
	sign      func([]byte) (protocol.Signature, error)
	jetzt     func() time.Time
	rand      io.Reader

	eingang chan job
	beenden chan struct{}
	fertig  chan struct{}
	tot     chan struct{}
	stopp   sync.Once
	endeErr error
	halt    bool

	mem     *abschluss.Spool
	next    uint64
	letzter protocol.Hash
	belegt  int

	puffer      []*warten
	pufferBytes int
	pufferSeit  time.Time
	nachID      map[protocol.ID]*warten
	queue       []*gespult

	laeufe map[stromSchluss]*lauf
	reihe  []*lauf
	kette  map[ablageSchluss]protocol.Hash

	naechsteFrist time.Time
	fristEnde     time.Time

	zielArt        string
	version        string
	digest         string
	start          time.Time
	loeschzeit     time.Duration
	aufbewahrung   time.Duration
	vermerke       Vermerke
	einreichen     func(mandant, ablage protocol.ID, nutzlast []byte, sig protocol.Signature) error
	naechsteLoesch time.Time
	spoolFehler    bool
	katalog        map[protocol.ID][]byte
	deck           map[protocol.ID]bool
	gedeckt        map[rasterSchluss]struct{}
	cacheSeit      map[protocol.ID]time.Time
	unaccepted     map[string]uint64
	kekFehlt       map[string]uint64
	zielFehler     map[string]uint64
	angenommen     map[string]uint64
	accept         histogramm
	segment        histogramm

	mu   sync.Mutex
	bild reihe
}

// Start lädt den Spool und nimmt danach Ereignisse an.
// Ein unerreichbares Ziel verhindert den Start nicht.
func Start(k Konfig) (*Prozess, error) {
	if k.Plattform.Pub == nil {
		return nil, ErrGeheimnis
	}
	if k.Instanz == (protocol.ID{}) || k.Spool == "" || k.Ziel == nil || k.Bestand == nil || k.Signatur == nil {
		return nil, protocol.ErrLength
	}
	if err := k.Schwellen.Pruefen(); err != nil {
		return nil, err
	}
	zielArt := k.ZielArt
	if zielArt == "" {
		zielArt = "platte"
	}
	if zielArt != "platte" && zielArt != "s3" {
		return nil, protocol.ErrLength
	}
	if k.Loeschzeit < 0 || (k.Loeschzeit > 0 && (k.Vermerk == nil || k.Einreichen == nil || k.Aufbewahrung <= 0 || k.Aufbewahrung%(24*time.Hour) != 0)) {
		return nil, protocol.ErrLength
	}
	if err := os.MkdirAll(k.Spool, 0o700); err != nil {
		return nil, err
	}
	jetzt := k.Jetzt
	if jetzt == nil {
		jetzt = func() time.Time { return time.Now().UTC() }
	}
	zufall := k.Rand
	if zufall == nil {
		zufall = rand.Reader
	}
	p := &Prozess{
		instanz:      k.Instanz,
		schwellen:    k.Schwellen,
		spoolDir:     k.Spool,
		ziel:         k.Ziel,
		plattform:    k.Plattform,
		index:        k.Index,
		bestand:      k.Bestand,
		sign:         k.Signatur,
		jetzt:        jetzt,
		rand:         zufall,
		eingang:      make(chan job),
		beenden:      make(chan struct{}),
		fertig:       make(chan struct{}),
		tot:          make(chan struct{}),
		nachID:       make(map[protocol.ID]*warten),
		laeufe:       make(map[stromSchluss]*lauf),
		kette:        make(map[ablageSchluss]protocol.Hash),
		next:         1,
		letzter:      protocol.AnnahmeGenesis(k.Instanz),
		zielArt:      zielArt,
		version:      k.Version,
		digest:       k.Digest,
		start:        jetzt(),
		loeschzeit:   k.Loeschzeit,
		aufbewahrung: k.Aufbewahrung,
		vermerke:     k.Vermerk,
		einreichen:   k.Einreichen,
		katalog:      map[protocol.ID][]byte{},
		deck:         map[protocol.ID]bool{},
		gedeckt:      map[rasterSchluss]struct{}{},
		cacheSeit:    map[protocol.ID]time.Time{},
		unaccepted:   map[string]uint64{},
		kekFehlt:     map[string]uint64{},
		zielFehler:   map[string]uint64{},
		angenommen:   map[string]uint64{},
		accept:       neueHistogramm(),
		segment:      neueHistogramm(),
	}
	if p.loeschzeit > 0 {
		p.naechsteLoesch = jetzt().Add(p.loeschzeit)
	}
	if err := p.laden(); err != nil {
		return nil, err
	}
	if err := p.katalogLaden(); err != nil {
		return nil, err
	}
	_ = p.fristSetzen()
	p.merken()
	go p.schleife()
	return p, nil
}

// Ereignis blockiert, bis die Annahme am Ziel liegt oder das Ereignis abgelehnt ist.
// Eine abgebrochene Wartezeit holt ein schon in den Spool geschriebenes Ereignis nicht zurück.
func (p *Prozess) Ereignis(ctx context.Context, ev strom.Ereignis) (Bestaetigung, error) {
	ch := make(chan ergebnis, 1)
	select {
	case <-p.tot:
		return Bestaetigung{}, ErrBeenden
	case <-ctx.Done():
		return Bestaetigung{}, ctx.Err()
	case p.eingang <- job{ev: ev, ctx: ctx, ch: ch}:
	}
	select {
	case r := <-ch:
		return r.best, r.err
	case <-ctx.Done():
		return Bestaetigung{}, ctx.Err()
	}
}

// Beenden nimmt nichts Neues mehr an, schreibt den Puffer zu Ende und schließt die offenen Epochen.
func (p *Prozess) Beenden(ctx context.Context) error {
	p.stopp.Do(func() { close(p.beenden) })
	select {
	case <-p.fertig:
		return p.endeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Prozess) schleife() {
	timer := time.NewTimer(p.naechstes())
	defer timer.Stop()
	for {
		select {
		case job := <-p.eingang:
			if job.ctx.Err() != nil {
				job.ch <- ergebnis{err: job.ctx.Err()}
			} else {
				p.aufnehmen(job)
			}
			_ = p.fristSetzen()
			p.merken()
			zuruecksetzen(timer, p.naechstes())
		case <-timer.C:
			if p.loeschenFaellig() {
				p.loeschlauf()
			}
			if len(p.puffer) > 0 && time.Since(p.pufferSeit) >= p.schwellen.PufferWarte {
				_ = p.pufferAbschluss()
			}
			_ = p.deckFuellen(false)
			if p.faellig() {
				_ = p.hochladen(true)
			}
			_ = p.fristSetzen()
			p.merken()
			zuruecksetzen(timer, p.naechstes())
		case <-p.beenden:
			p.halt = true
			p.merken()
			p.endeErr = p.stilllegen()
			p.merken()
			close(p.fertig)
			close(p.tot)
			return
		}
	}
}

func (p *Prozess) aufnehmen(j job) {
	if p.halt {
		p.scheitern(j, ErrBeenden)
		return
	}
	if err := p.deckFuellen(false); err != nil {
		p.scheitern(j, err)
		return
	}
	if p.loeschenFaellig() {
		p.loeschlauf()
	}
	lage, err := p.lageVon(j.ev.Mandant)
	if err != nil {
		p.scheitern(j, err)
		return
	}
	mandant := j.ev.Mandant
	if mandant == (protocol.ID{}) {
		mandant = protocol.PlattformMandant()
	}
	if err := p.katalogNachziehen(mandant, lage); err != nil {
		p.scheitern(j, err)
		return
	}
	if err := p.abloesen(mandant, lage); err != nil {
		p.scheitern(j, err)
		return
	}
	p.sperren(mandant, lage)
	zu, err := strom.Zuordnen(j.ev, strom.Eingang{
		KEKVorhanden: lage.KEKVorhanden && j.ev.Mandant != (protocol.ID{}),
		Register:     lage.Register,
		Pruef:        lage.Pruef,
	})
	if err != nil {
		p.scheitern(j, err)
		return
	}
	if w := p.nachID[j.ev.ID]; w != nil && w.fertig && w.err != nil {
		delete(p.nachID, j.ev.ID)
	}
	if w := p.nachID[j.ev.ID]; w != nil && !w.fertig {
		if w.hash != zu.Hash {
			p.scheitern(j, ErrBelegung)
			return
		}
		w.chs = append(w.chs, j.ch)
		return
	}
	if w := p.nachID[j.ev.ID]; w != nil && w.fertig && w.err == nil {
		if w.hash != zu.Hash {
			p.scheitern(j, ErrBelegung)
			return
		}
		j.ch <- ergebnis{best: w.best}
		return
	}
	entscheid, belegt, best, err := p.entscheiden(j.ev.ID, zu.Hash)
	if err != nil {
		p.scheitern(j, err)
		return
	}
	switch entscheid {
	case protocol.EntscheidBestaetigt:
		p.nachID[j.ev.ID] = &warten{id: j.ev.ID, hash: zu.Hash, fertig: true, best: best}
		j.ch <- ergebnis{best: best}
		return
	case protocol.EntscheidAbgelehnt:
		p.scheitern(j, ErrBelegung)
		return
	case protocol.EntscheidGehalten:
		p.scheitern(j, ErrGehalten)
		return
	case protocol.EntscheidWeiter:
		p.scheitern(j, ErrOffen)
		return
	}
	if p.belegt >= p.schwellen.SpoolGrenze {
		p.scheitern(j, abschluss.ErrGrenze)
		return
	}
	if brauchtIndex(zu) && p.index.Pub == nil {
		p.scheitern(j, ErrIndex)
		return
	}
	var generation uint64
	if entscheid == protocol.EntscheidUebernahme {
		if belegt == nil || belegt.Generation == ^uint64(0) {
			p.scheitern(j, protocol.ErrLength)
			return
		}
		generation = belegt.Generation + 1
	}
	bahnen, err := p.bahnen(zu, lage)
	if err != nil {
		p.scheitern(j, err)
		return
	}
	geschrieben, err := strom.Schreiben(zu, bahnen)
	if err != nil {
		p.toteEpochen()
		p.scheitern(j, err)
		return
	}
	for _, seg := range geschrieben.Segmente {
		l, lerr := p.laufZuSegment(seg)
		if lerr != nil {
			p.scheitern(j, lerr)
			return
		}
		l.segment(seg)
	}
	w := &warten{
		id: j.ev.ID, hash: zu.Hash, generation: generation, seit: time.Now(),
		chs: []chan ergebnis{j.ch}, zaehlen: !p.deck[mandant], mandant: mandant,
	}
	for _, ziel := range zu.Ziele {
		w.rollen = append(w.rollen, ziel.Rolle)
		if ziel.Grund == protocol.GrundKEKFehlt && j.ev.Mandant != (protocol.ID{}) {
			w.kek = true
			w.kekMandant = j.ev.Mandant
		}
	}
	n, err := p.zaehlen(zu, bahnen, geschrieben, w)
	if err != nil {
		p.scheitern(j, err)
		return
	}
	w.bytes = n
	p.nachID[w.id] = w
	if len(p.puffer) == 0 {
		p.pufferSeit = time.Now()
	}
	p.puffer = append(p.puffer, w)
	p.pufferBytes += n
	if p.pufferBytes >= p.schwellen.Puffer {
		_ = p.pufferAbschluss()
	}
}

func (p *Prozess) entscheiden(id protocol.ID, hash protocol.Hash) (protocol.Entscheid, *protocol.Belegung, Bestaetigung, error) {
	raw, ok, err := p.ziel.Lesen(protocol.BelegungSchluessel(id))
	if err != nil {
		return 0, nil, Bestaetigung{}, err
	}
	if !ok {
		return protocol.EntscheidNeu, nil, Bestaetigung{}, nil
	}
	beleg, err := protocol.ParseBelegung(raw)
	if err != nil {
		return 0, nil, Bestaetigung{}, err
	}
	if beleg.Hash != hash {
		return protocol.EntscheidAbgelehnt, &beleg, Bestaetigung{}, nil
	}
	best, gefunden, err := p.findeAnnahme(beleg.Instanz, id, hash)
	if err != nil {
		return 0, nil, Bestaetigung{}, err
	}
	var lauf *protocol.InstanzLauf
	lraw, lok, err := p.ziel.Lesen(protocol.InstanzSchluessel(beleg.Instanz))
	if err != nil {
		return 0, nil, Bestaetigung{}, err
	}
	if lok {
		parsed, err := protocol.ParseInstanzLauf(lraw)
		if err != nil {
			return 0, nil, Bestaetigung{}, err
		}
		lauf = &parsed
	}
	ms := p.jetzt().UnixMilli()
	if ms < 0 {
		return 0, nil, Bestaetigung{}, protocol.ErrLength
	}
	entscheid, err := protocol.Entscheiden(&beleg, hash, gefunden, p.instanz, uint64(ms), lauf)
	return entscheid, &beleg, best, err
}

func (p *Prozess) findeAnnahme(instanz, event protocol.ID, hash protocol.Hash) (Bestaetigung, bool, error) {
	var treffer *Bestaetigung
	pruefe := func(raw []byte, key string) error {
		nutz, err := protocol.ParseAnnahme(raw)
		if err != nil {
			return err
		}
		summe, err := protocol.AnnahmeHash(raw)
		if err != nil {
			return err
		}
		for _, slot := range nutz.Slots {
			if slot.Event != event {
				continue
			}
			if slot.Hash != hash {
				return ErrBelegung
			}
			if treffer != nil && treffer.Schluessel != key {
				return ErrKonflikt
			}
			treffer = &Bestaetigung{Seq: nutz.BatchSeq, Hash: summe, Schluessel: key}
		}
		return nil
	}
	if instanz == p.instanz {
		for _, g := range p.queue {
			key, err := protocol.AnnahmeSchluessel(p.instanz, g.seq)
			if err != nil {
				return Bestaetigung{}, false, err
			}
			if err := pruefe(g.ein.Annahme, key); err != nil {
				return Bestaetigung{}, false, err
			}
		}
	}
	keys, err := p.ziel.Liste("annahme/" + instanz.Hex() + "/")
	if err != nil {
		return Bestaetigung{}, false, err
	}
	for _, key := range keys {
		raw, ok, err := p.ziel.Lesen(key)
		if err != nil {
			return Bestaetigung{}, false, err
		}
		if !ok {
			continue
		}
		if err := pruefe(raw, key); err != nil {
			return Bestaetigung{}, false, err
		}
	}
	if treffer == nil {
		return Bestaetigung{}, false, nil
	}
	return *treffer, true, nil
}

func (p *Prozess) bahnen(z strom.Zuordnung, lage Lage) (strom.Bahnen, error) {
	schl, err := p.wrap(z.Wrap, lage)
	if err != nil {
		return strom.Bahnen{}, err
	}
	jetzt := p.jetzt()
	b := strom.Bahnen{
		Gruppe: map[protocol.ID]strom.Bahn{},
		Einzel: map[protocol.ID]strom.Bahn{},
	}
	for _, ziel := range z.Ziele {
		var bahn strom.Bahn
		switch ziel.Rolle {
		case protocol.RolleGruppe:
			bahn, err = p.bahn(z.Mandant, ziel.Ablage, ziel.Ablage, ziel.Rolle, schl, lage, jetzt)
			if err != nil {
				return strom.Bahnen{}, err
			}
			b.Gruppe[ziel.Ablage] = bahn
		case protocol.RolleEinzel:
			bahn, err = p.bahn(z.Mandant, ziel.Ablage, ziel.Bind, ziel.Rolle, schl, lage, jetzt)
			if err != nil {
				return strom.Bahnen{}, err
			}
			b.Einzel[ziel.Bind] = bahn
		case protocol.RolleAuffang:
			bahn, err = p.bahn(z.Mandant, lage.Auffang, lage.Auffang, ziel.Rolle, schl, lage, jetzt)
			if err != nil {
				return strom.Bahnen{}, err
			}
			b.Auffang = bahn
		default:
			return strom.Bahnen{}, strom.ErrBahn
		}
	}
	if brauchtVerzeichnis(z) {
		b.Verzeichnis, err = p.bahn(z.Mandant, lage.Verzeichnis, lage.Verzeichnis, protocol.RolleVerzeichnis, schl, lage, jetzt)
		if err != nil {
			return strom.Bahnen{}, err
		}
	}
	if brauchtIndex(z) {
		b.Vorgang, err = p.bahn(z.Mandant, lage.Vorgang, lage.Vorgang, protocol.RolleVorgang, p.index, lage, jetzt)
		if err != nil {
			return strom.Bahnen{}, err
		}
	}
	return b, nil
}

func (p *Prozess) wrap(w strom.Wrap, lage Lage) (Schluessel, error) {
	if w == strom.WrapPlattform {
		return p.plattform, nil
	}
	if !lage.KEKVorhanden || lage.KEK.Pub == nil {
		return Schluessel{}, ErrGeheimnis
	}
	return lage.KEK, nil
}

func (p *Prozess) zaehlen(z strom.Zuordnung, b strom.Bahnen, g strom.Geschrieben, w *warten) (int, error) {
	var bytes int
	for _, ziel := range z.Ziele {
		bahn, err := bahnDesZiels(b, ziel)
		if err != nil {
			return 0, err
		}
		logLauf := p.laufVonEpoche(bahn.Epoche)
		if logLauf == nil {
			return 0, strom.ErrBahn
		}
		klar, err := protocol.EreignisKlartext(ziel.Event, ziel.Zeit, bahn.Bind, ziel.Inhalt)
		if err != nil {
			return 0, err
		}
		n, err := rahmenZahl(len(klar), logLauf.rahmen)
		if err != nil {
			return 0, err
		}
		seq := logLauf.next
		logLauf.frames(ziel.Event, n)
		bytes += n * logLauf.rahmen
		stelle := strom.Stelle{Epoch: bahn.Epoche.Kennung(), Seq: seq}
		gezahlt := ziel
		if ziel.Rolle == protocol.RolleAuffang {
			gezahlt.Bind = bahn.Bind
			gezahlt.Ablage = bahn.Epoche.Ablage()
		}
		verweise, index, err := gezahlt.Nachweise(stelle, b.Verzeichnis.Bind, b.Vorgang.Bind)
		if err != nil {
			return 0, err
		}
		if len(verweise) > 0 {
			v := p.laufVonEpoche(b.Verzeichnis.Epoche)
			if v == nil {
				return 0, strom.ErrBahn
			}
			for _, klar := range verweise {
				n, err = rahmenZahl(len(klar), v.rahmen)
				if err != nil {
					return 0, err
				}
				v.frames(ziel.Event, n)
				bytes += n * v.rahmen
			}
		}
		if len(index) > 0 {
			ix := p.laufVonEpoche(b.Vorgang.Epoche)
			if ix == nil {
				return 0, strom.ErrBahn
			}
			for _, klar := range index {
				n, err = rahmenZahl(len(klar), ix.rahmen)
				if err != nil {
					return 0, err
				}
				ix.frames(ziel.Event, n)
				bytes += n * ix.rahmen
			}
		}
	}
	_ = w
	_ = g
	return bytes, nil
}

func (p *Prozess) pufferAbschluss() error {
	if len(p.puffer) == 0 {
		return nil
	}
	stuecke, err := p.sammeln()
	if err != nil {
		return err
	}
	if len(stuecke) == 0 {
		return protocol.ErrLength
	}
	werte := append([]*warten(nil), p.puffer...)
	if err := p.spulen(werte, stuecke); err != nil {
		return err
	}
	seq := p.queue[len(p.queue)-1].seq
	hash := p.queue[len(p.queue)-1].hash
	for _, st := range stuecke {
		if st.lauf == nil {
			continue
		}
		st.lauf.merken(seq, hash)
		st.lauf.eintraege = nil
		st.lauf.segmente = nil
	}
	return p.hochladen(false)
}

func (p *Prozess) sammeln() ([]stueck, error) {
	var out []stueck
	for _, l := range p.reihe {
		if l.ep == nil || l.rest != nil {
			continue
		}
		if err := p.schnittEiner(l); err != nil {
			return nil, err
		}
		if len(l.eintraege) == 0 && len(l.segmente) == 0 {
			continue
		}
		if len(l.segmente) == 0 {
			return nil, protocol.ErrLength
		}
		out = append(out, stueck{
			lauf:      l,
			mandant:   l.key.mandant,
			finger:    l.key.finger,
			pub:       l.pub,
			eintraege: append([]protocol.SeqEintrag(nil), l.eintraege...),
			segmente:  append([]epoch.Segment(nil), l.segmente...),
		})
	}
	return out, nil
}

func (p *Prozess) spulen(werte []*warten, stuecke []stueck) error {
	if len(stuecke) == 0 {
		return protocol.ErrLength
	}
	var batch protocol.ID
	if _, err := io.ReadFull(p.rand, batch[:]); err != nil {
		return err
	}
	if batch == (protocol.ID{}) {
		return protocol.ErrLength
	}
	type schluss struct {
		mandant protocol.ID
		finger  protocol.Hash
	}
	var reihe []schluss
	anteile := make(map[schluss]*abschluss.Anteil)
	var refs []protocol.SegmentRef
	var objekte []abschluss.Segmentobjekt
	for _, st := range stuecke {
		s := schluss{st.mandant, st.finger}
		ant, ok := anteile[s]
		if !ok {
			ant = &abschluss.Anteil{Mandant: st.mandant, KEK: st.finger, Pub: st.pub}
			anteile[s] = ant
			reihe = append(reihe, s)
		}
		ant.Eintraege = append(ant.Eintraege, st.eintraege...)
		for _, seg := range st.segmente {
			kopie := append([]byte(nil), seg.Bytes...)
			objekte = append(objekte, abschluss.Segmentobjekt{Schluessel: seg.Schluessel, Bytes: kopie})
			refs = append(refs, protocol.SegmentRef{ObjectKey: seg.Schluessel, Hash: protocol.SegmentHash(kopie)})
		}
	}
	gebautAnteile := make([]abschluss.Anteil, len(reihe))
	for i, s := range reihe {
		gebautAnteile[i] = *anteile[s]
	}
	var slots []protocol.Slot
	for _, w := range werte {
		slots = append(slots, protocol.Slot{Event: w.id, Hash: w.hash})
	}
	gebaut, err := abschluss.Bauen(abschluss.Auftrag{
		Batch:      batch,
		Instanz:    p.instanz,
		BatchSeq:   p.next,
		Previous:   p.letzter,
		Ereignisse: slots,
		Segmente:   refs,
		Anteile:    gebautAnteile,
		Rand:       p.rand,
	})
	if err != nil {
		return err
	}
	for i := range gebaut.Belegungen {
		ist, err := protocol.ParseBelegung(gebaut.Belegungen[i].Bytes)
		if err != nil {
			return err
		}
		gen := uint64(1)
		for _, w := range werte {
			if w.id == ist.Event && w.generation > 1 {
				gen = w.generation
			}
		}
		if gen == 1 {
			continue
		}
		raw, err := protocol.BelegungBytes(protocol.Belegung{
			Event: ist.Event, Instanz: p.instanz, Batch: batch, Generation: gen, Lage: protocol.LageOffen, Hash: ist.Hash,
		})
		if err != nil {
			return err
		}
		gebaut.Belegungen[i].Bytes = raw
	}
	ein := abschluss.Eintrag{
		Instanz:      p.instanz,
		BatchSeq:     p.next,
		Annahme:      gebaut.Annahme.Bytes,
		Vorbereitung: gebaut.Vorbereitung.Bytes,
		Segmente:     objekte,
	}
	for _, b := range gebaut.Belegungen {
		ein.Belegungen = append(ein.Belegungen, b.Bytes)
	}
	raw, err := abschluss.Encode(ein)
	if err != nil {
		return err
	}
	if p.belegt+len(raw) > p.schwellen.SpoolGrenze && p.belegt > 0 {
		if err := p.hochladen(true); err != nil {
			return err
		}
	}
	if p.belegt+len(raw) > p.schwellen.SpoolGrenze {
		return abschluss.ErrGrenze
	}
	seq := p.next
	datei := filepath.Join(p.spoolDir, strconv.FormatUint(seq, 10))
	if err := schreibeFest(datei, raw); err != nil {
		p.spoolFehler = true
		return err
	}
	if err := p.mem.Festhalten(ein); err != nil {
		os.Remove(datei)
		return err
	}
	p.belegt += len(raw)
	p.next = seq + 1
	p.letzter = gebaut.Hash
	_ = p.standSchreiben()
	g := &gespult{
		seq: seq, ein: ein, hash: gebaut.Hash, zeit: time.Now(), groesse: len(raw), werte: werte,
	}
	p.queue = append(p.queue, g)
	if werte != nil {
		p.pufferLeeren(werte)
	}
	return nil
}

func (p *Prozess) hochladen(zwang bool) error {
	if !zwang && !p.faellig() {
		return nil
	}
	for _, g := range p.queue {
		if g.gescheitert {
			return nil
		}
		if g.fertig {
			continue
		}
		if err := p.eine(g); err != nil {
			return err
		}
		if g.gescheitert {
			return nil
		}
	}
	return nil
}

func (p *Prozess) faellig() bool {
	var n int
	var aelteste time.Time
	for _, g := range p.queue {
		if g.fertig || g.gescheitert {
			continue
		}
		for _, seg := range g.ein.Segmente {
			n += len(seg.Bytes)
		}
		if aelteste.IsZero() || g.zeit.Before(aelteste) {
			aelteste = g.zeit
		}
	}
	if n == 0 {
		return false
	}
	if n >= p.schwellen.Segment {
		return true
	}
	return !aelteste.IsZero() && time.Since(aelteste) >= p.schwellen.SegmentWarte
}

func (p *Prozess) eine(g *gespult) error {
	for _, raw := range g.ein.Belegungen {
		if err := anheben(p.ziel, raw); err != nil {
			if errors.Is(err, abschluss.ErrBelegung) || errors.Is(err, abschluss.ErrObjekt) {
				return p.verwerfen(g, err)
			}
			p.zielFehl(err)
			return err
		}
	}
	anfang := time.Now()
	befund, err := p.mem.Fortsetzen(p.ziel, p.instanz, g.seq)
	p.segment.beobachten(time.Since(anfang).Seconds())
	if err != nil {
		if errors.Is(err, abschluss.ErrObjekt) || errors.Is(err, abschluss.ErrBelegung) || errors.Is(err, abschluss.ErrSegment) {
			return p.verwerfen(g, err)
		}
		p.zielFehl(err)
		return err
	}
	switch befund {
	case abschluss.BefundAngenommen:
		return p.abgeschlossen(g)
	case abschluss.BefundKonflikt, abschluss.BefundVerfallen, abschluss.BefundBeschaedigt:
		return p.verwerfen(g, ErrBelegung)
	default:
		return ErrBelegung
	}
}

func (p *Prozess) abgeschlossen(g *gespult) error {
	if err := p.manifestEinreichen(g); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(p.spoolDir, strconv.FormatUint(g.seq, 10)))
	p.belegt -= g.groesse
	if p.belegt < 0 {
		p.belegt = 0
	}
	if g.abdeckenFirst > 0 {
		_ = p.mem.Abdecken(p.instanz, g.abdeckenFirst, g.abdeckenLast)
	}
	_ = p.standSchreiben()
	key, err := protocol.AnnahmeSchluessel(p.instanz, g.seq)
	if err != nil {
		return err
	}
	best := Bestaetigung{Seq: g.seq, Hash: g.hash, Schluessel: key}
	g.fertig = true
	for _, w := range g.werte {
		if w == nil {
			continue
		}
		w.fertig = true
		w.best = best
		p.annahmeZaehlen(w)
		p.katalogSichern(w)
		for _, ch := range w.chs {
			ch <- ergebnis{best: best}
		}
		w.chs = nil
	}
	return nil
}

func (p *Prozess) annahmeZaehlen(w *warten) {
	if w == nil || w.seit.IsZero() {
		return
	}
	p.accept.beobachten(time.Since(w.seit).Seconds())
	if w.zaehlen {
		for _, rolle := range w.rollen {
			if schluessel := zaehlerSchluessel(w.mandant, rolle); schluessel != "" {
				p.angenommen[schluessel]++
			}
		}
	}
	if w.kek && w.kekMandant != (protocol.ID{}) {
		p.kekFehlt[w.kekMandant.Hex()]++
	}
}

func (p *Prozess) scheitern(j job, err error) {
	switch {
	case errors.Is(err, ErrBelegung), errors.Is(err, abschluss.ErrBelegung):
		p.unaccepted["belegung"]++
	case errors.Is(err, abschluss.ErrGrenze):
		p.unaccepted["spool"]++
	case j.ev.Mandant == (protocol.ID{}) && !errors.Is(err, ErrBeenden) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded):
		p.unaccepted["mandant_unbekannt"]++
	}
	j.ch <- ergebnis{err: err}
}

func (p *Prozess) verwerfen(g *gespult, err error) error {
	g.gescheitert = true
	for _, w := range g.werte {
		if w == nil {
			continue
		}
		w.fertig = true
		w.err = err
		delete(p.nachID, w.id)
		p.katalogVergessen(w)
		if errors.Is(err, ErrBelegung) || errors.Is(err, abschluss.ErrBelegung) {
			p.unaccepted["belegung"]++
		}
		for _, ch := range w.chs {
			ch <- ergebnis{err: err}
		}
		w.chs = nil
	}
	return nil
}

func (p *Prozess) stilllegen() error {
	p.halt = true
	var fehler error
	if err := p.pufferAbschluss(); err != nil {
		fehler = err
	}
	if err := p.hochladen(true); err != nil && fehler == nil {
		fehler = err
	}
	if err := p.deckFuellen(true); err != nil && fehler == nil {
		fehler = err
	}
	for _, l := range p.reihe {
		if l.ep == nil {
			continue
		}
		if l.rest == nil && (l.geschrieben || len(l.eintraege) > 0 || len(l.segmente) > 0 || l.annahmeFirst == 0) {
			continue
		}
		if err := p.manifest(l); err != nil && fehler == nil {
			fehler = err
		}
	}
	if err := p.hochladen(true); err != nil && fehler == nil {
		fehler = err
	}
	if fehler != nil {
		p.abbrechen(fehler)
	}
	return fehler
}

func (p *Prozess) abbrechen(err error) {
	gesehen := make(map[*warten]bool)
	liste := append([]*warten{}, p.puffer...)
	for _, g := range p.queue {
		if g.fertig {
			continue
		}
		liste = append(liste, g.werte...)
	}
	for _, w := range liste {
		if w == nil || gesehen[w] || w.fertig {
			continue
		}
		gesehen[w] = true
		w.fertig = true
		w.err = err
		for _, ch := range w.chs {
			ch <- ergebnis{err: err}
		}
		w.chs = nil
	}
}

type mitZielArt interface {
	ZielArt() string
}

// zielFehl zählt den Fehler unter der Art des Speichers, der ihn gemeldet hat.
// Ein Mandantenziel trägt seine eigene Art. Sonst gilt das gemeinsame Ziel.
func (p *Prozess) zielFehl(err error) {
	art := p.zielArt
	var mit mitZielArt
	if errors.As(err, &mit) {
		if a := mit.ZielArt(); a == "s3" || a == "platte" {
			art = a
		}
	}
	p.zielFehler[art]++
}

func (p *Prozess) fristSetzen() error {
	jetzt := p.jetzt()
	if !p.naechsteFrist.IsZero() && jetzt.Before(p.naechsteFrist) {
		return nil
	}
	ms := jetzt.Add(p.schwellen.Frist).UnixMilli()
	if ms < 0 {
		return protocol.ErrLength
	}
	if err := abschluss.FristSetzen(p.ziel, p.instanz, uint64(ms)); err != nil {
		p.zielFehl(err)
		return err
	}
	p.fristEnde = jetzt.Add(p.schwellen.Frist)
	halb := p.schwellen.Frist / 2
	if halb <= 0 {
		halb = p.schwellen.Frist
	}
	p.naechsteFrist = jetzt.Add(halb)
	return nil
}

func (p *Prozess) lageVon(mandant protocol.ID) (Lage, error) {
	if mandant == (protocol.ID{}) {
		mandant = protocol.PlattformMandant()
	}
	lage, err := p.bestand.Mandant(mandant)
	if err != nil {
		return Lage{}, err
	}
	p.deck[mandant] = lage.Deck
	if !lage.CacheSeit.IsZero() {
		p.cacheSeit[mandant] = lage.CacheSeit
	}
	return lage, nil
}

func (p *Prozess) toteEpochen() {
	for _, l := range p.reihe {
		if l.ep != nil && !l.ep.Offen() {
			p.entfernen(l)
		}
	}
}

func (p *Prozess) pufferScheitern(err error) {
	for _, w := range p.puffer {
		if w == nil || w.fertig {
			continue
		}
		w.fertig = true
		w.err = err
		delete(p.nachID, w.id)
		for _, ch := range w.chs {
			ch <- ergebnis{err: err}
		}
		w.chs = nil
	}
	p.puffer = nil
	p.pufferBytes = 0
	p.pufferSeit = time.Time{}
}

func (p *Prozess) pufferLeeren(weg []*warten) {
	wegSet := make(map[*warten]bool, len(weg))
	for _, w := range weg {
		wegSet[w] = true
	}
	var rest []*warten
	var n int
	for _, w := range p.puffer {
		if wegSet[w] {
			continue
		}
		rest = append(rest, w)
		n += w.bytes
	}
	p.puffer = rest
	p.pufferBytes = n
	if len(rest) == 0 {
		p.pufferSeit = time.Time{}
	}
}

func (p *Prozess) naechstes() time.Duration {
	d := p.schwellen.PufferWarte
	if len(p.puffer) > 0 {
		rest := p.schwellen.PufferWarte - time.Since(p.pufferSeit)
		if rest < time.Millisecond {
			rest = time.Millisecond
		}
		if rest < d {
			d = rest
		}
	}
	if p.loeschzeit > 0 && !p.naechsteLoesch.IsZero() {
		rest := p.naechsteLoesch.Sub(p.jetzt())
		if rest < time.Millisecond {
			rest = time.Millisecond
		}
		if rest < d {
			d = rest
		}
	}
	return d
}

func (p *Prozess) laden() error {
	eintraege, err := os.ReadDir(p.spoolDir)
	if err != nil {
		return err
	}
	if next, hash, ok, err := p.standLesen(); err != nil {
		return err
	} else if ok {
		p.next = next
		p.letzter = hash
	}
	var dateien []spoolDatei
	var summe int
	for _, eintrag := range eintraege {
		seq, ok := seqName(eintrag.Name())
		if !ok {
			continue
		}
		roh, err := os.ReadFile(filepath.Join(p.spoolDir, eintrag.Name()))
		if err != nil {
			return err
		}
		info, err := eintrag.Info()
		if err != nil {
			return err
		}
		dateien = append(dateien, spoolDatei{seq: seq, roh: roh, mod: info.ModTime()})
		summe += len(roh)
	}
	grenze := p.schwellen.SpoolGrenze
	if summe > grenze {
		grenze = summe
	}
	sp, err := abschluss.NeuSpool(grenze)
	if err != nil {
		return err
	}
	p.mem = sp
	sortDateien(dateien)
	for _, d := range dateien {
		ein, err := abschluss.Decode(d.roh)
		if err != nil {
			return err
		}
		if ein.Instanz != p.instanz {
			return protocol.ErrLength
		}
		if err := p.mem.Festhalten(ein); err != nil {
			return err
		}
		summeHash, err := protocol.AnnahmeHash(ein.Annahme)
		if err != nil {
			return err
		}
		g := &gespult{seq: d.seq, ein: ein, hash: summeHash, zeit: d.mod, groesse: len(d.roh)}
		for _, raw := range ein.Belegungen {
			beleg, err := protocol.ParseBelegung(raw)
			if err != nil {
				return err
			}
			w := &warten{id: beleg.Event, hash: beleg.Hash, generation: beleg.Generation}
			p.nachID[beleg.Event] = w
			g.werte = append(g.werte, w)
		}
		p.queue = append(p.queue, g)
		p.belegt += len(d.roh)
		if d.seq >= p.next {
			p.next = d.seq + 1
			p.letzter = summeHash
		}
	}
	return nil
}

func (p *Prozess) standLesen() (uint64, protocol.Hash, bool, error) {
	roh, err := os.ReadFile(filepath.Join(p.spoolDir, "stand"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, protocol.Hash{}, false, nil
	}
	if err != nil {
		return 0, protocol.Hash{}, false, err
	}
	prefix := protocol.Domain("stand")
	if !bytes.HasPrefix(roh, prefix) || len(roh) != len(prefix)+protocol.IDLen+8+protocol.HashLen {
		return 0, protocol.Hash{}, false, protocol.ErrLength
	}
	off := len(prefix)
	var instanz protocol.ID
	copy(instanz[:], roh[off:off+protocol.IDLen])
	if instanz != p.instanz {
		return 0, protocol.Hash{}, false, protocol.ErrLength
	}
	off += protocol.IDLen
	next := protocolU64(roh[off : off+8])
	off += 8
	var hash protocol.Hash
	copy(hash[:], roh[off:off+protocol.HashLen])
	if next == 0 {
		return 0, protocol.Hash{}, false, protocol.ErrSeq
	}
	return next, hash, true, nil
}

func (p *Prozess) standSchreiben() error {
	buf := protocol.AppendText(nil, "stand")
	buf = append(buf, p.instanz[:]...)
	buf = protocol.AppendU64(buf, p.next)
	buf = append(buf, p.letzter[:]...)
	return schreibeFest(filepath.Join(p.spoolDir, "stand"), buf)
}

func protocolU64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

type spoolDatei struct {
	seq uint64
	roh []byte
	mod time.Time
}

func sortDateien(in []spoolDatei) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].seq < in[j-1].seq; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func seqName(name string) (uint64, bool) {
	if name == "" || name[0] < '1' || name[0] > '9' {
		return 0, false
	}
	n, err := strconv.ParseUint(name, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != name {
		return 0, false
	}
	return n, true
}

func anheben(z abschluss.Ziel, raw []byte) error {
	neu, err := protocol.ParseBelegung(raw)
	if err != nil {
		return err
	}
	liegen, ok, err := z.Lesen(protocol.BelegungSchluessel(neu.Event))
	if err != nil || !ok {
		return err
	}
	if bytes.Equal(liegen, raw) {
		return nil
	}
	ist, err := protocol.ParseBelegung(liegen)
	if err != nil {
		return err
	}
	if ist.Lage == protocol.LageAngenommen && ist.Event == neu.Event && ist.Instanz == neu.Instanz && ist.Batch == neu.Batch && ist.Generation == neu.Generation && ist.Hash == neu.Hash {
		return nil
	}
	alt, err := protocol.ParseBelegung(liegen)
	if err != nil {
		return err
	}
	folgt, err := alt.Nachfolger(neu.Instanz, neu.Batch)
	if err != nil {
		return err
	}
	folgtRaw, err := protocol.BelegungBytes(folgt)
	if err != nil {
		return err
	}
	if !bytes.Equal(folgtRaw, raw) {
		return abschluss.ErrBelegung
	}
	return z.Ersetzen(protocol.BelegungSchluessel(neu.Event), liegen, raw)
}

func bahnDesZiels(b strom.Bahnen, z strom.Ziel) (strom.Bahn, error) {
	switch z.Rolle {
	case protocol.RolleGruppe:
		bahn, ok := b.Gruppe[z.Ablage]
		if !ok {
			return strom.Bahn{}, strom.ErrBahn
		}
		return bahn, nil
	case protocol.RolleEinzel:
		bahn, ok := b.Einzel[z.Bind]
		if !ok {
			return strom.Bahn{}, strom.ErrBahn
		}
		return bahn, nil
	case protocol.RolleAuffang:
		if b.Auffang.Epoche == nil {
			return strom.Bahn{}, strom.ErrBahn
		}
		return b.Auffang, nil
	default:
		return strom.Bahn{}, strom.ErrBahn
	}
}

func brauchtVerzeichnis(z strom.Zuordnung) bool {
	for _, ziel := range z.Ziele {
		if len(ziel.Personen) > 0 || ziel.Vorgang != "" {
			return true
		}
	}
	return false
}

func brauchtIndex(z strom.Zuordnung) bool {
	for _, ziel := range z.Ziele {
		if ziel.Vorgang != "" && len(ziel.Personen) > 0 {
			return true
		}
	}
	return false
}

func rahmenZahl(n, rahmen int) (int, error) {
	nutz, err := protocol.RahmenNutz(rahmen)
	if err != nil || n <= 0 || nutz <= protocol.EreignisKopf {
		return 0, protocol.ErrLength
	}
	erste := nutz - protocol.EreignisKopf
	if n <= erste {
		return 1, nil
	}
	rest := n - erste
	folge := nutz - 1
	return 1 + (rest+folge-1)/folge, nil
}

func rasterBeginn(t time.Time, d time.Duration) time.Time {
	t = t.UTC()
	tag := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	versatz := t.Sub(tag)
	return tag.Add(versatz - versatz%d)
}

func zuruecksetzen(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
