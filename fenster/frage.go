package fenster

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"time"

	"cryptlog/crypt"
	"cryptlog/protocol"
	"cryptlog/suchen"
	"cryptlog/werkzeug"
)

// Frage signiert diese eine Anfrage mit dem Aufrufschlüssel und zeigt die Treffer.
// Den Index öffnet das Fenster nicht. Eine Passphrase geht nicht mit.
func (f *Fenster) Frage(art protocol.AnfrageArt, schluessel string, von, bis time.Time) (suchen.Treffer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.aufruf == nil && f.aufrufT == nil {
		return suchen.Treffer{}, ErrAufruf
	}
	if f.person == "" || f.suche == "" {
		return suchen.Treffer{}, ErrAufruf
	}
	ziel, err := url.Parse(f.suche)
	if err != nil || (ziel.Scheme != "https" && ziel.Scheme != "http") || ziel.Host == "" {
		return suchen.Treffer{}, ErrAufruf
	}
	von, bis = von.UTC(), bis.UTC()
	if !bis.After(von) {
		return suchen.Treffer{}, werkzeug.ErrZeitraum
	}
	anfrage := protocol.Indexanfrage{
		Mandant: f.verb.Mandant, Zone: f.verb.Zone, Person: f.person, Art: art, Schluessel: schluessel,
		Von: uint64(von.UnixMilli()), Bis: uint64(bis.UnixMilli()),
		Zeitpunkt: uint64(f.jetzt().UnixMilli()),
	}
	raw, err := protocol.IndexanfrageBytes(anfrage)
	if err != nil {
		return suchen.Treffer{}, err
	}
	var sig protocol.Signature
	if f.aufruf != nil {
		sig, err = crypt.SignP256(f.aufruf, raw)
	} else {
		sig, err = f.aufrufT.Signieren(raw)
	}
	if err != nil {
		return suchen.Treffer{}, err
	}
	body := append(raw, sig[:]...)
	defer crypt.Wipe(body)
	client := f.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	req, err := http.NewRequest(http.MethodPost, f.suche, bytes.NewReader(body))
	if err != nil {
		return suchen.Treffer{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return suchen.Treffer{}, err
	}
	defer resp.Body.Close()
	antwort, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(antwort) > 1<<20 {
		return suchen.Treffer{}, ErrAufruf
	}
	gotArt, treffer, err := suchen.ParseTreffer(antwort)
	if err != nil || gotArt != art {
		return suchen.Treffer{}, ErrAufruf
	}
	return treffer, nil
}
