package schreiben

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"cryptlog/abschluss"
	"cryptlog/protocol"
	"cryptlog/strom"
)

const maxEreignis = 8<<20 + 1024

// Ereignisport ist die Ereignisschnittstelle.
// Er nimmt keine Metrik und keine Bereitschaft an.
func (p *Prozess) Ereignisport() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ereignis" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxEreignis+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body) > maxEreignis {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		aufruf, err := protocol.ParseEreignis(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		best, err := p.Ereignis(ctx, strom.Ereignis{
			ID: aufruf.ID, Zeit: aufruf.Zeit, Mandant: aufruf.Mandant, Angabe: aufruf.Angabe,
			Personen: aufruf.Personen, Vorgang: aufruf.Vorgang, Text: aufruf.Text,
		})
		if err != nil {
			ereignisFehler(w, err)
			return
		}
		roh, err := protocol.BestaetigtBytes(protocol.Bestaetigt{
			Event: aufruf.ID, Hash: best.Hash, Seq: best.Seq, Schluessel: best.Schluessel,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(roh)
	})
}

func ereignisFehler(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBelegung):
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, "belegung")
	case errors.Is(err, ErrGehalten), errors.Is(err, ErrOffen):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "gehalten")
	case errors.Is(err, abschluss.ErrGrenze):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "spool")
	case errors.Is(err, ErrBeenden):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "beenden")
	case errors.Is(err, ErrGeheimnis), errors.Is(err, ErrIndex), errors.Is(err, ErrSchluessel):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "secret")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}
