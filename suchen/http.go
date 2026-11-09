package suchen

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Suche ist die Suchschnittstelle. Sie nimmt keine Metrik und keine Verwaltung an.
func (p *Prozess) Suche() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/suche" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxAnfrage+1))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		treffer, err := p.Anfrage(body)
		if err != nil {
			sucheFehler(w, err)
			return
		}
		anfrage, _, err := teilen(body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		roh, err := TrefferBytes(anfrage.Art, treffer)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(roh)
	})
}

func sucheFehler(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFormat):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Is(err, ErrAnfrage), errors.Is(err, ErrWiederholt):
		w.WriteHeader(http.StatusForbidden)
	case errors.Is(err, ErrBeenden):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("beenden"))
	case errors.Is(err, ErrGeheimnis):
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("secret"))
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// Metrik ist der Metrikport. Er nimmt keine Suchanfrage an und gibt das Protokoll nicht heraus.
func (p *Prozess) Metrik() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/live":
			if p.Live() {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("beenden"))
		case "/ready":
			ok, grund := p.Ready()
			if ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, grund)
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = io.WriteString(w, p.metrikText())
		default:
			http.NotFound(w, r)
		}
	})
}

func (p *Prozess) metrikText() string {
	bereit, _ := p.Ready()
	p.mu.Lock()
	abgelehnt := p.abgelehnt
	autorisiert := p.autorisiert
	wiederholt := p.wiederholt
	hist := histogramm{
		grenzen: p.hist.grenzen,
		zahl:    append([]uint64(nil), p.hist.zahl...),
		summe:   p.hist.summe,
		anzahl:  p.hist.anzahl,
	}
	version, digest := p.version, p.digest
	p.mu.Unlock()

	var b strings.Builder
	b.WriteString("# TYPE cryptlog_ready gauge\n")
	if bereit {
		b.WriteString("cryptlog_ready 1\n")
	} else {
		b.WriteString("cryptlog_ready 0\n")
	}
	b.WriteString("# TYPE cryptlog_search_requests_total counter\n")
	b.WriteString("cryptlog_search_requests_total{ergebnis=\"abgelehnt\"} " + strconv.FormatUint(abgelehnt, 10) + "\n")
	b.WriteString("cryptlog_search_requests_total{ergebnis=\"autorisiert\"} " + strconv.FormatUint(autorisiert, 10) + "\n")
	b.WriteString("cryptlog_search_requests_total{ergebnis=\"wiederholt\"} " + strconv.FormatUint(wiederholt, 10) + "\n")
	b.WriteString("# TYPE cryptlog_search_seconds histogram\n")
	for i, grenze := range hist.grenzen {
		b.WriteString("cryptlog_search_seconds_bucket{le=\"" + strconv.FormatFloat(grenze, 'f', -1, 64) + "\"} " + strconv.FormatUint(hist.zahl[i], 10) + "\n")
	}
	b.WriteString("cryptlog_search_seconds_bucket{le=\"+Inf\"} " + strconv.FormatUint(hist.anzahl, 10) + "\n")
	b.WriteString("cryptlog_search_seconds_sum " + strconv.FormatFloat(hist.summe, 'f', -1, 64) + "\n")
	b.WriteString("cryptlog_search_seconds_count " + strconv.FormatUint(hist.anzahl, 10) + "\n")
	if version != "" && digest != "" {
		b.WriteString("# TYPE cryptlog_build_info gauge\n")
		b.WriteString("cryptlog_build_info{version=\"" + version + "\",digest=\"" + digest + "\"} 1\n")
	}
	return b.String()
}
