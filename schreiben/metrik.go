package schreiben

import (
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"cryptlog/protocol"
)

var acceptGrenzen = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogramm struct {
	grenzen []float64
	zahl    []uint64
	summe   float64
	anzahl  uint64
}

func neueHistogramm() histogramm {
	return histogramm{grenzen: acceptGrenzen, zahl: make([]uint64, len(acceptGrenzen))}
}

func (h *histogramm) beobachten(sec float64) {
	h.summe += sec
	h.anzahl++
	for i, grenze := range h.grenzen {
		if sec <= grenze {
			h.zahl[i]++
		}
	}
}

func (h histogramm) kopie() histogramm {
	return histogramm{
		grenzen: h.grenzen,
		zahl:    append([]uint64(nil), h.zahl...),
		summe:   h.summe,
		anzahl:  h.anzahl,
	}
}

// reihe ist der Stand, den der Metrikport liest.
// Die Schleife schreibt sie. Der Port liest sie.
type reihe struct {
	halt       bool
	grund      string
	unaccepted map[string]uint64
	kek        map[string]uint64
	zielFehler map[string]uint64
	spool      int
	grenze     int
	cache      map[string]float64
	lease      float64
	accept     histogramm
	segment    histogramm
	angenommen map[string]uint64
	offen      map[string]uint64
	version    string
	digest     string
	ziel       string
	start      float64
}

// Metrik ist der Metrikport.
// Er nimmt kein Ereignis an.
func (p *Prozess) Metrik() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/live":
			if p.live() {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "beenden")
		case "/ready":
			ok, grund := p.ready()
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

func (p *Prozess) live() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.bild.halt
}

func (p *Prozess) ready() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bild.grund == "" {
		return true, ""
	}
	return false, p.bild.grund
}

func (p *Prozess) metrikText() string {
	p.mu.Lock()
	bild := p.bild
	bild.unaccepted = kopieZaehler(bild.unaccepted)
	bild.kek = kopieZaehler(bild.kek)
	bild.zielFehler = kopieZaehler(bild.zielFehler)
	bild.cache = kopieAlter(bild.cache)
	bild.angenommen = kopieZaehler(bild.angenommen)
	bild.offen = kopieZaehler(bild.offen)
	bild.accept = bild.accept.kopie()
	bild.segment = bild.segment.kopie()
	p.mu.Unlock()

	var b strings.Builder
	b.WriteString("# TYPE cryptlog_ready gauge\n")
	if bild.grund == "" {
		b.WriteString("cryptlog_ready 1\n")
	} else {
		b.WriteString("cryptlog_ready 0\n")
	}
	b.WriteString("# TYPE cryptlog_events_unaccepted_total counter\n")
	for _, grund := range []string{"belegung", "mandant_unbekannt", "spool"} {
		b.WriteString("cryptlog_events_unaccepted_total{grund=\"" + grund + "\"} " + zahl(bild.unaccepted[grund]) + "\n")
	}
	b.WriteString("# TYPE cryptlog_kek_fehlt_total counter\n")
	for _, id := range sortiert(bild.kek) {
		b.WriteString("cryptlog_kek_fehlt_total{mandant_id=\"" + id + "\"} " + zahl(bild.kek[id]) + "\n")
	}
	b.WriteString("# TYPE cryptlog_target_errors_total counter\n")
	for _, ziel := range []string{"platte", "s3"} {
		b.WriteString("cryptlog_target_errors_total{ziel=\"" + ziel + "\"} " + zahl(bild.zielFehler[ziel]) + "\n")
	}
	b.WriteString("# TYPE cryptlog_spool_bytes gauge\n")
	b.WriteString("cryptlog_spool_bytes " + strconv.Itoa(bild.spool) + "\n")
	b.WriteString("# TYPE cryptlog_spool_limit_bytes gauge\n")
	b.WriteString("cryptlog_spool_limit_bytes " + strconv.Itoa(bild.grenze) + "\n")
	b.WriteString("# TYPE cryptlog_cache_age_seconds gauge\n")
	for _, id := range sortiertAlter(bild.cache) {
		b.WriteString("cryptlog_cache_age_seconds{mandant_id=\"" + id + "\"} " + flie(bild.cache[id]) + "\n")
	}
	b.WriteString("# TYPE cryptlog_instance_lease_seconds gauge\n")
	b.WriteString("cryptlog_instance_lease_seconds " + flie(bild.lease) + "\n")
	schreibeHistogramm(&b, "cryptlog_accept_seconds", "ziel", bild.ziel, bild.accept)
	schreibeHistogramm(&b, "cryptlog_segment_seconds", "ziel", bild.ziel, bild.segment)
	b.WriteString("# TYPE cryptlog_events_accepted_total counter\n")
	for _, schluessel := range sortiert(bild.angenommen) {
		mandant, rolle, ok := teilen(schluessel)
		if !ok {
			continue
		}
		b.WriteString("cryptlog_events_accepted_total{mandant_id=\"" + mandant + "\",rolle=\"" + rolle + "\"} " + zahl(bild.angenommen[schluessel]) + "\n")
	}
	b.WriteString("# TYPE cryptlog_epochs_open gauge\n")
	for _, schluessel := range sortiert(bild.offen) {
		mandant, rolle, ok := teilen(schluessel)
		if !ok {
			continue
		}
		b.WriteString("cryptlog_epochs_open{mandant_id=\"" + mandant + "\",rolle=\"" + rolle + "\"} " + zahl(bild.offen[schluessel]) + "\n")
	}
	if bild.version != "" && bild.digest != "" {
		b.WriteString("# TYPE cryptlog_build_info gauge\n")
		b.WriteString("cryptlog_build_info{version=\"" + prometheus(bild.version) + "\",digest=\"" + prometheus(bild.digest) + "\"} 1\n")
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	b.WriteString("# TYPE go_goroutines gauge\n")
	b.WriteString("go_goroutines " + strconv.Itoa(runtime.NumGoroutine()) + "\n")
	b.WriteString("# TYPE go_memstats_alloc_bytes gauge\n")
	b.WriteString("go_memstats_alloc_bytes " + strconv.FormatUint(mem.Alloc, 10) + "\n")
	b.WriteString("# TYPE process_start_time_seconds gauge\n")
	b.WriteString("process_start_time_seconds " + flie(bild.start) + "\n")
	return b.String()
}

func schreibeHistogramm(b *strings.Builder, name, label, wert string, h histogramm) {
	b.WriteString("# TYPE " + name + " histogram\n")
	feld := label + "=\"" + wert + "\""
	for i, grenze := range h.grenzen {
		b.WriteString(name + "_bucket{" + feld + ",le=\"" + strconv.FormatFloat(grenze, 'f', -1, 64) + "\"} " + zahl(h.zahl[i]) + "\n")
	}
	b.WriteString(name + "_bucket{" + feld + ",le=\"+Inf\"} " + zahl(h.anzahl) + "\n")
	b.WriteString(name + "_sum{" + feld + "} " + flie(h.summe) + "\n")
	b.WriteString(name + "_count{" + feld + "} " + zahl(h.anzahl) + "\n")
}

func (p *Prozess) merken() {
	bild := reihe{
		unaccepted: kopieZaehler(p.unaccepted),
		kek:        kopieZaehler(p.kekFehlt),
		zielFehler: kopieZaehler(p.zielFehler),
		spool:      p.belegt,
		grenze:     p.schwellen.SpoolGrenze,
		cache:      map[string]float64{},
		accept:     p.accept.kopie(),
		segment:    p.segment.kopie(),
		angenommen: kopieZaehler(p.angenommen),
		offen:      map[string]uint64{},
		version:    p.version,
		digest:     p.digest,
		ziel:       p.zielArt,
		start:      float64(p.start.Unix()),
		halt:       p.halt,
	}
	jetzt := p.jetzt()
	switch {
	case p.halt:
		bild.grund = "beenden"
	case p.plattform.Pub == nil:
		bild.grund = "secret"
	case p.spoolFehler || p.belegt >= p.schwellen.SpoolGrenze || !verzeichnisBeschreibbar(p.spoolDir):
		bild.grund = "spool"
	}
	if !p.fristEnde.IsZero() {
		rest := p.fristEnde.Sub(jetzt).Seconds()
		if rest < 0 {
			rest = 0
		}
		bild.lease = rest
	}
	for id, seit := range p.cacheSeit {
		if seit.IsZero() {
			continue
		}
		alter := jetzt.Sub(seit).Seconds()
		if alter < 0 {
			alter = 0
		}
		bild.cache[id.Hex()] = alter
	}
	for _, l := range p.reihe {
		if l == nil || l.ep == nil || !l.ep.Offen() || p.deck[l.key.mandant] {
			continue
		}
		name := rollenName(l.rolle)
		if name == "" {
			continue
		}
		bild.offen[l.key.mandant.Hex()+"/"+name]++
	}
	p.mu.Lock()
	p.bild = bild
	p.mu.Unlock()
}

func verzeichnisBeschreibbar(pfad string) bool {
	f, err := os.OpenFile(pfad, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	info, err := f.Stat()
	f.Close()
	return err == nil && info.IsDir()
}

func rollenName(r protocol.StromRolle) string {
	switch r {
	case protocol.RolleGruppe:
		return "gruppe"
	case protocol.RolleEinzel:
		return "einzel"
	case protocol.RolleAuffang:
		return "auffang"
	case protocol.RolleVerzeichnis:
		return "verzeichnis"
	case protocol.RolleVorgang:
		return "vorgang"
	case protocol.RolleKatalog:
		return "katalog"
	default:
		return ""
	}
}

func zaehlerSchluessel(mandant protocol.ID, rolle protocol.StromRolle) string {
	name := rollenName(rolle)
	if name == "" {
		return ""
	}
	return mandant.Hex() + "/" + name
}

func teilen(s string) (string, string, bool) {
	mandant, rolle, ok := strings.Cut(s, "/")
	if !ok || mandant == "" || rolle == "" || strings.Contains(rolle, "/") {
		return "", "", false
	}
	return mandant, rolle, true
}

func kopieZaehler(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func kopieAlter(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortiert(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	stringsSort(out)
	return out
}

func sortiertAlter(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	stringsSort(out)
	return out
}

func stringsSort(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

func zahl(n uint64) string { return strconv.FormatUint(n, 10) }

func flie(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func prometheus(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
