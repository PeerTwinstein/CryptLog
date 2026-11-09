package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"cryptlog/protocol"
	"cryptlog/schreiben"
)

func TestGrenzen(t *testing.T) {
	text := datei(t, filepath.Join("cryptlog", "templates", "_grenzen.tpl"))
	werte := datei(t, filepath.Join("cryptlog", "values.yaml"))
	zahl := func(name string) int {
		m := regexp.MustCompile(`\$` + name + ` := (\d+)`).FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("%s fehlt", name)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	pufferMin, pufferMax := zahl("pufferMin"), zahl("pufferMax")
	warteMin, warteMax := zahl("warteMin"), zahl("warteMax")
	segmentMin, segmentMax := zahl("segmentMin"), zahl("segmentMax")
	segmentWarteMin, segmentWarteMax := zahl("segmentWarteMin"), zahl("segmentWarteMax")
	epocheMin, epocheMax := zahl("epocheMin"), zahl("epocheMax")
	if zahl("beendenZusatz") != 30 || zahl("tag") != 86400 {
		t.Fatal("zusatz")
	}
	vor := schreiben.Voreinstellung()
	if vor.Puffer != 1<<20 || vor.PufferWarte != 100*time.Millisecond || vor.Segment != 4<<20 || vor.SegmentWarte != time.Minute {
		t.Fatalf("vorgabe %+v", vor)
	}
	if vor.Gruppe != time.Hour || vor.Einzel != 8*time.Hour || vor.Sonstige != time.Hour || vor.Klasse != protocol.Segment4MiB {
		t.Fatalf("epoche %+v", vor)
	}
	gueltig := func(s schreiben.Schwellen) {
		t.Helper()
		if err := s.Pruefen(); err != nil {
			t.Fatal(err)
		}
	}
	ungueltig := func(s schreiben.Schwellen) {
		t.Helper()
		if err := s.Pruefen(); err == nil {
			t.Fatal("angenommen")
		}
	}
	basis := vor
	basis.SpoolGrenze = basis.Klasse
	basis.Frist = basis.SegmentWarte + time.Second
	gueltig(basis)

	unten := basis
	unten.Puffer = pufferMin
	unten.PufferWarte = time.Duration(warteMin) * time.Millisecond
	unten.Segment = segmentMin
	unten.SegmentWarte = time.Duration(segmentWarteMin) * time.Second
	unten.Klasse = protocol.Segment256KiB
	unten.SpoolGrenze = unten.Klasse
	unten.Frist = unten.SegmentWarte + time.Second
	unten.Gruppe = time.Duration(epocheMin) * time.Second
	unten.Einzel = time.Duration(epocheMax) * time.Second
	unten.Sonstige = time.Duration(epocheMin) * time.Second
	gueltig(unten)
	oben := unten
	oben.Puffer = pufferMax
	oben.PufferWarte = time.Duration(warteMax) * time.Millisecond
	oben.Segment = segmentMax
	oben.SegmentWarte = time.Duration(segmentWarteMax) * time.Second
	oben.Klasse = protocol.Segment32MiB
	oben.SpoolGrenze = oben.Klasse
	oben.Frist = oben.SegmentWarte + time.Second
	gueltig(oben)

	for _, knick := range []schreiben.Schwellen{
		aendern(unten, func(s *schreiben.Schwellen) { s.Puffer-- }),
		aendern(oben, func(s *schreiben.Schwellen) { s.Puffer++ }),
		aendern(unten, func(s *schreiben.Schwellen) { s.PufferWarte -= time.Millisecond }),
		aendern(oben, func(s *schreiben.Schwellen) { s.PufferWarte += time.Millisecond }),
		aendern(unten, func(s *schreiben.Schwellen) { s.Segment-- }),
		aendern(oben, func(s *schreiben.Schwellen) { s.Segment++ }),
		aendern(unten, func(s *schreiben.Schwellen) { s.SegmentWarte -= time.Second }),
		aendern(oben, func(s *schreiben.Schwellen) { s.SegmentWarte += time.Second }),
		aendern(unten, func(s *schreiben.Schwellen) { s.Gruppe -= time.Second }),
		aendern(oben, func(s *schreiben.Schwellen) { s.Einzel += time.Second }),
		aendern(basis, func(s *schreiben.Schwellen) { s.Klasse = 3 }),
		aendern(basis, func(s *schreiben.Schwellen) { s.SpoolGrenze = s.Klasse - 1 }),
		aendern(basis, func(s *schreiben.Schwellen) { s.Frist = s.SegmentWarte }),
		aendern(basis, func(s *schreiben.Schwellen) { s.Gruppe = 7 * time.Hour }),
	} {
		ungueltig(knick)
	}
	for _, klasse := range []int{262144, 1048576, 4194304, 16777216, 33554432} {
		if !protocol.Segmentklasse(klasse) || !strings.Contains(text, strconv.Itoa(klasse)) {
			t.Fatalf("klasse %d", klasse)
		}
	}
	for _, zeile := range []string{
		"puffer: 1048576",
		"pufferWarteMs: 100",
		"segment: 4194304",
		"segmentWarteS: 60",
		"klasse: 4194304",
		"gruppeS: 3600",
		"einzelS: 28800",
		"sonstigeS: 3600",
		"spoolGrenze: 67108864",
		"fristS: 900",
		"beendenS: 390",
		"speicher: 268435456",
	} {
		if !strings.Contains(werte, zeile) {
			t.Fatalf("values ohne %s", zeile)
		}
	}
	if 268435456 <= (1<<20)+(4<<20) || 390 < 60+30 {
		t.Fatal("limit")
	}
}

func TestEinheit(t *testing.T) {
	schreiben := datei(t, filepath.Join("systemd", "cryptlog-schreiben.service"))
	suchen := datei(t, filepath.Join("systemd", "cryptlog-suchen.service"))
	for _, teil := range []string{"User=cryptlog-schreiben", "ExecStart=/usr/bin/cryptlog schreiben /etc/cryptlog/schreiben.conf", "TimeoutStopSec=390", "KillSignal=SIGTERM", "KillMode=process", "StateDirectory=cryptlog/schreiben"} {
		if !strings.Contains(schreiben, teil) {
			t.Fatalf("schreiben ohne %s", teil)
		}
	}
	for _, teil := range []string{"User=cryptlog-suchen", "ExecStart=/usr/bin/cryptlog suchen /etc/cryptlog/suchen.conf", "TimeoutStopSec=390", "KillSignal=SIGTERM"} {
		if !strings.Contains(suchen, teil) {
			t.Fatalf("suchen ohne %s", teil)
		}
	}
	if strings.Contains(schreiben, "User=cryptlog-suchen") || strings.Contains(suchen, "User=cryptlog-schreiben") {
		t.Fatal("dasselbe konto")
	}
	if strings.Contains(schreiben, "RuntimeDirectory=") || strings.Contains(suchen, "rm ") {
		t.Fatal("spool")
	}
	sys := datei(t, filepath.Join("systemd", "cryptlog.sysusers"))
	if !strings.Contains(sys, "cryptlog-schreiben") || !strings.Contains(sys, "cryptlog-suchen") || !strings.Contains(sys, "/usr/sbin/nologin") {
		t.Fatal(sys)
	}
	bild := datei(t, "..", "Dockerfile")
	for _, teil := range []string{"CGO_ENABLED=0", "-tags cryptlog_image", "USER 65532:65532", "ENTRYPOINT [\"/cryptlog\"]"} {
		if !strings.Contains(bild, teil) {
			t.Fatalf("image ohne %s", teil)
		}
	}
	if strings.Contains(bild, "apt-get") || strings.Contains(bild, "bash") {
		t.Fatal("shell")
	}
}

func TestFrist(t *testing.T) {
	sh, ok := findSh()
	if !ok {
		t.Skip("sh fehlt")
	}
	body, err := os.ReadFile(filepath.Join(wurzel(t), "systemd", "frist"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lauf := func(konfig, angabe string, wollen int) {
		t.Helper()
		pfad := filepath.Join(dir, "konfig")
		if err := os.WriteFile(pfad, []byte(konfig), 0o600); err != nil {
			t.Fatal(err)
		}
		code, aus := frist(t, sh, body, shPfad(pfad), angabe)
		if code != wollen {
			t.Fatalf("warte %s code %d wollen %d datei %s\n%s", angabe, code, wollen, shPfad(pfad), aus)
		}
	}
	lauf("", "90000000", 0)
	lauf("", "89999999", 1)
	lauf("segment_warte = 10s\n", "40000000", 0)
	lauf("segment_warte = 10s\n", "39999999", 1)
	lauf("segment_warte = 5m\n", "330000000", 0)
	lauf("segment_warte = 5m\n", "329999999", 1)
	lauf("segment_warte = 1m0s\n", "90000000", 0)
	lauf("# segment_warte = 1s\nsegment_warte = 60s\n", "90000000", 0)
	lauf("segment_warte = 10s\nsegment_warte = 60s\n", "400000000", 1)
	lauf("segment_warte = kurz\n", "400000000", 1)
	code, aus := frist(t, sh, body, shPfad(filepath.Join(dir, "fehlt")), "infinity")
	if code == 0 {
		t.Fatalf("infinity ohne datei %s", aus)
	}
	if err := os.WriteFile(filepath.Join(dir, "konfig"), []byte("segment_warte = 10s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, aus = frist(t, sh, body, shPfad(filepath.Join(dir, "konfig")), "infinity")
	if code != 0 {
		t.Fatalf("infinity %d %s", code, aus)
	}
}

func frist(t *testing.T, sh string, body []byte, konfig, angabe string) (int, string) {
	t.Helper()
	cmd := exec.Command(sh, "-s", konfig, angabe)
	cmd.Env = shEnv()
	cmd.Stdin = strings.NewReader(string(body))
	aus, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(aus)
	}
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatal(err)
	}
	return exit.ExitCode(), string(aus)
}

func aendern(s schreiben.Schwellen, f func(*schreiben.Schwellen)) schreiben.Schwellen {
	f(&s)
	return s
}

func datei(t *testing.T, teile ...string) string {
	t.Helper()
	pfad := filepath.Join(append([]string{wurzel(t)}, teile...)...)
	roh, err := os.ReadFile(pfad)
	if err != nil {
		t.Fatal(err)
	}
	return string(roh)
}

func wurzel(t *testing.T) string {
	t.Helper()
	_, datei, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("pfad")
	}
	return filepath.Dir(datei)
}

func shEnv() []string {
	return append(os.Environ(), "MSYS_NO_PATHCONV=1", "MSYS2_ARG_CONV_EXCL=*")
}

func shPfad(pfad string) string {
	pfad = strings.ReplaceAll(pfad, `\`, `/`)
	if len(pfad) >= 2 && pfad[1] == ':' {
		pfad = "/" + strings.ToLower(pfad[:1]) + pfad[2:]
	}
	return pfad
}

func findSh() (string, bool) {
	for _, pfad := range []string{
		`C:\Program Files\Git\bin\sh.exe`,
		`C:\Program Files\Git\usr\bin\sh.exe`,
	} {
		if _, err := os.Stat(pfad); err == nil {
			return pfad, true
		}
	}
	if pfad, err := exec.LookPath("sh"); err == nil {
		return pfad, true
	}
	return "", false
}
