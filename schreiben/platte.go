package schreiben

import (
	"bytes"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"cryptlog/abschluss"
	"cryptlog/protocol"
)

// Platte ist das Speicherziel auf einem Dateisystem.
// Jedes Schreiben endet mit einem Fsync. Der Fsync der Annahme ist die
// Annahme, sofern dieses Dateisystem den schreibenden Knoten überdauert.
type Platte struct {
	mu     sync.Mutex
	wurzel string
}

// OeffnenPlatte legt das Ziel unter wurzel an.
func OeffnenPlatte(wurzel string) (*Platte, error) {
	abs, err := filepath.Abs(wurzel)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &Platte{wurzel: abs}, nil
}

// Lesen liefert eine Kopie. Ein fehlendes Objekt ist kein Fehler.
func (p *Platte) Lesen(schluessel string) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sperre, err := p.exklusiv()
	if err != nil {
		return nil, false, err
	}
	defer freigeben(sperre)
	datei, err := p.datei(schluessel)
	if err != nil {
		return nil, false, err
	}
	roh, err := os.ReadFile(datei)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return roh, true, nil
}

// Schreiben legt inhalt ab und schließt die Datei mit Fsync.
// Dieselben Bytes sind ein wiederholtes Schreiben.
func (p *Platte) Schreiben(schluessel string, inhalt []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sperre, err := p.exklusiv()
	if err != nil {
		return err
	}
	defer freigeben(sperre)
	datei, err := p.datei(schluessel)
	if err != nil {
		return err
	}
	alt, err := os.ReadFile(datei)
	if err == nil {
		if bytes.Equal(alt, inhalt) {
			return nil
		}
		return abschluss.ErrObjekt
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return schreibenNeu(datei, inhalt)
}

// Ersetzen tauscht die Bytes nur, wenn bisher noch vorliegt.
func (p *Platte) Ersetzen(schluessel string, bisher, neu []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sperre, err := p.exklusiv()
	if err != nil {
		return err
	}
	defer freigeben(sperre)
	datei, err := p.datei(schluessel)
	if err != nil {
		return err
	}
	alt, err := os.ReadFile(datei)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return abschluss.ErrObjekt
		}
		return err
	}
	if !bytes.Equal(alt, bisher) {
		return abschluss.ErrObjekt
	}
	return schreibenNeu(datei, neu)
}

// Entfernen löscht das Objekt. Ein fehlendes Objekt ist bereits entfernt.
func (p *Platte) Entfernen(schluessel string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sperre, err := p.exklusiv()
	if err != nil {
		return err
	}
	defer freigeben(sperre)
	datei, err := p.datei(schluessel)
	if err != nil {
		return err
	}
	if err := os.Remove(datei); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncVerzeichnis(filepath.Dir(datei))
}

// Liste liefert die Objektschlüssel unter prefix.
func (p *Platte) Liste(prefix string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sperre, err := p.exklusiv()
	if err != nil {
		return nil, err
	}
	defer freigeben(sperre)
	var out []string
	err = filepath.WalkDir(p.wurzel, func(name string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(name) == ".sperre" {
			return nil
		}
		rel, err := filepath.Rel(p.wurzel, name)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
		return nil
	})
	return out, err
}

func (p *Platte) datei(schluessel string) (string, error) {
	if schluessel == "" || schluessel == ".sperre" || strings.HasPrefix(schluessel, ".sperre/") || strings.ContainsAny(schluessel, `\:`) || path.Clean(schluessel) != schluessel {
		return "", protocol.ErrLength
	}
	full := filepath.Join(p.wurzel, filepath.FromSlash(schluessel))
	rel, err := filepath.Rel(p.wurzel, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", protocol.ErrLength
	}
	return full, nil
}

func (p *Platte) exklusiv() (*os.File, error) {
	if p == nil {
		return nil, protocol.ErrLength
	}
	f, err := os.OpenFile(filepath.Join(p.wurzel, ".sperre"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := dateiSperren(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func freigeben(f *os.File) {
	if f == nil {
		return
	}
	_ = dateiEntsperren(f)
	f.Close()
}

func schreibenNeu(datei string, inhalt []byte) error {
	if err := os.MkdirAll(filepath.Dir(datei), 0o700); err != nil {
		return err
	}
	return schreibeFest(datei, inhalt)
}

// schreibeFest schreibt data und schließt Datei und Verzeichnis mit Fsync.
func schreibeFest(datei string, data []byte) error {
	dir := filepath.Dir(datei)
	tmp, err := os.CreateTemp(dir, ".schreiben-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, datei); err != nil {
		return err
	}
	ok = true
	return syncVerzeichnis(dir)
}

func syncVerzeichnis(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err == nil || verzeichnisOhneFsync(err) {
		return nil
	}
	return err
}

func verzeichnisOhneFsync(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	// FlushFileBuffers auf einem Verzeichnis liefert
	// ERROR_INVALID_FUNCTION (1) oder ERROR_ACCESS_DENIED (5).
	return errno == 1 || errno == 5 || errno == syscall.ENOTSUP
}
