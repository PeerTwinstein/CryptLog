package schluessel

import (
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"cryptlog/protocol"
)

// Server ist die Veröffentlichung des sicheren Modus.
// Er hängt jede Änderung an und liefert die signierte Fassung aus.
type Server struct {
	*ordner
	anker map[protocol.ID]*x509.Certificate
}

// NeuerServer legt die Ablage an. Anker kommt über Anker, getrennt von der Veröffentlichung.
func NeuerServer(wurzel string) (*Server, error) {
	o, err := oeffnenOrdner(wurzel)
	if err != nil {
		return nil, err
	}
	return &Server{ordner: o, anker: map[protocol.ID]*x509.Certificate{}}, nil
}

// Anker hinterlegt den Vertrauensanker. Ein anderer Anker ersetzt ihn nicht.
func (s *Server) Anker(id protocol.ID, certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil || !cert.IsCA {
		return ErrAnker
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if alt, ok := s.anker[id]; ok && !alt.Equal(cert) {
		return ErrAnker
	}
	s.anker[id] = cert
	return nil
}

// Lesen liefert die signierte Veröffentlichung.
func (s *Server) Lesen(id protocol.ID) ([]byte, []byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lesen(id)
}

// Stand ist die laufende Nummer und die aktuelle Veröffentlichung.
func (s *Server) Stand(id protocol.ID) (Stand, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stand(id)
}

// Fest hängt die Fassung an, wenn die Signatur unter dem Vertrauensanker prüft.
func (s *Server) Fest(id protocol.ID, pub, sig, eintrag []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	anker := s.anker[id]
	return s.fest(id, pub, sig, eintrag, func(pub, sig []byte) error {
		if anker == nil || !SignaturOK(anker.PublicKey, pub, sig) {
			return ErrSignatur
		}
		return nil
	})
}

// Privat lehnt ab. Der sichere Modus legt keinen privaten Schlüssel ab.
func (s *Server) Privat(protocol.ID, protocol.Hash, []byte) error { return ErrModus }

// Mandanten listet die Kennungen unter der Wurzel.
func (s *Server) Mandanten() ([]protocol.ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mandanten()
}

// Meta liest die Metadaten des Mandanten.
func (s *Server) Meta(id protocol.ID) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta(id)
}

// MetaSetzen schreibt die Metadaten des Mandanten.
func (s *Server) MetaSetzen(id protocol.ID, meta []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metaSetzen(id, meta)
}

// ServeHTTP liefert die Veröffentlichung. Die Signatur steht hexadezimal im Kopf Cryptlog-Signatur.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	pfad := strings.Trim(r.URL.Path, "/")
	if i := strings.LastIndex(pfad, "/"); i >= 0 {
		pfad = pfad[i+1:]
	}
	id, err := protocol.ParseID(pfad)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	pub, sig, da, err := s.Lesen(id)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if !da {
		http.NotFound(w, r)
		return
	}
	if len(sig) > 0 {
		w.Header().Set("Cryptlog-Signatur", hex.EncodeToString(sig))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pub)
}

// HTTPQuelle liest die Veröffentlichung eines Servers.
type HTTPQuelle struct {
	Basis  string
	Client *http.Client
}

// Lesen holt die Veröffentlichung. Die Signatur steht hexadezimal im Kopf Cryptlog-Signatur.
func (h HTTPQuelle) Lesen(id protocol.ID) ([]byte, []byte, bool, error) {
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	url := strings.TrimRight(h.Basis, "/") + "/" + id.Hex()
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, false, ErrQuelle
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, ErrQuelle
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFassung+1))
	if err != nil || len(body) == 0 || len(body) > maxFassung {
		return nil, nil, false, ErrQuelle
	}
	var sig []byte
	if text := resp.Header.Get("Cryptlog-Signatur"); text != "" {
		sig, err = hex.DecodeString(text)
		if err != nil {
			return nil, nil, false, ErrQuelle
		}
	}
	return body, sig, true, nil
}

// sicherstellen, dass der Server den Speicher erfüllt.
var (
	_ Speicher           = (*Verzeichnis)(nil)
	_ Speicher           = (*Server)(nil)
	_ Quelle             = HTTPQuelle{}
	_ AnkerRegistrierung = (*Server)(nil)
)
