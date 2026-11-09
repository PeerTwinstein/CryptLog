package schreiben

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"cryptlog/abschluss"
	"cryptlog/protocol"
)

const s3Lesegroesse = protocol.Segment32MiB + (1 << 20)

// S3Konfig nennt den Endpunkt eines S3-kompatiblen Speichers.
// Der Zugriff läuft im Pfadstil: der Bucket steht im Pfad, nicht im Host.
type S3Konfig struct {
	Endpunkt  string
	Bucket    string
	Region    string
	Zugang    string
	Geheimnis string
	Client    *http.Client
}

// S3 ist das Speicherziel im Bucket. Ein PUT ist atomar.
// Dieselben Bytes unter demselben Schlüssel sind ein wiederholtes Schreiben.
type S3 struct {
	endpunkt  *url.URL
	bucket    string
	region    string
	zugang    string
	geheimnis string
	client    *http.Client
}

// OeffnenS3 prüft die Konfiguration und baut den Client.
func OeffnenS3(k S3Konfig) (*S3, error) {
	if k.Bucket == "" || k.Region == "" || k.Zugang == "" || k.Geheimnis == "" || strings.Contains(k.Bucket, "/") {
		return nil, protocol.ErrLength
	}
	u, err := url.Parse(k.Endpunkt)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" && u.Path != "/" {
		return nil, protocol.ErrLength
	}
	u.Path = ""
	u.RawQuery = ""
	client := k.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	basis := *client
	basis.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &S3{
		endpunkt:  u,
		bucket:    k.Bucket,
		region:    k.Region,
		zugang:    k.Zugang,
		geheimnis: k.Geheimnis,
		client:    &basis,
	}, nil
}

// Lesen holt das Objekt. Ein fehlendes Objekt ist kein Fehler.
func (s *S3) Lesen(schluessel string) ([]byte, bool, error) {
	if err := schluesselOK(schluessel); err != nil {
		return nil, false, err
	}
	status, etag, body, err := s.anfrage(http.MethodGet, schluessel, nil, nil, nil)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, s3Status(status)
	}
	_ = etag
	return body, true, nil
}

// Schreiben legt inhalt ab. Liegt derselbe Inhalt, bleibt das Objekt.
// Ein anderer Inhalt wird nicht ersetzt.
func (s *S3) Schreiben(schluessel string, inhalt []byte) error {
	if err := schluesselOK(schluessel); err != nil {
		return err
	}
	status, _, _, err := s.anfrage(http.MethodPut, schluessel, nil, map[string]string{
		"if-none-match": "*",
	}, inhalt)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent {
		return nil
	}
	if status != http.StatusPreconditionFailed {
		return s3Status(status)
	}
	vorhanden, ok, err := s.Lesen(schluessel)
	if err != nil {
		return err
	}
	if ok && bytes.Equal(vorhanden, inhalt) {
		return nil
	}
	if !ok {
		return s3Status(status)
	}
	return abschluss.ErrObjekt
}

// Ersetzen tauscht das Objekt nur über den noch vorliegenden Inhalt bisher.
func (s *S3) Ersetzen(schluessel string, bisher, neu []byte) error {
	if err := schluesselOK(schluessel); err != nil {
		return err
	}
	status, etag, body, err := s.anfrage(http.MethodGet, schluessel, nil, nil, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return abschluss.ErrObjekt
	}
	if status != http.StatusOK {
		return s3Status(status)
	}
	if !bytes.Equal(body, bisher) || etag == "" {
		return abschluss.ErrObjekt
	}
	status, _, _, err = s.anfrage(http.MethodPut, schluessel, nil, map[string]string{
		"if-match": etag,
	}, neu)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent {
		return nil
	}
	if status == http.StatusPreconditionFailed {
		return abschluss.ErrObjekt
	}
	return s3Status(status)
}

// Entfernen löscht das Objekt. Ein fehlendes Objekt ist bereits entfernt.
func (s *S3) Entfernen(schluessel string) error {
	if err := schluesselOK(schluessel); err != nil {
		return err
	}
	status, _, _, err := s.anfrage(http.MethodDelete, schluessel, nil, nil, nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return s3Status(status)
}

// Liste liefert die Objektschlüssel unter prefix.
func (s *S3) Liste(prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("max-keys", "1000")
		q.Set("prefix", prefix)
		if token != "" {
			q.Set("continuation-token", token)
		}
		status, _, body, err := s.anfrage(http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, s3Status(status)
		}
		var seite listResult
		if err := xml.Unmarshal(body, &seite); err != nil {
			return nil, err
		}
		for _, c := range seite.Contents {
			if c.Key != "" {
				out = append(out, c.Key)
			}
		}
		if !seite.Truncated || seite.Next == "" {
			return out, nil
		}
		token = seite.Next
	}
}

type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	Truncated bool   `xml:"IsTruncated"`
	Next      string `xml:"NextContinuationToken"`
}

func (s *S3) anfrage(methode, schluessel string, query url.Values, extra map[string]string, body []byte) (int, string, []byte, error) {
	pfad := "/" + awsEscape(s.bucket)
	if schluessel != "" {
		pfad += "/" + escapeKey(schluessel)
	}
	roh := *s.endpunkt
	roh.Path = pfad
	if len(query) > 0 {
		roh.RawQuery = canonicalQuery(query)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(methode, roh.String(), rdr)
	if err != nil {
		return 0, "", nil, err
	}
	summe := sha256.Sum256(body)
	payload := hex.EncodeToString(summe[:])
	jetzt := time.Now().UTC()
	amz := jetzt.Format("20060102T150405Z")
	header := map[string]string{
		"host":                 roh.Host,
		"x-amz-content-sha256": payload,
		"x-amz-date":           amz,
	}
	for k, v := range extra {
		header[strings.ToLower(k)] = v
	}
	signed := make([]string, 0, len(header))
	for name := range header {
		signed = append(signed, name)
	}
	sort.Strings(signed)
	canon := canonicalRequest(methode, pfad, roh.RawQuery, header, signed, payload)
	scopeDate := jetzt.Format("20060102")
	scope := scopeDate + "/" + s.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(hash256([]byte(canon)))
	sig := signaturV4(s.geheimnis, scopeDate, s.region, "s3", stringToSign)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.zugang+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
	for _, name := range signed {
		if name == "host" {
			continue
		}
		req.Header.Set(name, header[name])
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	inhalt, err := io.ReadAll(io.LimitReader(resp.Body, s3Lesegroesse+1))
	if err != nil {
		return 0, "", nil, err
	}
	if len(inhalt) > s3Lesegroesse {
		return 0, "", nil, protocol.ErrLength
	}
	return resp.StatusCode, resp.Header.Get("ETag"), inhalt, nil
}

func canonicalRequest(methode, pfad, query string, header map[string]string, signed []string, payload string) string {
	var hb strings.Builder
	for _, name := range signed {
		hb.WriteString(name)
		hb.WriteByte(':')
		hb.WriteString(header[name])
		hb.WriteByte('\n')
	}
	return methode + "\n" + pfad + "\n" + query + "\n" + hb.String() + "\n" + strings.Join(signed, ";") + "\n" + payload
}

func canonicalQuery(v url.Values) string {
	type paar struct{ k, w string }
	var alle []paar
	for k, werte := range v {
		ek := awsEscape(k)
		for _, w := range werte {
			alle = append(alle, paar{ek, awsEscape(w)})
		}
	}
	sort.Slice(alle, func(i, j int) bool {
		if alle[i].k != alle[j].k {
			return alle[i].k < alle[j].k
		}
		return alle[i].w < alle[j].w
	})
	var b strings.Builder
	for i, p := range alle {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.w)
	}
	return b.String()
}

func signaturV4(secret, date, region, service, stringToSign string) string {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(data))
	return m.Sum(nil)
}

func hash256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func escapeKey(key string) string {
	teile := strings.Split(key, "/")
	for i := range teile {
		teile[i] = awsEscape(teile[i])
	}
	return strings.Join(teile, "/")
}

func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func schluesselOK(schluessel string) error {
	if schluessel == "" || strings.Contains(schluessel, "..") || strings.HasPrefix(schluessel, "/") {
		return protocol.ErrLength
	}
	return nil
}

func s3Status(code int) error {
	return fmt.Errorf("schreiben: S3 antwortet %d", code)
}
