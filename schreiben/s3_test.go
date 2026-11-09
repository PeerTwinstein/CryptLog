package schreiben

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cryptlog/abschluss"
)

func TestSignaturV4Beispiel(t *testing.T) {
	payload := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	namen := []string{"host", "range", "x-amz-content-sha256", "x-amz-date"}
	canon := canonicalRequest("GET", "/test.txt", "", map[string]string{
		"host":                 "examplebucket.s3.amazonaws.com",
		"range":                "bytes=0-9",
		"x-amz-content-sha256": payload,
		"x-amz-date":           "20130524T000000Z",
	}, namen, payload)
	summe := sha256.Sum256([]byte(canon))
	anfrage := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n" + hex.EncodeToString(summe[:])
	sig := signaturV4("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3", anfrage)
	const want = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if sig != want {
		t.Fatalf("signatur %s\n%s", sig, canon)
	}
}

func TestS3SchreibenListeErsetzen(t *testing.T) {
	var mu sync.Mutex
	store := map[string][]byte{}
	etag := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			http.Error(w, "auth", http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			prefix := r.URL.Query().Get("prefix")
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated>`)
			for key := range store {
				if strings.HasPrefix(key, prefix) {
					io.WriteString(w, `<Contents><Key>`+key+`</Key></Contents>`)
				}
			}
			io.WriteString(w, `</ListBucketResult>`)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			body, ok := store[key]
			tag := etag[key]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", tag)
			w.Write(body)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			if alt, ok := store[key]; ok && r.Header.Get("If-None-Match") == "*" {
				if bytes.Equal(alt, body) {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if match := r.Header.Get("If-Match"); match != "" && match != etag[key] {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			store[key] = append([]byte(nil), body...)
			etag[key] = `"a"`
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "methode", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	ziel, err := OeffnenS3(S3Konfig{
		Endpunkt: srv.URL, Bucket: "bucket", Region: "us-east-1",
		Zugang: "AKIAtest", Geheimnis: "geheimnis",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben("belegt/aa", []byte("eins")); err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben("belegt/aa", []byte("eins")); err != nil {
		t.Fatal(err)
	}
	if err := ziel.Schreiben("belegt/aa", []byte("zwei")); err != abschluss.ErrObjekt {
		t.Fatalf("konflikt %v", err)
	}
	if err := ziel.Ersetzen("belegt/aa", []byte("eins"), []byte("zwei")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := ziel.Lesen("belegt/aa")
	if err != nil || !ok || !bytes.Equal(got, []byte("zwei")) {
		t.Fatalf("%q %v %v", got, ok, err)
	}
	liste, err := ziel.Liste("belegt/")
	if err != nil || len(liste) != 1 || liste[0] != "belegt/aa" {
		t.Fatalf("%v %v", liste, err)
	}
}
