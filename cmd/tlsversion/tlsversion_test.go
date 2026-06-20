package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAcmeRedirect(t *testing.T) {
	t.Run("empty base URL returns 404", func(t *testing.T) {
		var a acmeRedirect = ""
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token", nil)
		a.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusNotFound)
		}
		if got := rr.Header().Get("Content-Length"); got != "0" {
			t.Errorf("Content-Length: got %q, want %q", got, "0")
		}
		if rr.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rr.Body.String())
		}
	})

	t.Run("exact challenge prefix returns 200 empty body", func(t *testing.T) {
		var a acmeRedirect = "https://acme.example.com"
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/", nil)
		a.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rr.Body.String())
		}
	})

	t.Run("challenge path redirects and preserves query", func(t *testing.T) {
		var a acmeRedirect = "https://acme.example.com"
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token?x=1", nil)
		a.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusFound)
		}
		want := "https://acme.example.com/.well-known/acme-challenge/token?x=1"
		if got := rr.Header().Get("Location"); got != want {
			t.Errorf("Location: got %q, want %q", got, want)
		}
	})
}

func TestPlaintextMux(t *testing.T) {
	h := plaintextMux("example.com")

	t.Run("healthcheck returns ok", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
		}
		if got := rr.Body.String(); got != "ok" {
			t.Errorf("body: got %q, want %q", got, "ok")
		}
	})

	t.Run("redirects to canonical https and preserves query", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/foo?x=1", nil)
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusMovedPermanently {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusMovedPermanently)
		}
		want := "https://example.com/foo?x=1"
		if got := rr.Header().Get("Location"); got != want {
			t.Errorf("Location: got %q, want %q", got, want)
		}
	})
}

func TestEncryptedMux(t *testing.T) {
	h := encryptedMux("example.com", "example.com")

	t.Run("missing TLS info on canonical host returns 500", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.TLS = nil
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("non-canonical host redirects to canonical domain", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://other.example.org/foo?x=1", nil)
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusMovedPermanently {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusMovedPermanently)
		}
		want := "https://example.com/foo?x=1"
		if got := rr.Header().Get("Location"); got != want {
			t.Errorf("Location: got %q, want %q", got, want)
		}
	})

	t.Run("v1/version.json reports the negotiated TLS version", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/v1/version.json", nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type: got %q, want %q", got, "application/json")
		}

		body, err := io.ReadAll(rr.Body)
		if err != nil {
			t.Fatalf("reading body: %s", err)
		}
		var resp tlsVersionResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshaling body %q: %s", body, err)
		}
		if want := tls.VersionName(tls.VersionTLS13); resp.Version != want {
			t.Errorf("version: got %q, want %q", resp.Version, want)
		}
	})
}
