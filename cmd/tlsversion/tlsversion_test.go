package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestValidateFlags(t *testing.T) {
	// valid is a set of flag values that should pass validation. Each subtest
	// mutates a copy to exercise one failure.
	type flags struct {
		httpsAddr, httpAddr, canonicalDomain, certPath, keyPath, acmeURL string
	}
	valid := flags{
		httpsAddr:       ":10443",
		httpAddr:        ":8080",
		canonicalDomain: "www.tlsversion.com",
		certPath:        "/secrets/tls.crt",
		keyPath:         "/secrets/tls.key",
		acmeURL:         "https://acme.example.com",
	}
	check := func(f flags) error {
		return validateFlags(f.httpsAddr, f.httpAddr, f.canonicalDomain, f.certPath, f.keyPath, f.acmeURL)
	}

	t.Run("accepts valid flags", func(t *testing.T) {
		if err := check(valid); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("accepts an empty acmeRedirect", func(t *testing.T) {
		f := valid
		f.acmeURL = ""
		if err := check(f); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("accepts a root-relative acmeRedirect", func(t *testing.T) {
		f := valid
		f.acmeURL = "/s/"
		if err := check(f); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("accepts a canonicalDomain with a port", func(t *testing.T) {
		f := valid
		f.canonicalDomain = "localhost:10443"
		if err := check(f); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(*flags)
		want   string
	}{
		{"empty httpsAddr", func(f *flags) { f.httpsAddr = "" }, "-httpsAddr must not be empty"},
		{"httpsAddr without port", func(f *flags) { f.httpsAddr = "localhost" }, "-httpsAddr"},
		{"empty httpAddr", func(f *flags) { f.httpAddr = "" }, "-httpAddr must not be empty"},
		{"httpAddr without port", func(f *flags) { f.httpAddr = "localhost" }, "-httpAddr"},
		{"empty canonicalDomain", func(f *flags) { f.canonicalDomain = "" }, "-canonicalDomain must not be empty"},
		{"malformed canonicalDomain", func(f *flags) { f.canonicalDomain = "host:port:extra" }, "-canonicalDomain"},
		{"empty cert", func(f *flags) { f.certPath = "" }, "-cert must not be empty"},
		{"empty key", func(f *flags) { f.keyPath = "" }, "-key must not be empty"},
		{"bad acmeRedirect", func(f *flags) { f.acmeURL = "acme.example.com" }, "-acmeRedirect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := valid
			tc.mutate(&f)
			err := check(f)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	t.Run("reports every problem at once", func(t *testing.T) {
		err := validateFlags("", "", "", "", "", "bad")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		for _, want := range []string{"-httpsAddr", "-httpAddr", "-canonicalDomain", "-cert", "-key", "-acmeRedirect"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
}

func TestHostForMatching(t *testing.T) {
	t.Run("strips the port", func(t *testing.T) {
		got, err := hostForMatching("localhost:10443")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got != "localhost" {
			t.Errorf("host: got %q, want %q", got, "localhost")
		}
	})

	t.Run("passes a portless host through unchanged", func(t *testing.T) {
		got, err := hostForMatching("www.tlsversion.com")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got != "www.tlsversion.com" {
			t.Errorf("host: got %q, want %q", got, "www.tlsversion.com")
		}
	})

	t.Run("errors on a malformed host:port", func(t *testing.T) {
		if _, err := hostForMatching("host:port:extra"); err == nil {
			t.Error("expected an error, got nil")
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

	t.Run("index page sets nosniff", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
		}
		if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options: got %q, want %q", got, "nosniff")
		}
	})

	t.Run("json endpoint sets nosniff", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/v1/version.json", nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options: got %q, want %q", got, "nosniff")
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
		if want := "max-age=63072000; includeSubDomains"; rr.Header().Get("Strict-Transport-Security") != want {
			t.Errorf("Strict-Transport-Security: got %q, want %q", rr.Header().Get("Strict-Transport-Security"), want)
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
