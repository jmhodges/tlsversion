package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
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
		httpsAddr, httpAddr, http3Addr, canonicalDomain, certPath, keyPath, acmeURL string
	}
	valid := flags{
		httpsAddr:       ":10443",
		httpAddr:        ":8080",
		http3Addr:       ":10443",
		canonicalDomain: "www.tlsversion.com",
		certPath:        "/secrets/tls.crt",
		keyPath:         "/secrets/tls.key",
		acmeURL:         "https://acme.example.com",
	}
	check := func(f flags) error {
		return validateFlags(f.httpsAddr, f.httpAddr, f.http3Addr, f.canonicalDomain, f.certPath, f.keyPath, f.acmeURL)
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

	t.Run("accepts an empty http3Addr", func(t *testing.T) {
		f := valid
		f.http3Addr = ""
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
		{"http3Addr without port", func(f *flags) { f.http3Addr = "localhost" }, "-http3Addr"},
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
		err := validateFlags("", "", "noport", "", "", "", "bad")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		for _, want := range []string{"-httpsAddr", "-httpAddr", "-http3Addr", "-canonicalDomain", "-cert", "-key", "-acmeRedirect"} {
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

// testLogger returns the analytics logger to hand to encryptedMux in tests.
// These tests are about the responses, not the log lines, so it throws them
// away rather than cluttering the test output.
func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestEncryptedMux(t *testing.T) {
	h := encryptedMux("example.com", "example.com", testLogger())

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

	t.Run("json endpoint allows cross-origin reads", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/v1/version.json", nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Access-Control-Allow-Origin: got %q, want %q", got, "*")
		}
	})

	t.Run("html pages do not allow cross-origin reads", func(t *testing.T) {
		for _, path := range []string{"/", "/about"} {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
			req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			h.ServeHTTP(rr, req)

			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s Access-Control-Allow-Origin: got %q, want empty", path, got)
			}
		}
	})

	t.Run("no Alt-Svc header without the withAltSvc wrapper", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if got := rr.Header().Get("Alt-Svc"); got != "" {
			t.Errorf("Alt-Svc: got %q, want empty", got)
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

func TestCrawlerFiles(t *testing.T) {
	h := encryptedMux("example.com", "example.com", testLogger())

	// get fetches path over the mux as a TLS request on the canonical host and
	// asserts the response is a 200 with the given Content-Type, returning the
	// body for content checks.
	get := func(t *testing.T, path, wantContentType string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("%s status: got %d, want %d", path, rr.Code, http.StatusOK)
		}
		if got := rr.Header().Get("Content-Type"); got != wantContentType {
			t.Errorf("%s Content-Type: got %q, want %q", path, got, wantContentType)
		}
		if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s X-Content-Type-Options: got %q, want %q", path, got, "nosniff")
		}
		return rr.Body.String()
	}

	t.Run("robots.txt allows all crawlers and points at the sitemap", func(t *testing.T) {
		body := get(t, "/robots.txt", "text/plain; charset=utf-8")

		for _, want := range []string{
			"User-agent: *",
			"Allow: /",
			"Sitemap: https://example.com/sitemap.xml",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("robots.txt body %q does not contain %q", body, want)
			}
		}
	})

	t.Run("sitemap.xml lists the human-facing pages only", func(t *testing.T) {
		body := get(t, "/sitemap.xml", "application/xml; charset=utf-8")

		for _, want := range []string{
			`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`,
			"<loc>https://example.com/</loc>",
			"<loc>https://example.com/about</loc>",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("sitemap.xml body %q does not contain %q", body, want)
			}
		}
		if strings.Contains(body, "version.json") {
			t.Errorf("sitemap.xml body %q lists the JSON API endpoint, want human-facing pages only", body)
		}
	})

	t.Run("llms.txt follows the llms.txt convention", func(t *testing.T) {
		body := get(t, "/llms.txt", "text/markdown; charset=utf-8")

		if !strings.HasPrefix(body, "# tlsversion.com\n") {
			t.Errorf("llms.txt body %q does not start with the H1 site name", body)
		}
		for _, want := range []string{
			"\n> ",
			"https://example.com/v1/version.json",
			"[Home](https://example.com/)",
			"[About](https://example.com/about)",
			"howsmyssl.com",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("llms.txt body %q does not contain %q", body, want)
			}
		}
	})

	t.Run("uses the canonicalDomain flag value in URLs", func(t *testing.T) {
		prodBody := robotsTxt("www.tlsversion.com")
		if want := "Sitemap: https://www.tlsversion.com/sitemap.xml"; !strings.Contains(prodBody, want) {
			t.Errorf("robots.txt body %q does not contain %q", prodBody, want)
		}
	})
}

func TestAltSvcValue(t *testing.T) {
	cases := []struct {
		name, domain, want string
		wantErr            bool
	}{
		{"portless domain advertises 443", "www.tlsversion.com", `h3=":443"; ma=2592000`, false},
		{"domain with port advertises that port", "localhost:10443", `h3=":10443"; ma=2592000`, false},
		{"malformed domain errors", "host:port:extra", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := altSvcValue(tc.domain)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Errorf("altSvcValue(%q): got %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestWithAltSvc(t *testing.T) {
	altSvc, err := altSvcValue("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	h := withAltSvc(altSvc, encryptedMux("example.com", "example.com", testLogger()))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}
	if want := `h3=":443"; ma=2592000`; rr.Header().Get("Alt-Svc") != want {
		t.Errorf("Alt-Svc: got %q, want %q", rr.Header().Get("Alt-Svc"), want)
	}
}

// TestHTTP3EndToEnd boots a real HTTP/3 server on a loopback UDP port with the
// development certificates and drives the same handler stack main() gives the
// production HTTP/3 server (encryptedMux) over QUIC. It verifies the handlers
// behave correctly when requests arrive via HTTP/3: quic-go populates r.TLS
// (so expectTLS doesn't 500 and the version handlers see the negotiated
// version), the security headers are set, and both the JSON API and the HTML
// index render, reporting TLS 1.3 (the only version QUIC permits).
func TestHTTP3EndToEnd(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../../config/development_cert.pem", "../../config/development_key.pem")
	if err != nil {
		t.Fatalf("loading development keypair: %s", err)
	}

	h3srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler:   encryptedMux("localhost", "localhost", testLogger()),
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback UDP: %s", err)
	}
	defer udpConn.Close()
	go h3srv.Serve(udpConn)
	defer h3srv.Close()

	caPEM, err := os.ReadFile("../../config/development_ca_cert.pem")
	if err != nil {
		t.Fatalf("reading development CA cert: %s", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("unable to parse development CA cert")
	}

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
			// The development cert only covers "localhost" but the request
			// below dials 127.0.0.1 to avoid any localhost-resolves-to-::1
			// mismatch with the IPv4 listener.
			ServerName: "localhost",
		},
	}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	// get fetches path over HTTP/3 and returns the response and its body,
	// after asserting the invariants every response from the handler stack
	// must have: it arrived over HTTP/3 and carries the headers expectTLS
	// sets. Those headers are the proof that quic-go populated r.TLS: a nil
	// r.TLS would have taken the 500 branch before setting them.
	get := func(t *testing.T, path string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d%s", port, path), nil)
		if err != nil {
			t.Fatalf("building request for %s: %s", path, err)
		}
		// The mux serves content only on the canonical host.
		req.Host = "localhost"

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP/3 GET %s: %s", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body of %s: %s", path, err)
		}

		if resp.ProtoMajor != 3 {
			t.Errorf("%s protocol: got %q, want HTTP/3", path, resp.Proto)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status: got %d, want %d (body %q)", path, resp.StatusCode, http.StatusOK, body)
		}
		if want := "max-age=63072000; includeSubDomains"; resp.Header.Get("Strict-Transport-Security") != want {
			t.Errorf("%s Strict-Transport-Security: got %q, want %q", path, resp.Header.Get("Strict-Transport-Security"), want)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s X-Content-Type-Options: got %q, want %q", path, got, "nosniff")
		}
		return resp, body
	}

	t.Run("v1/version.json reports TLS 1.3", func(t *testing.T) {
		resp, body := get(t, "/v1/version.json")

		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type: got %q, want %q", got, "application/json")
		}
		var vr tlsVersionResponse
		if err := json.Unmarshal(body, &vr); err != nil {
			t.Fatalf("unmarshaling body %q: %s", body, err)
		}
		if want := tls.VersionName(tls.VersionTLS13); vr.Version != want {
			t.Errorf("version: got %q, want %q", vr.Version, want)
		}
	})

	t.Run("index page renders the negotiated version", func(t *testing.T) {
		resp, body := get(t, "/")

		if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type: got %q, want %q", got, "text/html; charset=utf-8")
		}
		if want := tls.VersionName(tls.VersionTLS13); !strings.Contains(string(body), want) {
			t.Errorf("index body does not contain %q", want)
		}
	})
}
