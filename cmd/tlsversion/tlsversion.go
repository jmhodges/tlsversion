package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jmhodges/tlsversion"
)

var (
	httpsAddr = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr  = flag.String("httpAddr", "localhost:8080", "address to boot the HTTP server on")
	rawDomain = flag.String("canonicalDomain", "localhost:10443", "domain to use as base URL host when rendering redirects and templates (may include a port if necessary)")
	certPath  = flag.String("cert", "./config/development_cert.pem", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development_key.pem", "file path to the TLS key to serve with")
	acmeURL   = flag.String("acmeRedirect", "", "URL to join with .well-known/acme paths and redirect to")
)

func main() {
	flag.Parse()

	if err := validateFlags(*httpsAddr, *httpAddr, *rawDomain, *certPath, *keyPath, *acmeURL); err != nil {
		log.Fatal(err)
	}

	tlsConf := makeTLSConfig(*certPath, *keyPath)

	canonicalDomain := *rawDomain
	domainForMatching, err := hostForMatching(canonicalDomain)
	if err != nil {
		log.Fatalf("failed to split host and port in canonicalDomain %#v: %s", canonicalDomain, err)
	}

	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetHTTP1(true)
	httpsSrv := &http.Server{
		Addr:      *httpsAddr,
		TLSConfig: tlsConf,
		Handler:   encryptedMux(domainForMatching, canonicalDomain),
		Protocols: protos,
		// Timeouts bound how long a single connection can tie up server
		// resources, which protects against slow-client attacks (e.g.
		// Slowloris) and stuck peers. This service only serves tiny
		// responses, so the windows can be short. ReadTimeout also covers
		// the TLS handshake for this server.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Cap request header size to blunt memory-exhaustion attempts. The
		// default is 1MB; 64KB is plenty for the requests this service sees.
		MaxHeaderBytes: 64 << 10,
	}
	plaintextSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: plaintextMux(canonicalDomain),
		// The plaintext server only issues redirects and healthchecks, so it
		// can use the same conservative bounds as the HTTPS server.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	if err := runServersWithGracefulShutdown(httpsSrv, plaintextSrv); err != nil {
		// The failures were already logged as they happened; the non-zero
		// exit is the signal to the process supervisor.
		os.Exit(1)
	}
}

// validateFlags checks the command-line flag values for problems that would
// stop the servers from booting correctly, or that would boot a misconfigured
// service. It reports every problem it finds in one error (rather than failing
// on the first) so the operator can fix them all in a single pass instead of
// rebooting repeatedly to discover them one at a time.
func validateFlags(httpsAddr, httpAddr, canonicalDomain, certPath, keyPath, acmeURL string) error {
	var problems []string

	for _, f := range []struct {
		name, value string
	}{
		{"httpsAddr", httpsAddr},
		{"httpAddr", httpAddr},
	} {
		if f.value == "" {
			problems = append(problems, fmt.Sprintf("-%s must not be empty", f.name))
			continue
		}
		// net/http and net.Listen want a host:port address (the host may be
		// empty, e.g. ":10443"). SplitHostPort rejects values with no port,
		// which would otherwise fail only once a server tried to listen.
		if _, _, err := net.SplitHostPort(f.value); err != nil {
			problems = append(problems, fmt.Sprintf("-%s %#v is not a valid host:port address: %s", f.name, f.value, err))
		}
	}

	if canonicalDomain == "" {
		problems = append(problems, "-canonicalDomain must not be empty")
	} else if _, err := hostForMatching(canonicalDomain); err != nil {
		problems = append(problems, fmt.Sprintf("-canonicalDomain %#v could not be parsed: %s", canonicalDomain, err))
	}

	if certPath == "" {
		problems = append(problems, "-cert must not be empty")
	}
	if keyPath == "" {
		problems = append(problems, "-key must not be empty")
	}

	// acmeRedirect is optional. When set it is joined with request paths to
	// build a redirect target, so it must be an absolute URL or a root-relative
	// path. Anything else would produce broken redirects.
	if acmeURL != "" &&
		!strings.HasPrefix(acmeURL, "/") &&
		!strings.HasPrefix(acmeURL, "https://") &&
		!strings.HasPrefix(acmeURL, "http://") {
		problems = append(problems, fmt.Sprintf("-acmeRedirect must start with 'http://', 'https://', or '/' but does not: %#v", acmeURL))
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid flag values:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// hostForMatching returns the bare host (no port) from a canonical domain value
// that may include a port, e.g. "localhost:10443" in development. net/http
// strips the port from request Host headers, so the ServeMux host pattern must
// be portless to match. A value without a port is returned unchanged.
func hostForMatching(canonicalDomain string) (string, error) {
	if !strings.Contains(canonicalDomain, ":") {
		return canonicalDomain, nil
	}
	host, _, err := net.SplitHostPort(canonicalDomain)
	if err != nil {
		return "", err
	}
	return host, nil
}

func encryptedMux(domainForMatching, canonicalDomain string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/acme-challenge/", acmeRedirect(*acmeURL))
	mux.HandleFunc("/v1/version.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out, err := json.Marshal(tlsVersionResponse{Version: tls.VersionName(r.TLS.Version)})
		if err != nil {
			http.Error(w, "unable to marshal TLS version response", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	})
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := tlsversion.IndexData{Version: tls.VersionName(r.TLS.Version)}
		if err := tlsversion.Index.Execute(w, data); err != nil {
			http.Error(w, "unable to render index", http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tlsversion.About.Execute(w, nil); err != nil {
			http.Error(w, "unable to render about", http.StatusInternalServerError)
			return
		}
	})
	expectTLS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			// This is the mux for the HTTPS server, but we're not receiving TLS
			// connection info, which means something was configured
			// incorrectly.
			http.Error(w, "brown paper bag bug", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// nosniff applies to every response the HTTPS server serves (HTML and
		// the JSON API alike): it stops browsers from MIME-sniffing a response
		// into a type we didn't intend.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})

	// domainRedirect redirects all requests to the canonical domain for this
	// service. It has to work to make sure it handles ports in the domain flag
	// value and in HTTP client headers correctly. net/http will strip ports
	// from the Host header, so we can match against the domain and know we're
	// getting the right request, even when using a localhost with port in
	// development. Dropping ports is important because some clients include
	// them in their `Host` header. See
	// https://github.com/golang/go/issues/10463
	domainRedirect := http.NewServeMux()
	domainRedirect.HandleFunc(domainForMatching+"/", func(w http.ResponseWriter, r *http.Request) {
		expectTLS.ServeHTTP(w, r)
	})
	domainRedirect.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("https://%s%s", canonicalDomain, r.URL.Path)
		if r.URL.RawQuery != "" {
			url += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})
	return domainRedirect
}

type tlsVersionResponse struct {
	Version string `json:"version"`
}

func plaintextMux(canonicalDomain string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/acme-challenge/", acmeRedirect(*acmeURL))
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		newURL := fmt.Sprintf("https://%s%s", canonicalDomain, r.URL.Path)
		if r.URL.RawQuery != "" {
			newURL += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, newURL, http.StatusMovedPermanently)
	})
	return mux
}

// runServersWithGracefulShutdown runs both servers until an OS signal arrives
// or a listener fails, then drains in-flight requests on both before
// returning. Listener errors are logged as they are seen; the returned error
// is non-nil if any server failed, so main can exit non-zero for the process
// supervisor.
func runServersWithGracefulShutdown(httpsSrv *http.Server, plaintextSrv *http.Server) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	servers := []struct {
		name   string
		srv    *http.Server
		listen func() error
	}{
		// Empty paths: certs come from TLSConfig's GetCertificate (the keypair
		// reloader). Passing file paths here would make ServeTLS load a static
		// copy into Certificates[0], which clients without SNI would then be
		// served forever, never seeing reloaded certs.
		{"https", httpsSrv, func() error { return httpsSrv.ListenAndServeTLS("", "") }},
		{"http", plaintextSrv, func() error { return plaintextSrv.ListenAndServe() }},
	}

	// serveErr carries fatal listener errors (e.g. the port is already in
	// use). It is buffered for every sender so no sender blocks after the
	// first error triggers shutdown.
	serveErr := make(chan error, len(servers))

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	var serveWG sync.WaitGroup
	for _, s := range servers {
		serveWG.Go(func() {
			err := s.listen()
			if err != nil && err != http.ErrServerClosed {
				serveErr <- fmt.Errorf("%s server error: %w", s.name, err)
			}
		})
	}

	// Wait for either an operator-initiated stop (a signal) or a fatal
	// listener error. Either way both servers get the graceful drain below,
	// so a listener error doesn't drop the healthy server's in-flight
	// requests mid-response.
	var listenErrs []error
	select {
	case <-stop:
	case err := <-serveErr:
		log.Printf("shutting down after %s", err)
		listenErrs = append(listenErrs, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A signal during the drain (including a second signal after the one
	// that started it) abandons the drain so an operator or supervisor can
	// always force a prompt exit instead of waiting out the full timeout.
	go func() {
		<-stop
		log.Printf("signal received during drain, shutting down immediately")
		cancel()
	}()

	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Go(func() {
			if err := s.srv.Shutdown(ctx); err != nil {
				log.Printf("error shutting down %s: %s", strings.ToUpper(s.name), err)
			}
		})
	}
	wg.Wait()

	// Sweep up any listener errors not seen by the select above: the second
	// failure when both servers die, or one that raced (or arrived after) a
	// signal. Without this they would go unlogged and the process would exit
	// 0 despite a crashed server. Shutdown has closed the listeners, so the
	// serve goroutines are done or about to be — wait for them so every
	// error has been sent before we drain.
	serveWG.Wait()
	for {
		select {
		case err := <-serveErr:
			log.Printf("server error during shutdown: %s", err)
			listenErrs = append(listenErrs, err)
		default:
			return errors.Join(listenErrs...)
		}
	}
}

func makeTLSConfig(certPath, keyPath string) *tls.Config {
	kpr, err := newKeypairReloader(certPath, keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}
	go reloadKeypairForever(kpr, time.NewTicker(1*time.Hour))
	// This TLS config is deliberately permissive: old MinVersion and legacy
	// (RC4/3DES/CBC) cipher suites. This service exists to report whatever TLS
	// version a client negotiated, so it must accept the oldest clients we can
	// rather than reject them. Do not "harden" this — being permissive is the
	// product. (CipherSuites only affects TLS 1.2 and below; it's ignored for
	// TLS 1.3.)
	tlsConf := &tls.Config{
		GetCertificate: kpr.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	return tlsConf
}

// acmeRedirect is a string that represents the base URL (e.g.
// "https://example.com") to redirect to for ACME challenges. The paths appended
// to this base URL will include the `/.well-known/acme-challenge/` prefix. If
// the base URL is empty, a 404 error will be returned. If the original path was
// for "/.well-known/acme-challenge/" exactly, a 200 OK will be returned with an
// empty body.
type acmeRedirect string

func (a acmeRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if string(a) == "" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if p == "/.well-known/acme-challenge/" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, string(a)+p, http.StatusFound)
}
