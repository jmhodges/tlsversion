package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

	tlsConf := makeTLSConfig(*certPath, *keyPath)

	f, err := os.Open(*certPath)
	if err != nil {
		log.Fatalf("failed to open cert file %s: %s", *certPath, err)
	}
	f.Close()

	canonicalDomain := *rawDomain
	domainForMatching := canonicalDomain
	if strings.Contains(canonicalDomain, ":") {
		domainForMatching, _, err = net.SplitHostPort(canonicalDomain)
		if err != nil {
			log.Fatalf("failed to split host and port in canonicalDomain %#v: %s", canonicalDomain, err)
		}
	}

	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetHTTP1(true)
	httpsSrv := &http.Server{
		Addr:      *httpsAddr,
		TLSConfig: tlsConf,
		Handler:   encryptedMux(domainForMatching, canonicalDomain),
		Protocols: protos,
	}
	plaintextSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: plaintextMux(canonicalDomain),
	}

	runServersWithGracefulShutdown(httpsSrv, plaintextSrv)
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

func runServersWithGracefulShutdown(httpsSrv *http.Server, plaintextSrv *http.Server) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	go func() {
		err := httpsSrv.ListenAndServeTLS(*certPath, *keyPath)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("https server error: %s", err)
		}
	}()
	go func() {
		err := plaintextSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %s", err)
		}
	}()

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := httpsSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTPS: %s", err)
		}
	}()
	go func() {
		defer wg.Done()
		err := plaintextSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTP: %s", err)
		}
	}()
	wg.Wait()
	cancel()
}

func makeTLSConfig(certPath, keyPath string) *tls.Config {
	kpr, err := newKeypairReloader(certPath, keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}
	go reloadKeypairForever(kpr, time.NewTicker(1*time.Hour))
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
