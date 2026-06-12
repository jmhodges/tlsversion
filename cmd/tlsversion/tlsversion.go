package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	httpsAddr = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr  = flag.String("httpAddr", "localhost:8080", "address to boot the HTTP server on")
	rawVHost  = flag.String("vhost", "localhost:10443", "public domain to use in redirects and templates")
	certPath  = flag.String("cert", "./config/development_cert.pem", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development_key.pem", "file path to the TLS key to serve with")
	acmeURL   = flag.String("acmeRedirect", "/s/", "URL to join with .well-known/acme paths and redirect to")
)

func main() {

	tlsConf := makeTLSConfig(*certPath, *keyPath)

	mux := http.NewServeMux()
	plaintextMux := http.NewServeMux()

	f, err := os.Open(*certPath)
	if err != nil {
		log.Fatalf("failed to open cert file %s: %s", *certPath, err)
	}
	f.Close()
	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetHTTP1(true)
	httpsSrv := &http.Server{
		Addr:      *httpsAddr,
		TLSConfig: tlsConf,
		Handler:   mux,
		Protocols: protos,
	}
	plaintextSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: plaintextMux,
	}

	runServersWithGracefulShutdown(httpsSrv, plaintextSrv)
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
