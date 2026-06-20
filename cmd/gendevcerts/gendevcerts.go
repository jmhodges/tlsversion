// Command gendevcerts regenerates the local-development TLS certificates that
// tlsversion serves with by default (the config/development_*.pem files).
//
// It writes a self-signed CA plus a leaf certificate signed by that CA. The
// leaf is given a distinct Subject DN and a standard Authority Key Id ->
// Subject Key Id link so that OpenSSL/curl chain it to the CA rather than
// treating it as a self-signed root (see the test for the bug this guards).
//
// Usage:
//
//	go run ./cmd/gendevcerts -d ./config
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var dirName = flag.String("d", "", "dir name to generate files in")

func main() {
	flag.Parse()
	if *dirName == "" {
		log.Fatalf("the non-empty -d parameter is required")
	}
	caCert, caKey, err := generateCACert(*dirName)
	if err != nil {
		log.Fatalf("unable to make CA certificates: %s", err)
	}
	if err := generateLeafCert(*dirName, caCert, caKey); err != nil {
		log.Fatalf("unable to make leaf certificates: %s", err)
	}
}

func generateCACert(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			CommonName: "tlsversion development CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pub := &priv.PublicKey
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create ca failed: %s", err)
	}

	// Parse the freshly-created cert so the leaf is signed against a parent
	// that carries the Go-generated Subject Key Id. That makes
	// CreateCertificate populate the leaf's Authority Key Id, giving a
	// standard, chainable AKID->SKID link.
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca failed: %s", err)
	}

	if err := writePEM(filepath.Join(dir, "development_ca_cert.pem"), "CERTIFICATE", caBytes, 0644); err != nil {
		return nil, nil, err
	}
	log.Println("written development_ca_cert.pem")

	if err := writePEM(filepath.Join(dir, "development_ca_key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv), 0600); err != nil {
		return nil, nil, err
	}
	log.Println("written development_ca_key.pem")

	return caCert, priv, nil
}

func generateLeafCert(dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pub := &priv.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, caKey)
	if err != nil {
		return err
	}

	if err := writePEM(filepath.Join(dir, "development_cert.pem"), "CERTIFICATE", certBytes, 0644); err != nil {
		return err
	}
	log.Println("written development_cert.pem")

	if err := writePEM(filepath.Join(dir, "development_key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv), 0600); err != nil {
		return err
	}
	log.Println("written development_key.pem")
	return nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
