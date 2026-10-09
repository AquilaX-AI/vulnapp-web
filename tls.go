package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// loadOrGenerateCert returns the TLS certificate the HTTPS listener should
// use. If TLS_CERT_FILE/TLS_KEY_FILE are set, those are loaded (useful if
// you want a real certificate instead). Otherwise a fresh self-signed
// certificate is generated in memory on every startup, so the app never
// depends on any cert/key files existing on disk - matches the rest of
// this binary being fully self-contained.
func loadOrGenerateCert() (tls.Certificate, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	return generateSelfSignedCert()
}

// defaultTLSHostname is the name the self-signed cert is issued for.
// Override with TLS_HOSTNAME if you're serving this under a different
// domain. The cert is still self-signed (not issued by a trusted CA), so
// browsers/clients will show the usual untrusted-certificate warning;
// matching the hostname just means that's the *only* warning - no extra
// "hostname mismatch" error on top of it. Visitors can still reach the
// site by explicitly accepting the risk (e.g. "Advanced -> Proceed" in a
// browser, or curl -k / --insecure on the command line).
const defaultTLSHostname = "velocity-labs.dev"

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	hostname := getenvDefault("TLS_HOSTNAME", defaultTLSHostname)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Acme Supplies (vulnapp-web demo)"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostname, "*." + hostname, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
