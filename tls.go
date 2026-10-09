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
	"strings"
	"sync"
	"time"
)

// defaultTLSHostname is used only when a client connects with no SNI
// hostname at all (e.g. a bare IP connection). Override with TLS_HOSTNAME.
const defaultTLSHostname = "velocity-labs.dev"

// certSource returns the tls.Config field that supplies certificates for
// the HTTPS listener. If TLS_CERT_FILE/TLS_KEY_FILE are set, a single real
// certificate is loaded and reused for every connection. Otherwise the
// cert is self-signed and minted on demand per hostname (see
// getCertificateForClient), so the listener accepts *any* hostname a
// client connects with - there's no fixed set of names to run out of.
// Either way it's still just a self-signed cert: browsers/clients will
// show the normal untrusted-certificate warning, and a visitor can still
// reach the site by explicitly accepting that risk.
func certSource() (*tls.Config, error) {
	certFile := getenvDefault("TLS_CERT_FILE", "")
	keyFile := getenvDefault("TLS_KEY_FILE", "")
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	return &tls.Config{GetCertificate: getCertificateForClient}, nil
}

var (
	hostKeyOnce sync.Once
	hostKey     *rsa.PrivateKey
	hostKeyErr  error

	certCacheMu sync.Mutex
	certCache   = map[string]*tls.Certificate{}
)

// sharedSigningKey lazily creates one RSA key pair for the process and
// reuses it to sign every per-hostname certificate, so minting a cert for
// a newly-seen hostname only costs an x509.CreateCertificate call, not a
// fresh (slow) RSA key generation.
func sharedSigningKey() (*rsa.PrivateKey, error) {
	hostKeyOnce.Do(func() {
		hostKey, hostKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return hostKey, hostKeyErr
}

// getCertificateForClient mints (and caches) a self-signed certificate
// whose CN/SAN exactly matches the hostname the client asked for via SNI,
// so it's valid for literally any hostname, not a fixed list.
func getCertificateForClient(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := chi.ServerName
	if host == "" {
		host = getenvDefault("TLS_HOSTNAME", defaultTLSHostname)
	}

	certCacheMu.Lock()
	defer certCacheMu.Unlock()

	if cert, ok := certCache[host]; ok {
		return cert, nil
	}

	cert, err := generateCertForHost(host)
	if err != nil {
		return nil, err
	}
	certCache[host] = &cert
	return &cert, nil
}

func generateCertForHost(host string) (tls.Certificate, error) {
	priv, err := sharedSigningKey()
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Acme Supplies (vulnapp-web demo)"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
		if strings.Contains(host, ".") {
			template.DNSNames = append(template.DNSNames, "*."+host)
		}
	}
	if host != "localhost" {
		template.DNSNames = append(template.DNSNames, "localhost")
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
