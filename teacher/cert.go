package teacher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CreateCertificate creates a self-signed P-256 HTTPS certificate for the teacher API.
// Never overwrites existing certificate or key files.
func CreateCertificate(certPath, keyPath, host string) error {
	if _, err := os.Stat(certPath); err == nil {
		return os.ErrExist
	}
	if _, err := os.Stat(keyPath); err == nil {
		return os.ErrExist
	}
	var dnsNames []string
	var ipAddrs []net.IP
	cn := host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		ipAddrs = append(ipAddrs, net.IP(addr.AsSlice()))
		cn = addr.String()
	} else {
		lower := strings.ToLower(host)
		if !isValidHostname(lower) {
			return errors.New("invalid server hostname")
		}
		cn = lower
		dnsNames = append(dnsNames, lower)
	}
	// Always include localhost and 127.0.0.1 SANs matching teacher/server.py.
	hasLocalhost := false
	for _, d := range dnsNames {
		if d == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		dnsNames = append(dnsNames, "localhost")
	}
	hasLoopback := false
	for _, ip := range ipAddrs {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		ipAddrs = append(ipAddrs, net.IPv4(127, 0, 0, 1))
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := kf.Write(keyPEM); err != nil {
		kf.Close()
		_ = os.Remove(keyPath)
		return err
	}
	if err := kf.Close(); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	cf, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	if _, err := cf.Write(certPEM); err != nil {
		cf.Close()
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
		return err
	}
	if err := cf.Close(); err != nil {
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
		return err
	}
	return nil
}
