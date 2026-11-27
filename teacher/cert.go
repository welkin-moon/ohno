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

func buildCertificatePEM(host string, extraIPs []string) (certPEM, keyPEM []byte, err error) {
	var dnsNames []string
	var ipAddrs []net.IP
	addDNS := func(name string) {
		for _, d := range dnsNames {
			if d == name {
				return
			}
		}
		dnsNames = append(dnsNames, name)
	}
	addIP := func(ip net.IP) {
		for _, existing := range ipAddrs {
			if existing.Equal(ip) {
				return
			}
		}
		ipAddrs = append(ipAddrs, ip)
	}

	cn := host
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil && addr.Zone() == "" {
		addIP(net.IP(addr.AsSlice()))
		cn = addr.String()
	} else {
		lower := strings.ToLower(host)
		if !isValidHostname(lower) {
			return nil, nil, errors.New("invalid server hostname")
		}
		cn = lower
		addDNS(lower)
	}
	// Always include localhost, 127.0.0.1, and any detected/configured LAN IPs.
	addDNS("localhost")
	addIP(net.IPv4(127, 0, 0, 1))
	for _, raw := range extraIPs {
		if addr, parseErr := netip.ParseAddr(strings.TrimSpace(raw)); parseErr == nil && addr.Zone() == "" {
			addIP(net.IP(addr.AsSlice()))
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	return certPEM, keyPEM, nil
}

// CreateCertificate creates a self-signed P-256 HTTPS certificate for the teacher API.
// Never overwrites existing certificate or key files.
func CreateCertificate(certPath, keyPath, host string) error {
	return CreateCertificateWithIPs(certPath, keyPath, host, nil)
}

// CreateCertificateWithIPs creates a self-signed P-256 HTTPS certificate including extraIPs in SANs.
// Never overwrites existing certificate or key files.
func CreateCertificateWithIPs(certPath, keyPath, host string, extraIPs []string) error {
	if _, err := os.Stat(certPath); err == nil {
		return os.ErrExist
	}
	if _, err := os.Stat(keyPath); err == nil {
		return os.ErrExist
	}
	certPEM, keyPEM, err := buildCertificatePEM(host, extraIPs)
	if err != nil {
		return err
	}
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

// RegenerateCertificate atomically replaces the teacher HTTPS certificate and private key
// with a newly issued pair covering host and extraIPs.
func RegenerateCertificate(certPath, keyPath, host string, extraIPs []string) ([]byte, []byte, error) {
	certPEM, keyPEM, err := buildCertificatePEM(host, extraIPs)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, nil, err
	}
	writeTemp := func(target string, data []byte, perm os.FileMode) (string, error) {
		f, err := os.CreateTemp(filepath.Dir(target), ".ohno-cert-*")
		if err != nil {
			return "", err
		}
		tmp := f.Name()
		if err := f.Chmod(perm); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		if err := syncFile(f); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		return tmp, nil
	}
	tmpKey, err := writeTemp(keyPath, keyPEM, 0o600)
	if err != nil {
		return nil, nil, err
	}
	tmpCert, err := writeTemp(certPath, certPEM, 0o644)
	if err != nil {
		_ = os.Remove(tmpKey)
		return nil, nil, err
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		_ = os.Remove(tmpKey)
		_ = os.Remove(tmpCert)
		return nil, nil, err
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		_ = os.Remove(tmpCert)
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}
