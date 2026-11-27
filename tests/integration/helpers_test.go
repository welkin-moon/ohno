package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/welkin-moon/ohno/teacher"
)

func buildDir() string {
	if d := os.Getenv("OHNO_BUILD_DIR"); d != "" {
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
		return d
	}
	if abs, err := filepath.Abs(filepath.Join("..", "..")); err == nil {
		return abs
	}
	return filepath.Join("..", "..")
}

func resolveBuildArtifact(envKey, defaultName string) string {
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			if abs, err := filepath.Abs(v); err == nil {
				return abs
			}
			return v
		}
	}
	return filepath.Join(buildDir(), defaultName)
}

func fixtureExe() []byte {
	data := make([]byte, 1024)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:0x84], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(data[0x84:0x86], 0x8664)
	binary.LittleEndian.PutUint16(data[0x94:0x96], 2)
	binary.LittleEndian.PutUint16(data[0x98:0x9a], 0x20b)
	return data
}

func fixturePackage(t *testing.T, version string, workerOverride []byte) []byte {
	t.Helper()
	if version == "" {
		version = "0.2.0"
	}
	files := make(map[string][]byte, len(teacher.PackageFiles))
	for i, name := range teacher.PackageFiles {
		if i < 4 {
			files[name] = fixtureExe()
		} else {
			files[name] = []byte("fixture license\n")
		}
	}
	if workerOverride != nil {
		files["ohno-worker.exe"] = workerOverride
	}
	pkg, err := teacher.BuildPackage(version, files)
	if err != nil {
		t.Fatalf("BuildPackage(%s): %v", version, err)
	}
	return pkg
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type certFixture struct {
	key      *rsa.PrivateKey
	pem      string
	certPath string
	keyPath  string
	tlsCert  tls.Certificate
}

type certOpts struct {
	hostname    bool
	expired     bool
	future      bool
	serverUsage bool
	privateKey  *rsa.PrivateKey
}

func newCertFixture(t *testing.T, dir, name string, opts certOpts) *certFixture {
	t.Helper()
	key := opts.privateKey
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	before := now.Add(-5 * time.Minute)
	after := now.Add(1 * time.Hour)
	if opts.expired {
		before = now.Add(-2 * time.Hour)
		after = now.Add(-1 * time.Hour)
	}
	if opts.future {
		before = now.Add(1 * time.Hour)
		after = now.Add(2 * time.Hour)
	}
	cn := "wrong.example"
	dns := []string{"wrong.example"}
	var ips []net.IP
	if opts.hostname {
		cn = "localhost"
		dns = []string{"localhost"}
		ips = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	eku := x509.ExtKeyUsageClientAuth
	if opts.serverUsage {
		eku = x509.ExtKeyUsageServerAuth
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             before,
		NotAfter:              after,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &certFixture{
		key:      key,
		pem:      string(certPEM),
		certPath: certPath,
		keyPath:  keyPath,
		tlsCert:  tlsCert,
	}
}
