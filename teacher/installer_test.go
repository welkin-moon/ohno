package teacher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func TestSchoolInstallerRoundTripAndTrust(t *testing.T) {
	base := append([]byte("MZ"), make([]byte, 4096)...)
	cert := []byte("-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 160) + "\n-----END CERTIFICATE-----\n")

	packaged, err := BuildSchoolInstaller(base, "https://teacher-pc:8443", cert, "")
	if err != nil {
		t.Fatalf("BuildSchoolInstaller v1 failed: %v", err)
	}
	gotURL, gotCert, err := GetSchoolConfiguration(packaged)
	if err != nil || gotURL != "https://teacher-pc:8443" || !bytes.Equal(gotCert, cert) {
		t.Fatalf("v1 roundtrip mismatch: %q %v", gotURL, err)
	}
	var wantTrailer [TrailerV1Size]byte
	binary.LittleEndian.PutUint32(wantTrailer[0:4], 23)
	binary.LittleEndian.PutUint32(wantTrailer[4:8], uint32(len(cert)))
	copy(wantTrailer[8:16], InstallerMagicV1)
	if !bytes.HasSuffix(packaged, wantTrailer[:]) {
		t.Fatal("v1 trailer format mismatch")
	}

	// v2 with P-256 public key.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubHex, _ := PublicKeyHex(&priv.PublicKey)
	packagedV2, err := BuildSchoolInstaller(base, "https://teacher-pc:8443", cert, pubHex)
	if err != nil {
		t.Fatalf("BuildSchoolInstaller v2 failed: %v", err)
	}
	u2, c2, k2, err := GetSchoolTrust(packagedV2)
	if err != nil || u2 != "https://teacher-pc:8443" || !bytes.Equal(c2, cert) || k2 != pubHex {
		t.Fatalf("v2 roundtrip mismatch: %q %q %v", u2, k2, err)
	}
	if bytes.Contains(packagedV2, []byte("PRIVATE KEY")) {
		t.Fatal("private key material found in installer")
	}
	for _, invalid := range []string{strings.ToUpper(pubHex), "04" + strings.Repeat("0", 128), pubHex[:len(pubHex)-1], pubHex + "0"} {
		if _, err := BuildSchoolInstaller(base, "https://teacher-pc:8443", cert, invalid); err == nil {
			t.Fatalf("expected error for invalid release key %q", invalid[:min(8, len(invalid))])
		}
	}
	malformed := append([]byte{}, packagedV2...)
	copy(malformed[len(malformed)-12:len(malformed)-8], []byte{0, 0, 0, 0})
	if _, _, _, err := GetSchoolTrust(malformed); err == nil {
		t.Fatal("expected error for malformed v2 trailer")
	}

	// Reject insecure/broken origins.
	badOrigins := []string{
		"http://teacher-pc:8443", "https://teacher-pc:8443/path",
		"https://user:pw@teacher:8443", "https://teacher-pc:8443?x=1",
		"https://teacher-pc", "https://teacher-pc:abc",
		"https://tea\ncher:8443", "https://tea\tcher:8443",
		"https://bad host:8443", "https://teacher:8443?",
		"https://teacher:8443#", "https://teacher:0",
		"https://teacher:65536", "https://teacher:8443\\",
		"https://teacher:8443/\x00",
	}
	for _, origin := range badOrigins {
		if _, err := BuildSchoolInstaller(base, origin, cert, ""); err == nil {
			t.Fatalf("expected rejection for origin %q", origin)
		}
	}
	for _, badCert := range [][]byte{{}, []byte("not a certificate"), append([]byte("-----BEGIN PRIVATE KEY-----"), bytes.Repeat([]byte("A"), 256)...)} {
		if _, err := BuildSchoolInstaller(base, "https://teacher-pc:8443", badCert, ""); err == nil {
			t.Fatal("expected rejection for invalid certificate")
		}
	}
	if _, _, err := GetSchoolConfiguration(base); err == nil {
		t.Fatal("expected error without trailer")
	}
	if _, _, err := GetSchoolConfiguration(packaged[:len(packaged)-1]); err == nil {
		t.Fatal("expected error on truncated trailer")
	}

	// IPv6 bracketing.
	v6, err := EnrollmentOrigin("2001:db8::1", 8443)
	if err != nil || v6 != "https://[2001:db8::1]:8443" {
		t.Fatalf("unexpected IPv6 origin %q %v", v6, err)
	}
	pkgV6, err := BuildSchoolInstaller(base, v6, cert, "")
	if err != nil {
		t.Fatalf("v6 build failed: %v", err)
	}
	gotV6, _, err := GetSchoolConfiguration(pkgV6)
	if err != nil || gotV6 != v6 {
		t.Fatalf("v6 roundtrip failed: %q %v", gotV6, err)
	}
}
