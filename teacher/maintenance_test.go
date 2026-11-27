package teacher

import (
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestMaintenanceGuard(t *testing.T) {
	const password = "A classroom maintenance phrase!"
	cred, err := CreateCredential(password)
	if err != nil {
		t.Fatal(err)
	}

	// Salted slow hash and Unicode password.
	first, err := CreateCredential("教师维护密码只用于安装和卸载")
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateCredential("教师维护密码只用于安装和卸载")
	if err != nil {
		t.Fatal(err)
	}
	if first.Salt == second.Salt || first.Digest == second.Digest {
		t.Fatal("credentials must use unique random salts")
	}
	if first.Iterations != MaintenanceIterations {
		t.Fatalf("unexpected iterations %d", first.Iterations)
	}
	if !NewMaintenanceGuard().Verify("教师维护密码只用于安装和卸载", first, "test") {
		t.Fatal("unicode maintenance password failed verification")
	}

	// Password boundaries.
	for _, bad := range []string{"", "short", strings.Repeat("a", 129), strings.Repeat("a", 11) + "\n", strings.Repeat("a", 11) + "\x00", string([]byte{0xff, 0xfe}) + strings.Repeat("a", 12)} {
		if _, err := PasswordBytes(bad); err == nil {
			t.Fatalf("expected PasswordBytes rejection for %q", bad)
		}
	}
	if b, err := PasswordBytes(strings.Repeat("a", 12)); err != nil || len(b) != 12 {
		t.Fatalf("12 ASCII chars should succeed: %v", err)
	}
	if b, err := PasswordBytes(strings.Repeat("😀", 128)); err != nil || len(b) != 512 {
		t.Fatalf("128 4-byte runes should succeed: %v", err)
	}

	// Malformed credentials never invoke PBKDF2.
	calls := 0
	guard := NewMaintenanceGuard()
	guard.derive = func(p, s []byte, it int) ([]byte, error) {
		calls++
		return pbkdf2SHA256(p, s, it)
	}
	badCreds := []*MaintenanceCredential{
		nil,
		{},
		{Algorithm: "pbkdf2-sha256", Iterations: 1000, Salt: cred.Salt, Digest: cred.Digest},
		{Algorithm: "pbkdf2-sha256", Iterations: MaintenanceIterations, Salt: strings.Repeat("z", 32), Digest: cred.Digest},
		{Algorithm: "pbkdf2-sha256", Iterations: MaintenanceIterations, Salt: cred.Salt, Digest: strings.Repeat("a", 63)},
		{Algorithm: "sha256", Iterations: MaintenanceIterations, Salt: cred.Salt, Digest: cred.Digest},
	}
	for _, bc := range badCreds {
		if guard.Verify(password, bc, "test") {
			t.Fatal("malformed credential accepted")
		}
	}
	if calls != 0 {
		t.Fatalf("PBKDF2 called %d times on malformed credentials", calls)
	}
	if guard.Verify("Wrong classroom maintenance phrase!", cred, "test") {
		t.Fatal("wrong password accepted")
	}
	if !guard.Verify(password, cred, "test") {
		t.Fatal("valid password rejected")
	}

	// Per-source, global, and retained history bounds.
	now := 0.0
	deriveCalls := 0
	digestBytes, _ := hex.DecodeString(cred.Digest)
	bounded := NewMaintenanceGuard()
	bounded.clock = func() float64 { return now }
	bounded.derive = func(p, s []byte, it int) ([]byte, error) {
		deriveCalls++
		return digestBytes, nil
	}
	for i := 0; i < MaintenancePerSource; i++ {
		if !bounded.Verify(password, cred, "one") {
			t.Fatalf("per-source attempt %d failed", i)
		}
	}
	if bounded.Verify(password, cred, "one") {
		t.Fatal("exceeded per-source limit")
	}
	for i := 0; i < MaintenanceGlobalLimit-MaintenancePerSource; i++ {
		if !bounded.Verify(password, cred, strconv.Itoa(i)) {
			t.Fatalf("global attempt %d failed", i)
		}
	}
	for i := 0; i < 1000; i++ {
		if bounded.Verify(password, cred, "new-"+strconv.Itoa(i)) {
			t.Fatal("exceeded global limit")
		}
	}
	if deriveCalls != MaintenanceGlobalLimit || bounded.AttemptCount() != MaintenanceGlobalLimit {
		t.Fatalf("unexpected deriveCalls=%d attempts=%d", deriveCalls, bounded.AttemptCount())
	}
	now = MaintenanceWindow
	if !bounded.Verify(password, cred, "one") || bounded.AttemptCount() != 1 {
		t.Fatal("window expiry did not reset attempts")
	}

	// Only two concurrent KDFs.
	conc := NewMaintenanceGuard()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	conc.derive = func(p, s []byte, it int) ([]byte, error) {
		entered <- struct{}{}
		<-release
		return digestBytes, nil
	}
	var wg sync.WaitGroup
	results := make([]bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = conc.Verify(password, cred, "test")
		}(i)
	}
	<-entered
	<-entered
	if conc.Verify(password, cred, "third") {
		t.Fatal("third concurrent KDF should be rejected")
	}
	close(release)
	wg.Wait()
	if !results[0] || !results[1] {
		t.Fatalf("expected both concurrent verifies to succeed, got %v", results)
	}
}
