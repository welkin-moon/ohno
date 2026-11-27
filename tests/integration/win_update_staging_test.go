//go:build windows

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/welkin-moon/ohno/teacher"
)

const (
	fixtureUpdateDevice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixtureUpdateKey    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type updateFixtureServer struct {
	mu       sync.Mutex
	srv      *http.Server
	ln       net.Listener
	origin   string
	mode     string
	offer    teacher.UpdateManifest
	pkg      []byte
	requests []string
}

func startUpdateFixtureServer(t *testing.T, certPath, keyPath string) *updateFixtureServer {
	t.Helper()
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &updateFixtureServer{
		ln:     rawLn,
		origin: "https://127.0.0.1:" + strconv.Itoa(rawLn.Addr().(*net.TCPAddr).Port),
		mode:   "normal",
	}
	u.srv = &http.Server{Handler: http.HandlerFunc(u.handle)}
	tlsLn := tls.NewListener(rawLn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsCert}})
	go func() { _ = u.srv.Serve(tlsLn) }()
	return u
}

func (u *updateFixtureServer) close() {
	_ = u.srv.Close()
}

func (u *updateFixtureServer) setState(mode string, offer teacher.UpdateManifest, pkg []byte) {
	u.mu.Lock()
	u.mode = mode
	u.offer = offer
	u.pkg = pkg
	u.mu.Unlock()
}

func (u *updateFixtureServer) setMode(mode string) {
	u.mu.Lock()
	u.mode = mode
	u.mu.Unlock()
}

func (u *updateFixtureServer) requestPaths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, len(u.requests))
	copy(out, u.requests)
	return out
}

func (u *updateFixtureServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Ohno-Key") != "" || r.Header.Get("X-Ohno-Device") != "" {
		w.WriteHeader(500)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2048))
	if err != nil || len(raw) == 0 {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return
	}
	u.mu.Lock()
	u.requests = append(u.requests, r.URL.Path)
	mode := u.mode
	offer := u.offer
	pkg := u.pkg
	origin := u.origin
	u.mu.Unlock()

	if body["device_id"] != fixtureUpdateDevice || body["device_key"] != fixtureUpdateKey {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte("{}"))
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/offer"):
		if mode == "no_offer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte("{}"))
			return
		}
		if mode == "bad_signature" {
			offer.Signature = strings.Repeat("0", 128)
		}
		if mode == "wrong_platform" {
			offer.Platform = "windows-arm64"
		}
		b, _ := json.Marshal(offer)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(200)
		_, _ = w.Write(b)
	case strings.Contains(r.URL.Path, "/package/"):
		if mode == "redirect" {
			w.Header().Set("Location", origin+"/trap")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(307)
			_, _ = w.Write([]byte("{}"))
			return
		}
		data := append([]byte(nil), pkg...)
		switch mode {
		case "tampered":
			data[len(data)-1] ^= 1
		case "oversized":
			data = append(data, 'x')
		case "short":
			data = data[:len(data)-1]
		case "slow":
			time.Sleep(300 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(200)
		_, _ = w.Write(data)
	case strings.HasSuffix(r.URL.Path, "/authorize"):
		if mode == "revoked" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			_, _ = w.Write([]byte("{}"))
			return
		}
		now := time.Now().Unix()
		nonce, _ := body["nonce"].(string)
		res := map[string]any{
			"authorized":    true,
			"nonce":         nonce,
			"device_id":     fixtureUpdateDevice,
			"sequence":      offer.Sequence,
			"sha256":        offer.SHA256,
			"authorized_at": now,
			"expires_at":    now + 120,
		}
		switch mode {
		case "wrong_nonce":
			res["nonce"] = strings.Repeat("0", 64)
		case "wrong_hash":
			res["sha256"] = strings.Repeat("0", 64)
		case "wrong_device":
			res["device_id"] = strings.Repeat("c", 32)
		case "wrong_sequence":
			res["sequence"] = offer.Sequence + 1
		case "expired":
			res["authorized_at"] = now - 151
			res["expires_at"] = now - 31
		}
		b, _ := json.Marshal(res)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(200)
		_, _ = w.Write(b)
	default:
		w.WriteHeader(404)
	}
}

func TestWindowsUpdateStaging(t *testing.T) {
	absClient := resolveBuildArtifact("OHNO_UPDATE_CLIENT", "update-client-test.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("client %s not found: %v", absClient, err)
	}

	root := t.TempDir()
	if err := teacher.CreateCertificate(filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem"), "localhost"); err != nil {
		t.Fatal(err)
	}
	if err := teacher.CreateCertificate(filepath.Join(root, "other.pem"), filepath.Join(root, "other.key"), "localhost"); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(filepath.Join(root, "cert.pem"))
	otherPEM, _ := os.ReadFile(filepath.Join(root, "other.pem"))

	releaseKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubHex, _ := teacher.PublicKeyHex(&releaseKey.PublicKey)
	payload := fixturePackage(t, "0.2.0", nil)
	pkgFile := filepath.Join(root, "source.ohno")
	_ = os.WriteFile(pkgFile, payload, 0o600)
	sum := sha256.Sum256(payload)
	now := time.Now().Unix()
	manifest, err := teacher.SignManifest(teacher.UpdateManifestFields{
		Schema: 1, Platform: "windows-x64", Sequence: 7, Version: "0.2.0", MinUpdater: 1,
		IssuedAt: now, ExpiresAt: now + 3600, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]),
	}, releaseKey)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, _ := json.Marshal(manifest)

	srv := startUpdateFixtureServer(t, filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem"))
	defer srv.close()
	srv.setState("normal", manifest, payload)

	invoke := func(dir, mode string, expected int, initialize bool, overrides map[string]any) map[string]any {
		t.Helper()
		_ = os.MkdirAll(dir, 0o700)
		cfg := map[string]any{
			"mode": mode, "root": dir, "initialize": initialize, "server": srv.origin,
			"certificate": string(certPEM), "public_key": pubHex,
			"device_id": fixtureUpdateDevice, "device_key": fixtureUpdateKey,
			"document": string(manifestJSON), "package": pkgFile,
		}
		for k, v := range overrides {
			cfg[k] = v
		}
		inBytes, _ := json.Marshal(cfg)
		cmd := exec.Command(absClient)
		cmd.Stdin = bytes.NewReader(inBytes)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		_ = cmd.Run()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		if code != expected {
			t.Fatalf("%s (%s): exit %d, want %d: %s", filepath.Base(dir), mode, code, expected, stderr.String())
		}
		if stdout.Len() == 0 {
			return nil
		}
		var out map[string]any
		_ = json.Unmarshal(stdout.Bytes(), &out)
		return out
	}

	for _, mode := range []string{"normal", "revoked", "wrong_nonce", "wrong_hash", "wrong_device", "wrong_sequence", "expired"} {
		srv.setMode(mode)
		dir := filepath.Join(root, mode)
		res := invoke(dir, "fetch", 0, true, nil)
		if res["staged"] != true || res["authorized"] != (mode == "normal") {
			t.Fatalf("execution decision binding failed for %s: %v", mode, res)
		}
		var st map[string]any
		rawSt, _ := os.ReadFile(filepath.Join(dir, "update-state.json"))
		_ = json.Unmarshal(rawSt, &st)
		if st["high_water"].(float64) != 0 || st["phase"] != "stable" {
			t.Fatalf("staging changed active selector: %v", st)
		}
		staged := filepath.Join(dir, "versions", "7-"+manifest.SHA256)
		for _, name := range teacher.PackageFiles {
			if _, err := os.Stat(filepath.Join(staged, name)); err != nil {
				t.Fatalf("missing staged file %s", name)
			}
		}
		if tmps, _ := filepath.Glob(filepath.Join(dir, "download-*.tmp")); len(tmps) > 0 {
			t.Fatal("download buffer not cleaned")
		}
	}

	for _, mode := range []string{"bad_signature", "wrong_platform", "tampered", "oversized", "short", "redirect"} {
		srv.setMode(mode)
		dir := filepath.Join(root, mode)
		before := len(srv.requestPaths())
		invoke(dir, "fetch", 1, true, nil)
		if _, err := os.Stat(filepath.Join(dir, "versions")); err == nil {
			t.Fatalf("%s: invalid package reached extraction", mode)
		}
		reqs := srv.requestPaths()
		if (mode == "bad_signature" || mode == "wrong_platform") && len(reqs) != before+1 {
			t.Fatalf("%s: download preceded manifest authentication", mode)
		}
		for _, p := range reqs {
			if strings.HasSuffix(p, "/trap") {
				t.Fatal("redirect followed")
			}
		}
		if tmps, _ := filepath.Glob(filepath.Join(dir, "download-*.tmp")); len(tmps) > 0 {
			t.Fatal("failed download left tmp file")
		}
	}

	srv.setMode("normal")
	before := len(srv.requestPaths())
	invoke(filepath.Join(root, "wrong-pin"), "fetch", 1, true, map[string]any{"certificate": string(otherPEM)})
	if len(srv.requestPaths()) != before {
		t.Fatal("wrong TLS pin received credentials")
	}
	otherRelKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPubHex, _ := teacher.PublicKeyHex(&otherRelKey.PublicKey)
	invoke(filepath.Join(root, "wrong-release-key"), "fetch", 1, true, map[string]any{"public_key": otherPubHex})
	invoke(filepath.Join(root, "replay"), "fetch", 1, true, map[string]any{"floor": 7})
	before = len(srv.requestPaths())
	invoke(filepath.Join(root, "canceled-before"), "fetch", 1, true, map[string]any{"cancel_before": true})
	if len(srv.requestPaths()) != before {
		t.Fatal("canceled operation contacted teacher")
	}
	srv.setMode("slow")
	invoke(filepath.Join(root, "canceled-download"), "fetch", 1, true, map[string]any{"cancel_ms": 50})
	srv.setMode("no_offer")
	noOffer := invoke(filepath.Join(root, "no-offer"), "fetch", 0, true, nil)
	if noOffer["staged"] != false {
		t.Fatalf("missing offer staged candidate: %v", noOffer)
	}
	srv.setMode("normal")

	// Tamper check on extracted file.
	staged := filepath.Join(root, "normal", "versions", "7-"+manifest.SHA256)
	target := filepath.Join(staged, teacher.PackageFiles[0])
	saved, _ := os.ReadFile(target)
	tampered := append([]byte(nil), saved...)
	tampered[len(tampered)-1] = 'x'
	_ = os.WriteFile(target, tampered, 0o600)
	invoke(filepath.Join(root, "normal"), "verify", 1, false, nil)
	_ = os.WriteFile(target, saved, 0o600)
	invoke(filepath.Join(root, "normal"), "verify", 0, false, nil)

	// Hardlink archive rejected.
	linked := filepath.Join(root, "source-link.ohno")
	_ = os.Link(pkgFile, linked)
	invoke(filepath.Join(root, "hardlink"), "stage", 1, true, nil)
	_ = os.Remove(linked)

	// Blocked versions path preserved.
	blocked := filepath.Join(root, "blocked-directory")
	_ = os.Mkdir(blocked, 0o700)
	_ = os.WriteFile(filepath.Join(blocked, "versions"), []byte("fixture obstacle"), 0o600)
	invoke(blocked, "stage", 1, true, nil)
	if got, _ := os.ReadFile(filepath.Join(blocked, "versions")); string(got) != "fixture obstacle" {
		t.Fatal("failed staging overwrote obstacle")
	}

	// 10 staging crash points.
	for point := 1; point <= 10; point++ {
		dir := filepath.Join(root, "crash-"+strconv.Itoa(point))
		invoke(dir, "stage", 100+point, true, map[string]any{"fault": point})
		var st map[string]any
		rawSt, _ := os.ReadFile(filepath.Join(dir, "update-state.json"))
		_ = json.Unmarshal(rawSt, &st)
		if st["phase"] != "stable" || st["high_water"].(float64) != 0 {
			t.Fatalf("partial payload selected at crash %d", point)
		}
		invoke(dir, "stage", 0, false, nil)
		if leftover, _ := filepath.Glob(filepath.Join(dir, "versions", ".stage-*")); len(leftover) > 0 {
			t.Fatalf("interrupted staging dir not reclaimed at crash %d", point)
		}
	}

	// Initial unsigned baseline.
	initial := invoke(filepath.Join(root, "initial"), "initial", 0, false, nil)
	active := initial["active"].(map[string]any)
	if active["sequence"].(float64) != 0 {
		t.Fatalf("baseline sequence wrong: %v", active)
	}
}
