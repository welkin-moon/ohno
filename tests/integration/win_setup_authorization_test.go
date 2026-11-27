//go:build windows

package integration

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/welkin-moon/ohno/teacher"
)

func assertCleanMachineState(t *testing.T) {
	t.Helper()
	cmd := exec.Command("sc.exe", "query", "Ohno")
	_ = cmd.Run()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1060 {
		t.Fatal("unexpected existing/mutated Ohno service; aborting")
	}
	for _, p := range []string{`SOFTWARE\Ohno`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ohno`} {
		if regKeyExists(p) {
			t.Fatalf("unexpected existing/mutated registry key %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("ProgramFiles"), "Ohno")); err == nil {
		t.Fatal("unexpected existing/mutated Program Files\\Ohno directory")
	}
}

func TestWindowsSetupAuthorization(t *testing.T) {
	absSetup := resolveBuildArtifact("OHNO_SETUP_EXE", "ohno-setup.exe")
	if _, err := os.Stat(absSetup); err != nil {
		t.Skipf("setup binary %s not found: %v", absSetup, err)
	}

	const password = "CI fixture classroom maintenance passphrase"
	assertCleanMachineState(t)

	root := t.TempDir()
	goodCert := filepath.Join(root, "good.pem")
	goodKey := filepath.Join(root, "good.key")
	otherCert := filepath.Join(root, "other.pem")
	otherKey := filepath.Join(root, "other.key")
	if err := teacher.CreateCertificate(goodCert, goodKey, "localhost"); err != nil {
		t.Fatal(err)
	}
	if err := teacher.CreateCertificate(otherCert, otherKey, "localhost"); err != nil {
		t.Fatal(err)
	}

	tlsCert, err := tls.LoadX509KeyPair(goodCert, goodKey)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	mode := "nonce"
	var bodies [][]byte
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 2048))
		mu.Lock()
		bodies = append(bodies, raw)
		curMode := mode
		mu.Unlock()
		if len(raw) == 0 {
			return
		}
		var req map[string]string
		if err := json.Unmarshal(raw, &req); err != nil {
			return
		}
		now := time.Now().Unix()
		nonce := req["nonce"]
		if curMode == "nonce" && len(nonce) > 0 {
			if nonce[0] == '0' {
				nonce = "1" + nonce[1:]
			} else {
				nonce = "0" + nonce[1:]
			}
		}
		status := 200
		if curMode == "revoked" {
			status = 403
		}
		out, _ := json.Marshal(map[string]any{
			"authorized": true, "action": req["action"], "nonce": nonce,
			"device_id": "", "authorized_at": now, "expires_at": now + 120,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		w.WriteHeader(status)
		_, _ = w.Write(out)
	})}
	go func() {
		_ = srv.Serve(tls.NewListener(rawLn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsCert}}))
	}()
	defer srv.Close()

	origin := "https://localhost:" + strconv.Itoa(rawLn.Addr().(*net.TCPAddr).Port)
	attempt := func(orig, cert string) {
		t.Helper()
		assertCleanMachineState(t)
		cmd := exec.Command(absSetup, "--install", orig, "--certificate", cert, "--password-stdin")
		cmd.Stdin = strings.NewReader(password + "\n")
		_ = cmd.Run()
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
			t.Fatal("negative setup unexpectedly succeeded")
		}
		assertCleanMachineState(t)
	}

	attempt(origin, otherCert)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	for _, b := range bodies {
		if len(b) > 0 {
			mu.Unlock()
			t.Fatal("wrong pinned cert received secret body")
		}
	}
	mu.Unlock()

	attempt(origin, goodCert)
	mu.Lock()
	mode = "revoked"
	mu.Unlock()
	attempt(origin, goodCert)

	// Cancel native maintenance password prompt via WM_CLOSE -> status 2, zero requests.
	mu.Lock()
	before := len(bodies)
	mu.Unlock()

	findPrompt := func(proc *exec.Cmd) uintptr {
		cls, _ := syscall.UTF16PtrFromString("OhnoMaintenancePasswordV1")
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
			if hwnd != 0 {
				return hwnd
			}
			time.Sleep(100 * time.Millisecond)
		}
		return 0
	}

	proc := exec.Command(absSetup, "--install", origin, "--certificate", goodCert)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	hwnd := findPrompt(proc)
	if hwnd == 0 {
		_ = proc.Process.Kill()
		t.Fatal("native maintenance password prompt did not appear")
	}
	pPostMessageW.Call(hwnd, 0x0010, 0, 0) // WM_CLOSE
	_ = proc.Wait()
	if proc.ProcessState.ExitCode() != 2 {
		t.Fatalf("cancel returned %d, want 2", proc.ProcessState.ExitCode())
	}
	assertCleanMachineState(t)
	mu.Lock()
	if len(bodies) != before {
		mu.Unlock()
		t.Fatal("cancel contacted teacher server")
	}
	mode = "nonce"
	mu.Unlock()

	// Enter password through edit control and double-submit IDOK.
	proc2 := exec.Command(absSetup, "--install", origin, "--certificate", goodCert)
	if err := proc2.Start(); err != nil {
		t.Fatal(err)
	}
	hwnd = findPrompt(proc2)
	if hwnd == 0 {
		_ = proc2.Process.Kill()
		t.Fatal("repeated password prompt did not appear")
	}
	edit, _, _ := pGetDlgItem.Call(hwnd, 201)
	pwUTF16, _ := syscall.UTF16FromString(password)
	var reply uintptr
	okSend, _, _ := pSendMessageTimeoutW.Call(edit, 0x000C, 0, uintptr(unsafe.Pointer(&pwUTF16[0])), 3, 5000, uintptr(unsafe.Pointer(&reply)))
	if edit == 0 || okSend == 0 || reply == 0 {
		_ = proc2.Process.Kill()
		t.Fatal("password edit unavailable")
	}
	pPostMessageW.Call(hwnd, 0x0111, 1, 0)
	pPostMessageW.Call(hwnd, 0x0111, 1, 0)
	_ = proc2.Wait()
	if proc2.ProcessState.ExitCode() != 1 {
		t.Fatalf("mismatched nonce returned %d, want 1", proc2.ProcessState.ExitCode())
	}
	assertCleanMachineState(t)

	// Offline port refused.
	unused, _ := net.Listen("tcp", "127.0.0.1:0")
	offPort := unused.Addr().(*net.TCPAddr).Port
	_ = unused.Close()
	attempt("https://localhost:"+strconv.Itoa(offPort), goodCert)

	// Confirm neither cert was added to LocalMachine Root.
	for _, p := range []string{goodCert, otherCert} {
		raw, _ := os.ReadFile(p)
		blk, _ := pem.Decode(raw)
		sum := sha1.Sum(blk.Bytes)
		thumb := strings.ToUpper(hex.EncodeToString(sum[:]))
		c := exec.Command("certutil", "-store", "Root", thumb)
		if c.Run() == nil {
			t.Fatalf("rejected setup installed machine root %s", thumb)
		}
	}
	_ = bytes.NewReader
}
