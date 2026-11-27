//go:build windows

package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsEdgePolicyProbe(t *testing.T) {
	if os.Getenv("OHNO_RUN_EDGE_PROBE") != "1" {
		t.Skip("set OHNO_RUN_EDGE_PROBE=1 to run headless Edge policy test")
	}
	candidates := []string{
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Microsoft", "Edge", "Application", "msedge.exe"),
	}
	edge := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			edge = c
			break
		}
	}
	if edge == "" {
		t.Fatal("Microsoft Edge is not installed on the runner")
	}

	const marker = "ohno-browser-policy-fixture-7e03"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<!doctype html><title>" + marker + "</title><p>" + marker + "</p>"
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	blockKey, err := regCreateKey(`SOFTWARE\Policies\Microsoft\Edge\URLBlocklist`, keyRead|keyWrite|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	defer regClose(blockKey)
	allowKey, err := regCreateKey(`SOFTWARE\Policies\Microsoft\Edge\URLAllowlist`, keyRead|keyWrite|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	defer regClose(allowKey)

	prevBlock, prevBlockErr := regQueryString(blockKey, "1")
	prevAllow, prevAllowErr := regQueryString(allowKey, "1")
	defer func() {
		if prevBlockErr == nil {
			_ = regSetString(blockKey, "1", prevBlock)
		} else {
			_ = regDeleteValue(blockKey, "1")
		}
		if prevAllowErr == nil {
			_ = regSetString(allowKey, "1", prevAllow)
		} else {
			_ = regDeleteValue(allowKey, "1")
		}
	}()

	tmp := t.TempDir()
	runEdge := func(addr string, idx int) (string, string) {
		cmd := exec.Command(edge, "--headless", "--disable-gpu", "--no-first-run",
			"--disable-background-networking", "--user-data-dir="+filepath.Join(tmp, fmt.Sprintf("profile%d", idx)),
			"--dump-dom", addr)
		var out, errBuf strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		_ = cmd.Run()
		return out.String(), errBuf.String()
	}

	pageURL := fmt.Sprintf("http://localhost:%d/", ln.Addr().(*net.TCPAddr).Port)
	_ = regDeleteValue(blockKey, "1")
	if out, _ := runEdge(pageURL, 0); !strings.Contains(out, marker) {
		t.Fatal("baseline local page did not load in Edge")
	}
	if err := regSetString(blockKey, "1", "localhost"); err != nil {
		t.Fatal(err)
	}
	blocked, errs := runEdge(pageURL, 1)
	if strings.Contains(blocked, marker) {
		t.Fatal("Edge URLBlocklist did not block localhost")
	}
	if !strings.Contains(blocked+errs, "ERR_BLOCKED_BY_ADMINISTRATOR") {
		t.Fatalf("could not confirm browser policy as block reason: %s", errs)
	}
	if err := regSetString(allowKey, "1", ".localhost"); err != nil {
		t.Fatal(err)
	}
	if out, _ := runEdge(pageURL, 10); !strings.Contains(out, marker) {
		t.Fatal("Edge exact-host allowlist did not override block")
	}
}
