//go:build windows

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsCmdExitGate(t *testing.T) {
	wfPath := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	raw, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("read workflow %s: %v", wfPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	count := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "if errorlevel 1 exit /b 1" {
			count++
			if i+1 >= len(lines) || strings.TrimSpace(lines[i+1]) != "if not errorlevel 0 exit /b 1" {
				t.Fatalf("workflow line %d can swallow a negative crash exit", i+1)
			}
		}
	}
	if count <= 20 {
		t.Fatalf("expected >20 native cmd exit guards in release.yml, got %d", count)
	}

	script := filepath.Join(t.TempDir(), "native-gate.cmd")
	content := "@echo off\r\ncmd /d /c exit /b %1\r\nif errorlevel 1 exit /b 1\r\nif not errorlevel 0 exit /b 1\r\nexit /b 0\r\n"
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"0", "1", "2", "-1", "-1073740791", "-1073741819"} {
		cmd := exec.Command("cmd", "/d", "/c", script, code)
		err := cmd.Run()
		got := 0
		if cmd.ProcessState != nil {
			got = cmd.ProcessState.ExitCode()
		}
		want := 1
		if code == "0" {
			want = 0
		}
		if got != want {
			t.Fatalf("exit gate for %s returned %d (err=%v), want %d", code, got, err, want)
		}
	}
}
