//go:build windows

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsInstalledPayload(t *testing.T) {
	absClient := resolveBuildArtifact("OHNO_INSTALLED_PAYLOAD_CLIENT", "installed-payload-test.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("client %s not found: %v", absClient, err)
	}

	root := t.TempDir()
	pkgPath := filepath.Join(root, "fixture.ohno")
	if err := os.WriteFile(pkgPath, fixturePackage(t, "0.2.0", nil), 0o600); err != nil {
		t.Fatal(err)
	}

	call := func(dir, action string, expected int) {
		t.Helper()
		args := []string{dir, action}
		if action == "init" {
			args = append(args, pkgPath)
		}
		cmd := exec.Command(absClient, args...)
		_ = cmd.Run()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		if code != expected {
			t.Fatalf("%s %s: exit %d, want %d", filepath.Base(dir), action, code, expected)
		}
	}
	install := func(name string) (string, string) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		call(dir, "init", 0)
		entries, err := os.ReadDir(filepath.Join(dir, "versions"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("missing version dir in %s: %v", dir, err)
		}
		return dir, filepath.Join(dir, "versions", entries[0].Name())
	}

	dir, _ := install("normal")
	call(dir, "view", 0)
	_ = os.WriteFile(filepath.Join(dir, "download-"+strings.Repeat("a", 64)+".tmp"), []byte("partial"), 0o600)
	call(dir, "remove", 0)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("expected empty dir after remove, got %d entries", len(entries))
	}

	dir, ver := install("tamper")
	_ = os.WriteFile(filepath.Join(ver, "ohno-request.exe"), []byte("changed"), 0o600)
	call(dir, "view", 1)
	call(dir, "remove", 0)

	dir, ver = install("unknown")
	unknown := filepath.Join(ver, "school-note.txt")
	_ = os.WriteFile(unknown, []byte("do not delete"), 0o600)
	call(dir, "remove", 1)
	if got, _ := os.ReadFile(unknown); string(got) != "do not delete" {
		t.Fatal("unknown file deleted")
	}

	dir, ver = install("hardlink")
	outside := filepath.Join(root, "outside.txt")
	_ = os.WriteFile(outside, []byte("leave outside"), 0o600)
	target := filepath.Join(ver, "ohno-request.exe")
	_ = os.Remove(target)
	if err := os.Link(outside, target); err != nil {
		t.Fatal(err)
	}
	call(dir, "view", 1)
	call(dir, "remove", 1)
	if got, _ := os.ReadFile(outside); string(got) != "leave outside" {
		t.Fatal("hardlink outside modified")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("hardlink target unexpectedly removed")
	}

	dir, _ = install("bad-state")
	_ = os.WriteFile(filepath.Join(dir, "update-state.json"), []byte("{bad"), 0o600)
	call(dir, "view", 1)
	call(dir, "remove", 0)

	dir, ver = install("reparse")
	link := filepath.Join(root, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v (%s)", err, string(out))
	}
	call(link, "view", 1)
	call(link, "remove", 1)
	if _, err := os.Stat(filepath.Join(ver, "ohno-worker.exe")); err != nil {
		t.Fatal("reparse remove touched target")
	}
	_ = os.Remove(link)

	dir, _ = install("unknown-root")
	unknownRoot := filepath.Join(dir, "school-note.txt")
	_ = os.WriteFile(unknownRoot, []byte("retained"), 0o600)
	call(dir, "remove", 0)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "school-note.txt" {
		t.Fatalf("unknown root file not preserved: %v", entries)
	}
}
