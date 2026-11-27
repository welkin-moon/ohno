//go:build windows

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestWindowsUpdateJournal(t *testing.T) {
	absClient := resolveBuildArtifact("OHNO_UPDATE_JOURNAL_CLIENT", "update-journal-test.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("client %s not found: %v", absClient, err)
	}

	call := func(root, action string, fault int, expected int) string {
		t.Helper()
		args := []string{root, action}
		if fault > 0 {
			args = append(args, strconv.Itoa(fault))
		}
		cmd := exec.Command(absClient, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		_ = cmd.Run()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		if code != expected {
			t.Fatalf("%s/%d: exit %d, want %d: %s", action, fault, code, expected, stderr.String())
		}
		return stdout.String()
	}

	type jState struct {
		Phase      string `json:"phase"`
		Generation int64  `json:"generation"`
		HighWater  int64  `json:"high_water"`
		Active     struct {
			Sequence int64  `json:"sequence"`
			SHA256   string `json:"sha256"`
		} `json:"active"`
	}
	readState := func(root string) (jState, string) {
		raw := call(root, "read", 0, 0)
		var st jState
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			t.Fatalf("parse journal: %v (%s)", err, raw)
		}
		return st, raw
	}

	base := t.TempDir()
	cases := 0
	scenarios := []struct {
		action string
		prior  []string
	}{
		{"prepare", nil},
		{"activate", []string{"prepare"}},
		{"commit", []string{"prepare", "activate"}},
		{"rollback", []string{"prepare"}},
		{"rollback", []string{"prepare", "activate"}},
	}
	for _, sc := range scenarios {
		for point := 1; point <= 7; point++ {
			root := filepath.Join(base, fmt.Sprintf("case-%d", cases))
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			call(root, "init", 0, 0)
			for _, step := range sc.prior {
				call(root, step, 0, 0)
			}
			before, beforeRaw := readState(root)
			call(root, sc.action, point, 100+point)
			landed, landedRaw := readState(root)
			if point <= 5 && landedRaw != beforeRaw {
				t.Fatalf("pre-rename crash altered committed state: %s vs %s", landedRaw, beforeRaw)
			}
			if point >= 6 && landed.Generation != before.Generation+1 {
				t.Fatalf("post-rename crash lost atomic record: gen %d vs %d", landed.Generation, before.Generation+1)
			}
			call(root, "recover", 0, 0)
			after, _ := readState(root)
			if after.Phase != "stable" || after.HighWater < before.HighWater {
				t.Fatalf("recovery lost floor or stayed pending: %+v", after)
			}
			wantHash := strings.Repeat("a", 64)
			if sc.action == "commit" && point >= 6 {
				wantHash = strings.Repeat("b", 64)
			}
			if after.Active.SHA256 != wantHash {
				t.Fatalf("unhealthy candidate ran after recovery: %s != %s", after.Active.SHA256, wantHash)
			}
			if after.HighWater >= 7 {
				call(root, "prepare", 0, 1)
			}
			call(root, "recover", 0, 0)
			cases++
		}
	}

	normal := filepath.Join(base, "normal")
	_ = os.Mkdir(normal, 0o700)
	call(normal, "init", 0, 0)
	call(normal, "init", 0, 1)

	hold := exec.Command(absClient, normal, "hold")
	stdin, _ := hold.StdinPipe()
	stdout, _ := hold.StdoutPipe()
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if strings.TrimSpace(line) != "locked" {
		_ = hold.Process.Kill()
		t.Fatalf("journal lock not acquired: %q", line)
	}
	call(normal, "read", 0, 1)
	_, _ = stdin.Write([]byte("\n"))
	_ = stdin.Close()
	_ = hold.Wait()

	_ = os.WriteFile(filepath.Join(normal, "update-state.next"), []byte("{incomplete"), 0o600)
	call(normal, "prepare", 0, 0)
	call(normal, "activate", 0, 0)
	call(normal, "commit", 0, 0)
	if st, _ := readState(normal); st.Active.Sequence != 7 {
		t.Fatalf("normal commit did not persist: %+v", st)
	}

	stateFile := filepath.Join(normal, "update-state.json")
	good, _ := os.ReadFile(stateFile)
	for _, bad := range [][]byte{{}, []byte("{truncated"), bytes.Repeat([]byte(" "), 4097)} {
		_ = os.WriteFile(stateFile, bad, 0o600)
		call(normal, "read", 0, 1)
		call(normal, "recover", 0, 1)
		got, _ := os.ReadFile(stateFile)
		if !bytes.Equal(got, bad) {
			t.Fatal("corruption silently reconstructed")
		}
	}
	_ = os.WriteFile(stateFile, good, 0o600)

	for _, name := range []string{"update-state.json", "update-state.next", "update.lock"} {
		loc := filepath.Join(base, "links-"+name)
		_ = os.Mkdir(loc, 0o700)
		call(loc, "init", 0, 0)
		target := filepath.Join(loc, name)
		_ = os.Remove(target)
		outside := filepath.Join(base, "outside-"+name)
		_ = os.WriteFile(outside, good, 0o600)
		if err := os.Link(outside, target); err != nil {
			t.Fatal(err)
		}
		call(loc, "prepare", 0, 1)
		got, _ := os.ReadFile(outside)
		if !bytes.Equal(got, good) {
			t.Fatal("hardlink target modified")
		}
	}

	ro := filepath.Join(base, "readonly")
	_ = os.Mkdir(ro, 0o700)
	call(ro, "init", 0, 0)
	roRec := filepath.Join(ro, "update-state.json")
	_ = os.Chmod(roRec, 0o444)
	defer os.Chmod(roRec, 0o666)
	call(ro, "prepare", 0, 1)
	if st, _ := readState(ro); st.HighWater != 0 {
		t.Fatal("failed rename changed selector")
	}
	t.Logf("%d native journal crash cases passed", cases)
}
