//go:build windows

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/welkin-moon/ohno/teacher"
)

func TestWindowsUpdateRuntime(t *testing.T) {
	absClient := resolveBuildArtifact("OHNO_UPDATE_RUNTIME_CLIENT", "update-runtime-test.exe")
	absWorker := resolveBuildArtifact("OHNO_WORKER_FIXTURE", "worker-fixture.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("client %s not found: %v", absClient, err)
	}
	workerBytes, err := os.ReadFile(absWorker)
	if err != nil {
		t.Skipf("worker fixture %s not found: %v", absWorker, err)
	}

	root := t.TempDir()
	_ = teacher.CreateCertificate(filepath.Join(root, "cert.pem"), filepath.Join(root, "tls.key"), "localhost")
	_ = teacher.CreateCertificate(filepath.Join(root, "other.pem"), filepath.Join(root, "other.key"), "localhost")
	certPEM, _ := os.ReadFile(filepath.Join(root, "cert.pem"))
	otherPEM, _ := os.ReadFile(filepath.Join(root, "other.pem"))

	releaseKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubHex, _ := teacher.PublicKeyHex(&releaseKey.PublicKey)

	baseline := filepath.Join(root, "baseline.ohno")
	_ = os.WriteFile(baseline, fixturePackage(t, "0.1.0", workerBytes), 0o600)

	srv := startUpdateFixtureServer(t, filepath.Join(root, "cert.pem"), filepath.Join(root, "tls.key"))
	defer srv.close()

	setOffer := func(version string, seq int64, mode string) {
		pkg := fixturePackage(t, version, workerBytes)
		sum := sha256.Sum256(pkg)
		now := time.Now().Unix()
		m, err := teacher.SignManifest(teacher.UpdateManifestFields{
			Schema: 1, Platform: "windows-x64", Sequence: seq, Version: version, MinUpdater: 1,
			IssuedAt: now, ExpiresAt: now + 3600, Size: int64(len(pkg)), SHA256: hex.EncodeToString(sum[:]),
		}, releaseKey)
		if err != nil {
			t.Fatal(err)
		}
		srv.setState(mode, m, pkg)
	}

	makeCfg := func(dir string, initialize bool, overrides map[string]any) map[string]any {
		_ = os.MkdirAll(dir, 0o700)
		cfg := map[string]any{
			"root": dir, "initialize": initialize, "baseline": baseline, "server": srv.origin,
			"certificate": string(certPEM), "public_key": pubHex,
			"device_id": fixtureUpdateDevice, "device_key": fixtureUpdateKey,
			"stop_ms": 20000, "crash": 0, "stop_at": 0,
			"fail_drain": false, "fail_start": false, "fail_drain_on_start": false,
			"stop_after_poll": true, "stop_after_rollback": false,
		}
		for k, v := range overrides {
			cfg[k] = v
		}
		return cfg
	}

	readEvents := func(dir string) []string {
		raw, err := os.ReadFile(filepath.Join(dir, "worker-events.log"))
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}

	assertStopped := func(dir string) {
		t.Helper()
		pids := map[uint32]struct{}{}
		for _, line := range readEvents(dir) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if p, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					pids[uint32(p)] = struct{}{}
				}
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			anyAlive := false
			for p := range pids {
				if winProcessAlive(p) {
					anyAlive = true
					break
				}
			}
			if !anyAlive {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: orphan worker process still alive", filepath.Base(dir))
	}

	type runtimeState struct {
		Phase     string `json:"phase"`
		HighWater int64  `json:"high_water"`
		Active    struct {
			Sequence int64 `json:"sequence"`
		} `json:"active"`
	}

	runCase := func(dir string, expected int, initialize bool, overrides map[string]any) runtimeState {
		t.Helper()
		inBytes, _ := json.Marshal(makeCfg(dir, initialize, overrides))
		cmd := exec.Command(absClient)
		cmd.Stdin = bytes.NewReader(inBytes)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		if code != expected {
			t.Fatalf("%s: exit %d, want %d; stderr=%s events=%v", filepath.Base(dir), code, expected, stderr.String(), readEvents(dir))
		}
		raw, err := os.ReadFile(filepath.Join(dir, "update-state.json"))
		if err != nil {
			t.Fatalf("%s: read journal: %v", filepath.Base(dir), err)
		}
		var st runtimeState
		_ = json.Unmarshal(raw, &st)
		return st
	}

	assertState := func(st runtimeState, seq, floor int64) {
		t.Helper()
		if st.Phase != "stable" || st.Active.Sequence != seq || st.HighWater != floor {
			t.Fatalf("unexpected state: %+v (want stable seq=%d floor=%d)", st, seq, floor)
		}
	}

	countMatching := func(lines []string, sub string) int {
		n := 0
		for _, l := range lines {
			if strings.Contains(l, sub) {
				n++
			}
		}
		return n
	}

	// Normal healthy update & offline restart.
	setOffer("0.2.0", 7, "normal")
	dir := filepath.Join(root, "success")
	assertState(runCase(dir, 0, true, nil), 7, 7)
	if countMatching(readEvents(dir), " start 7 ") != 1 {
		t.Fatal("expected single start of seq 7")
	}
	assertStopped(dir)
	srv.setMode("no_offer")
	assertState(runCase(dir, 0, false, nil), 7, 7)
	assertStopped(dir)

	// Authorization / signature / tamper rejections.
	for _, mode := range []string{"revoked", "wrong_nonce", "wrong_hash", "wrong_device", "wrong_sequence", "expired", "bad_signature", "tampered"} {
		setOffer("0.2.0", 7, mode)
		d := filepath.Join(root, mode)
		assertState(runCase(d, 0, true, nil), 0, 0)
		if countMatching(readEvents(d), " start 7 ") != 0 {
			t.Fatalf("%s unexpectedly started seq 7", mode)
		}
		assertStopped(d)
	}

	setOffer("0.2.0", 7, "normal")
	dWrongCert := filepath.Join(root, "wrong-cert")
	assertState(runCase(dWrongCert, 0, true, map[string]any{"certificate": string(otherPEM)}), 0, 0)
	assertStopped(dWrongCert)

	// Unhealthy candidate rollback & silent health timeout.
	for _, bad := range []string{"exit", "nohealth", "nohealth-open", "nonce", "revision", "zero", "malformed", "oversize"} {
		setOffer("0.2.0-"+bad, 7, "normal")
		d := filepath.Join(root, "bad-"+bad)
		assertState(runCase(d, 0, true, map[string]any{"stop_after_poll": false, "stop_after_rollback": true}), 0, 7)
		evs := readEvents(d)
		if countMatching(evs, " start 7 ") != 1 || countMatching(evs, " start 0 ") < 2 {
			t.Fatalf("bad-%s events mismatch: %v", bad, evs)
		}
		assertStopped(d)
		if bad == "nohealth-open" {
			var silences []int
			for _, l := range evs {
				if strings.Contains(l, " silent-ms ") {
					parts := strings.Fields(l)
					if ms, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
						silences = append(silences, ms)
					}
				}
			}
			if len(silences) != 1 || silences[0] < 2800 || silences[0] > 6000 {
				t.Fatalf("bounded silent health timeout mismatch: %v", silences)
			}
		}
	}

	// Stop at boundary points.
	for _, pt := range []int{4, 5, 6, 7, 10, 11, 12} {
		setOffer("0.2.0", 7, "normal")
		d := filepath.Join(root, "stop-"+strconv.Itoa(pt))
		assertState(runCase(d, 0, true, map[string]any{"stop_at": pt}), 0, 7)
		if countMatching(readEvents(d), " start 0 ") != 1 {
			t.Fatalf("stop-%d unexpected start count", pt)
		}
		assertStopped(d)
	}

	// Nine host crashes + offline recovery.
	for _, pt := range []int{4, 5, 6, 7, 8, 9, 10, 11, 12} {
		ver := "0.2.0-descendant"
		if pt == 9 {
			ver = "0.2.0-nohealth"
		}
		setOffer(ver, 7, "normal")
		d := filepath.Join(root, "crash-"+strconv.Itoa(pt))
		runCase(d, 100+pt, true, map[string]any{"crash": pt})
		assertStopped(d)
		srv.setMode("no_offer")
		wantSeq := int64(0)
		if pt == 8 {
			wantSeq = 7
		}
		assertState(runCase(d, 0, false, nil), wantSeq, 7)
		assertStopped(d)
	}

	// Drain unconfirmed / start failed / start drain unconfirmed.
	setOffer("0.2.0", 7, "normal")
	dDrain := filepath.Join(root, "drain-unconfirmed")
	stDrain := runCase(dDrain, 1, true, map[string]any{"fail_drain": true, "stop_after_poll": false})
	if stDrain.Phase != "prepared" || stDrain.HighWater != 7 || countMatching(readEvents(dDrain), " start 7 ") != 0 {
		t.Fatalf("drain-unconfirmed mismatch: %+v", stDrain)
	}
	assertStopped(dDrain)

	setOffer("0.2.0", 7, "normal")
	dStartFail := filepath.Join(root, "start-failed")
	assertState(runCase(dStartFail, 0, true, map[string]any{"fail_start": true, "stop_after_poll": false, "stop_after_rollback": true}), 0, 7)
	if countMatching(readEvents(dStartFail), " start 0 ") != 2 {
		t.Fatal("start-failed expected rollback restart")
	}
	assertStopped(dStartFail)

	setOffer("0.2.0", 7, "normal")
	dStartDrain := filepath.Join(root, "start-drain-unconfirmed")
	stSD := runCase(dStartDrain, 1, true, map[string]any{"fail_start": true, "fail_drain_on_start": true})
	if stSD.Phase != "probation" || countMatching(readEvents(dStartDrain), " start 0 ") != 1 {
		t.Fatalf("start-drain-unconfirmed mismatch: %+v", stSD)
	}
	assertStopped(dStartDrain)

	// Corrupt journal refuses startup.
	setOffer("0.2.0", 7, "normal")
	dCorrupt := filepath.Join(root, "corrupt")
	assertState(runCase(dCorrupt, 0, true, nil), 7, 7)
	beforeEv := len(readEvents(dCorrupt))
	_ = os.WriteFile(filepath.Join(dCorrupt, "update-state.json"), []byte("{truncated"), 0o600)
	inBytes, _ := json.Marshal(makeCfg(dCorrupt, false, nil))
	c := exec.Command(absClient)
	c.Stdin = bytes.NewReader(inBytes)
	_ = c.Run()
	if c.ProcessState.ExitCode() != 1 || len(readEvents(dCorrupt)) != beforeEv {
		t.Fatal("corrupt journal did not fail closed")
	}

	// Keepalive restart.
	_ = os.WriteFile(baseline, fixturePackage(t, "0.1.0-restart", workerBytes), 0o600)
	setOffer("0.2.0", 7, "no_offer")
	dKeep := filepath.Join(root, "keepalive")
	assertState(runCase(dKeep, 0, true, nil), 0, 0)
	if countMatching(readEvents(dKeep), " start 0 ") != 2 {
		t.Fatal("keepalive did not restart worker once")
	}
	assertStopped(dKeep)

	// Kill host while worker + descendant are alive: job object reaps tree.
	_ = os.WriteFile(baseline, fixturePackage(t, "0.1.0-descendant", workerBytes), 0o600)
	dKill := filepath.Join(root, "host-killed")
	killCfg, _ := json.Marshal(makeCfg(dKill, true, map[string]any{"stop_after_poll": false}))
	proc := exec.Command(absClient)
	stdinPipe, _ := proc.StdinPipe()
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = stdinPipe.Write(append(killCfg, '\n'))
	_ = stdinPipe.Close()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if countMatching(readEvents(dKill), " descendant") > 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if countMatching(readEvents(dKill), " descendant") == 0 {
		_ = proc.Process.Kill()
		t.Fatal("descendant did not start")
	}
	_ = proc.Process.Kill()
	_ = proc.Wait()
	assertStopped(dKill)

	// Missing journal fails closed.
	dMissing := filepath.Join(root, "missing")
	missCfg, _ := json.Marshal(makeCfg(dMissing, false, nil))
	cm := exec.Command(absClient)
	cm.Stdin = bytes.NewReader(missCfg)
	_ = cm.Run()
	if cm.ProcessState.ExitCode() != 1 || len(readEvents(dMissing)) != 0 {
		t.Fatal("missing journal did not fail closed")
	}
}
