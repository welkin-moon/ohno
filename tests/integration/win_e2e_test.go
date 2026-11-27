//go:build windows

package integration

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/welkin-moon/ohno/teacher"
)

func TestWindowsEndToEnd(t *testing.T) {
	if os.Getenv("OHNO_RUN_E2E") != "1" {
		t.Skip("set OHNO_RUN_E2E=1 on an ephemeral Windows runner to execute full E2E suite")
	}
	root := buildDir()
	setupExe := filepath.Join(root, "ohno-setup.exe")
	teacherExe := filepath.Join(root, "dist", "ohno-teacher.exe")
	if _, err := os.Stat(teacherExe); err != nil {
		teacherExe = filepath.Join(root, "ohno-teacher.exe")
	}
	targetExe := filepath.Join(root, "test-target.exe")
	pipeClientExe := filepath.Join(root, "pipe-client.exe")
	networkTargetExe := filepath.Join(root, "network-target.exe")
	probeExe := filepath.Join(root, "installed-update-probe.exe")

	const (
		pin                 = "2468"
		maintenancePassword = "CI fixture classroom maintenance passphrase"
	)

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	certPath := filepath.Join(tmp, "test-cert.pem")
	keyPath := filepath.Join(tmp, "test-key.pem")
	if err := teacher.CreateCertificate(certPath, keyPath, "localhost"); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	thumbBytes := sha1.Sum(blk.Bytes)
	thumb := strings.ToUpper(hex.EncodeToString(thumbBytes[:]))

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	apiClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}},
	}
	ctrlClient := &http.Client{
		Timeout:       120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	prepared, err := teacher.InitializeStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	pw := maintenancePassword
	if err := prepared.SetMaintenancePassword(&pw); err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	if err := prepared.InitializeReleases(); err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	releasePublicKey := prepared.ReleaseCatalog.PublicKey
	prepared.Close()

	var serverProc *exec.Cmd
	var childProc *exec.Cmd
	var netListener net.Listener
	zoneStream := ""
	installed := false
	certCleanup := false

	defer func() {
		if childProc != nil && childProc.Process != nil && childProc.ProcessState == nil {
			_ = childProc.Process.Kill()
			_ = childProc.Wait()
		}
		if netListener != nil {
			_ = netListener.Close()
		}
		if zoneStream != "" {
			_ = os.Remove(zoneStream)
		}
		if installed {
			rm := exec.Command(setupExe, "--remove", "--password-stdin")
			rm.Stdin = strings.NewReader(maintenancePassword + "\n")
			if rm.Run() != nil {
				_ = exec.Command(setupExe, "--admin-recovery-remove").Run()
			}
		}
		if serverProc != nil && serverProc.Process != nil && serverProc.ProcessState == nil {
			_ = serverProc.Process.Kill()
			_ = serverProc.Wait()
		}
		if certCleanup {
			_ = exec.Command("certutil", "-delstore", "Root", thumb).Run()
		}
	}()

	serverProc = exec.Command(teacherExe, "--state", statePath, "--cert", certPath, "--key", keyPath, "--bind", "127.0.0.1", "--port", "8443", "--trace-update-http")
	serverProc.Stdout = os.Stdout
	serverProc.Stderr = os.Stderr
	if err := serverProc.Start(); err != nil {
		t.Fatalf("start teacher: %v", err)
	}

	waitFor := func(desc string, limit time.Duration, fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for time.Now().Before(deadline) {
			if fn() {
				return
			}
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("timed out waiting for %s", desc)
	}

	waitFor("teacher /health", 15*time.Second, func() bool {
		resp, err := apiClient.Get("https://localhost:8443/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	ctrlCall := func(method, path string, body []byte, hdrs map[string]string) (int, string) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://127.0.0.1:8765"+path, r)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "127.0.0.1"
		if body != nil {
			req.ContentLength = int64(len(body))
		}
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err := ctrlClient.Do(req)
		if err != nil {
			t.Fatalf("ctrl %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	postForm := func(path string, vals map[string]string) {
		t.Helper()
		f := url.Values{}
		for k, v := range vals {
			f.Set(k, v)
		}
		code, txt := ctrlCall("POST", path, []byte(f.Encode()), nil)
		if code != 303 {
			t.Fatalf("form %s rejected: %d %s", path, code, txt)
		}
	}

	setupBytes, err := os.ReadFile(setupExe)
	if err != nil {
		t.Fatal(err)
	}
	schoolSetup := filepath.Join(tmp, "Ohno-School-Setup.exe")
	bundled, err := teacher.BuildSchoolInstaller(setupBytes, "https://localhost:8443", certPEM, releasePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schoolSetup, bundled, 0o755); err != nil {
		t.Fatal(err)
	}

	// Wrong maintenance password refused with zero OS mutations.
	rej := exec.Command(schoolSetup, "--install-bundled", "--password-stdin")
	rej.Stdin = strings.NewReader("wrong classroom maintenance passphrase\n")
	if rej.Run() == nil {
		t.Fatal("incorrect password installed service")
	}
	assertCleanMachineState(t)

	// Install school bundle.
	installed = true
	certCleanup = true
	instCmd := exec.Command(schoolSetup, "--install-bundled", "--password-stdin")
	instCmd.Stdin = strings.NewReader(maintenancePassword + "\n")
	if out, err := instCmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture install failed: %v (%s)", err, string(out))
	}

	assertNoRootImport := func() {
		t.Helper()
		h, err := regOpenKey(`SOFTWARE\Ohno`, keyRead|keyWOW64_64Key)
		if err != nil {
			t.Fatal(err)
		}
		defer regClose(h)
		if _, err := regQueryString(h, "ImportedRootSha1"); err == nil {
			t.Fatal("new installer recorded ImportedRootSha1")
		}
		if exec.Command("certutil", "-store", "Root", thumb).Run() == nil {
			t.Fatal("new installer added machine-wide certificate trust")
		}
	}
	assertNoRootImport()

	// Check SCM non-crash failure flag.
	svcNamePtr, _ := syscall.UTF16PtrFromString("Ohno")
	scm, _, _ := pOpenSCManagerW.Call(0, 0, 1)
	svc, _, _ := pOpenServiceW.Call(scm, uintptr(unsafe.Pointer(svcNamePtr)), 1)
	var flagVal int32
	var needed uint32
	okCfg, _, _ := pQueryServiceConfig2W.Call(svc, 4, uintptr(unsafe.Pointer(&flagVal)), 4, uintptr(unsafe.Pointer(&needed)))
	pCloseServiceHandle.Call(svc)
	pCloseServiceHandle.Call(scm)
	if okCfg == 0 || flagVal == 0 {
		t.Fatal("SCM non-crash failure recovery flag not configured")
	}

	// Verify pinned ReleasePublicKey, PayloadLayout=1, and UninstallString.
	ohnoKey, err := regOpenKey(`SOFTWARE\Ohno`, keyRead|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := regQueryString(ohnoKey, "ReleasePublicKey")
	gotLayout, err2 := regQueryDWORD(ohnoKey, "PayloadLayout")
	regClose(ohnoKey)
	if err != nil || gotPub != releasePublicKey || err2 != nil || gotLayout != 1 {
		t.Fatalf("registry config mismatch: pub=%q layout=%d", gotPub, gotLayout)
	}
	uninstKey, err := regOpenKey(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ohno`, keyRead|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	uninstCmd, err := regQueryString(uninstKey, "UninstallString")
	regClose(uninstKey)
	if err != nil || !strings.Contains(uninstCmd, "ohno-maintenance.exe") || !strings.HasSuffix(uninstCmd, " --remove") {
		t.Fatalf("unexpected UninstallString: %q", uninstCmd)
	}

	readState := func() teacher.StateData {
		raw, err := os.ReadFile(statePath)
		if err != nil {
			return teacher.StateData{}
		}
		var st teacher.StateData
		_ = json.Unmarshal(raw, &st)
		return st
	}

	var device string
	waitFor("device registration", 90*time.Second, func() bool {
		for id := range readState().Devices {
			device = id
			return true
		}
		return false
	})
	waitFor("TUN running", 90*time.Second, func() bool {
		d := readState().Devices[device]
		return d != nil && d.TUN != nil && *d.TUN
	})
	var firstMAC string
	waitFor("primary MAC", 45*time.Second, func() bool {
		d := readState().Devices[device]
		if d != nil && d.PrimaryMAC != "" {
			firstMAC = d.PrimaryMAC
			return true
		}
		return false
	})
	if err := exec.Command("powershell", "-NoProfile", "-Command", "if (Get-NetAdapter -Name 'ohno-tun' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }").Run(); err != nil {
		t.Fatal("TUN adapter ohno-tun not found")
	}

	code, page := ctrlCall("GET", "/", nil, nil)
	if code != 200 || strings.Contains(page, `action="/login"`) || strings.Contains(page, `name="password"`) {
		t.Fatalf("unexpected control UI: status=%d", code)
	}
	csrfRe := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	csrf := csrfRe.FindStringSubmatch(page)[1]
	postForm("/unlock-pin", map[string]string{"csrf": csrf, "action": "set", "pin": pin})
	postForm("/device", map[string]string{"csrf": csrf, "id": device, "approved": "1"})

	// Hash block + approval + allow.
	targetBytes, _ := os.ReadFile(targetExe)
	targetHashBytes := sha256.Sum256(targetBytes)
	targetHash := hex.EncodeToString(targetHashBytes[:])
	postForm("/policy", map[string]string{"csrf": csrf, "domains": "game.example", "hashes": targetHash, "names": ""})
	childProc = exec.Command(targetExe)
	if err := childProc.Start(); err != nil {
		t.Fatal(err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- childProc.Wait() }()
	select {
	case <-childDone:
	case <-time.After(120 * time.Second):
		t.Fatal("blocked target executable was not terminated")
	}
	childProc = nil

	var appReqID string
	waitFor("application request", 90*time.Second, func() bool {
		for _, r := range readState().Requests {
			if r.Object == targetHash {
				appReqID = r.ID
				return true
			}
		}
		return false
	})
	postForm("/request", map[string]string{"csrf": csrf, "id": appReqID, "action": "approve"})
	time.Sleep(25 * time.Second)
	childProc = exec.Command(targetExe)
	if err := childProc.Start(); err != nil {
		t.Fatal(err)
	}
	childDone2 := make(chan error, 1)
	go func() { childDone2 <- childProc.Wait() }()
	select {
	case <-childDone2:
		t.Fatal("approved target was unexpectedly stopped")
	case <-time.After(20 * time.Second):
		_ = childProc.Process.Kill()
		<-childDone2
		childProc = nil
	}

	// Website request via pipe-client + Edge URLAllowlist.
	if err := exec.Command(pipeClientExe, "W:game.example").Run(); err != nil {
		t.Fatalf("pipe-client website request: %v", err)
	}
	var webReqID string
	waitFor("website request", 90*time.Second, func() bool {
		for _, r := range readState().Requests {
			if r.Kind == "website" && r.Object == "game.example" {
				webReqID = r.ID
				return true
			}
		}
		return false
	})
	postForm("/request", map[string]string{"csrf": csrf, "id": webReqID, "action": "approve"})
	waitFor("Edge URLAllowlist .game.example", 90*time.Second, func() bool {
		h, err := regOpenKey(`SOFTWARE\Policies\Microsoft\Edge\URLAllowlist`, keyRead|keyWOW64_64Key)
		if err != nil {
			return false
		}
		defer regClose(h)
		vals, _ := regEnumStringValues(h)
		for _, v := range vals {
			if v == ".game.example" {
				return true
			}
		}
		return false
	})

	// WFP downloaded-origin block + approval.
	netTargetBytes, _ := os.ReadFile(networkTargetExe)
	netHashBytes := sha256.Sum256(netTargetBytes)
	netHash := hex.EncodeToString(netHashBytes[:])
	zoneStream = networkTargetExe + ":Zone.Identifier"
	_ = os.WriteFile(zoneStream, []byte("[ZoneTransfer]\r\nZoneId=3\r\n"), 0o600)
	netListener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	netPort := strconv.Itoa(netListener.Addr().(*net.TCPAddr).Port)
	childProc = exec.Command(networkTargetExe, netPort, "60000")
	if err := childProc.Start(); err != nil {
		t.Fatal(err)
	}
	var netReqID string
	waitFor("WFP network request", 80*time.Second, func() bool {
		for _, r := range readState().Requests {
			if r.Kind == "network" && r.Object == netHash {
				netReqID = r.ID
				return true
			}
		}
		return false
	})
	if childProc.Wait() == nil {
		t.Fatal("untrusted executable connected despite WFP rule")
	}
	childProc = nil
	postForm("/request", map[string]string{"csrf": csrf, "id": netReqID, "action": "approve"})
	waitFor("approved WFP connection", 90*time.Second, func() bool {
		return exec.Command(networkTargetExe, netPort).Run() == nil
	})

	// Classroom PIN pause unblocks Edge URLBlocklist.
	if err := exec.Command(pipeClientExe, "U:"+pin).Run(); err != nil {
		t.Fatalf("pipe-client PIN unlock: %v", err)
	}
	waitFor("pause grant", 30*time.Second, func() bool {
		for _, r := range readState().Requests {
			if r.Kind == "pause" && r.DeviceID == device {
				return true
			}
		}
		return false
	})
	waitFor("Edge URLBlocklist cleared", 90*time.Second, func() bool {
		h, err := regOpenKey(`SOFTWARE\Policies\Microsoft\Edge\URLBlocklist`, keyRead|keyWOW64_64Key)
		if err != nil {
			return true
		}
		defer regClose(h)
		vals, _ := regEnumStringValues(h)
		for _, v := range vals {
			if v == "game.example" {
				return false
			}
		}
		return true
	})

	// Managed update commit + unhealthy rollback + launcher verification.
	installation := filepath.Join(os.Getenv("ProgramFiles"), "Ohno")
	type jRev struct {
		Sequence int64  `json:"sequence"`
		Version  string `json:"version"`
		SHA256   string `json:"sha256"`
	}
	type jDoc struct {
		Phase      string `json:"phase"`
		Generation int64  `json:"generation"`
		HighWater  int64  `json:"high_water"`
		Active     jRev   `json:"active"`
		LastGood   jRev   `json:"last_good"`
	}
	readJournal := func() jDoc {
		raw, _ := os.ReadFile(filepath.Join(installation, "update-state.json"))
		var d jDoc
		_ = json.Unmarshal(raw, &d)
		return d
	}

	requestWindow := func(expectedExe string) {
		t.Helper()
		cls, _ := syscall.UTF16PtrFromString("OhnoRequestWindow")
		launcher := exec.Command(filepath.Join(installation, "ohno-request.exe"))
		if err := launcher.Start(); err != nil {
			t.Fatal(err)
		}
		var hwnd uintptr
		waitFor("OhnoRequestWindow", 20*time.Second, func() bool {
			hwnd, _, _ = pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
			return hwnd != 0
		})
		var pid uint32
		pGetWindowThreadProcessI.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		ph, _, _ := pOpenProcess.Call(0x101001, 0, uintptr(pid))
		buf := make([]uint16, 32768)
		sz := uint32(len(buf))
		okQ, _, _ := pQueryFullProcessImageNameW.Call(ph, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
		if ph == 0 || okQ == 0 {
			t.Fatal("QueryFullProcessImageNameW failed")
		}
		gotExe := syscall.UTF16ToString(buf[:sz])
		if !strings.EqualFold(gotExe, expectedExe) {
			pTerminateProcess.Call(ph, 1)
			pCloseHandle.Call(ph)
			t.Fatalf("launcher selected %s, want %s", gotExe, expectedExe)
		}
		pPostMessageW.Call(hwnd, 0x0010, 0, 0)
		r, _, _ := pWaitForSingleObject.Call(ph, 10000)
		pCloseHandle.Call(ph)
		if r != 0 {
			t.Fatal("request GUI did not close normally")
		}
		if err := launcher.Wait(); err != nil {
			t.Fatalf("launcher exited with error: %v", err)
		}
	}

	reqExeFor := func(rev jRev) string {
		return filepath.Join(installation, "versions", fmt.Sprintf("%d-%s", rev.Sequence, rev.SHA256), "ohno-request.exe")
	}
	baseJ := readJournal()
	if baseJ.Active.Sequence != 0 {
		t.Fatalf("expected baseline seq 0, got %+v", baseJ)
	}
	requestWindow(reqExeFor(baseJ.Active))

	publish := func(version, workerName string) {
		files := map[string][]byte{}
		for _, name := range teacher.PackageFiles {
			src := name
			if name == "ohno-worker.exe" && workerName != "" {
				src = workerName
			}
			b, err := os.ReadFile(filepath.Join(root, src))
			if err != nil {
				t.Fatal(err)
			}
			files[name] = b
		}
		pkg, err := teacher.BuildPackage(version, files)
		if err != nil {
			t.Fatal(err)
		}
		stCode, body := ctrlCall("POST", "/updates/approve", pkg, map[string]string{
			"Content-Type": "application/octet-stream", "X-Ohno-CSRF": csrf,
		})
		if stCode != 200 {
			t.Fatalf("approve %s failed: %d %s", version, stCode, body)
		}
	}

	publish("1.0.1", "ohno-worker.exe")
	if out, err := exec.Command(probeExe).CombinedOutput(); err != nil {
		t.Fatalf("installed-update-probe failed: %v (%s)", err, string(out))
	}
	var goodJ jDoc
	waitFor("commit seq 1", 180*time.Second, func() bool {
		j := readJournal()
		if j.Phase == "stable" && j.Active.Sequence == 1 {
			goodJ = j
			return true
		}
		return false
	})
	if goodJ.Active.Version != "1.0.1" || goodJ.HighWater != 1 {
		t.Fatalf("unexpected committed journal: %+v", goodJ)
	}
	requestWindow(reqExeFor(goodJ.Active))
	if readState().Devices[device].BoundMAC != firstMAC {
		t.Fatal("MAC binding lost across update")
	}

	// Unhealthy silent worker rolls back after 90s health timeout without lowering high-water.
	publish("1.0.2-nohealth-open", "worker-fixture.exe")
	var rolledJ jDoc
	waitFor("rollback seq 2", 180*time.Second, func() bool {
		j := readJournal()
		if j.Phase == "stable" && j.HighWater == 2 {
			rolledJ = j
			return true
		}
		return false
	})
	if rolledJ.Active != goodJ.Active || rolledJ.LastGood != goodJ.Active {
		t.Fatalf("rollback mismatch: %+v vs %+v", rolledJ, goodJ)
	}
	fixLog := filepath.Join(installation, "worker-events.log")
	fixRaw, err := os.ReadFile(fixLog)
	if err != nil {
		t.Fatal(err)
	}
	fixStr := string(fixRaw)
	if !strings.Contains(fixStr, " start 2 1.0.2-nohealth-open") || !strings.Contains(fixStr, " stop 2 1.0.2-nohealth-open") {
		t.Fatalf("missing start/stop events: %s", fixStr)
	}
	_ = os.Remove(fixLog)
	requestWindow(reqExeFor(rolledJ.LastGood))

	// Verify failed sequence does not retry and pipe works.
	waitFor("pipe after rollback", 90*time.Second, func() bool {
		return exec.Command(pipeClientExe, "W:after-update.example").Run() == nil
	})
	beforeGen := readJournal().Generation
	time.Sleep(65 * time.Second)
	if readJournal().Generation != beforeGen {
		t.Fatal("failed update sequence retried")
	}

	// Standard STOP stays stopped; explicit start works; crash triggers SCM recovery.
	serviceStopped := func() bool {
		out, _ := exec.Command("sc.exe", "query", "Ohno").Output()
		return strings.Contains(string(out), "STOPPED")
	}
	hostPID := func() int {
		out, _ := exec.Command("sc.exe", "queryex", "Ohno").Output()
		m := regexp.MustCompile(`PID\s*:\s*(\d+)`).FindStringSubmatch(string(out))
		if len(m) < 2 {
			return 0
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	if err := exec.Command("sc.exe", "stop", "Ohno").Run(); err != nil {
		t.Fatal(err)
	}
	waitFor("service stopped", 25*time.Second, serviceStopped)
	time.Sleep(12 * time.Second)
	if !serviceStopped() {
		t.Fatal("stopped service resurrected")
	}
	if err := exec.Command("sc.exe", "start", "Ohno").Run(); err != nil {
		t.Fatal(err)
	}
	waitFor("pipe after restart", 90*time.Second, func() bool {
		return exec.Command(pipeClientExe, "W:after-restart.example").Run() == nil
	})
	prevHost := hostPID()
	if prevHost == 0 {
		t.Fatal("missing host PID")
	}
	if err := exec.Command("taskkill", "/PID", strconv.Itoa(prevHost), "/F").Run(); err != nil {
		t.Fatal(err)
	}
	waitFor("SCM recovery restart", 40*time.Second, func() bool {
		p := hostPID()
		return p != 0 && p != prevHost
	})
	waitFor("pipe after recovery", 60*time.Second, func() bool {
		return exec.Command(pipeClientExe, "W:after-recovery.example").Run() == nil
	})

	// Disabled maintenance password refuses removal.
	postForm("/maintenance-password", map[string]string{"csrf": csrf, "action": "clear"})
	deniedRm := exec.Command(setupExe, "--remove", "--password-stdin")
	deniedRm.Stdin = strings.NewReader(maintenancePassword + "\n")
	if deniedRm.Run() == nil {
		t.Fatal("disabled maintenance password removed service")
	}

	// Simulate cloned OEM identity while maintenance auth is disabled.
	beforeClone := readJournal()
	_ = exec.Command("sc.exe", "stop", "Ohno").Run()
	waitFor("stop for clone", 25*time.Second, serviceStopped)
	idKey, err := regOpenKey(`SOFTWARE\Ohno\Identity`, keyRead|keySetValue|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := regQueryString(idKey, "Credentials")
	if err != nil {
		regClose(idKey)
		t.Fatal(err)
	}
	parts := strings.Split(copied, ":")
	oldID, oldKey := parts[len(parts)-2], parts[len(parts)-1]
	_ = regSetString(idKey, "Credentials", "fixture-source-machine:"+oldID+":"+oldKey)
	regClose(idKey)

	postForm("/device", map[string]string{"csrf": csrf, "id": device, "approved": "0"})
	known := map[string]bool{}
	for id := range readState().Devices {
		known[id] = true
	}
	_ = exec.Command("sc.exe", "start", "Ohno").Run()
	var cloneDev string
	waitFor("clone registration", 90*time.Second, func() bool {
		for id := range readState().Devices {
			if !known[id] {
				cloneDev = id
				return true
			}
		}
		return false
	})
	if readJournal() != beforeClone {
		t.Fatal("clone boot altered update journal")
	}
	postForm("/device", map[string]string{"csrf": csrf, "id": cloneDev, "approved": "1"})
	device = cloneDev
	waitFor("pipe after clone", 90*time.Second, func() bool {
		return exec.Command(pipeClientExe, "W:after-clone.example").Run() == nil
	})

	// Re-enable maintenance password, revoke device, add legacy ImportedRootSha1 fixture, test normal removal.
	postForm("/maintenance-password", map[string]string{"csrf": csrf, "action": "set", "maintenance_password": maintenancePassword})
	postForm("/device", map[string]string{"csrf": csrf, "id": device, "approved": "0"})
	_ = exec.Command("certutil", "-addstore", "Root", certPath).Run()
	ohnoW, err := regOpenKey(`SOFTWARE\Ohno`, keySetValue|keyWOW64_64Key)
	if err != nil {
		t.Fatal(err)
	}
	_ = regSetBinary(ohnoW, "ImportedRootSha1", thumbBytes[:])
	regClose(ohnoW)

	rmNormal := exec.Command(setupExe, "--remove", "--password-stdin")
	rmNormal.Stdin = strings.NewReader(maintenancePassword + "\n")
	if out, err := rmNormal.CombinedOutput(); err != nil {
		t.Fatalf("normal removal failed: %v (%s)", err, string(out))
	}
	installed = false
	assertCleanMachineState(t)
	if exec.Command("certutil", "-store", "Root", thumb).Run() == nil {
		t.Fatal("legacy root remained after removal")
	}

	// Reinstall, stop teacher, verify offline normal removal rejected and admin recovery succeeds.
	installed = true
	inst2 := exec.Command(schoolSetup, "--install-bundled", "--password-stdin")
	inst2.Stdin = strings.NewReader(maintenancePassword + "\n")
	if out, err := inst2.CombinedOutput(); err != nil {
		t.Fatalf("reinstall failed: %v (%s)", err, string(out))
	}
	assertNoRootImport()
	_ = serverProc.Process.Kill()
	_ = serverProc.Wait()
	serverProc = nil

	rmOff := exec.Command(setupExe, "--remove", "--password-stdin")
	rmOff.Stdin = strings.NewReader(maintenancePassword + "\n")
	if rmOff.Run() == nil {
		t.Fatal("offline normal removal unexpectedly succeeded")
	}
	if out, err := exec.Command(setupExe, "--admin-recovery-remove").CombinedOutput(); err != nil {
		t.Fatalf("admin recovery removal failed: %v (%s)", err, string(out))
	}
	installed = false
	assertCleanMachineState(t)
}
