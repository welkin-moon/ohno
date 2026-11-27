package teacher

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testHarness struct {
	t         *testing.T
	dir       string
	store     *Store
	apiH      *TeacherHandler
	ctrlH     *TeacherHandler
	apiSrv    *http.Server
	ctrlSrv   *http.Server
	apiPort   int
	ctrlPort  int
	apiClient *http.Client
	ctlClient *http.Client
	certPEM   []byte
	certPath  string
	keyPath   string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	dir := t.TempDir()
	st, err := InitializeStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := CreateCertificate(certPath, keyPath, "localhost"); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		apiLn.Close()
		t.Fatal(err)
	}

	apiH := NewTeacherHandler(ServerConfig{Store: st, Control: false})
	ctrlH := NewTeacherHandler(ServerConfig{
		Store:             st,
		Control:           true,
		ControlCSRF:       "test-control-csrf",
		SchoolInstaller:   append([]byte("MZ"), make([]byte, 5000)...),
		EnrollmentOrigin:  "https://teacher-pc:8443",
		PublicCertificate: certPEM,
	})

	apiSrv := &http.Server{Handler: apiH, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	ctrlSrv := &http.Server{Handler: ctrlH, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}

	go func() {
		_ = apiSrv.Serve(tls.NewListener(newBoundedListener(apiLn, DefaultWorkers, nil), &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tlsCert},
		}))
	}()
	go func() {
		_ = ctrlSrv.Serve(newBoundedListener(ctrlLn, DefaultWorkers, nil))
	}()

	apiClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctlClient := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	h := &testHarness{
		t:         t,
		dir:       dir,
		store:     st,
		apiH:      apiH,
		ctrlH:     ctrlH,
		apiSrv:    apiSrv,
		ctrlSrv:   ctrlSrv,
		apiPort:   apiLn.Addr().(*net.TCPAddr).Port,
		ctrlPort:  ctrlLn.Addr().(*net.TCPAddr).Port,
		apiClient: apiClient,
		ctlClient: ctlClient,
		certPEM:   certPEM,
		certPath:  certPath,
		keyPath:   keyPath,
	}
	t.Cleanup(func() {
		_ = apiSrv.Close()
		_ = ctrlSrv.Close()
		apiClient.CloseIdleConnections()
		ctlClient.CloseIdleConnections()
		h.store.Close()
	})
	return h
}

func (h *testHarness) apiReq(method, path string, body []byte, headers map[string]string) (int, http.Header, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(h.apiPort)+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = "teacher-pc"
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.apiClient.Do(req)
	if err != nil {
		h.t.Fatalf("apiReq %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

func (h *testHarness) ctrlReq(method, path string, body []byte, headers map[string]string) (int, http.Header, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(h.ctrlPort)+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = "127.0.0.1"
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := h.ctlClient.Do(req)
	if err != nil {
		h.t.Fatalf("ctrlReq %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *testHarness) csrf() string {
	h.t.Helper()
	code, _, body := h.ctrlReq("GET", "/", nil, nil)
	if code != 200 {
		h.t.Fatalf("GET / status %d", code)
	}
	page := string(body)
	if strings.Contains(page, `action="/login"`) || strings.Contains(page, `name="password"`) {
		h.t.Fatal("control page must not expose a login form")
	}
	m := csrfRe.FindStringSubmatch(page)
	if len(m) < 2 {
		h.t.Fatal("csrf token missing from control page")
	}
	return m[1]
}

func (h *testHarness) form(path string, vals map[string]string) {
	h.t.Helper()
	form := url.Values{}
	for k, v := range vals {
		form.Set(k, v)
	}
	code, _, body := h.ctrlReq("POST", path, []byte(form.Encode()), nil)
	if code != 303 {
		h.t.Fatalf("POST %s expected 303, got %d: %s", path, code, string(body))
	}
}

func (h *testHarness) approvedDevice() (string, string, map[string]string) {
	h.t.Helper()
	dev := strings.Repeat("R", 24)
	key := strings.Repeat("S", 32)
	payload, _ := json.Marshal(map[string]any{
		"id": dev, "key": key, "name": "test-pc",
		"macs": []string{"00:15:5d:77:88:99"}, "primary_mac": "00:15:5d:77:88:99",
	})
	code, _, _ := h.apiReq("POST", "/api/device/register", payload, nil)
	if code != 201 {
		h.t.Fatalf("register status %d", code)
	}
	h.form("/device", map[string]string{"csrf": h.csrf(), "id": dev, "approved": "1"})
	return dev, key, map[string]string{"X-Ohno-Device": dev, "X-Ohno-Key": key}
}

func (h *testHarness) maintReq(pw, action string, auth map[string]string, nonce string) (int, http.Header, []byte) {
	if pw == "" {
		pw = "A classroom maintenance phrase!"
	}
	if action == "" {
		action = "install"
	}
	if nonce == "" {
		nonce = strings.Repeat("c", 64)
	}
	b, _ := json.Marshal(map[string]any{
		"action": action, "nonce": nonce, "maintenance_password": pw,
	})
	return h.apiReq("POST", "/api/maintenance/authorize", b, auth)
}

func TestDailyBodyCredentialsAndLegacyCompatibility(t *testing.T) {
	h := newTestHarness(t)
	dev, key, legacy := h.approvedDevice()
	pin := "2468"
	if err := h.store.SetUnlockPIN(&pin); err != nil {
		t.Fatal(err)
	}
	post := func(path string, extra map[string]any, hdrs map[string]string) int {
		m := map[string]any{"device_id": dev, "device_key": key}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		code, _, _ := h.apiReq("POST", "/api/device/"+path, b, hdrs)
		return code
	}
	if post("policy", nil, nil) != 200 {
		t.Fatal("body policy failed")
	}
	if post("request", map[string]any{"kind": "website", "object": "game.example"}, nil) != 201 {
		t.Fatal("body request failed")
	}
	if post("unlock", map[string]any{"pin": "2468"}, nil) != 201 {
		t.Fatal("body unlock failed")
	}
	if code, _, _ := h.apiReq("GET", "/api/device/policy", nil, legacy); code != 200 {
		t.Fatalf("legacy GET policy: %d", code)
	}
	if code, _, _ := h.apiReq("POST", "/api/device/request", []byte(`{"kind":"website","object":"legacy.example"}`), legacy); code != 201 {
		t.Fatalf("legacy request: %d", code)
	}
	if code, _, _ := h.apiReq("POST", "/api/device/unlock", []byte(`{"pin":"2468"}`), legacy); code != 201 {
		t.Fatalf("legacy unlock: %d", code)
	}
	// Mixed / invalid / control-plane requests must fail closed.
	for _, tc := range []struct {
		p     string
		extra map[string]any
	}{
		{"policy", nil},
		{"request", map[string]any{"kind": "website", "object": "game.example"}},
		{"unlock", map[string]any{"pin": "2468"}},
	} {
		if post(tc.p, tc.extra, legacy) != 403 {
			t.Fatalf("%s mixed creds not rejected", tc.p)
		}
		if post(tc.p, tc.extra, map[string]string{"X-Ohno-Device": dev}) != 403 {
			t.Fatalf("%s partial header not rejected", tc.p)
		}
		if post(tc.p, tc.extra, map[string]string{"Authorization": "Bearer fixture"}) != 403 {
			t.Fatalf("%s Authorization header not rejected", tc.p)
		}
		m := map[string]any{"device_id": dev, "device_key": nil}
		for k, v := range tc.extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		if code, _, _ := h.apiReq("POST", "/api/device/"+tc.p, b, nil); code != 403 {
			t.Fatalf("%s null device_key got %d", tc.p, code)
		}
		if code, _, _ := h.ctrlReq("POST", "/api/device/"+tc.p, b, nil); code != 404 {
			t.Fatalf("%s on control got %d", tc.p, code)
		}
	}
	if post("policy", map[string]any{"extra": true}, nil) != 400 {
		t.Fatal("policy with extra field must return 400")
	}
	h.form("/device", map[string]string{"csrf": h.csrf(), "id": dev, "approved": "0"})
	if post("policy", nil, nil) != 403 || post("request", map[string]any{"kind": "website", "object": "game.example"}, nil) != 403 || post("unlock", map[string]any{"pin": "2468"}, nil) != 403 {
		t.Fatal("revoked device must be rejected")
	}
}

func TestRegistrationRejectsAmbiguousAuth(t *testing.T) {
	h := newTestHarness(t)
	reg := map[string]any{
		"id": strings.Repeat("c", 32), "key": strings.Repeat("d", 64), "name": "fixture",
		"macs": []string{"00:15:5d:77:88:aa"}, "primary_mac": "00:15:5d:77:88:aa",
	}
	raw, _ := json.Marshal(reg)
	for _, hdr := range []map[string]string{
		{"Authorization": "Bearer fixture"},
		{"X-Ohno-Key": strings.Repeat("d", 64)},
		{"X-Ohno-Device": strings.Repeat("c", 32)},
	} {
		if code, _, _ := h.apiReq("POST", "/api/device/register", raw, hdr); code != 400 {
			t.Fatalf("ambiguous header got %d", code)
		}
	}
	for _, k := range []string{"device_id", "device_key"} {
		cp := map[string]any{}
		for rk, rv := range reg {
			cp[rk] = rv
		}
		cp[k] = strings.Repeat("c", 32)
		b, _ := json.Marshal(cp)
		if code, _, _ := h.apiReq("POST", "/api/device/register", b, nil); code != 400 {
			t.Fatalf("ambiguous field %s got %d", k, code)
		}
	}
	if code, _, _ := h.apiReq("POST", "/api/device/register", raw, nil); code != 201 {
		t.Fatalf("valid registration got %d", code)
	}
}

func TestReleaseApprovalPauseAndDeviceBoundaries(t *testing.T) {
	h := newTestHarness(t)
	payload := FixturePackage("0.2.0")
	csrf := h.csrf()
	if code, _, _ := h.ctrlReq("POST", "/updates/approve", payload, map[string]string{
		"Content-Type": "application/octet-stream", "X-Ohno-CSRF": "wrong",
	}); code != 403 {
		t.Fatalf("wrong CSRF got %d", code)
	}
	if _, err := os.Stat(h.store.ReleaseDirectory); !os.IsNotExist(err) {
		t.Fatal("release dir should not exist before init")
	}
	if code, _, _ := h.apiReq("POST", "/updates/initialize", []byte(url.Values{"csrf": {csrf}}.Encode()), nil); code != 404 {
		t.Fatalf("API /updates/initialize got %d", code)
	}
	h.form("/updates/initialize", map[string]string{"csrf": csrf})
	if h.store.ReleaseCatalog == nil {
		t.Fatal("release catalog not initialized")
	}

	// School installer now pins v2 release public key.
	code, _, instBytes := h.ctrlReq("GET", "/school-installer", nil, nil)
	if code != 200 {
		t.Fatalf("GET /school-installer got %d", code)
	}
	_, _, pinnedKey, err := GetSchoolTrust(instBytes)
	if err != nil || pinnedKey != h.store.ReleaseCatalog.PublicKey {
		t.Fatalf("school installer trust mismatch: %q %v", pinnedKey, err)
	}

	dev, key, _ := h.approvedDevice()
	reqBase := map[string]any{"device_id": dev, "device_key": key, "nonce": strings.Repeat("d", 64)}
	ask := func(sub string, body map[string]any) (int, []byte) {
		if body == nil {
			body = reqBase
		}
		b, _ := json.Marshal(body)
		c, _, out := h.apiReq("POST", "/api/device/update/"+sub, b, nil)
		return c, out
	}
	if c, _ := ask("offer", nil); c != 404 {
		t.Fatalf("offer before approve got %d", c)
	}
	headers := map[string]string{"Content-Type": "application/octet-stream", "X-Ohno-CSRF": csrf}
	if c, _, _ := h.ctrlReq("POST", "/updates/approve", []byte("bad"), headers); c != 400 {
		t.Fatalf("bad package got %d", c)
	}
	c, _, respBody := h.ctrlReq("POST", "/updates/approve", payload, headers)
	if c != 200 {
		t.Fatalf("approve got %d: %s", c, string(respBody))
	}
	c, offerDoc := ask("offer", nil)
	if c != 200 {
		t.Fatalf("offer got %d", c)
	}
	offer, err := VerifyManifest(offerDoc, h.store.ReleaseCatalog.PublicKey, 0, 1, time.Now().Unix())
	if err != nil {
		t.Fatalf("verify offered manifest: %v", err)
	}
	pkgPath := "package/" + offer.SHA256
	c, pkgBody := ask(pkgPath, nil)
	if c != 200 || !bytes.Equal(pkgBody, payload) {
		t.Fatalf("package download mismatch: status=%d len=%d", c, len(pkgBody))
	}

	// Download capacity limit (2 slots).
	h.store.ReleaseDownloadSlots <- struct{}{}
	h.store.ReleaseDownloadSlots <- struct{}{}
	c, _ = ask(pkgPath, nil)
	<-h.store.ReleaseDownloadSlots
	<-h.store.ReleaseDownloadSlots
	if c != 503 {
		t.Fatalf("expected 503 when download slots full, got %d", c)
	}

	// MAC mismatch rejects offer.
	h.store.mu.Lock()
	origMACs := h.store.Data.Devices[dev].MACs
	h.store.Data.Devices[dev].MACs = []string{"00:15:5d:11:22:33"}
	h.store.mu.Unlock()
	if c, _ := ask("offer", nil); c != 403 {
		t.Fatalf("MAC changed got %d", c)
	}
	h.store.mu.Lock()
	h.store.Data.Devices[dev].MACs = origMACs
	// Revoke during package disk read rejects before output.
	h.store.packageReader = func(digest string) ([]byte, error) {
		h.store.mu.Lock()
		h.store.Data.Devices[dev].Approved = false
		h.store.mu.Unlock()
		return payload, nil
	}
	h.store.mu.Unlock()
	if c, _ := ask(pkgPath, nil); c != 403 {
		t.Fatalf("revoked during read got %d", c)
	}
	h.store.mu.Lock()
	h.store.packageReader = nil
	h.store.mu.Unlock()
	h.form("/device", map[string]string{"csrf": csrf, "id": dev, "approved": "1"})

	// Traversal path rejected.
	if c, _ := ask("package/..%2frelease-key.pem", nil); c != 404 {
		t.Fatalf("traversal got %d", c)
	}

	// Execution authorization.
	execReq := map[string]any{
		"device_id": dev, "device_key": key, "nonce": strings.Repeat("d", 64),
		"sequence": offer.Sequence, "sha256": offer.SHA256,
	}
	c, execBody := ask("authorize", execReq)
	if c != 200 {
		t.Fatalf("authorize got %d: %s", c, string(execBody))
	}
	var decision map[string]any
	_ = json.Unmarshal(execBody, &decision)
	if decision["nonce"] != reqBase["nonce"] || decision["device_id"] != dev {
		t.Fatalf("unexpected authorize decision: %v", decision)
	}
	if c, _ := ask("authorize", map[string]any{"device_id": dev, "device_key": key, "nonce": strings.Repeat("d", 64), "sequence": true, "sha256": offer.SHA256}); c != 403 {
		t.Fatalf("bool sequence got %d", c)
	}
	if c, _ := ask("authorize", map[string]any{"device_id": dev, "device_key": key, "nonce": strings.Repeat("d", 64), "sequence": offer.Sequence, "sha256": strings.Repeat("f", 64)}); c != 403 {
		t.Fatalf("wrong sha256 got %d", c)
	}

	// Duplicate JSON key rejected.
	bReq, _ := json.Marshal(reqBase)
	dup := string(bReq[:len(bReq)-1]) + `,"nonce":"` + strings.Repeat("d", 64) + `"}`
	if c, _, _ := h.apiReq("POST", "/api/device/update/offer", []byte(dup), nil); c != 400 {
		t.Fatalf("duplicate key got %d", c)
	}

	// Pause stops offer, package, and authorize.
	h.form("/updates/pause", map[string]string{"csrf": csrf})
	if c, _ := ask("offer", nil); c != 404 {
		t.Fatalf("paused offer got %d", c)
	}
	if c, _ := ask(pkgPath, nil); c != 404 {
		t.Fatalf("paused pkg got %d", c)
	}
	if c, _ := ask("authorize", execReq); c != 404 {
		t.Fatalf("paused authorize got %d", c)
	}

	// Re-approve increments sequence; old execution sequence rejected.
	if c, _, _ := h.ctrlReq("POST", "/updates/approve", payload, headers); c != 200 {
		t.Fatalf("re-approve got %d", c)
	}
	if c, _ := ask("authorize", execReq); c != 403 {
		t.Fatalf("stale sequence got %d", c)
	}

	// Control serves /updates.js with CSP, API rejects it.
	c, hdr, script := h.ctrlReq("GET", "/updates.js", nil, nil)
	if c != 200 || !strings.Contains(string(script), "redirect: 'error'") || !strings.Contains(hdr.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("/updates.js mismatch: status=%d csp=%q", c, hdr.Get("Content-Security-Policy"))
	}
	if c, _, _ := h.apiReq("GET", "/updates.js", nil, nil); c != 404 {
		t.Fatalf("API /updates.js got %d", c)
	}
}

func TestMaintenanceAuthAndStateRollback(t *testing.T) {
	h := newTestHarness(t)
	if c, _, _ := h.maintReq("", "", nil, ""); c != 403 {
		t.Fatalf("unset maintenance password got %d", c)
	}
	if c, _, _ := h.ctrlReq("POST", "/api/maintenance/authorize", []byte("{}"), nil); c != 404 {
		t.Fatalf("control maintenance route got %d", c)
	}
	csrf := h.csrf()
	const pw = "A classroom maintenance phrase!"
	h.form("/maintenance-password", map[string]string{"csrf": csrf, "action": "set", "maintenance_password": pw})

	c, _, body := h.maintReq(pw, "install", nil, "")
	if c != 200 {
		t.Fatalf("install maintenance auth got %d: %s", c, string(body))
	}
	saved, _ := os.ReadFile(h.store.Path)
	if strings.Contains(string(saved), pw) {
		t.Fatal("plaintext maintenance password saved to state.json")
	}
	// Installer must not contain maintenance password or hash.
	_, _, inst := h.ctrlReq("GET", "/school-installer", nil, nil)
	if bytes.Contains(inst, []byte(pw)) || bytes.Contains(inst, []byte(h.store.Data.MaintenanceCredential.Digest)) {
		t.Fatal("maintenance secret leaked into school installer")
	}

	// Uninstall with body credentials vs legacy headers vs mixed.
	dev, key, legacy := h.approvedDevice()
	uninstBody, _ := json.Marshal(map[string]any{
		"action": "uninstall", "nonce": strings.Repeat("d", 64),
		"maintenance_password": pw, "device_id": dev, "device_key": key,
	})
	if c, _, _ := h.apiReq("POST", "/api/maintenance/authorize", uninstBody, nil); c != 200 {
		t.Fatalf("body uninstall auth got %d", c)
	}
	if c, _, _ := h.apiReq("POST", "/api/maintenance/authorize", uninstBody, legacy); c != 400 {
		t.Fatalf("mixed uninstall auth got %d", c)
	}
	// Revoked device can still uninstall.
	h.form("/device", map[string]string{"csrf": csrf, "id": dev, "approved": "0"})
	if c, _, _ := h.apiReq("POST", "/api/maintenance/authorize", uninstBody, nil); c != 200 {
		t.Fatalf("revoked device uninstall got %d", c)
	}

	// Persistence failure rolls back state and returns 503.
	beforeBytes, _ := os.ReadFile(h.store.Path)
	origReplace := storeReplace
	storeReplace = func(oldpath, newpath string) error { return errors.New("disk full") }
	c1, _, _ := h.maintReq(pw, "install", nil, "")
	c2, _, _ := h.ctrlReq("POST", "/maintenance-password", []byte(url.Values{
		"csrf": {csrf}, "action": {"set"}, "maintenance_password": {"A different classroom phrase!"},
	}.Encode()), nil)
	storeReplace = origReplace
	if c1 != 503 || c2 != 503 {
		t.Fatalf("expected 503 on disk failure, got %d %d", c1, c2)
	}
	afterBytes, _ := os.ReadFile(h.store.Path)
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("state.json mutated on failed save")
	}

	// Invalid unicode surrogates and duplicate keys rejected.
	if c, _, _ := h.apiReq("POST", "/api/device/register", []byte(`{"id":"XXXXXXXXXXXXXXXXXXXXXXXX","key":"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY","name":"\ud800"}`), nil); c != 400 {
		t.Fatalf("surrogate device name got %d", c)
	}
	if c, _, _ := h.apiReq("POST", "/api/maintenance/authorize", []byte(`{"action":"install","nonce":"`+strings.Repeat("c", 64)+`","maintenance_password":"`+pw+`","\u0061ction":"uninstall"}`), nil); c != 400 {
		t.Fatalf("unicode duplicate key got %d", c)
	}
}

func TestTruncatedBodyDeepJSONAndLegacyMigration(t *testing.T) {
	h := newTestHarness(t)
	// Truncated body returns 413.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(h.ctrlPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("POST /policy HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\nxx"))
	_ = conn.(*net.TCPConn).CloseWrite()
	respBytes, _ := io.ReadAll(conn)
	_ = conn.Close()
	if !strings.Contains(string(respBytes), " 413 ") {
		t.Fatalf("expected 413 for truncated body, got %q", string(respBytes))
	}

	// Deep JSON returns 400.
	deep := []byte(strings.Repeat("[", 2000) + "0" + strings.Repeat("]", 2000))
	if c, _, _ := h.apiReq("POST", "/api/device/register", deep, nil); c != 400 {
		t.Fatalf("deep JSON got %d", c)
	}

	// Non-ASCII CSRF rejected with 403.
	if c, _, _ := h.ctrlReq("POST", "/policy", []byte(url.Values{"csrf": {"错误"}}.Encode()), nil); c != 403 {
		t.Fatalf("non-ASCII CSRF got %d", c)
	}

	// Host header validation on control plane.
	if c, _, _ := h.ctrlReq("GET", "/", nil, map[string]string{"Host": "evil.example"}); c != 404 {
		t.Fatalf("evil Host got %d", c)
	}

	// Legacy state migration removes salt/password_hash and compacts pending duplicates.
	legacyPath := filepath.Join(t.TempDir(), "legacy.json")
	legacyJSON := `{"version":1,"salt":"00000000000000000000000000000000","password_hash":"deadbeef","policy_revision":0,"web_domains":[],"program_hashes":[],"program_names":[],"block_local_files":false,"devices":{},"requests":[{"id":"first","device_id":"old-device","kind":"application","object":"` + strings.Repeat("a", 64) + `","label":"","state":"pending","created":1},{"id":"latest","device_id":"old-device","kind":"application","object":"` + strings.Repeat("a", 64) + `","label":"","state":"pending","created":1},{"id":"denied","device_id":"old-device","kind":"application","object":"` + strings.Repeat("a", 64) + `","label":"","state":"denied","created":1}]}`
	if err := os.WriteFile(legacyPath, []byte(legacyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Data.UnlockPINHash != nil || len(loaded.Data.Requests) != 2 || loaded.Data.Requests[0].ID != "latest" || loaded.Data.Requests[1].ID != "denied" {
		t.Fatalf("legacy migration failed: %+v", loaded.Data.Requests)
	}
	migratedRaw, _ := os.ReadFile(legacyPath)
	if strings.Contains(string(migratedRaw), "password_hash") || strings.Contains(string(migratedRaw), `"salt"`) {
		t.Fatal("legacy password fields remained after migration")
	}
}

func TestConnectionLimitAndControlBindCleanup(t *testing.T) {
	// Bounded listener drops excess connections and recovers after idle timeout.
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{}, 4)
	bl := newBoundedListener(rawLn, 1, func() { released <- struct{}{} })
	srv := &http.Server{
		Handler:           NewTeacherHandler(ServerConfig{}),
		ReadHeaderTimeout: 1 * time.Second,
		IdleTimeout:       1 * time.Second,
	}
	go func() { _ = srv.Serve(bl) }()
	defer srv.Close()

	addr := rawLn.Addr().String()
	idle, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	// Give accept loop a moment to hold the single slot.
	time.Sleep(100 * time.Millisecond)

	rejected, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		_ = rejected.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		n, _ := rejected.Read(buf)
		_ = rejected.Close()
		if n != 0 {
			t.Fatalf("expected immediate EOF on rejected connection, read %d bytes", n)
		}
	}
	// Wait for idle connection timeout and slot release.
	select {
	case <-released:
	case <-time.After(4 * time.Second):
		t.Fatal("idle connection did not release worker slot")
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + addr + "/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("server failed to recover after idle timeout: %v", err)
	}
	_ = resp.Body.Close()

	// Control bind failure releases API port cleanly.
	dir := t.TempDir()
	st, _ := InitializeStore(filepath.Join(dir, "state.json"))
	st.Close()
	_ = CreateCertificate(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), "localhost")
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	err = ServeTeacher(ServeOptions{
		StatePath:   filepath.Join(dir, "state.json"),
		CertPath:    filepath.Join(dir, "cert.pem"),
		KeyPath:     filepath.Join(dir, "key.pem"),
		Bind:        "127.0.0.1",
		Port:        0,
		ControlPort: occupied.Addr().(*net.TCPAddr).Port,
	})
	if err == nil {
		t.Fatal("expected error when control port is occupied")
	}
}
