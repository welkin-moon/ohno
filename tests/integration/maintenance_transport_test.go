package integration

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedReq struct {
	method     string
	path       string
	headers    map[string]string
	body       []byte
	connection int
}

type adversaryServer struct {
	ln            net.Listener
	url           string
	mode          string
	redirect      string
	fixture       *certFixture
	secondFixture *certFixture
	mu            sync.Mutex
	connections   int
	records       []recordedReq
	wg            sync.WaitGroup
	stop          chan struct{}
}

func startAdversaryServer(t *testing.T, fixture *certFixture, mode, redirect string, second *certFixture, customHandler func(*adversaryServer, net.Conn, int)) *adversaryServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &adversaryServer{
		ln:            ln,
		url:           "https://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		mode:          mode,
		redirect:      redirect,
		fixture:       fixture,
		secondFixture: second,
		stop:          make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections++
			idx := s.connections
			s.mu.Unlock()
			s.wg.Add(1)
			go func(c net.Conn, connIdx int) {
				defer s.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				fx := s.fixture
				if connIdx > 1 && s.secondFixture != nil {
					fx = s.secondFixture
				}
				tlsConn := tls.Server(c, &tls.Config{
					MinVersion:   tls.VersionTLS12,
					Certificates: []tls.Certificate{fx.tlsCert},
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				if customHandler != nil {
					customHandler(s, tlsConn, connIdx)
				} else {
					s.handleMaintenanceConn(tlsConn, connIdx)
				}
			}(raw, idx)
		}
	}()
	return s
}

func (s *adversaryServer) close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *adversaryServer) getRecords() []recordedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedReq, len(s.records))
	copy(out, s.records)
	return out
}

func (s *adversaryServer) getConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
}

func readRawHTTPRequest(conn net.Conn, maxBody int) (method, path string, headers map[string]string, body []byte, ok bool) {
	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return "", "", nil, nil, false
	}
	parts := strings.SplitN(strings.TrimSpace(reqLine), " ", 3)
	if len(parts) < 2 {
		return "", "", nil, nil, false
	}
	method, path = parts[0], parts[1]
	headers = map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return method, path, headers, nil, false
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, found := strings.Cut(line, ":"); found {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	cl, _ := strconv.Atoi(headers["content-length"])
	if cl > maxBody {
		cl = maxBody
	}
	if cl > 0 {
		body = make([]byte, cl)
		n, _ := io.ReadFull(br, body)
		body = body[:n]
		if n != cl {
			return method, path, headers, body, false
		}
	}
	return method, path, headers, body, len(body) > 0
}

func (s *adversaryServer) handleMaintenanceConn(conn net.Conn, connIdx int) {
	mode := s.mode
	if mode == "disconnect_rotate" && connIdx == 1 {
		// Record connection arrival without replying and immediately close.
		s.mu.Lock()
		s.records = append(s.records, recordedReq{method: "POST", path: "/api/maintenance/authorize", headers: map[string]string{}, connection: connIdx})
		s.mu.Unlock()
		return
	}
	method, path, headers, body, ok := readRawHTTPRequest(conn, 32768)
	rec := recordedReq{method: method, path: path, headers: headers, body: body, connection: connIdx}
	s.mu.Lock()
	s.records = append(s.records, rec)
	s.mu.Unlock()
	if !ok {
		return
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}
	now := time.Now().Unix()
	action, _ := data["action"].(string)
	nonce, _ := data["nonce"].(string)
	devID, _ := data["device_id"].(string)
	reply := map[string]any{
		"authorized":    true,
		"action":        action,
		"nonce":         nonce,
		"device_id":     devID,
		"authorized_at": now,
		"expires_at":    now + 120,
	}
	status := 200
	extra := map[string]string{}
	switch {
	case mode == "denied":
		status = 403
		reply = map[string]any{"error": "test rejection"}
	case mode == "save_failure":
		status = 503
		reply = map[string]any{"error": "test rejection"}
	case mode == "authentication":
		status = 401
		reply = map[string]any{"error": "test rejection"}
		extra["WWW-Authenticate"] = "Negotiate, NTLM"
	case mode == "proxy_authentication":
		status = 407
		reply = map[string]any{"error": "test rejection"}
		extra["Proxy-Authenticate"] = "Negotiate, NTLM"
	case strings.HasPrefix(mode, "redirect_"):
		status, _ = strconv.Atoi(strings.TrimPrefix(mode, "redirect_"))
		extra["Location"] = s.redirect + "/credential-trap"
	case mode == "wrong_nonce":
		if len(nonce) > 0 && nonce[0] != '0' {
			reply["nonce"] = "0" + nonce[1:]
		} else if len(nonce) > 0 {
			reply["nonce"] = "1" + nonce[1:]
		}
	case mode == "wrong_action":
		if action == "install" {
			reply["action"] = "uninstall"
		} else {
			reply["action"] = "install"
		}
	case mode == "wrong_device":
		reply["device_id"] = randomHex(16)
	case mode == "authorized_false":
		reply["authorized"] = false
	case mode == "authorized_number":
		reply["authorized"] = 1
	case mode == "nonce_number":
		reply["nonce"] = 3
	case mode == "expiry_string":
		reply["expires_at"] = strconv.FormatInt(now+120, 10)
	case mode == "expiry_float":
		reply["expires_at"] = json.Number(strconv.FormatInt(now+120, 10) + ".0")
	case mode == "issued_boolean":
		reply["authorized_at"] = true
	case mode == "wrong_window":
		reply["expires_at"] = now + 121
	case mode == "expired_response":
		reply["authorized_at"] = now - 151
		reply["expires_at"] = now - 31
	case mode == "clock_ahead":
		reply["authorized_at"] = now + 15
		reply["expires_at"] = now + 135
	case mode == "clock_behind":
		reply["authorized_at"] = now - 130
		reply["expires_at"] = now - 10
	case mode == "future_response":
		reply["authorized_at"] = now + 3600
		reply["expires_at"] = now + 3720
	case mode == "huge_timestamp":
		reply["authorized_at"] = json.Number("10000000000000000000000000000000000000000")
		reply["expires_at"] = json.Number("10000000000000000000000000000000000000120")
	case mode == "missing_field":
		delete(reply, "authorized_at")
	case mode == "extra_field":
		reply["bearer_token"] = "not-supported"
	}

	payload, _ := json.Marshal(reply)
	switch mode {
	case "duplicate_field":
		payload = append(payload[:len(payload)-1], []byte(`,"authorized":true}`)...)
	case "invalid_json":
		payload = append(payload, []byte("not-json")...)
	case "invalid_utf8":
		payload = append(payload[:len(payload)-1], []byte(`,"bad":"`)...)
		payload = append(payload, 0xff)
		payload = append(payload, []byte(`"}`)...)
	case "oversized", "chunked_oversized":
		payload = append(payload, bytes.Repeat([]byte(" "), 2049)...)
	case "array_response":
		payload = append([]byte("["), append(payload, ']')...)
	}
	if mode == "oversized_headers" {
		extra["X-Test-Padding"] = strings.Repeat("x", 10000)
	}
	if mode == "content_encoding" {
		extra["Content-Encoding"] = "gzip"
	}

	var resp bytes.Buffer
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if mode != "missing_content_type" {
		ct := "application/json; charset=utf-8"
		if mode == "wrong_content_type" {
			ct = "text/html"
		}
		fmt.Fprintf(&resp, "Content-Type: %s\r\n", ct)
	}
	if mode == "chunked" || mode == "chunked_oversized" {
		resp.WriteString("Transfer-Encoding: chunked\r\n")
	} else {
		cl := len(payload)
		if mode == "truncated" {
			cl += 5
		}
		fmt.Fprintf(&resp, "Content-Length: %d\r\n", cl)
	}
	resp.WriteString("Connection: close\r\n")
	for k, v := range extra {
		fmt.Fprintf(&resp, "%s: %s\r\n", k, v)
	}
	resp.WriteString("\r\n")
	if mode == "chunked" || mode == "chunked_oversized" {
		fmt.Fprintf(&resp, "%x\r\n", len(payload))
		resp.Write(payload)
		resp.WriteString("\r\n0\r\n\r\n")
	} else {
		resp.Write(payload)
	}
	_, _ = conn.Write(resp.Bytes())
}

func makeMaintenanceInput(serverURL string, fx *certFixture, action string) map[string]string {
	if action == "" {
		action = "install"
	}
	m := map[string]string{
		"server":          serverURL,
		"certificate_pem": fx.pem,
		"action":          action,
		"nonce":           randomHex(32),
		"password":        "ephemeral-" + randomHex(16),
		"device_id":       "",
		"device_key":      "",
	}
	if action == "uninstall" {
		m["device_id"] = randomHex(16)
		m["device_key"] = randomHex(32)
	}
	return m
}

func TestMaintenanceTransportPortableSelfTest(t *testing.T) {
	dir := t.TempDir()
	good := newCertFixture(t, dir, "good", certOpts{hostname: true, serverUsage: true})
	expired := newCertFixture(t, dir, "expired", certOpts{hostname: true, expired: true, serverUsage: true})
	future := newCertFixture(t, dir, "future", certOpts{hostname: true, future: true, serverUsage: true})
	reissued := newCertFixture(t, dir, "reissued", certOpts{hostname: true, serverUsage: true, privateKey: good.key})

	srv := startAdversaryServer(t, good, "normal", "", nil, nil)
	defer srv.close()

	data := makeMaintenanceInput(srv.url, good, "install")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(good.pem))
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	wire, _ := json.Marshal(map[string]string{
		"action": data["action"], "nonce": data["nonce"], "maintenance_password": data["password"],
	})
	resp, err := client.Post(srv.url+"/api/maintenance/authorize", "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if out["nonce"] != data["nonce"] {
		t.Fatal("nonce mismatch")
	}
	if reissued.key != good.key || reissued.pem == good.pem {
		t.Fatal("reissued cert should share key but differ in PEM")
	}
	now := time.Now().UTC()
	for name, fx := range map[string]*certFixture{"good": good, "expired": expired, "future": future} {
		parsed, err := x509.ParseCertificate(fx.tlsCert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if name == "expired" && !parsed.NotAfter.Before(now) {
			t.Fatal("expired fixture not expired")
		}
		if name == "future" && !parsed.NotBefore.After(now) {
			t.Fatal("future fixture not in future")
		}
	}
}

func TestWindowsMaintenanceTransport(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native WinHTTP maintenance transport tests require Windows")
	}
	absClient := resolveBuildArtifact("OHNO_MAINTENANCE_CLIENT", "maintenance-client.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("maintenance client %s not found: %v", absClient, err)
	}

	dir := t.TempDir()
	good := newCertFixture(t, dir, "good", certOpts{hostname: true, serverUsage: true})
	other := newCertFixture(t, dir, "other", certOpts{hostname: true, serverUsage: true})
	hostname := newCertFixture(t, dir, "hostname", certOpts{hostname: false, serverUsage: true})
	expired := newCertFixture(t, dir, "expired", certOpts{hostname: true, expired: true, serverUsage: true})
	future := newCertFixture(t, dir, "future", certOpts{hostname: true, future: true, serverUsage: true})
	usage := newCertFixture(t, dir, "usage", certOpts{hostname: true, serverUsage: false})
	reissued := newCertFixture(t, dir, "reissued", certOpts{hostname: true, serverUsage: true, privateKey: good.key})

	invoke := func(data map[string]string, expected ...string) {
		t.Helper()
		rawIn, _ := json.Marshal(data)
		cmd := exec.Command(absClient)
		cmd.Stdin = bytes.NewReader(rawIn)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		_ = cmd.Run()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		names := map[int]string{0: "Authorized", 10: "Denied", 11: "Unavailable", 12: "InvalidResponse"}
		gotName := names[code]
		matched := false
		for _, e := range expected {
			if gotName == e {
				matched = true
			}
		}
		if !matched || strings.TrimSpace(stdout.String()) != gotName {
			t.Fatalf("native driver got exit=%d stdout=%q expected=%v", code, strings.TrimSpace(stdout.String()), expected)
		}
		combined := stdout.String() + stderr.String()
		for _, secret := range []string{data["password"], data["device_key"]} {
			if secret != "" && strings.Contains(combined, secret) {
				t.Fatal("native driver disclosed a secret in diagnostics")
			}
		}
	}

	verifyRecs := func(records []recordedReq, data map[string]string, bodyMode string) {
		t.Helper()
		for _, rec := range records {
			for _, badHdr := range []string{"authorization", "proxy-authorization", "x-ohno-key", "x-ohno-device", "cookie"} {
				if _, ok := rec.headers[badHdr]; ok {
					t.Fatalf("secret/automatic header %s transmitted", badHdr)
				}
			}
			for _, v := range rec.headers {
				for _, secret := range []string{data["password"], data["device_key"]} {
					if secret != "" && strings.Contains(v, secret) {
						t.Fatal("secret occurred in request header")
					}
				}
			}
			if bodyMode == "none" && len(rec.body) > 0 {
				t.Fatal("body bytes reached an unauthenticated TLS peer")
			}
			if rec.method != "POST" || rec.path != "/api/maintenance/authorize" {
				t.Fatalf("unexpected method/path: %s %s", rec.method, rec.path)
			}
		}
		if bodyMode == "full" {
			if len(records) != 1 {
				t.Fatalf("expected exactly 1 POST without retries, got %d", len(records))
			}
			var actual map[string]string
			if err := json.Unmarshal(records[0].body, &actual); err != nil {
				t.Fatalf("invalid wire JSON: %v", err)
			}
			wanted := map[string]string{
				"action": data["action"], "nonce": data["nonce"], "maintenance_password": data["password"],
			}
			if data["action"] == "uninstall" {
				wanted["device_id"] = data["device_id"]
				wanted["device_key"] = data["device_key"]
			}
			if len(actual) != len(wanted) {
				t.Fatalf("wire schema length mismatch: %v vs %v", actual, wanted)
			}
			for k, v := range wanted {
				if actual[k] != v {
					t.Fatalf("wire field %s mismatch", k)
				}
			}
		}
	}

	type caseSpec struct {
		name     string
		fx       *certFixture
		pin      *certFixture
		second   *certFixture
		mode     string
		redirect string
		action   string
		changes  map[string]string
		expected []string
		bodyMode string
	}

	runCase := func(cs caseSpec) {
		t.Helper()
		fx := cs.fx
		if fx == nil {
			fx = good
		}
		pin := cs.pin
		if pin == nil {
			pin = good
		}
		mode := cs.mode
		if mode == "" {
			mode = "normal"
		}
		bodyMode := cs.bodyMode
		if bodyMode == "" {
			bodyMode = "full"
		}
		srv := startAdversaryServer(t, fx, mode, cs.redirect, cs.second, nil)
		defer srv.close()
		data := makeMaintenanceInput(srv.url, pin, cs.action)
		for k, v := range cs.changes {
			data[k] = v
		}
		invoke(data, cs.expected...)
		recs := srv.getRecords()
		verifyRecs(recs, data, bodyMode)
		if mode == "disconnect_rotate" {
			var later []recordedReq
			for _, r := range recs {
				if r.connection > 1 {
					later = append(later, r)
				}
			}
			verifyRecs(later, data, "none")
		}
	}

	runCase(caseSpec{name: "pinned self-signed install", expected: []string{"Authorized"}})
	runCase(caseSpec{name: "pinned self-signed uninstall", action: "uninstall", expected: []string{"Authorized"}})
	runCase(caseSpec{name: "UTF-8/escaped password", changes: map[string]string{"password": `教室维护口令够长十二字符"\结束`}, expected: []string{"Authorized"}})
	runCase(caseSpec{name: "valid chunked JSON", mode: "chunked", expected: []string{"Authorized"}})
	runCase(caseSpec{name: "clock ahead", mode: "clock_ahead", expected: []string{"Authorized"}})
	runCase(caseSpec{name: "clock behind", mode: "clock_behind", expected: []string{"Authorized"}})
	runCase(caseSpec{name: "password denial", mode: "denied", expected: []string{"Denied"}})
	runCase(caseSpec{name: "save failure", mode: "save_failure", expected: []string{"Unavailable"}})
	runCase(caseSpec{name: "wrong pin sends no body", fx: other, action: "uninstall", expected: []string{"Unavailable"}, bodyMode: "none"})
	runCase(caseSpec{name: "reissued cert rejected", fx: reissued, expected: []string{"Unavailable"}, bodyMode: "none"})

	for name, fx := range map[string]*certFixture{"hostname": hostname, "expired": expired, "future": future, "usage": usage} {
		runCase(caseSpec{name: "invalid " + name, fx: fx, pin: fx, action: "uninstall", expected: []string{"Unavailable"}, bodyMode: "none"})
	}
	runCase(caseSpec{name: "OS trust rejects self-signed without pin", changes: map[string]string{"certificate_pem": ""}, expected: []string{"Unavailable"}, bodyMode: "none"})
	runCase(caseSpec{name: "malformed pin", changes: map[string]string{"certificate_pem": "invalid PEM"}, expected: []string{"InvalidResponse"}, bodyMode: "none"})
	runCase(caseSpec{name: "multiple PEMs", changes: map[string]string{"certificate_pem": good.pem + other.pem}, expected: []string{"InvalidResponse"}, bodyMode: "none"})
	runCase(caseSpec{name: "no integrated auth", mode: "authentication", expected: []string{"InvalidResponse"}})
	runCase(caseSpec{name: "no proxy auth", mode: "proxy_authentication", expected: []string{"InvalidResponse"}})

	trap := startAdversaryServer(t, good, "normal", "", nil, nil)
	for _, code := range []int{301, 302, 303, 307, 308} {
		runCase(caseSpec{
			name: fmt.Sprintf("redirect %d", code), mode: fmt.Sprintf("redirect_%d", code),
			redirect: trap.url, action: "uninstall", expected: []string{"InvalidResponse"},
		})
	}
	if trap.getConnections() != 0 || len(trap.getRecords()) != 0 {
		trap.close()
		t.Fatal("redirect target received a connection")
	}
	trap.close()

	runCase(caseSpec{
		name: "disconnect_rotate", mode: "disconnect_rotate", second: other,
		action: "uninstall", expected: []string{"Unavailable", "InvalidResponse"}, bodyMode: "optional",
	})

	for _, mode := range []string{
		"wrong_nonce", "wrong_action", "wrong_device", "authorized_false", "authorized_number",
		"nonce_number", "expiry_string", "expiry_float", "issued_boolean", "wrong_window",
		"expired_response", "future_response", "huge_timestamp", "missing_field", "extra_field",
		"duplicate_field", "invalid_json", "invalid_utf8", "array_response", "oversized",
		"chunked_oversized", "wrong_content_type", "missing_content_type", "content_encoding",
	} {
		runCase(caseSpec{name: "reject " + mode, mode: mode, expected: []string{"InvalidResponse"}})
	}
	runCase(caseSpec{name: "uninstall wrong device", mode: "wrong_device", action: "uninstall", expected: []string{"InvalidResponse"}})
	runCase(caseSpec{name: "truncated", mode: "truncated", expected: []string{"Unavailable", "InvalidResponse"}})
	runCase(caseSpec{name: "oversized headers", mode: "oversized_headers", expected: []string{"Unavailable", "InvalidResponse"}})

	for _, origin := range []string{
		"http://127.0.0.1:1", "https://teacher:secret@127.0.0.1:1",
		"https://@127.0.0.1:1", "https://127.0.0.1:1/path",
		"https://127.0.0.1:1/?query", "https://127.0.0.1:1/#fragment",
		"https://127.0.0.1:1/%2e", "https://127.0.0.1:1/\x00ignored",
	} {
		runCase(caseSpec{name: "bad origin", changes: map[string]string{"server": origin}, expected: []string{"InvalidResponse"}, bodyMode: "none"})
	}
	for _, ch := range []map[string]string{
		{"nonce": strings.Repeat("F", 64)}, {"nonce": strings.Repeat("a", 63)},
		{"action": "upgrade"}, {"password": "too short"},
		{"password": strings.Repeat("a", 129)}, {"device_key": strings.Repeat("a", 64)},
	} {
		runCase(caseSpec{name: "bad request", changes: ch, expected: []string{"InvalidResponse"}, bodyMode: "none"})
	}
	runCase(caseSpec{name: "uninstall empty key", action: "uninstall", changes: map[string]string{"device_key": ""}, expected: []string{"InvalidResponse"}, bodyMode: "none"})

	// Offline port fails closed.
	unused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	offlinePort := unused.Addr().(*net.TCPAddr).Port
	_ = unused.Close()
	invoke(makeMaintenanceInput(fmt.Sprintf("https://127.0.0.1:%d", offlinePort), good, "install"), "Unavailable")
}
