//go:build windows

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestWindowsDeviceTransport(t *testing.T) {
	absClient := resolveBuildArtifact("OHNO_DEVICE_TRANSPORT_CLIENT", "device-transport-test.exe")
	if _, err := os.Stat(absClient); err != nil {
		t.Skipf("client %s not found: %v", absClient, err)
	}

	handler := func(s *adversaryServer, conn net.Conn, connIdx int) {
		method, path, headers, body, ok := readRawHTTPRequest(conn, 2048)
		s.mu.Lock()
		s.records = append(s.records, recordedReq{method: method, path: path, headers: headers, body: body, connection: connIdx})
		s.mu.Unlock()
		if !ok {
			return
		}
		isPolicy := path == "/api/device/policy"
		pad := ""
		if isPolicy {
			pad = strings.Repeat("x", 40000)
		}
		payload, _ := json.Marshal(map[string]any{"approved": true, "padding": pad})
		status := 201
		if isPolicy {
			status = 200
		}
		if s.mode == "oversized" {
			n := 8193
			if isPolicy {
				n = 1024*1024 + 1
			}
			payload = bytes.Repeat([]byte(" "), n)
		}
		if s.mode == "redirect" {
			status = 307
		}
		var resp bytes.Buffer
		fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n", status, http.StatusText(status), len(payload))
		if status == 307 {
			fmt.Fprintf(&resp, "Location: %s/credential-trap\r\n", s.redirect)
		}
		resp.WriteString("\r\n")
		resp.Write(payload)
		_, _ = conn.Write(resp.Bytes())
	}

	dir := t.TempDir()
	valid := newCertFixture(t, dir, "valid", certOpts{hostname: true, serverUsage: true})
	other := newCertFixture(t, dir, "other", certOpts{hostname: true, serverUsage: true})
	expired := newCertFixture(t, dir, "expired", certOpts{hostname: true, expired: true, serverUsage: true})
	wrongHost := newCertFixture(t, dir, "wrong-host", certOpts{hostname: false, serverUsage: true})

	count := 0
	for _, route := range []string{"register", "policy", "request", "unlock"} {
		for _, mode := range []string{"normal", "wrong-pin", "expired", "wrong-host", "redirect", "oversized"} {
			cert := valid
			if mode == "expired" {
				cert = expired
			} else if mode == "wrong-host" {
				cert = wrongHost
			}
			pin := cert
			if mode == "wrong-pin" {
				pin = other
			}
			device := randomHex(16)
			key := randomHex(32)
			body := map[string]any{"device_id": device, "device_key": key}
			if route == "register" {
				body = map[string]any{"id": device, "key": key, "name": "fixture"}
			} else if route == "request" {
				body["kind"] = "website"
				body["object"] = "fixture.example"
			} else if route == "unlock" {
				body["pin"] = "2468"
			}
			bodyJSON, _ := json.Marshal(body)

			trap := startAdversaryServer(t, valid, "normal", "", nil, handler)
			srv := startAdversaryServer(t, cert, mode, trap.url, nil, handler)
			input, _ := json.Marshal(map[string]string{
				"server":          srv.url,
				"certificate_pem": pin.pem,
				"path":            "/api/device/" + route,
				"body":            string(bodyJSON),
			})
			cmd := exec.Command(absClient)
			cmd.Stdin = bytes.NewReader(input)
			out, err := cmd.Output()
			srv.close()
			trap.close()
			if err != nil {
				t.Fatalf("%s/%s: native driver failed", route, mode)
			}
			fields := strings.Fields(string(out))
			if len(fields) != 3 {
				t.Fatalf("%s/%s: invalid driver output", route, mode)
			}
			failure := fields[0]
			status, _ := strconv.Atoi(fields[1])
			length, _ := strconv.Atoi(fields[2])

			recs := srv.getRecords()
			if len(recs) > 1 {
				t.Fatalf("%s/%s: request replayed", route, mode)
			}
			if trap.getConnections() != 0 || len(trap.getRecords()) != 0 {
				t.Fatalf("%s/%s: redirect followed", route, mode)
			}
			for _, rec := range recs {
				for _, bad := range []string{"authorization", "cookie", "x-ohno-device", "x-ohno-key"} {
					if _, exists := rec.headers[bad]; exists {
						t.Fatalf("%s/%s: forbidden header %s", route, mode, bad)
					}
				}
				for _, v := range rec.headers {
					if strings.Contains(v, key) {
						t.Fatalf("%s/%s: key leaked into header", route, mode)
					}
				}
			}
			if mode == "normal" {
				wantStatus := 201
				wantMinLen := 1
				if route == "policy" {
					wantStatus = 200
					wantMinLen = 8193
				}
				if failure != "None" || status != wantStatus || length < wantMinLen || len(recs) != 1 {
					t.Fatalf("%s/%s: unexpected normal result failure=%s status=%d len=%d recs=%d", route, mode, failure, status, length, len(recs))
				}
			} else {
				if failure == "None" {
					t.Fatalf("%s/%s: unexpected success", route, mode)
				}
				if mode == "wrong-pin" || mode == "expired" || mode == "wrong-host" {
					for _, rec := range recs {
						if len(rec.body) > 0 {
							t.Fatalf("%s/%s: secret sent before trust", route, mode)
						}
					}
				}
			}
			count++
		}
	}
	t.Logf("Native daily device TLS: %d cases passed", count)
}
