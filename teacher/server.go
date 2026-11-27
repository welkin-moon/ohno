package teacher

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

//go:embed update_ui.js
var updateUIJS []byte

const (
	MaxBodyBytes     = 65536
	DefaultWorkers   = 64
	DefaultTimeout   = 10 * time.Second
	BinaryDeadline   = 300 * time.Second
	BinaryChunkBytes = 65536
)

// ServerConfig configures an API or Control HTTP(S) server instance.
type ServerConfig struct {
	Store             *Store
	Control           bool
	ControlCSRF       string
	SchoolInstaller   []byte
	SchoolInstallerFn func() ([]byte, error)
	EnrollmentOrigin  string
	PublicCertificate []byte
	RequestTimeout    time.Duration
	TraceUpdateHTTP   bool
	Clock             func() time.Time
}

// boundedListener limits concurrent active connections and immediately closes
// overflow peers without blocking the accept loop.
type boundedListener struct {
	net.Listener
	slots     chan struct{}
	onRelease func()
}

func newBoundedListener(inner net.Listener, maxWorkers int, onRelease func()) *boundedListener {
	if maxWorkers <= 0 {
		maxWorkers = DefaultWorkers
	}
	return &boundedListener{
		Listener:  inner,
		slots:     make(chan struct{}, maxWorkers),
		onRelease: onRelease,
	}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &trackedConn{Conn: c, slots: l.slots, onRelease: l.onRelease}, nil
		default:
			_ = c.Close()
		}
	}
}

type trackedConn struct {
	net.Conn
	slots     chan struct{}
	onRelease func()
	closed    atomic.Bool
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		<-c.slots
		if c.onRelease != nil {
			c.onRelease()
		}
	}
	return err
}

// TeacherHandler implements both the loopback control UI and the separate LAN HTTPS device API.
type TeacherHandler struct {
	mu                sync.RWMutex
	store             *Store
	control           bool
	controlCSRF       string
	schoolInstaller   []byte
	schoolInstallerFn func() ([]byte, error)
	enrollmentOrigin  string
	publicCertificate []byte
	requestTimeout    time.Duration
	traceUpdateHTTP   bool
	clock             func() time.Time
}

// NewTeacherHandler creates a TeacherHandler from cfg.
func NewTeacherHandler(cfg ServerConfig) *TeacherHandler {
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}
	return &TeacherHandler{
		store:             cfg.Store,
		control:           cfg.Control,
		controlCSRF:       cfg.ControlCSRF,
		schoolInstaller:   cfg.SchoolInstaller,
		schoolInstallerFn: cfg.SchoolInstallerFn,
		enrollmentOrigin:  cfg.EnrollmentOrigin,
		publicCertificate: cfg.PublicCertificate,
		requestTimeout:    timeout,
		traceUpdateHTTP:   cfg.TraceUpdateHTTP,
		clock:             clk,
	}
}

// SetStore swaps the active Store (used by tests reusing listening sockets).
func (h *TeacherHandler) SetStore(s *Store) {
	h.mu.Lock()
	h.store = s
	h.mu.Unlock()
}

func (h *TeacherHandler) getStore() *Store {
	h.mu.RLock()
	s := h.store
	h.mu.RUnlock()
	return s
}

func (h *TeacherHandler) isControl(r *http.Request) bool {
	if !h.control {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(remoteHost)
	if err != nil || !addr.IsLoopback() {
		return false
	}
	reqHost := r.Host
	if hostOnly, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = hostOnly
	}
	reqHost = strings.ToLower(reqHost)
	return reqHost == "127.0.0.1" || reqHost == "localhost"
}

func (h *TeacherHandler) setCommonHeaders(w http.ResponseWriter, contentType string) {
	hdr := w.Header()
	hdr.Set("Server", "ohno-teacher/1.0")
	hdr.Set("Content-Type", contentType)
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	hdr.Set("Referrer-Policy", "no-referrer")
}

func (h *TeacherHandler) traceUpdate(path string, status int) {
	if !h.traceUpdateHTTP {
		return
	}
	// Public updater route/status metadata only; never headers, bodies, device IDs or secrets.
	if path == "/api/device/update/offer" || path == "/api/device/update/authorize" || path == "/api/maintenance/authorize" {
		fmt.Printf("FIXTURE UPDATE HTTP %s %d\n", path, status)
	} else if strings.HasPrefix(path, "/api/device/update/package/") {
		fmt.Printf("FIXTURE UPDATE HTTP package %d\n", status)
	}
}

func (h *TeacherHandler) reply(w http.ResponseWriter, r *http.Request, status int, data []byte, contentType string, extra [][2]string) {
	h.traceUpdate(r.URL.Path, status)
	h.setCommonHeaders(w, contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	for _, kv := range extra {
		w.Header().Set(kv[0], kv[1])
	}
	if contentType == "application/octet-stream" {
		w.Header().Set("Connection", "close")
		h.writeBinaryReply(w, status, data)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeBinaryReply streams large binary packages in bounded 64 KiB chunks with
// per-chunk I/O timeout and a 300-second aggregate deadline. Never writes a second
// response after headers are started.
func (h *TeacherHandler) writeBinaryReply(w http.ResponseWriter, status int, data []byte) {
	rc := http.NewResponseController(w)
	deadline := h.clock().Add(BinaryDeadline)
	_ = rc.SetWriteDeadline(h.clock().Add(h.requestTimeout))
	w.WriteHeader(status)
	for offset := 0; offset < len(data); offset += BinaryChunkBytes {
		now := h.clock()
		remaining := deadline.Sub(now)
		if remaining <= 0 {
			return
		}
		chunkTimeout := h.requestTimeout
		if remaining < chunkTimeout {
			chunkTimeout = remaining
		}
		_ = rc.SetWriteDeadline(now.Add(chunkTimeout))
		end := offset + BinaryChunkBytes
		if end > len(data) {
			end = len(data)
		}
		if _, err := w.Write(data[offset:end]); err != nil {
			return
		}
		_ = rc.Flush()
	}
}

func (h *TeacherHandler) replyText(w http.ResponseWriter, r *http.Request, status int, text string) {
	h.reply(w, r, status, []byte(text), "text/plain; charset=utf-8", nil)
}

func (h *TeacherHandler) jsonReply(w http.ResponseWriter, r *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		h.replyText(w, r, 500, "internal encoding error")
		return
	}
	h.reply(w, r, status, encoded, "application/json; charset=utf-8", nil)
}

func (h *TeacherHandler) redirect(w http.ResponseWriter, r *http.Request, location string) {
	h.reply(w, r, http.StatusSeeOther, nil, "text/plain; charset=utf-8", [][2]string{{"Location", location}})
}

func (h *TeacherHandler) readBody(w http.ResponseWriter, r *http.Request, limit int64, timeout time.Duration) ([]byte, bool) {
	if len(r.TransferEncoding) > 0 || len(r.Header.Values("Transfer-Encoding")) > 0 {
		return nil, false
	}
	clValues := r.Header.Values("Content-Length")
	if len(clValues) != 1 {
		return nil, false
	}
	length, err := strconv.ParseInt(strings.TrimSpace(clValues[0]), 10, 64)
	if err != nil || length < 0 || length > limit {
		return nil, false
	}
	rc := http.NewResponseController(w)
	if timeout <= 0 {
		timeout = h.requestTimeout
	}
	_ = rc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			return nil, false
		}
	}
	return buf, true
}

func (h *TeacherHandler) deviceCredentials(r *http.Request, data map[string]any) (string, string) {
	if len(r.Header.Values("Authorization")) > 0 {
		return "", ""
	}
	hasDev := false
	hasKey := false
	if data != nil {
		_, hasDev = data["device_id"]
		_, hasKey = data["device_key"]
	}
	var devID, key string
	if hasDev || hasKey {
		if len(r.Header.Values("X-Ohno-Device")) > 0 || len(r.Header.Values("X-Ohno-Key")) > 0 {
			return "", ""
		}
		var ok1, ok2 bool
		devID, ok1 = data["device_id"].(string)
		key, ok2 = data["device_key"].(string)
		if !ok1 || !ok2 {
			return "", ""
		}
	} else {
		devs := r.Header.Values("X-Ohno-Device")
		keys := r.Header.Values("X-Ohno-Key")
		if len(devs) != 1 || len(keys) != 1 {
			return "", ""
		}
		devID = devs[0]
		key = keys[0]
	}
	if !IDRegexp.MatchString(devID) || !IDRegexp.MatchString(key) {
		return "", ""
	}
	return devID, key
}

func (h *TeacherHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.doGet(w, r)
	case http.MethodPost:
		h.doPost(w, r)
	default:
		h.replyText(w, r, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *TeacherHandler) doGet(w http.ResponseWriter, r *http.Request) {
	// Use RawPath / RequestURI path without implicit cleaning so traversal attempts fail cleanly.
	path := r.URL.Path
	if r.URL.RawPath != "" {
		path = r.URL.RawPath
	}
	if path == "/health" {
		h.jsonReply(w, r, 200, map[string]any{"ok": true, "control": h.control})
		return
	}
	if path == "/api/device/policy" {
		if h.control {
			h.replyText(w, r, 404, "Not found")
			return
		}
		h.devicePolicy(w, r, nil)
		return
	}
	if !h.isControl(r) {
		h.replyText(w, r, 404, "Not found")
		return
	}
	if path == "/updates.js" {
		h.reply(w, r, 200, updateUIJS, "application/javascript; charset=utf-8", nil)
		return
	}
	if path == "/school-installer" {
		h.serveSchoolInstaller(w, r)
		return
	}
	if path != "/" {
		h.replyText(w, r, 404, "Not found")
		return
	}
	h.renderDashboard(w, r)
}

func (h *TeacherHandler) baseSetupBytes() ([]byte, error) {
	if len(h.schoolInstaller) > 0 {
		return h.schoolInstaller, nil
	}
	if h.schoolInstallerFn != nil {
		return h.schoolInstallerFn()
	}
	return nil, errors.New("not available")
}

func (h *TeacherHandler) hasSchoolInstaller() bool {
	if h.enrollmentOrigin == "" || len(h.publicCertificate) == 0 {
		return false
	}
	return len(h.schoolInstaller) > 0 || h.schoolInstallerFn != nil
}

func (h *TeacherHandler) serveSchoolInstaller(w http.ResponseWriter, r *http.Request) {
	if !h.hasSchoolInstaller() {
		h.replyText(w, r, 503, "School installer is not available")
		return
	}
	setupBytes, err := h.baseSetupBytes()
	if err != nil || len(setupBytes) == 0 {
		h.replyText(w, r, 503, "Cannot prepare school installer")
		return
	}
	store := h.getStore()
	store.mu.Lock()
	pubKey := ""
	if store.ReleaseCatalog != nil {
		pubKey = store.ReleaseCatalog.PublicKey
	}
	store.mu.Unlock()
	packaged, err := BuildSchoolInstaller(setupBytes, h.enrollmentOrigin, h.publicCertificate, pubKey)
	if err != nil {
		h.replyText(w, r, 503, "Cannot prepare school installer")
		return
	}
	h.reply(w, r, 200, packaged, "application/octet-stream", [][2]string{
		{"Content-Disposition", `attachment; filename="Ohno-School-Setup.exe"`},
	})
}

const uiStyle = `<style>
:root{--bg:#f5f7fb;--card:#fff;--ink:#1f2937;--muted:#5b6778;--accent:#1d4ed8;--border:#dde3ec;--ok:#15693c;--ok-bg:#e8f6ee;--warn:#9a4a00;--warn-bg:#fef3e2}
*{box-sizing:border-box}
body{font:15px/1.55 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:1.5rem 1rem}
main{max-width:1080px;margin:0 auto}
h1{margin:0 0 .25rem;color:#162b54;font-size:1.65rem}
h2{margin:0 0 .65rem;font-size:1.15rem;color:#1e3a6d}
section{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.25rem;margin:1rem 0;box-shadow:0 1px 2px rgba(15,23,42,.04)}
input,textarea,button{font:inherit;padding:.45rem .65rem;border:1px solid #cbd5e1;border-radius:6px;max-width:100%}
textarea{width:100%;height:7rem;display:block;margin:.3rem 0 .8rem;font-family:ui-monospace,Consolas,monospace;font-size:13px}
button{cursor:pointer;background:#f8fafc;color:var(--ink)}
button:hover{background:#eef2f7}
button[type="submit"],.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button[type="submit"]:hover,.primary:hover{background:#1e40af}
table{border-collapse:collapse;width:100%;font-size:14px}
td,th{padding:.55rem .5rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}
small{color:var(--muted)}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:12px;font-weight:600}
.ok{color:var(--ok);background:var(--ok-bg)}
.pending{color:var(--warn);background:var(--warn-bg)}
.dl{display:inline-block;padding:.5rem .9rem;background:var(--accent);color:#fff;text-decoration:none;border-radius:6px;font-weight:600}
.dl:hover{background:#1e40af}
</style>`

func esc(s string) string { return html.EscapeString(s) }

func (h *TeacherHandler) renderDashboard(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	type devEntry struct {
		id  string
		dev DeviceRecord
	}
	store.mu.Lock()
	devices := make([]devEntry, 0, len(store.Data.Devices))
	for id, dev := range store.Data.Devices {
		cp := *dev
		cp.MACs = append([]string{}, dev.MACs...)
		devices = append(devices, devEntry{id: id, dev: cp})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].id < devices[j].id })
	startReq := 0
	if len(store.Data.Requests) > 100 {
		startReq = len(store.Data.Requests) - 100
	}
	reqs := make([]RequestRecord, 0, len(store.Data.Requests)-startReq)
	for i := len(store.Data.Requests) - 1; i >= startReq; i-- {
		reqs = append(reqs, *store.Data.Requests[i])
	}
	domains := strings.Join(store.Data.WebDomains, "\n")
	hashes := strings.Join(store.Data.ProgramHashes, "\n")
	names := strings.Join(store.Data.ProgramNames, "\n")
	blockLocalFiles := store.Data.BlockLocalFiles
	revision := store.Data.PolicyRevision
	pinEnabled := store.Data.UnlockPINHash != nil && *store.Data.UnlockPINHash != ""
	maintenanceEnabled := store.Data.MaintenanceCredential != nil
	catalog := store.ReleaseCatalog
	releaseError := store.ReleaseError
	var offer *UpdateManifest
	if catalog != nil {
		var err error
		offer, err = catalog.Offer(0)
		if err != nil {
			releaseError = true
			offer = nil
		}
	}
	store.mu.Unlock()

	hidden := `<input type="hidden" name="csrf" value="` + esc(h.controlCSRF) + `">`
	nowUnix := time.Now().Unix()
	var rows strings.Builder
	for _, entry := range devices {
		devID := entry.id
		dev := entry.dev
		active := dev.Approved && MACBound(&dev)
		collision := false
		for _, other := range devices {
			if other.id != devID && other.dev.Approved && other.dev.BoundMAC != "" {
				for _, m := range dev.MACs {
					if other.dev.BoundMAC == m {
						collision = true
						break
					}
				}
			}
			if collision {
				break
			}
		}
		var status string
		if active {
			status = "已批准"
		} else if dev.Approved {
			status = "MAC 变更，需核验并重新绑定"
		} else {
			status = "待批准"
		}
		if collision {
			status += " / MAC 冲突"
		}
		var cmds strings.Builder
		if dev.PrimaryMAC != "" && !active {
			label := "批准并绑定 MAC"
			if dev.Approved {
				label = "重新绑定"
			}
			cmds.WriteString(`<button name="approved" value="1">` + label + `</button> `)
		}
		if dev.Approved {
			cmds.WriteString(`<button name="approved" value="0">停用</button>`)
		}
		if dev.PrimaryMAC == "" {
			cmds.WriteString(`<small>没有可绑定的 MAC，检查网卡</small>`)
		}
		action := `<form method="post" action="/device">` + hidden + `<input type="hidden" name="id" value="` + esc(devID) + `">` + cmds.String() + `</form>`
		boundLabel := dev.BoundMAC
		if boundLabel == "" {
			boundLabel = "未绑定"
		}
		primaryLabel := dev.PrimaryMAC
		if primaryLabel == "" {
			primaryLabel = "未知"
		}
		macText := `<strong>` + esc(boundLabel) + `</strong><small> 当前: ` + esc(primaryLabel) + `</small>`
		if len(dev.MACs) > 1 {
			macText += `<small> 其他: ` + esc(strings.Join(dev.MACs[1:], ", ")) + `</small>`
		}
		lastIP := dev.LastIP
		if lastIP == "" {
			lastIP = "未知"
		}
		online := "离线"
		if nowUnix-dev.LastSeen < 60 {
			online = "在线"
		}
		tunStr := "未知"
		if dev.TUN != nil {
			if *dev.TUN {
				tunStr = "运行"
			} else {
				tunStr = "不可用"
			}
		}
		wfpStr := "未知"
		if dev.WFP != nil {
			if *dev.WFP {
				wfpStr = "可用"
			} else {
				wfpStr = "不可用"
			}
		}
		shortID := devID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		rows.WriteString(`<tr><td>` + esc(dev.Name) + `</td><td>` + esc(shortID) + `</td><td>` + macText +
			`</td><td>` + esc(lastIP) + `</td><td>` + status + ` / ` + online + ` / TUN: ` + tunStr + ` / WFP: ` + wfpStr +
			`</td><td>` + action + `</td></tr>`)
	}

	var reqRows strings.Builder
	for _, item := range reqs {
		action := ""
		if item.State == "pending" {
			action = `<form method="post" action="/request">` + hidden + `<input type="hidden" name="id" value="` + esc(item.ID) + `"><button name="action" value="approve">允许 1 小时</button> <button name="action" value="deny">拒绝</button></form>`
		}
		shortID := item.DeviceID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		objText := esc(item.Object)
		if item.Label != "" {
			objText = esc(item.Label) + ` <small>` + esc(item.Object) + `</small>`
		}
		reqRows.WriteString(`<tr><td>` + esc(shortID) + `</td><td>` + esc(item.Kind) + `</td><td>` + objText + `</td><td>` + esc(item.State) + `</td><td>` + action + `</td></tr>`)
	}

	var c strings.Builder
	c.WriteString(`<main><h1>ohno 教师端</h1><p>仅本机可管理 · 策略版本 ` + strconv.Itoa(revision) + `</p>`)
	maintStatus := `<span class="badge pending">未设置，维护授权拒绝</span>`
	if maintenanceEnabled {
		maintStatus = `<span class="badge ok">已设置</span>`
	}
	c.WriteString(`<section><h2>教师维护密码（安装 / 卸载）</h2><p>仅用于新增安装 / 卸载授权，不是后台登录或课堂 PIN。镜像分发后的启动不重复输入。支持一句话式长口令，不要求大小写或符号组合。当前：` + maintStatus + `</p><p><small>安装器在安装 / 卸载时在线验证此密码。系统管理员仍可通过标准 Windows 恢复途径处理故障。</small></p><form method="post" action="/maintenance-password">` + hidden + `<input name="maintenance_password" type="password" aria-label="教师维护密码" minlength="12" maxlength="128" autocomplete="new-password" placeholder="12–128 字符的维护密码"> <button name="action" value="set">设置 / 更新</button> <button name="action" value="clear" formnovalidate>停用维护授权</button></form></section>`)

	c.WriteString(`<section><h2>客户端受管升级</h2><p>只下发教师明确批准的本地构建，不自动信任上游 latest。日常批准不重复输入维护密码。</p>`)
	if releaseError {
		c.WriteString(`<p>发布状态或签名密钥不可用；升级拒绝。请恢复原状态，勿生成新身份冒充旧学校。</p>`)
	} else if catalog == nil {
		c.WriteString(`<p>尚未初始化独立发布签名身份。私钥仅留在教师机，公开验证钥可进入学校镜像。</p><form method="post" action="/updates/initialize">` + hidden + `<button type="submit">初始化本校发布信任</button></form>`)
	} else {
		curText := "暂停或无有效批准"
		if offer != nil {
			curText = esc(offer.Version) + " / 序号 " + strconv.FormatInt(offer.Sequence, 10)
		}
		c.WriteString(`<p>当前：` + curText + `</p><p><small>公开验证钥：` + esc(catalog.PublicKey) + `</small></p>`)
		c.WriteString(`<form id="update-approval">` + hidden + `<input type="file" accept=".ohno" aria-label="本地 OHNO 更新包" required> <button type="submit">验证并批准此包</button> <button type="button" id="cancel-update-upload" disabled>取消请求</button></form><p id="update-upload-status" role="status"></p><script src="/updates.js" defer></script>`)
		c.WriteString(`<form method="post" action="/updates/pause">` + hidden + `<button>暂停下发与执行授权</button></form>`)
	}
	c.WriteString(`</section>`)

	pinStatus := `<span class="badge pending">关闭</span>`
	if pinEnabled {
		pinStatus = `<span class="badge ok">已启用</span>`
	}
	c.WriteString(`<section><h2>课堂解锁 PIN</h2><p>可选，只用于学生机现场暂停限制 1 小时；后台管理仅在教师机本地开放并免登录。当前：` + pinStatus + `</p><form method="post" action="/unlock-pin">` + hidden + `<input name="pin" type="password" inputmode="numeric" pattern="[0-9]{4,8}" maxlength="8" placeholder="4–8 位数字"> <button name="action" value="set">设置 / 更新</button> <button name="action" value="clear">关闭 PIN 解锁</button></form></section>`)

	checked := ""
	if blockLocalFiles {
		checked = " checked"
	}
	c.WriteString(`<section><h2>网站与程序规则</h2><form method="post" action="/policy">` + hidden + `<label>屏蔽域名<textarea name="domains">` + esc(domains) + `</textarea></label><label>屏蔽程序 SHA-256<textarea name="hashes">` + esc(hashes) + `</textarea></label><label>屏蔽程序文件名<textarea name="names">` + esc(names) + `</textarea></label><p><label><input type="checkbox" name="block_local_files" value="1"` + checked + `> 限制 Edge 打开本地文件</label></p><button type="submit">保存规则</button></form></section>`)

	if h.hasSchoolInstaller() {
		c.WriteString(`<section><h2>学生机一键安装</h2><p><a class="dl" href="/school-installer">下载 Ohno-School-Setup.exe</a></p><p>复制到模板机双击、允许 UAC，再输入教师维护密码。镜像分发后不重复输入。</p><small>包内只有教师 API 地址、公开证书及已初始化的发布验证公钥，没有教师 PIN、密码或私钥。</small></section>`)
	}
	c.WriteString(`<section><h2>设备</h2><p><small>MAC 用于设备关联；DHCP IP 仅显示最近地址。真正认证仍使用每机独立密钥。</small></p><table><tr><th>名称</th><th>ID</th><th>MAC</th><th>最近 IP</th><th>状态</th><th>操作</th></tr>` + rows.String() + `</table></section>`)
	c.WriteString(`<section><h2>审批请求</h2><table><tr><th>设备</th><th>类型</th><th>对象</th><th>状态</th><th>操作</th></tr>` + reqRows.String() + `</table></section></main>`)

	page := `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ohno 教师端</title>` + uiStyle + `<body>` + c.String() + `</body></html>`
	h.reply(w, r, 200, []byte(page), "text/html; charset=utf-8", nil)
}

func (h *TeacherHandler) doPost(w http.ResponseWriter, r *http.Request) {
	err := h.handlePost(w, r)
	if err != nil {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.jsonReply(w, r, 503, map[string]string{"error": "state unavailable; retry later"})
			return
		}
		h.replyText(w, r, 503, "保存失败，修改未生效。请检查磁盘和文件权限后重试。")
	}
}

func (h *TeacherHandler) handlePost(w http.ResponseWriter, r *http.Request) error {
	path := r.URL.Path
	if r.URL.RawPath != "" {
		path = r.URL.RawPath
	}
	store := h.getStore()

	if path == "/updates/approve" {
		if !h.isControl(r) {
			h.replyText(w, r, 404, "Not found")
			return nil
		}
		token := r.Header.Get("X-Ohno-CSRF")
		if subtle.ConstantTimeCompare([]byte(h.controlCSRF), []byte(token)) != 1 {
			h.replyText(w, r, 403, "Invalid CSRF token")
			return nil
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			h.replyText(w, r, 400, "Expected binary update package")
			return nil
		}
		raw, ok := h.readBody(w, r, MaxPackageSize, 120*time.Second)
		if !ok {
			h.replyText(w, r, 413, "Invalid update length")
			return nil
		}
		store.mu.Lock()
		cat := store.ReleaseCatalog
		store.mu.Unlock()
		if cat == nil {
			h.replyText(w, r, 409, "Initialize release trust first")
			return nil
		}
		approved, err := cat.Approve(raw, nil)
		if err != nil {
			var catErr *CatalogError
			if errors.As(err, &catErr) {
				return err
			}
			h.replyText(w, r, 400, "Invalid x64 update package")
			return nil
		}
		h.jsonReply(w, r, 200, map[string]any{
			"approved": true,
			"sequence": approved.Sequence,
			"sha256":   approved.SHA256,
		})
		return nil
	}

	limit := int64(MaxBodyBytes)
	if strings.HasPrefix(path, "/api/device/update/") {
		limit = 2048
	}
	raw, ok := h.readBody(w, r, limit, h.requestTimeout)
	if !ok {
		h.replyText(w, r, 413, "Invalid request length")
		return nil
	}

	if strings.HasPrefix(path, "/api/device/") || path == "/api/maintenance/authorize" {
		if h.control {
			h.replyText(w, r, 404, "Not found")
			return nil
		}
		if path == "/api/maintenance/authorize" {
			req, err := ParseAuthorizationRequest(raw)
			if err != nil {
				h.jsonReply(w, r, 400, map[string]string{"error": "invalid JSON"})
				return nil
			}
			return h.maintenanceAuthorization(w, r, req)
		}
		data, err := ParseStrictJSONObject(raw)
		if err != nil {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid JSON"})
			return nil
		}
		if strings.HasPrefix(path, "/api/device/update/") {
			return h.deviceUpdate(w, r, path, data)
		}
		switch path {
		case "/api/device/register":
			return h.register(w, r, data)
		case "/api/device/policy":
			h.devicePolicy(w, r, data)
			return nil
		case "/api/device/request":
			return h.submitRequest(w, r, data)
		case "/api/device/unlock":
			return h.unlockDevice(w, r, data)
		default:
			h.jsonReply(w, r, 404, map[string]string{"error": "not found"})
			return nil
		}
	}

	if !h.isControl(r) {
		h.replyText(w, r, 404, "Not found")
		return nil
	}
	form, err := parseStrictForm(raw, 20)
	if err != nil {
		h.replyText(w, r, 400, "Invalid form")
		return nil
	}
	one := func(key string) string {
		if vals := form[key]; len(vals) > 0 {
			return vals[0]
		}
		return ""
	}
	if subtle.ConstantTimeCompare([]byte(h.controlCSRF), []byte(one("csrf"))) != 1 {
		h.replyText(w, r, 403, "Invalid CSRF token")
		return nil
	}

	switch path {
	case "/updates/initialize":
		if err := store.InitializeReleases(); err != nil {
			return err
		}
		h.redirect(w, r, "/")
		return nil
	case "/updates/pause":
		store.mu.Lock()
		cat := store.ReleaseCatalog
		store.mu.Unlock()
		if cat == nil {
			h.replyText(w, r, 409, "No release trust")
			return nil
		}
		if err := cat.Pause(); err != nil {
			return err
		}
		h.redirect(w, r, "/")
		return nil
	case "/maintenance-password":
		action := one("action")
		if action != "set" && action != "clear" {
			h.replyText(w, r, 400, "Invalid maintenance action")
			return nil
		}
		var pw *string
		if action == "set" {
			v := one("maintenance_password")
			pw = &v
		}
		if err := store.SetMaintenancePassword(pw); err != nil {
			var saveErr *StateSaveError
			if errors.As(err, &saveErr) {
				return err
			}
			h.replyText(w, r, 400, "Maintenance password must be 12-128 printable characters")
			return nil
		}
		h.redirect(w, r, "/")
		return nil
	case "/unlock-pin":
		action := one("action")
		switch action {
		case "clear":
			if err := store.SetUnlockPIN(nil); err != nil {
				return err
			}
		case "set":
			v := one("pin")
			if err := store.SetUnlockPIN(&v); err != nil {
				var saveErr *StateSaveError
				if errors.As(err, &saveErr) {
					return err
				}
				h.replyText(w, r, 400, "PIN must be 4-8 digits")
				return nil
			}
		default:
			h.replyText(w, r, 400, "Invalid PIN action")
			return nil
		}
		h.redirect(w, r, "/")
		return nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	switch path {
	case "/policy":
		domains := uniqueSortedLines(one("domains"))
		hashes := uniqueSortedLines(one("hashes"))
		names := uniqueSortedLines(one("names"))
		blockLocal := one("block_local_files") == "1"
		extraDomain := 0
		if blockLocal {
			extraDomain = 1
		}
		if len(domains)+extraDomain > 1000 || len(hashes) > 1000 || len(names) > 1000 {
			h.replyText(w, r, 400, "Invalid domains or SHA-256 values")
			return nil
		}
		for _, d := range domains {
			if !isValidHostname(d) {
				h.replyText(w, r, 400, "Invalid domains or SHA-256 values")
				return nil
			}
		}
		for _, hv := range hashes {
			if !HashRegexp.MatchString(hv) {
				h.replyText(w, r, 400, "Invalid domains or SHA-256 values")
				return nil
			}
		}
		for _, n := range names {
			if !ProgramNameRegexp.MatchString(n) {
				h.replyText(w, r, 400, "Invalid domains or SHA-256 values")
				return nil
			}
		}
		store.Data.WebDomains = domains
		store.Data.ProgramHashes = hashes
		store.Data.ProgramNames = names
		store.Data.BlockLocalFiles = blockLocal
		store.Data.PolicyRevision++
	case "/device":
		devID := one("id")
		approvedStr := one("approved")
		dev, ok := store.Data.Devices[devID]
		if !ok || (approvedStr != "0" && approvedStr != "1") {
			h.replyText(w, r, 400, "Unknown device")
			return nil
		}
		if approvedStr == "1" {
			primary := dev.PrimaryMAC
			hasPrimary := false
			for _, m := range dev.MACs {
				if m == primary {
					hasPrimary = true
					break
				}
			}
			if !ValidMAC(primary) || !hasPrimary {
				h.replyText(w, r, 400, "No valid hardware MAC to bind")
				return nil
			}
			for otherID, other := range store.Data.Devices {
				if otherID != devID && other.Approved && other.BoundMAC != "" {
					for _, m := range dev.MACs {
						if other.BoundMAC == m {
							h.replyText(w, r, 409, "MAC already bound to another approved device")
							return nil
						}
					}
				}
			}
			dev.BoundMAC = primary
			dev.Approved = true
		} else {
			dev.Approved = false
		}
	case "/request":
		reqID := one("id")
		action := one("action")
		var target *RequestRecord
		for _, item := range store.Data.Requests {
			if item.ID == reqID {
				target = item
				break
			}
		}
		if target == nil || target.State != "pending" || (action != "approve" && action != "deny") {
			h.replyText(w, r, 400, "Invalid request")
			return nil
		}
		if action == "approve" {
			target.State = "approved"
			target.Expires = time.Now().Unix() + 3600
		} else {
			target.State = "denied"
		}
	default:
		h.replyText(w, r, 404, "Not found")
		return nil
	}
	if err := store.saveLocked(); err != nil {
		return err
	}
	h.redirect(w, r, "/")
	return nil
}

func parseStrictForm(raw []byte, maxFields int) (url.Values, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8 form")
	}
	s := string(raw)
	if s == "" {
		return url.Values{}, nil
	}
	parts := strings.Split(s, "&")
	if len(parts) > maxFields {
		return nil, errors.New("too many form fields")
	}
	vals := make(url.Values, len(parts))
	for _, p := range parts {
		k, v, _ := strings.Cut(p, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			return nil, err
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			return nil, err
		}
		vals.Add(dk, dv)
	}
	return vals, nil
}

func uniqueSortedLines(s string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

func (h *TeacherHandler) devicePolicy(w http.ResponseWriter, r *http.Request, data map[string]any) {
	if data != nil {
		if len(data) != 2 {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid policy request"})
			return
		}
		if _, ok1 := data["device_id"]; !ok1 {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid policy request"})
			return
		}
		if _, ok2 := data["device_key"]; !ok2 {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid policy request"})
			return
		}
	}
	devID, key := h.deviceCredentials(r, data)
	store := h.getStore()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deviceLocked(devID, key, true) == nil {
		h.jsonReply(w, r, 403, map[string]string{"error": "not authorized or pending"})
		return
	}
	now := time.Now().Unix()
	type grantOut struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		Object  string `json:"object"`
		Expires int64  `json:"expires"`
	}
	grants := []grantOut{}
	for _, x := range store.Data.Requests {
		if x.DeviceID == devID && x.State == "approved" && x.Expires > now {
			grants = append(grants, grantOut{ID: x.ID, Kind: x.Kind, Object: x.Object, Expires: x.Expires})
		}
	}
	h.jsonReply(w, r, 200, map[string]any{
		"revision":          store.Data.PolicyRevision,
		"web_domains":       store.Data.WebDomains,
		"program_hashes":    store.Data.ProgramHashes,
		"program_names":     store.Data.ProgramNames,
		"block_local_files": store.Data.BlockLocalFiles,
		"grants":            grants,
	})
}

func (h *TeacherHandler) deviceUpdate(w http.ResponseWriter, r *http.Request, path string, data map[string]any) error {
	execute := path == "/api/device/update/authorize"
	expectedFields := 3
	if execute {
		expectedFields = 5
	}
	devID, ok1 := data["device_id"].(string)
	devKey, ok2 := data["device_key"].(string)
	nonce, ok3 := data["nonce"].(string)
	_, hasSeq := data["sequence"]
	_, hasSha := data["sha256"]
	if len(data) != expectedFields || !ok1 || !ok2 || !ok3 ||
		(execute && (!hasSeq || !hasSha)) ||
		!IDRegexp.MatchString(devID) || !IDRegexp.MatchString(devKey) || !HashRegexp.MatchString(nonce) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid update request"})
		return nil
	}

	store := h.getStore()
	store.mu.Lock()
	if store.deviceLocked(devID, devKey, true) == nil {
		store.mu.Unlock()
		h.jsonReply(w, r, 403, map[string]string{"error": "device not approved or MAC changed"})
		return nil
	}
	catalog := store.ReleaseCatalog
	if catalog == nil {
		store.mu.Unlock()
		h.jsonReply(w, r, 503, map[string]string{"error": "release trust unavailable"})
		return nil
	}
	offer, err := catalog.Offer(0)
	if err != nil {
		store.mu.Unlock()
		return err
	}
	if offer == nil {
		store.mu.Unlock()
		h.jsonReply(w, r, 404, map[string]string{"error": "no currently approved release"})
		return nil
	}
	if path == "/api/device/update/offer" {
		store.mu.Unlock()
		h.jsonReply(w, r, 200, offer)
		return nil
	}
	if execute {
		seq, okSeq := StrictInt64(data["sequence"], 1, MaxSequence)
		sha, okSha := data["sha256"].(string)
		store.mu.Unlock()
		if !okSeq || !okSha || seq != offer.Sequence || sha != offer.SHA256 {
			h.jsonReply(w, r, 403, map[string]string{"error": "release approval changed"})
			return nil
		}
		now := time.Now().Unix()
		h.jsonReply(w, r, 200, map[string]any{
			"authorized":    true,
			"nonce":         nonce,
			"device_id":     devID,
			"sequence":      offer.Sequence,
			"sha256":        offer.SHA256,
			"authorized_at": now,
			"expires_at":    now + 120,
		})
		return nil
	}
	expectedPath := "/api/device/update/package/" + offer.SHA256
	readerFn := store.packageReader
	store.mu.Unlock()

	if path != expectedPath {
		h.jsonReply(w, r, 404, map[string]string{"error": "unknown update path"})
		return nil
	}
	select {
	case store.ReleaseDownloadSlots <- struct{}{}:
	default:
		h.jsonReply(w, r, 503, map[string]string{"error": "download capacity; retry later"})
		return nil
	}
	defer func() { <-store.ReleaseDownloadSlots }()

	var payload []byte
	if readerFn != nil {
		payload, err = readerFn(offer.SHA256)
	} else {
		payload, err = catalog.Package(offer.SHA256, 0)
	}
	if err != nil {
		return err
	}
	store.mu.Lock()
	if store.deviceLocked(devID, devKey, true) == nil {
		store.mu.Unlock()
		h.jsonReply(w, r, 403, map[string]string{"error": "device authorization changed"})
		return nil
	}
	current, err := catalog.Offer(0)
	store.mu.Unlock()
	if err != nil {
		return err
	}
	if payload == nil || current == nil || current.Sequence != offer.Sequence {
		h.jsonReply(w, r, 404, map[string]string{"error": "release no longer approved"})
		return nil
	}
	h.reply(w, r, 200, payload, "application/octet-stream", nil)
	return nil
}

func (h *TeacherHandler) maintenanceAuthorization(w http.ResponseWriter, r *http.Request, req MaintenanceAuthRequest) error {
	devID := r.Header.Get("X-Ohno-Device")
	key := r.Header.Get("X-Ohno-Key")
	if req.HasDevice {
		if devID != "" || key != "" {
			h.jsonReply(w, r, 400, map[string]string{"error": "ambiguous maintenance device credentials"})
			return nil
		}
		devID = req.DeviceID
		key = req.DeviceKey
	}
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = r.RemoteAddr
	}
	ev, err := h.getStore().AuthorizeMaintenance(req.MaintenancePassword, sourceIP, req.Action, req.Nonce, devID, key)
	if err != nil {
		return err
	}
	if ev == nil {
		h.jsonReply(w, r, 403, map[string]string{"error": "maintenance authorization denied or temporarily unavailable"})
		return nil
	}
	h.jsonReply(w, r, 200, map[string]any{
		"action":        ev.Action,
		"nonce":         ev.Nonce,
		"device_id":     ev.DeviceID,
		"authorized_at": ev.AuthorizedAt,
		"expires_at":    ev.ExpiresAt,
		"authorized":    true,
	})
	return nil
}

func (h *TeacherHandler) register(w http.ResponseWriter, r *http.Request, data map[string]any) error {
	for _, hdr := range []string{"Authorization", "X-Ohno-Device", "X-Ohno-Key"} {
		if len(r.Header.Values(hdr)) > 0 {
			h.jsonReply(w, r, 400, map[string]string{"error": "ambiguous registration credentials"})
			return nil
		}
	}
	if _, ok := data["device_id"]; ok {
		h.jsonReply(w, r, 400, map[string]string{"error": "ambiguous registration credentials"})
		return nil
	}
	if _, ok := data["device_key"]; ok {
		h.jsonReply(w, r, 400, map[string]string{"error": "ambiguous registration credentials"})
		return nil
	}

	var tunPtr, wfpPtr *bool
	if raw, exists := data["tun"]; exists && raw != nil {
		b, ok := raw.(bool)
		if !ok {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid status"})
			return nil
		}
		tunPtr = &b
	}
	if raw, exists := data["wfp"]; exists && raw != nil {
		b, ok := raw.(bool)
		if !ok {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid status"})
			return nil
		}
		wfpPtr = &b
	}
	devID, ok1 := data["id"].(string)
	key, ok2 := data["key"].(string)
	name, ok3 := data["name"].(string)
	if !ok1 || !ok2 || !ok3 || !IDRegexp.MatchString(devID) || !IDRegexp.MatchString(key) || !ValidText(name, 128, false) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid device registration"})
		return nil
	}

	macs := []string{}
	if rawMacs, exists := data["macs"]; exists {
		arr, ok := rawMacs.([]any)
		if !ok || len(arr) > 16 {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid MAC inventory"})
			return nil
		}
		seen := map[string]struct{}{}
		for _, el := range arr {
			s, ok := el.(string)
			if !ok || !ValidMAC(s) {
				h.jsonReply(w, r, 400, map[string]string{"error": "invalid MAC inventory"})
				return nil
			}
			if _, dup := seen[s]; dup {
				h.jsonReply(w, r, 400, map[string]string{"error": "invalid MAC inventory"})
				return nil
			}
			seen[s] = struct{}{}
			macs = append(macs, s)
		}
	}
	primary := ""
	if rawPrimary, exists := data["primary_mac"]; exists {
		var ok bool
		primary, ok = rawPrimary.(string)
		if !ok {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid MAC inventory"})
			return nil
		}
	}
	expectedPrimary := ""
	if len(macs) > 0 {
		expectedPrimary = macs[0]
	}
	if primary != expectedPrimary {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid MAC inventory"})
		return nil
	}

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}
	store := h.getStore()
	store.mu.Lock()
	defer store.mu.Unlock()
	digest := sha256Hex(key)
	now := time.Now().Unix()
	if dev, exists := store.Data.Devices[devID]; exists {
		if subtle.ConstantTimeCompare([]byte(dev.KeyHash), []byte(digest)) != 1 {
			h.jsonReply(w, r, 403, map[string]string{"error": "device id already used"})
			return nil
		}
		dev.Name = name
		dev.MACs = macs
		dev.PrimaryMAC = primary
		dev.LastIP = remoteIP
		dev.LastSeen = now
		dev.TUN = tunPtr
		dev.WFP = wfpPtr
		if err := store.saveLocked(); err != nil {
			return err
		}
		h.jsonReply(w, r, 200, map[string]bool{"approved": store.deviceLocked(devID, key, true) != nil})
		return nil
	}
	if len(store.Data.Devices) >= 1000 {
		h.jsonReply(w, r, 429, map[string]string{"error": "device capacity"})
		return nil
	}
	store.Data.Devices[devID] = &DeviceRecord{
		Name:       name,
		KeyHash:    digest,
		Approved:   false,
		BoundMAC:   "",
		MACs:       macs,
		PrimaryMAC: primary,
		LastIP:     remoteIP,
		LastSeen:   now,
		TUN:        tunPtr,
		WFP:        wfpPtr,
	}
	if err := store.saveLocked(); err != nil {
		return err
	}
	h.jsonReply(w, r, 201, map[string]bool{"approved": false})
	return nil
}

func (h *TeacherHandler) unlockDevice(w http.ResponseWriter, r *http.Request, data map[string]any) error {
	devID, key := h.deviceCredentials(r, data)
	rawPin, ok := data["pin"]
	if !ok {
		rawPin = data["password"]
	}
	pin, okStr := rawPin.(string)
	if !okStr || !PINRegexp.MatchString(pin) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid unlock PIN"})
		return nil
	}
	store := h.getStore()
	store.mu.Lock()
	authorized := store.deviceLocked(devID, key, true) != nil
	store.mu.Unlock()
	if !authorized {
		h.jsonReply(w, r, 403, map[string]string{"error": "device not authorized"})
		return nil
	}
	if !store.VerifyUnlockPIN(pin, "device:"+devID) {
		h.jsonReply(w, r, 403, map[string]string{"error": "unlock disabled, invalid PIN, or temporarily rate limited"})
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deviceLocked(devID, key, true) == nil {
		h.jsonReply(w, r, 403, map[string]string{"error": "device not authorized"})
		return nil
	}
	item, err := store.addRequestLocked(devID, "pause", "*", "", true)
	if err != nil {
		return err
	}
	if item == nil {
		h.jsonReply(w, r, 429, map[string]string{"error": "request capacity"})
		return nil
	}
	h.jsonReply(w, r, 201, map[string]int64{"expires": item.Expires})
	return nil
}

func (h *TeacherHandler) submitRequest(w http.ResponseWriter, r *http.Request, data map[string]any) error {
	devID, key := h.deviceCredentials(r, data)
	kind, ok1 := data["kind"].(string)
	obj, ok2 := data["object"].(string)
	label := ""
	if rawLabel, exists := data["label"]; exists {
		var ok bool
		label, ok = rawLabel.(string)
		if !ok {
			h.jsonReply(w, r, 400, map[string]string{"error": "invalid program label"})
			return nil
		}
	}
	if !ValidText(label, 128, true) || strings.ContainsAny(label, `/\`) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid program label"})
		return nil
	}
	if !ok1 || !ok2 || (kind != "website" && kind != "application" && kind != "network" && kind != "local_html") || !ValidText(obj, 512, false) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid request"})
		return nil
	}
	if (kind == "website" && !isValidHostname(obj)) || ((kind == "application" || kind == "network") && !HashRegexp.MatchString(obj)) {
		h.jsonReply(w, r, 400, map[string]string{"error": "invalid object identity"})
		return nil
	}
	store := h.getStore()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deviceLocked(devID, key, true) == nil {
		h.jsonReply(w, r, 403, map[string]string{"error": "device not authorized"})
		return nil
	}
	item, err := store.addRequestLocked(devID, kind, obj, label, false)
	if err != nil {
		return err
	}
	if item == nil {
		h.jsonReply(w, r, 429, map[string]string{"error": "request capacity"})
		return nil
	}
	h.jsonReply(w, r, 201, map[string]string{"id": item.ID})
	return nil
}

// LocateBaseInstaller finds embedded ohno-setup.exe or an adjacent file on disk.
func LocateBaseInstaller() ([]byte, func() ([]byte, error)) {
	if len(EmbeddedSetupExe) > 0 {
		return EmbeddedSetupExe, nil
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "ohno-setup.exe"))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "ohno-setup.exe"))
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			path := p
			return nil, func() ([]byte, error) { return os.ReadFile(path) }
		}
	}
	return nil, nil
}

func listenExclusive(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: listenControl}
	return lc.Listen(context.Background(), "tcp", addr)
}

// ServeOptions configures ServeTeacher.
type ServeOptions struct {
	StatePath       string
	CertPath        string
	KeyPath         string
	Bind            string
	Port            int
	ControlPort     int
	EnrollmentHost  string
	OpenBrowser     bool
	TraceUpdateHTTP bool
}

// ServeTeacher starts both the LAN HTTPS device API and the loopback control server.
// If binding the second listener fails, the first listener is closed immediately.
func ServeTeacher(opts ServeOptions) error {
	store, err := OpenStore(opts.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()

	cert, err := tls.LoadX509KeyPair(opts.CertPath, opts.KeyPath)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(opts.CertPath)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	apiAddr := net.JoinHostPort(opts.Bind, strconv.Itoa(opts.Port))
	rawAPIListener, err := listenExclusive(apiAddr)
	if err != nil {
		return err
	}
	ctrlAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.ControlPort))
	rawCtrlListener, err := listenExclusive(ctrlAddr)
	if err != nil {
		_ = rawAPIListener.Close()
		return err
	}

	apiPort := rawAPIListener.Addr().(*net.TCPAddr).Port
	ctrlPort := rawCtrlListener.Addr().(*net.TCPAddr).Port

	apiListener := tls.NewListener(newBoundedListener(rawAPIListener, DefaultWorkers, nil), tlsCfg)
	ctrlListener := newBoundedListener(rawCtrlListener, DefaultWorkers, nil)

	embeddedBytes, diskFn := LocateBaseInstaller()
	origin := ""
	if opts.EnrollmentHost != "" && (len(embeddedBytes) > 0 || diskFn != nil) {
		origin, err = EnrollmentOrigin(opts.EnrollmentHost, apiPort)
		if err != nil {
			_ = apiListener.Close()
			_ = ctrlListener.Close()
			return err
		}
	}

	apiHandler := NewTeacherHandler(ServerConfig{
		Store:           store,
		Control:         false,
		TraceUpdateHTTP: opts.TraceUpdateHTTP,
	})
	ctrlHandler := NewTeacherHandler(ServerConfig{
		Store:             store,
		Control:           true,
		ControlCSRF:       tokenURLSafe(32),
		SchoolInstaller:   embeddedBytes,
		SchoolInstallerFn: diskFn,
		EnrollmentOrigin:  origin,
		PublicCertificate: certPEM,
		TraceUpdateHTTP:   opts.TraceUpdateHTTP,
	})

	apiSrv := &http.Server{
		Handler:           apiHandler,
		ReadHeaderTimeout: DefaultTimeout,
		IdleTimeout:       DefaultTimeout,
	}
	ctrlSrv := &http.Server{
		Handler:           ctrlHandler,
		ReadHeaderTimeout: DefaultTimeout,
		IdleTimeout:       DefaultTimeout,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- apiSrv.Serve(apiListener) }()
	go func() { errCh <- ctrlSrv.Serve(ctrlListener) }()

	fmt.Printf("ohno student API listening on https://%s:%d\n", opts.Bind, apiPort)
	fmt.Printf("ohno teacher control listening on http://127.0.0.1:%d\n", ctrlPort)
	if opts.OpenBrowser {
		openBrowserURL("http://127.0.0.1:" + strconv.Itoa(ctrlPort) + "/")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	var serveErr error
	select {
	case <-sigCh:
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(ctx)
	_ = ctrlSrv.Shutdown(ctx)
	return serveErr
}

// EasyStart handles double-click launch: initializes state & cert in LOCALAPPDATA/OhnoTeacher
// (or ~/OhnoTeacher on Unix), binds API + loopback control, and opens the local UI.
func EasyStart() error {
	baseDir := os.Getenv("LOCALAPPDATA")
	if baseDir == "" {
		var err error
		baseDir, err = os.UserHomeDir()
		if err != nil {
			return err
		}
	}
	home := filepath.Join(baseDir, "OhnoTeacher")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	statePath := filepath.Join(home, "state.json")
	certPath := filepath.Join(home, "teacher-cert.pem")
	keyPath := filepath.Join(home, "teacher-key.pem")

	rawHost, err := os.Hostname()
	if err != nil {
		return err
	}
	hostname := strings.ToLower(strings.SplitN(rawHost, ".", 2)[0])
	if !isValidHostname(hostname) {
		return errors.New("computer hostname is not suitable for teacher HTTPS certificate")
	}
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		if err := CreateCertificate(certPath, keyPath, hostname); err != nil {
			return err
		}
	} else if certErr != nil || keyErr != nil {
		return errors.New("incomplete teacher certificate files; restore the matching cert/key pair")
	}
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		st, err := InitializeStore(statePath)
		if err != nil {
			return err
		}
		st.Close()
	}
	return ServeTeacher(ServeOptions{
		StatePath:      statePath,
		CertPath:       certPath,
		KeyPath:        keyPath,
		Bind:           "0.0.0.0",
		Port:           8443,
		ControlPort:    8765,
		EnrollmentHost: hostname,
		OpenBrowser:    true,
	})
}
