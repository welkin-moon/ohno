package teacher

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeDeadlineWriter struct {
	header      http.Header
	statusCalls int
	lastStatus  int
	chunks      [][]byte
	deadlines   []time.Time
	advance     time.Duration
	failAfter   int
	clock       *time.Time
}

func newFakeDeadlineWriter(start time.Time, advance time.Duration, failAfter int) *fakeDeadlineWriter {
	now := start
	return &fakeDeadlineWriter{
		header:    make(http.Header),
		advance:   advance,
		failAfter: failAfter,
		clock:     &now,
	}
}

func (f *fakeDeadlineWriter) Header() http.Header { return f.header }
func (f *fakeDeadlineWriter) WriteHeader(code int) {
	f.statusCalls++
	f.lastStatus = code
}
func (f *fakeDeadlineWriter) SetWriteDeadline(t time.Time) error {
	f.deadlines = append(f.deadlines, t)
	return nil
}
func (f *fakeDeadlineWriter) Flush() {}
func (f *fakeDeadlineWriter) Write(p []byte) (int, error) {
	if f.failAfter >= 0 && len(f.chunks) == f.failAfter {
		return 0, errors.New("broken pipe")
	}
	cp := append([]byte(nil), p...)
	f.chunks = append(f.chunks, cp)
	*f.clock = f.clock.Add(f.advance)
	return len(p), nil
}

func TestBinaryTransferChunkingAndDeadlines(t *testing.T) {
	start := time.Unix(1000, 0)

	// Continuous progress can exceed single-chunk 10s timeout.
	fw := newFakeDeadlineWriter(start, 3*time.Second, -1)
	h := NewTeacherHandler(ServerConfig{
		RequestTimeout: 10 * time.Second,
		Clock:          func() time.Time { return *fw.clock },
	})
	data := bytes.Repeat([]byte{'x'}, 20*65536+7)
	req := httptest.NewRequest("POST", "/api/device/update/package/"+strings.Repeat("a", 64), nil)
	h.reply(fw, req, 200, data, "application/octet-stream", nil)
	if fw.statusCalls != 1 || fw.lastStatus != 200 {
		t.Fatalf("expected single 200 status, got %d (%d)", fw.statusCalls, fw.lastStatus)
	}
	if fw.clock.Sub(start) <= 10*time.Second {
		t.Fatalf("expected transfer to exceed 10s, elapsed %v", fw.clock.Sub(start))
	}
	if !bytes.Equal(bytes.Join(fw.chunks, nil), data) {
		t.Fatal("reassembled chunks did not match input")
	}
	for _, c := range fw.chunks {
		if len(c) > 65536 {
			t.Fatalf("chunk exceeded 65536 bytes: %d", len(c))
		}
	}

	// Total 300s deadline bounds remaining chunk deadline and stops output.
	fw2 := newFakeDeadlineWriter(start, 295*time.Second, -1)
	h2 := NewTeacherHandler(ServerConfig{
		RequestTimeout: 10 * time.Second,
		Clock:          func() time.Time { return *fw2.clock },
	})
	h2.reply(fw2, req, 200, bytes.Repeat([]byte{'x'}, 3*65536), "application/octet-stream", nil)
	if len(fw2.chunks) != 2 {
		t.Fatalf("expected 2 chunks before 300s deadline, got %d", len(fw2.chunks))
	}
	// First chunk deadline = start+10s, second chunk deadline = start+300s (remaining 5s).
	if len(fw2.deadlines) < 3 || fw2.deadlines[1].Sub(start) != 10*time.Second || fw2.deadlines[2].Sub(start.Add(295*time.Second)) != 5*time.Second {
		t.Fatalf("unexpected chunk deadlines: %v", fw2.deadlines)
	}
	if fw2.header.Get("Connection") != "close" {
		t.Fatal("expected Connection: close on binary reply")
	}

	// Disconnect never appends a second HTTP response.
	fw3 := newFakeDeadlineWriter(start, 0, 1)
	h3 := NewTeacherHandler(ServerConfig{
		RequestTimeout: 10 * time.Second,
		Clock:          func() time.Time { return *fw3.clock },
	})
	h3.reply(fw3, req, 200, bytes.Repeat([]byte{'x'}, 3*65536), "application/octet-stream", nil)
	if len(fw3.chunks) != 1 || fw3.statusCalls != 1 {
		t.Fatalf("unexpected disconnect behavior: chunks=%d statusCalls=%d", len(fw3.chunks), fw3.statusCalls)
	}

	// Ordinary JSON reply leaves Connection unset and sends once.
	fw4 := newFakeDeadlineWriter(start, 0, -1)
	h4 := NewTeacherHandler(ServerConfig{RequestTimeout: 10 * time.Second})
	h4.reply(fw4, req, 200, []byte(`{"ok":true}`), "application/json; charset=utf-8", nil)
	if len(fw4.chunks) != 1 || string(fw4.chunks[0]) != `{"ok":true}` || fw4.header.Get("Connection") != "" {
		t.Fatalf("unexpected JSON reply behavior: %v", fw4.chunks)
	}
}
