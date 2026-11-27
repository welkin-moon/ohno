//go:build windows

package integration

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsRequestGUI(t *testing.T) {
	absFixture := resolveBuildArtifact("OHNO_REQUEST_GUI_FIXTURE", "request-ui-fixture.exe")
	absProd := resolveBuildArtifact("OHNO_REQUEST_GUI_PROD", "ohno-request.exe")
	if _, err := os.Stat(absFixture); err != nil {
		t.Skipf("GUI fixture %s not found: %v", absFixture, err)
	}

	windowForPID := func(pid uint32) uintptr {
		var found uintptr
		cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
			var owner uint32
			pGetWindowThreadProcessI.Call(hwnd, uintptr(unsafe.Pointer(&owner)))
			if owner == pid {
				buf := make([]uint16, 128)
				pGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
				if syscall.UTF16ToString(buf) == "OhnoRequestWindow" {
					found = hwnd
					return 0
				}
			}
			return 1
		})
		pEnumWindows.Call(cb, 0)
		return found
	}

	waitFor := func(check func() bool, sec time.Duration) {
		t.Helper()
		deadline := time.Now().Add(sec)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("GUI condition timed out")
	}

	sendMsg := func(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
		t.Helper()
		var res uintptr
		ok, _, e := pSendMessageTimeoutW.Call(hwnd, uintptr(msg), wp, lp, 2, 1000, uintptr(unsafe.Pointer(&res)))
		if ok == 0 {
			t.Fatalf("SendMessageTimeoutW failed msg=0x%x err=%v", msg, e)
		}
		return res
	}
	ctrl := func(hwnd uintptr, id int) uintptr {
		t.Helper()
		h, _, _ := pGetDlgItem.Call(hwnd, uintptr(id))
		if h == 0 {
			t.Fatalf("control %d missing", id)
		}
		return h
	}
	setText := func(hwnd uintptr, id int, val string) {
		buf, _ := syscall.UTF16FromString(val)
		if sendMsg(ctrl(hwnd, id), 0x000c, 0, uintptr(unsafe.Pointer(&buf[0]))) == 0 {
			t.Fatalf("WM_SETTEXT failed on %d", id)
		}
	}
	getText := func(hwnd uintptr, id int) string {
		buf := make([]uint16, 512)
		sendMsg(ctrl(hwnd, id), 0x000d, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
		return syscall.UTF16ToString(buf)
	}
	getLen := func(hwnd uintptr, id int) uintptr { return sendMsg(ctrl(hwnd, id), 0x000e, 0, 0) }
	command := func(hwnd uintptr, id int) { sendMsg(hwnd, 0x0111, uintptr(id), 0) }
	isEnabled := func(hwnd uintptr, id int) bool {
		r, _, _ := pIsWindowEnabled.Call(ctrl(hwnd, id))
		return r != 0
	}

	captureBMP := func(hwnd uintptr, name string) {
		t.Helper()
		type rect struct{ left, top, right, bottom int32 }
		var r rect
		ok, _, _ := pGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		if ok == 0 {
			return
		}
		w, h := int(r.right-r.left), int(r.bottom-r.top)
		if w <= 0 || h <= 0 {
			return
		}
		dc, _, _ := pGetWindowDC.Call(hwnd)
		mem, _, _ := pCreateCompatibleDC.Call(dc)
		bmp, _, _ := pCreateCompatibleBitmap.Call(dc, uintptr(w), uintptr(h))
		old, _, _ := pSelectObject.Call(mem, bmp)
		defer func() {
			if old != 0 {
				pSelectObject.Call(mem, old)
			}
			if bmp != 0 {
				pDeleteObject.Call(bmp)
			}
			if mem != 0 {
				pDeleteDC.Call(mem)
			}
			if dc != 0 {
				pReleaseDC.Call(hwnd, dc)
			}
		}()
		pPrintWindow.Call(hwnd, mem, 0)
		pSelectObject.Call(mem, old)
		old = 0
		pixels := make([]byte, w*h*4)
		var info [40]byte
		binary.LittleEndian.PutUint32(info[0:4], 40)
		binary.LittleEndian.PutUint32(info[4:8], uint32(int32(w)))
		binary.LittleEndian.PutUint32(info[8:12], uint32(int32(-h)))
		binary.LittleEndian.PutUint16(info[12:14], 1)
		binary.LittleEndian.PutUint16(info[14:16], 32)
		binary.LittleEndian.PutUint32(info[20:24], uint32(len(pixels)))
		pGetDIBits.Call(dc, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&info[0])), 0)
		evDir := filepath.Join(buildDir(), "request-ui-evidence")
		_ = os.MkdirAll(evDir, 0o755)
		var fileHdr [14]byte
		fileHdr[0], fileHdr[1] = 'B', 'M'
		binary.LittleEndian.PutUint32(fileHdr[2:6], uint32(54+len(pixels)))
		binary.LittleEndian.PutUint32(fileHdr[10:14], 54)
		out := append(append(fileHdr[:], info[:]...), pixels...)
		_ = os.WriteFile(filepath.Join(evDir, name+".bmp"), out, 0o644)
	}

	launch := func(bin string, fixture bool) (*exec.Cmd, uintptr, []uintptr, func()) {
		t.Helper()
		proc := exec.Command(bin)
		if err := proc.Start(); err != nil {
			t.Fatal(err)
		}
		var handles []uintptr
		if fixture {
			prefix := "Local\\OhnoRequestGuiTest-" + strconv.Itoa(proc.Process.Pid)
			makeSem := func(suffix string) uintptr {
				n, _ := syscall.UTF16PtrFromString(prefix + suffix)
				h, _, _ := pCreateSemaphoreW.Call(0, 0, 100, uintptr(unsafe.Pointer(n)))
				return h
			}
			makeEv := func(suffix string) uintptr {
				n, _ := syscall.UTF16PtrFromString(prefix + suffix)
				h, _, _ := pCreateEventW.Call(0, 1, 0, uintptr(unsafe.Pointer(n)))
				return h
			}
			handles = []uintptr{makeSem("-calls"), makeEv("-finish"), makeEv("-timeout"), makeEv("-real-io")}
		}
		var hwnd uintptr
		waitFor(func() bool {
			hwnd = windowForPID(uint32(proc.Process.Pid))
			return hwnd != 0
		}, 5*time.Second)
		cleanup := func() {
			if proc.ProcessState == nil {
				if w := windowForPID(uint32(proc.Process.Pid)); w != 0 {
					pPostMessageW.Call(w, 0x0010, 0, 0)
				}
				done := make(chan error, 1)
				go func() { done <- proc.Wait() }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = proc.Process.Kill()
					<-done
				}
			}
			for _, h := range handles {
				if h != 0 {
					pCloseHandle.Call(h)
				}
			}
		}
		return proc, hwnd, handles, cleanup
	}

	pending := func(hwnd, calls uintptr, id int) {
		if id == 102 {
			setText(hwnd, 101, "test.example")
		} else {
			setText(hwnd, 103, "2468")
		}
		command(hwnd, id)
		r, _, _ := pWaitForSingleObject.Call(calls, 3000)
		if r != 0 {
			t.Fatal("worker call semaphore not signaled")
		}
		for _, cid := range []int{101, 102, 103, 104} {
			if isEnabled(hwnd, cid) {
				t.Fatalf("control %d should be disabled while pending", cid)
			}
		}
		if !isEnabled(hwnd, 2) || getLen(hwnd, 103) != 0 {
			t.Fatal("cancel must be enabled and PIN cleared")
		}
		for i := 0; i < 5; i++ {
			command(hwnd, 102)
			command(hwnd, 104)
		}
		r, _, _ = pWaitForSingleObject.Call(calls, 50)
		if r != 258 {
			t.Fatal("duplicate request started")
		}
		sendMsg(hwnd, 0, 0, 0) // WM_NULL responsiveness check
	}

	// Main fixture walkthrough.
	proc, hwnd, handles, cleanup := launch(absFixture, true)
	calls, finish, timeoutEv, realIO := handles[0], handles[1], handles[2], handles[3]
	captureBMP(hwnd, "idle")
	setText(hwnd, 103, "not-a-PIN")
	if getLen(hwnd, 103) != 9 {
		cleanup()
		t.Fatal("PIN text length mismatch")
	}
	command(hwnd, 104)
	captureBMP(hwnd, "invalid-pin-cleared")
	if getLen(hwnd, 103) != 0 || !strings.Contains(getText(hwnd, 105), "数字") {
		cleanup()
		t.Fatal("invalid PIN not cleared/reported")
	}
	pending(hwnd, calls, 102)
	captureBMP(hwnd, "pending")
	command(hwnd, 2)
	waitFor(func() bool { return isEnabled(hwnd, 102) }, 5*time.Second)
	waitFor(func() bool { return strings.Contains(getText(hwnd, 105), "已取消等待") }, 5*time.Second)
	captureBMP(hwnd, "cancelled")
	if r, _, _ := pWaitForSingleObject.Call(calls, 0); r != 258 {
		cleanup()
		t.Fatal("cancel replayed request")
	}
	pending(hwnd, calls, 104)
	pSetEvent.Call(finish)
	waitFor(func() bool { return isEnabled(hwnd, 102) }, 5*time.Second)
	waitFor(func() bool { return strings.Contains(getText(hwnd, 105), "PIN 验证通过") }, 5*time.Second)
	pResetEvent.Call(finish)
	pending(hwnd, calls, 102)
	pSetEvent.Call(timeoutEv)
	waitFor(func() bool { return isEnabled(hwnd, 102) }, 5*time.Second)
	waitFor(func() bool { return strings.Contains(getText(hwnd, 105), "等待超时") }, 5*time.Second)
	pResetEvent.Call(timeoutEv)
	pSetEvent.Call(realIO)
	pending(hwnd, calls, 104)
	start := time.Now()
	pPostMessageW.Call(hwnd, 0x0010, 0, 0)
	if err := proc.Wait(); err != nil || time.Since(start) >= 3*time.Second {
		cleanup()
		t.Fatalf("close while pending failed: err=%v dur=%v", err, time.Since(start))
	}
	cleanup()

	// Reopen check.
	_, hwnd2, h2, cleanup2 := launch(absFixture, true)
	if getLen(hwnd2, 103) != 0 || getText(hwnd2, 105) != "" || !isEnabled(hwnd2, 102) {
		cleanup2()
		t.Fatal("reopened GUI had stale state")
	}
	if r, _, _ := pWaitForSingleObject.Call(h2[0], 100); r != 258 {
		cleanup2()
		t.Fatal("reopened GUI started stale request")
	}
	cleanup2()

	// Production GUI against absent service.
	if _, err := os.Stat(absProd); err == nil {
		_, hwnd3, _, cleanup3 := launch(absProd, false)
		setText(hwnd3, 103, "2468")
		command(hwnd3, 104)
		waitFor(func() bool { return isEnabled(hwnd3, 102) }, 5*time.Second)
		waitFor(func() bool { return strings.Contains(getText(hwnd3, 105), "尚未发送") }, 5*time.Second)
		if getLen(hwnd3, 103) != 0 {
			cleanup3()
			t.Fatal("absent service did not clear PIN")
		}
		cleanup3()
	}
}
