//go:build windows

package integration

import (
	"errors"
	"syscall"
	"unsafe"
)

var (
	winKernel32 = syscall.NewLazyDLL("kernel32.dll")
	winUser32   = syscall.NewLazyDLL("user32.dll")
	winGdi32    = syscall.NewLazyDLL("gdi32.dll")
	winAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	pOpenProcess                = winKernel32.NewProc("OpenProcess")
	pWaitForSingleObject        = winKernel32.NewProc("WaitForSingleObject")
	pCloseHandle                = winKernel32.NewProc("CloseHandle")
	pTerminateProcess           = winKernel32.NewProc("TerminateProcess")
	pQueryFullProcessImageNameW = winKernel32.NewProc("QueryFullProcessImageNameW")
	pCreateSemaphoreW           = winKernel32.NewProc("CreateSemaphoreW")
	pCreateEventW               = winKernel32.NewProc("CreateEventW")
	pSetEvent                   = winKernel32.NewProc("SetEvent")
	pResetEvent                 = winKernel32.NewProc("ResetEvent")

	pEnumWindows             = winUser32.NewProc("EnumWindows")
	pFindWindowW             = winUser32.NewProc("FindWindowW")
	pGetWindowThreadProcessI = winUser32.NewProc("GetWindowThreadProcessId")
	pGetClassNameW           = winUser32.NewProc("GetClassNameW")
	pGetDlgItem              = winUser32.NewProc("GetDlgItem")
	pSendMessageTimeoutW     = winUser32.NewProc("SendMessageTimeoutW")
	pPostMessageW            = winUser32.NewProc("PostMessageW")
	pIsWindowEnabled         = winUser32.NewProc("IsWindowEnabled")
	pGetWindowRect           = winUser32.NewProc("GetWindowRect")
	pGetWindowDC             = winUser32.NewProc("GetWindowDC")
	pReleaseDC               = winUser32.NewProc("ReleaseDC")
	pPrintWindow             = winUser32.NewProc("PrintWindow")

	pCreateCompatibleDC     = winGdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = winGdi32.NewProc("CreateCompatibleBitmap")
	pSelectObject           = winGdi32.NewProc("SelectObject")
	pGetDIBits              = winGdi32.NewProc("GetDIBits")
	pDeleteObject           = winGdi32.NewProc("DeleteObject")
	pDeleteDC               = winGdi32.NewProc("DeleteDC")

	pOpenSCManagerW       = winAdvapi32.NewProc("OpenSCManagerW")
	pOpenServiceW         = winAdvapi32.NewProc("OpenServiceW")
	pQueryServiceConfig2W = winAdvapi32.NewProc("QueryServiceConfig2W")
	pCloseServiceHandle   = winAdvapi32.NewProc("CloseServiceHandle")

	pRegCreateKeyExW  = winAdvapi32.NewProc("RegCreateKeyExW")
	pRegOpenKeyExW    = winAdvapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey      = winAdvapi32.NewProc("RegCloseKey")
	pRegQueryValueExW = winAdvapi32.NewProc("RegQueryValueExW")
	pRegSetValueExW   = winAdvapi32.NewProc("RegSetValueExW")
	pRegDeleteValueW  = winAdvapi32.NewProc("RegDeleteValueW")
	pRegEnumValueW    = winAdvapi32.NewProc("RegEnumValueW")
)

const (
	hkeyLocalMachine = uintptr(0x80000002)
	keyRead          = 0x20019
	keyWrite         = 0x20006
	keySetValue      = 0x0002
	keyWOW64_64Key   = 0x0100
	regSZ            = 1
	regBinary        = 3
	regDWORD         = 4
	errFileNotFound  = 2
	errNoMoreItems   = 259
)

func winProcessAlive(pid uint32) bool {
	h, _, _ := pOpenProcess.Call(0x100000, 0, uintptr(pid)) // SYNCHRONIZE
	if h == 0 {
		return false
	}
	defer pCloseHandle.Call(h)
	r, _, _ := pWaitForSingleObject.Call(h, 0)
	return r == 258 // WAIT_TIMEOUT
}

func regOpenKey(subkey string, access uint32) (uintptr, error) {
	p, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := pRegOpenKeyExW.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(p)), 0, uintptr(access), uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return h, nil
}

func regCreateKey(subkey string, access uint32) (uintptr, error) {
	p, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := pRegCreateKeyExW.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(p)), 0, 0, 0, uintptr(access), 0, uintptr(unsafe.Pointer(&h)), 0)
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return h, nil
}

func regClose(h uintptr) {
	if h != 0 {
		pRegCloseKey.Call(h)
	}
}

func regKeyExists(subkey string) bool {
	h, err := regOpenKey(subkey, keyRead|keyWOW64_64Key)
	if err != nil {
		return false
	}
	regClose(h)
	return true
}

func regQueryString(h uintptr, name string) (string, error) {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var typ, size uint32
	r, _, _ := pRegQueryValueExW.Call(h, uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", syscall.Errno(r)
	}
	if typ != regSZ || size == 0 {
		return "", errors.New("unexpected registry string type")
	}
	buf := make([]uint16, size/2+1)
	r, _, _ = pRegQueryValueExW.Call(h, uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", syscall.Errno(r)
	}
	return syscall.UTF16ToString(buf), nil
}

func regQueryDWORD(h uintptr, name string) (uint32, error) {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var typ, val uint32
	size := uint32(4)
	r, _, _ := pRegQueryValueExW.Call(h, uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	if typ != regDWORD {
		return 0, errors.New("unexpected registry dword type")
	}
	return val, nil
}

func regSetString(h uintptr, name, value string) error {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	vp, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	r, _, _ := pRegSetValueExW.Call(h, uintptr(unsafe.Pointer(np)), 0, regSZ, uintptr(unsafe.Pointer(&vp[0])), uintptr(len(vp)*2))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regSetBinary(h uintptr, name string, data []byte) error {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var ptr uintptr
	if len(data) > 0 {
		ptr = uintptr(unsafe.Pointer(&data[0]))
	}
	r, _, _ := pRegSetValueExW.Call(h, uintptr(unsafe.Pointer(np)), 0, regBinary, ptr, uintptr(len(data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regDeleteValue(h uintptr, name string) error {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := pRegDeleteValueW.Call(h, uintptr(unsafe.Pointer(np)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regEnumStringValues(h uintptr) ([]string, error) {
	var out []string
	for idx := uint32(0); ; idx++ {
		nameBuf := make([]uint16, 256)
		nameLen := uint32(len(nameBuf))
		valBuf := make([]uint16, 1024)
		valBytes := uint32(len(valBuf) * 2)
		var typ uint32
		r, _, _ := pRegEnumValueW.Call(
			h, uintptr(idx),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
			0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&valBuf[0])), uintptr(unsafe.Pointer(&valBytes)),
		)
		if r == errNoMoreItems {
			return out, nil
		}
		if r != 0 {
			return nil, syscall.Errno(r)
		}
		if typ == regSZ {
			out = append(out, syscall.UTF16ToString(valBuf))
		}
	}
}
