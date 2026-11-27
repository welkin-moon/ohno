//go:build windows

package teacher

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetVolumePathNameW                               = modKernel32.NewProc("GetVolumePathNameW")
	procGetVolumeInformationW                            = modKernel32.NewProc("GetVolumeInformationW")
	procCreateDirectoryW                                 = modKernel32.NewProc("CreateDirectoryW")
	procMoveFileExW                                      = modKernel32.NewProc("MoveFileExW")
	procLockFileEx                                       = modKernel32.NewProc("LockFileEx")
	procLocalFree                                        = modKernel32.NewProc("LocalFree")
	procConvertSidToStringSidW                           = modAdvapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSecurityDescriptorToSecurityDescW   = modAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
)

const (
	filePersistentACLS      = 0x00000008
	fileFlagOpenReparse     = 0x00200000
	fileAttrReparsePoint    = 0x00000400
	fileAttrDirectory       = 0x00000010
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
	errorAlreadyExists      = syscall.Errno(183)
	soExclusiveAddrUse      = -5
)

type winSecurityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      uint32
}

// CreatePrivateDirectory creates a new directory with a protected DACL granting
// full access only to SYSTEM, built-in Administrators, and the current user.
func CreatePrivateDirectory(path string) error {
	parent := filepath.Dir(path)
	parentPtr, err := syscall.UTF16PtrFromString(parent)
	if err != nil {
		return err
	}
	volume := make([]uint16, 32768)
	r1, _, e1 := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(parentPtr)),
		uintptr(unsafe.Pointer(&volume[0])),
		uintptr(len(volume)),
	)
	if r1 == 0 {
		return e1
	}
	var flags uint32
	r1, _, e1 = procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(&volume[0])),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&flags)),
		0, 0,
	)
	if r1 == 0 {
		return e1
	}
	if flags&filePersistentACLS == 0 {
		return errors.New("release keys require persistent filesystem ACLs")
	}

	var token syscall.Token
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	if err := syscall.OpenProcessToken(proc, syscall.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	var sidStrPtr uintptr
	r1, _, e1 = procConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(user.User.Sid)),
		uintptr(unsafe.Pointer(&sidStrPtr)),
	)
	if r1 == 0 {
		return e1
	}
	defer procLocalFree.Call(sidStrPtr)

	sid := utf16PtrToString((*uint16)(unsafe.Pointer(sidStrPtr)))
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")"
	sddlPtr, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var descriptor uintptr
	r1, _, e1 = procConvertStringSecurityDescriptorToSecurityDescW.Call(
		uintptr(unsafe.Pointer(sddlPtr)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	if r1 == 0 {
		return e1
	}
	defer procLocalFree.Call(descriptor)

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs := winSecurityAttributes{
		Length:             uint32(unsafe.Sizeof(winSecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}
	r1, _, e1 = procCreateDirectoryW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&attrs)),
	)
	if r1 == 0 {
		if e1 == errorAlreadyExists {
			return os.ErrExist
		}
		return e1
	}
	return nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var chars []uint16
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2)) {
		chars = append(chars, *ptr)
	}
	return syscall.UTF16ToString(chars)
}

func checkHandleRegularPrivate(h syscall.Handle) error {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&(fileAttrDirectory|fileAttrReparsePoint) != 0 || info.NumberOfLinks != 1 {
		return &CatalogError{Msg: "release file is not a private regular file"}
	}
	return nil
}

func checkRegularPrivateFile(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(
		pathPtr,
		0x00000080, // FILE_READ_ATTRIBUTES
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagOpenReparse,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return checkHandleRegularPrivate(h)
}

func openExclusiveLock(path string) (*os.File, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|fileFlagOpenReparse,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := checkHandleRegularPrivate(h); err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	var ov syscall.Overlapped
	r1, _, e1 := procLockFileEx.Call(
		uintptr(h),
		lockfileExclusiveLock|lockfileFailImmediately,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ov)),
	)
	if r1 == 0 {
		syscall.CloseHandle(h)
		return nil, e1
	}
	return os.NewFile(uintptr(h), path), nil
}

func durableReplaceImpl(src, dst string) error {
	srcPtr, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	r1, _, e1 := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func syncFile(f *os.File) error {
	return f.Sync()
}

func listenControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

func openBrowserURL(u string) {
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", u).Start()
}
