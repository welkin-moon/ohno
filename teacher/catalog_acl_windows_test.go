//go:build windows

package teacher

import (
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func verifyPrivateDirectoryACL(t *testing.T, root string) {
	t.Helper()
	procGetNamedSecurityInfoW := modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procConvertSDToStringSDW := modAdvapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")

	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	var desc uintptr
	r1, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		1, // SE_FILE_OBJECT
		4, // DACL_SECURITY_INFORMATION
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&desc)),
	)
	if r1 != 0 {
		t.Fatalf("GetNamedSecurityInfoW failed: %d", r1)
	}
	defer procLocalFree.Call(desc)

	var textPtr uintptr
	r1, _, e1 := procConvertSDToStringSDW.Call(
		desc,
		1, // SDDL_REVISION_1
		4, // DACL_SECURITY_INFORMATION
		uintptr(unsafe.Pointer(&textPtr)),
		0,
	)
	if r1 == 0 {
		t.Fatalf("ConvertSecurityDescriptorToStringSecurityDescriptorW failed: %v", e1)
	}
	defer procLocalFree.Call(textPtr)

	sddl := utf16PtrToString((*uint16)(unsafe.Pointer(textPtr)))
	if !strings.Contains(sddl, "D:P") {
		t.Fatalf("expected protected DACL (D:P), got %s", sddl)
	}
	for _, broad := range []string{";;;WD)", ";;;BU)", ";;;AU)"} {
		if strings.Contains(sddl, broad) {
			t.Fatalf("unexpected broad principal %s in SDDL %s", broad, sddl)
		}
	}
	if !strings.Contains(sddl, ";;;SY)") || !strings.Contains(sddl, ";;;BA)") {
		t.Fatalf("expected SY and BA in SDDL %s", sddl)
	}
}
