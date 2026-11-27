//go:build !windows

package teacher

import (
	"os"
	"path/filepath"
	"testing"
)

func verifyPrivateDirectoryACL(t *testing.T, root string) {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 on release dir, got %o", info.Mode().Perm())
	}
	keyInfo, err := os.Stat(filepath.Join(root, "release-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 on release key, got %o", keyInfo.Mode().Perm())
	}
}
