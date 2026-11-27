//go:build !windows

package teacher

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// CreatePrivateDirectory creates a strictly new directory with mode 0700.
func CreatePrivateDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}

func checkRegularPrivateFile(path string) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return err
	}
	if (st.Mode&syscall.S_IFMT) != syscall.S_IFREG || st.Nlink != 1 {
		return &CatalogError{Msg: "release file is not a private regular file"}
	}
	return nil
}

func openExclusiveLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := checkRegularPrivateFile(path); err != nil {
		f.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func durableReplaceImpl(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	dirFD, err := syscall.Open(filepath.Dir(dst), syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFD)
	return syscall.Fsync(dirFD)
}

func syncFile(f *os.File) error {
	return f.Sync()
}

func listenControl(network, address string, c syscall.RawConn) error {
	return nil
}

func openBrowserURL(u string) {
	_ = exec.Command("xdg-open", u).Start()
}

var errLinkUnsupported = errors.New("not supported")
