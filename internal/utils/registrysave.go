package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

const regLatestFormat = 2

var (
	modAdvapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procRegSaveKeyExW = modAdvapi32.NewProc("RegSaveKeyExW")
)

func SaveRegistryHive(root winreg.Key, keyPath, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}
	// RegSaveKeyExW refuses to write over an existing file, so a leftover from an
	// earlier attempt has to go first. Every caller passes a path inside the run
	// directory — this must never be handed a live hive path, because that is
	// what the delete would take out.
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear stale destination %s: %w", dst, err)
	}

	key, err := winreg.OpenKey(root, keyPath, winreg.READ)
	if err != nil {
		return fmt.Errorf("open registry key %s: %w", keyPath, err)
	}
	defer key.Close()

	pathPtr, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return fmt.Errorf("utf16 destination %s: %w", dst, err)
	}

	r1, _, _ := procRegSaveKeyExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(regLatestFormat),
	)
	if r1 != 0 {
		return fmt.Errorf("RegSaveKeyExW %s: %w", keyPath, syscall.Errno(r1))
	}
	return nil
}
