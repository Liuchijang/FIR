package analyzers

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

var (
	modAdvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegLoadAppKeyW   = modAdvapi32.NewProc("RegLoadAppKeyW")
	procRegQueryInfoKeyW = modAdvapi32.NewProc("RegQueryInfoKeyW")
)

func loadRegistryAppKey(path string) (winreg.Key, error) {
	absPath, err := filepathAbs(path)
	if err != nil {
		return 0, err
	}
	pathPtr, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return 0, fmt.Errorf("utf16 hive path %s: %w", absPath, err)
	}

	var key winreg.Key
	r1, _, _ := procRegLoadAppKeyW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&key)),
		uintptr(winreg.READ),
		0,
		0,
	)
	if r1 != 0 {
		return 0, fmt.Errorf("RegLoadAppKeyW %s: %w", absPath, syscall.Errno(r1))
	}
	return key, nil
}

func openRegistryKeyOptional(root winreg.Key, path string) (winreg.Key, bool, error) {
	key, err := winreg.OpenKey(root, path, winreg.READ)
	if err != nil {
		if err == winreg.ErrNotExist {
			return 0, false, nil
		}
		return 0, false, err
	}
	return key, true, nil
}

func readRegistryStringValue(key winreg.Key, name string) (string, bool) {
	if value, _, err := key.GetStringValue(name); err == nil {
		return strings.TrimSpace(value), true
	}
	if value, _, err := key.GetStringsValue(name); err == nil {
		return strings.Join(value, ";"), true
	}
	if value, _, err := key.GetIntegerValue(name); err == nil {
		return strconv.FormatUint(value, 10), true
	}
	return "", false
}

func readRegistryFirstString(key winreg.Key, names ...string) string {
	for _, name := range names {
		if value, ok := readRegistryStringValue(key, name); ok {
			return value
		}
	}
	return ""
}

func readRegistryIntegerValue(key winreg.Key, name string) (uint64, bool) {
	if value, _, err := key.GetIntegerValue(name); err == nil {
		return value, true
	}
	if value, ok := readRegistryStringValue(key, name); ok && value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func readRegistryFirstUint64(key winreg.Key, names ...string) (uint64, bool) {
	for _, name := range names {
		if value, ok := readRegistryIntegerValue(key, name); ok {
			return value, true
		}
	}
	return 0, false
}

func readRegistryBinaryValue(key winreg.Key, name string) ([]byte, bool) {
	value, _, err := key.GetBinaryValue(name)
	if err != nil || len(value) == 0 {
		return nil, false
	}
	return value, true
}

func registryKeyLastWriteString(key winreg.Key) string {
	var lastWrite windows.Filetime
	r1, _, _ := procRegQueryInfoKeyW.Call(
		uintptr(key),
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&lastWrite)),
	)
	if r1 != 0 {
		return ""
	}
	return filetimeUint64String((uint64(lastWrite.HighDateTime) << 32) | uint64(lastWrite.LowDateTime))
}

func registryValueNames(key winreg.Key) map[string]bool {
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

func normalizeRegistryDateString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z07:00",
		"01/02/2006 15:04:05",
		"1/2/2006 15:04:05",
		"01/02/2006 3:04:05 PM",
		"1/2/2006 3:04:05 PM",
		"01/02/2006",
		"1/2/2006",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return value
}

func filepathAbs(path string) (string, error) {
	return filepath.Abs(path)
}
