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
	absPath, err := filepath.Abs(path)
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
	return formatFiletimeParts(lastWrite.LowDateTime, lastWrite.HighDateTime, "")
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

// registryDateLayouts are the shapes a date-bearing registry value arrives in.
//
// Every one of them was taken off a real Amcache export rather than guessed at.
// A single hive holds three separate conventions: DriverLastWriteTime as
// "07/16/2016 13:18:02", InventoryDevicePnp's DriverVerDate as "06-21-2006"
// (the INF's DriverVer directive, month first), and InventoryDriverPackage's
// Date as "2008-3-14" — year first and neither field zero-padded, which no
// fixed-width layout matches.
//
// Order matters twice over. Layouts that carry a time come before their
// date-only equivalent, so a value that has a time keeps it. Year-first comes
// before month-first, so "2008-3-14" is not read as month 20.
var registryDateLayouts = []string{
	time.RFC3339,
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02T15:04:05",
	"2006-1-2 15:04:05",
	"2006-01-02",
	"2006-1-2",
	"01/02/2006 15:04:05",
	"1/2/2006 15:04:05",
	"01/02/2006 3:04:05 PM",
	"1/2/2006 3:04:05 PM",
	"01/02/2006 15:04",
	"1/2/2006 15:04",
	"01-02-2006 15:04:05",
	"1-2-2006 15:04:05",
	"01/02/2006",
	"1/2/2006",
	"01-02-2006",
	"1-2-2006",
}

// normalizeRegistryDateString renders a registry value that holds a date.
//
// It returns "" for anything it cannot resolve to an instant rather than the
// original text, because these values land in timestamp columns and a consumer
// that types those columns rejects the entire CSV over one cell it cannot
// convert — see the invariant in common.go.
func normalizeRegistryDateString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	// Not every date in a hive is text. Amcache stores DriverTimeStamp as a
	// REG_DWORD holding the driver's PE TimeDateStamp, so it reaches here as a
	// bare integer that no layout below will ever match.
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		return normalizeRegistryDateNumber(number)
	}

	for _, layout := range registryDateLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return formatTime(parsed, "")
		}
	}
	return ""
}

// normalizeRegistryDateNumber renders a numeric registry date, picking the unit
// from the magnitude: a FILETIME is counted from 1601 in 100ns ticks and so is
// always at least windowsEpoch100ns, which no Unix-epoch seconds value inside
// the representable range can reach.
func normalizeRegistryDateNumber(value int64) string {
	if value <= 0 {
		return ""
	}
	if uint64(value) >= windowsEpoch100ns {
		return formatFiletime(uint64(value), "")
	}
	return formatEpochSeconds(value, "")
}
