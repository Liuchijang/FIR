package analyzers

import (
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

// procRegQueryInfoKeyW is called directly because x/sys/windows/registry exposes
// no accessor for a key's last write time. It is the only Windows registry entry
// point left here: a collected hive is read from its file by
// internal/registryfile, so RegLoadAppKeyW is gone along with everything that
// existed to work around it.
var (
	modAdvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegQueryInfoKeyW = modAdvapi32.NewProc("RegQueryInfoKeyW")
)

func readRegistryStringValue(key registryKey, name string) (string, bool) {
	if value, ok := key.StringValue(name); ok {
		return strings.TrimSpace(value), true
	}
	if value, ok := key.StringsValue(name); ok {
		return strings.Join(value, ";"), true
	}
	if value, ok := key.IntegerValue(name); ok {
		return strconv.FormatUint(value, 10), true
	}
	return "", false
}

func readRegistryFirstString(key registryKey, names ...string) string {
	for _, name := range names {
		if value, ok := readRegistryStringValue(key, name); ok {
			return value
		}
	}
	return ""
}

func readRegistryIntegerValue(key registryKey, name string) (uint64, bool) {
	if value, ok := key.IntegerValue(name); ok {
		return value, true
	}
	if value, ok := readRegistryStringValue(key, name); ok && value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func readRegistryFirstUint64(key registryKey, names ...string) (uint64, bool) {
	for _, name := range names {
		if value, ok := readRegistryIntegerValue(key, name); ok {
			return value, true
		}
	}
	return 0, false
}

func readRegistryBinaryValue(key registryKey, name string) ([]byte, bool) {
	return key.BinaryValue(name)
}

// registryKeyLastWriteString reads a mounted key's last write time.
//
// x/sys/windows/registry exposes no last-write accessor, hence the direct
// RegQueryInfoKeyW call. A hive read from file carries the timestamp in the key
// node itself and does not come through here.
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
//
// The zoneless layouts below are parsed as UTC, and that is measured rather than
// assumed. It was an open question — time.Parse assumes UTC on a layout with no
// zone, so a value Windows wrote in local time would land in the CSV off by the
// machine's offset — and it is answered on a run collected from a UTC+7 host,
// where local time would show up as a flat 7-hour skew:
//
//   - DriverLastWriteTime is the driver file's own mtime, so the run's $MFT
//     carries the same instant as a FILETIME. 75 of the 83 rows that could be
//     joined on path agree to the second; the 8 that do not are off by weeks or
//     years, which is a file replaced after Amcache recorded it, and none is off
//     by the offset.
//   - LinkDate is a PE TimeDateStamp. 49 of the entries name a binary present on
//     the analysis host with a matching SHA-1 — the identical file, so the
//     identical header — and 46 match the TimeDateStamp read out of it exactly.
//
// DriverVerDate and InventoryDriverPackage's Date are the ones a blanket
// conversion would damage: they come from an INF DriverVer directive and are
// vendor-authored calendar dates with no time and no zone, so every one of the
// 308 in that run is midnight. Shifting a midnight by an offset moves it to the
// previous day.
//
// So: no ParseInLocation here. Anything reopening this needs the same two joins,
// not a plausible argument.
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
