//go:build windows

package platform

import (
	winreg "golang.org/x/sys/windows/registry"
)

// timezoneKeyName reads Windows' own name for the machine's current timezone.
//
// The standard library will not answer this: time.Now().Zone() returns "+07" on
// Windows — an offset spelled as a name — so the region and its DST ruleset are
// gone by the time the value reaches Go. TimeZoneKeyName is the string Windows
// itself stores, and it lives in the SYSTEM hive that the registry collector
// already brings home, so a manifest carrying it can be checked against the
// evidence rather than taken on trust.
//
// A failure here is not worth reporting: the offset from the standard library is
// still recorded, and a run must not fail over a descriptive field.
func timezoneKeyName() string {
	key, err := winreg.OpenKey(winreg.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, winreg.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	name, _, err := key.GetStringValue("TimeZoneKeyName")
	if err != nil {
		return ""
	}
	return name
}
