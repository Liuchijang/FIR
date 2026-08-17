//go:build !windows

package platform

// timezoneKeyName has no non-Windows equivalent. DetectTimezone still reports the
// offset and abbreviation, which is everything the standard library knows.
func timezoneKeyName() string { return "" }
