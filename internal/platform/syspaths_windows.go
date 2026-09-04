//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

// systemWindowsDirectory asks the kernel where Windows is installed.
//
// GetSystemWindowsDirectory rather than GetWindowsDirectory: on a Terminal
// Services host the latter can answer a per-session private directory, and the
// artifacts a collection is after live in the shared one.
func systemWindowsDirectory() string {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return ""
	}
	return dir
}

func expandEnvironmentStrings(path string) string {
	src, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	// A first call with a nil buffer reports the size needed, in UTF-16 units
	// including the terminator.
	n, err := windows.ExpandEnvironmentStrings(src, nil, 0)
	if err != nil || n == 0 {
		return path
	}
	buf := make([]uint16, n)
	if _, err := windows.ExpandEnvironmentStrings(src, &buf[0], n); err != nil {
		return path
	}
	return windows.UTF16ToString(buf)
}

func profilesDirectoryFromRegistry() string {
	key, err := winreg.OpenKey(winreg.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, winreg.READ)
	if err != nil {
		return ""
	}
	defer key.Close()

	value, _, err := key.GetStringValue("ProfilesDirectory")
	if err != nil || value == "" {
		return ""
	}
	// ExpandEnv, not registry.ExpandString: the value is REG_EXPAND_SZ and its
	// default content is "%SystemDrive%\Users", so it depends on exactly the
	// variable that may be missing from the environment.
	return ExpandEnv(value)
}
