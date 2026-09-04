//go:build !windows

package platform

import "os"

func systemWindowsDirectory() string { return "" }

func expandEnvironmentStrings(path string) string { return os.ExpandEnv(path) }

func profilesDirectoryFromRegistry() string { return "" }
