package platform

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SystemRoot is the Windows directory of the machine being collected from.
//
// os.Getenv("SystemRoot") on its own is not enough, and the failure is silent
// rather than loud: filepath.Join("", "Prefetch") yields the *relative* path
// "Prefetch", so a collector built on an empty variable reads whatever sits
// beside the working directory, and acquisition.driveLetterOf then answers "C"
// for the raw-read fallback without saying it guessed. An interactive shell
// always sets the variable; a service, a scheduled task or a psexec'd session
// with a scrubbed environment block does not. The kernel's own answer cannot be
// scrubbed, so it is the fallback.
func SystemRoot() string {
	if root := strings.TrimSpace(os.Getenv("SystemRoot")); root != "" {
		return filepath.Clean(root)
	}
	if root := systemWindowsDirectory(); root != "" {
		return filepath.Clean(root)
	}
	return `C:\Windows`
}

// systemDrive is the volume Windows is installed on, spelled the way the
// environment spells it ("C:", no trailing separator) because that is what a
// %SystemDrive% reference expands to.
func systemDrive() string {
	if drive := strings.TrimSpace(os.Getenv("SystemDrive")); drive != "" {
		// Not filepath.Clean: it turns "C:" into "C:.", the drive-relative current
		// directory, which then joins as "C:Users" — a valid path pointing somewhere
		// else entirely.
		return strings.TrimRight(drive, `\/`)
	}
	if vol := filepath.VolumeName(SystemRoot()); vol != "" {
		return vol
	}
	return "C:"
}

// ExpandEnv expands the %VAR% references in a path the way Windows does.
//
// ProfileImagePath and ProfilesDirectory are REG_EXPAND_SZ, so what the registry
// hands back routinely reads "%SystemDrive%\Users\alice". Two byte-identical
// copies of a three-entry replacement table used to do this — one in the
// registry collector, one in the hive analyzer — and anything outside those
// three entries survived into a path that was then opened and found missing.
//
// %SystemRoot% and %SystemDrive% are substituted here rather than left to the
// Win32 expansion, because the whole reason SystemRoot() exists is that those
// two variables are the ones that can be absent from the environment.
func ExpandEnv(path string) string {
	if path == "" {
		return ""
	}
	path = replaceFold(path, "%SystemDrive%", systemDrive())
	path = replaceFold(path, "%SystemRoot%", SystemRoot())
	return filepath.Clean(expandEnvironmentStrings(path))
}

var profilesDir struct {
	once  sync.Once
	value string
}

// ProfilesDirectory is the root this machine keeps user profiles under.
//
// Not %SystemDrive%\Users — that is only the default. Four separate places
// hardcoded it (the registry collector's SID→profile map, the hive analyzer's
// live fallback, browser profile discovery, and the autoruns startup-folder
// scan), so on a host whose ProfilesDirectory has been relocated — an
// enterprise image keeping profiles on D:, a Server build — every one of them
// matched nothing and reported "no user profiles", which is indistinguishable
// from a machine that genuinely has none. Windows records the real answer next
// to the profile list itself.
//
// Cached: the run-config screen re-derives its storage estimate on every
// keypress, and this cannot change under a run.
func ProfilesDirectory() string {
	profilesDir.once.Do(func() {
		if dir := profilesDirectoryFromRegistry(); dir != "" {
			profilesDir.value = dir
			return
		}
		profilesDir.value = filepath.Join(systemDrive()+`\`, "Users")
	})
	return profilesDir.value
}

// replaceFold replaces every case-insensitive occurrence of needle.
//
// The tables this replaced carried "%SystemRoot%" and "%systemroot%" as separate
// entries, which is someone having hit the casing problem once and fixed only
// the spelling they saw.
//
// The match is looked for in the original string, never in a lowercased copy:
// lowercasing can change a string's length — U+0130 is two bytes and lowercases
// to one — so an index taken from the copy and used to slice the original drifts
// by however many such characters preceded it. It ate the separator before the
// variable and left its trailing percent behind, turning
// `...\İbrahim\%SystemDrive%\x` into `...\İbrahimD:%\x`. A Turkish account name
// in a ProfileImagePath is all that takes.
func replaceFold(s, needle, replacement string) string {
	if needle == "" || replacement == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+len(needle) <= len(s) && strings.EqualFold(s[i:i+len(needle)], needle) {
			b.WriteString(replacement)
			i += len(needle)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// UserProfile is one real user's profile directory.
type UserProfile struct {
	Name string
	Path string
}

// UserProfiles lists the profile directories that belong to actual users.
//
// It exists so that "which directories under ProfilesDirectory are users" is
// answered in one place. Every module that walks profiles needs both halves of
// this — the root, which is not always %SystemDrive%\Users, and the exclusion of
// the template and service profiles Windows keeps beside the real ones — and the
// second half was previously spelled out separately in each of them.
func UserProfiles() ([]UserProfile, error) {
	root := ProfilesDirectory()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	profiles := make([]UserProfile, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || IsReservedProfileName(entry.Name()) {
			continue
		}
		profiles = append(profiles, UserProfile{Name: entry.Name(), Path: filepath.Join(root, entry.Name())})
	}
	return profiles, nil
}

// IsReservedProfileName reports the directories Windows keeps under the profile
// root that are not a user: the templates new profiles are copied from and the
// shared and service ones.
func IsReservedProfileName(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "defaultapppool":
		return true
	default:
		return false
	}
}
