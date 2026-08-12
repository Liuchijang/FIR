package analyzers

import (
	"os"
	"path/filepath"
	"strings"

	winreg "golang.org/x/sys/windows/registry"
)

// srumExtensionsKey is where Windows registers the SRUM data providers, one
// subkey per provider GUID — the same GUIDs that name the tables inside
// SRUDB.dat.
//
// Reading it makes the provider names Microsoft's own data rather than a list
// transcribed from another tool, and it means a provider introduced by a future
// Windows release gets named without this file being touched. The key is
// readable only to SYSTEM and Administrators, which Tyto already requires.
const srumExtensionsKey = `Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`

// srumProviderNameValues are the value names checked, in order, for something
// that names a provider.
//
// The key's ACL blocks a non-elevated read, so the layout of its values could not
// be inspected while writing this: several plausible names are tried and each
// candidate is validated by srumProviderName before use. A key that holds only a
// DLL path yields nothing and the built-in table takes over.
var srumProviderNameValues = []string{"", "FriendlyName", "Name", "Description", "ProviderName"}

// loadSRUMProviderNames maps provider GUID to a filename-safe name, preferring
// the SOFTWARE hive this run collected over the live one.
//
// Failure is silent and total: the caller falls back to the built-in table and
// then to the GUID itself, so a host that does not register its providers still
// produces a complete export.
func loadSRUMProviderNames(outputDir string) map[string]string {
	if dir, ok := existingModuleDir(outputDir, "registry"); ok {
		hive := filepath.Join(dir, "SOFTWARE")
		if _, err := os.Stat(hive); err == nil {
			if root, err := loadRegistryAppKey(hive); err == nil {
				names := readSRUMProviderNames(root, srumExtensionsKey)
				root.Close()
				if len(names) > 0 {
					return names
				}
			}
		}
	}
	return readSRUMProviderNames(winreg.LOCAL_MACHINE, `SOFTWARE\`+srumExtensionsKey)
}

func readSRUMProviderNames(root winreg.Key, path string) map[string]string {
	extensions, ok, err := openRegistryKeyOptional(root, path)
	if err != nil || !ok {
		return nil
	}
	defer extensions.Close()

	guids, err := extensions.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	names := make(map[string]string)
	for _, guid := range guids {
		provider, ok, err := openRegistryKeyOptional(extensions, guid)
		if err != nil || !ok {
			continue
		}
		name := srumProviderName(provider)
		provider.Close()
		if name != "" {
			names[strings.ToUpper(guid)] = name
		}
	}
	return names
}

// srumProviderName reads a usable provider name out of one registration.
func srumProviderName(provider winreg.Key) string {
	for _, value := range srumProviderNameValues {
		candidate := readRegistryFirstString(provider, value)
		if slug := srumProviderSlug(candidate); slug != "" {
			return slug
		}
	}
	return ""
}

// srumProviderSlug turns a registry string into a filename token, or rejects it.
//
// The registration is as likely to hold a DLL path as a display name, and
// "%SystemRoot%\System32\eeprov.dll" is not a provider name — it would produce a
// misleading CSV filename, which is worse than falling back to the GUID.
func srumProviderSlug(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}
	if strings.ContainsAny(value, `\/:%`) || strings.HasSuffix(strings.ToLower(value), ".dll") {
		return ""
	}

	var out strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r + ('a' - 'A'))
			lastUnderscore = false
		default:
			if !lastUnderscore && out.Len() > 0 {
				out.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(out.String(), "_")
}
