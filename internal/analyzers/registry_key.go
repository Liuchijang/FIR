package analyzers

import (
	"errors"

	"github.com/Liuchijang/Tyto/internal/registryfile"
	winreg "golang.org/x/sys/windows/registry"
)

// registryKey is a key in either place registry data comes from: a mounted hive —
// the live machine — and a collected hive file parsed by internal/registryfile.
//
// One interface rather than two copies of every parser. The alternative was
// duplicating the amcache, UserAssist, RecentDocs and RunMRU walks per source, and
// those walks are what decide what a run's CSVs contain; two copies of that is two
// answers to the same question waiting to drift apart.
//
// The typed readers return ok rather than an error because every caller treats an
// absent or wrong-typed value the same way — as "this key does not carry that
// field" — and the shape matches the helpers that were already here.
type registryKey interface {
	// OpenSubkey resolves a backslash-separated path below this key. ok is false
	// when the path is simply absent, which is not an error.
	OpenSubkey(path string) (registryKey, bool, error)
	SubkeyNames() ([]string, error)
	ValueNames() ([]string, error)
	StringValue(name string) (string, bool)
	StringsValue(name string) ([]string, bool)
	IntegerValue(name string) (uint64, bool)
	BinaryValue(name string) ([]byte, bool)
	// LastWriteString is the key's last write time as an RFC3339 instant, or ""
	// when the source cannot supply one.
	LastWriteString() string
	// Close releases a mounted key. It is a no-op for a hive read from file, so a
	// caller can close unconditionally.
	Close()
}

// mountedKey reads through a key Windows has mounted: the live registry.
//
// It delegates to the platform's own typed accessors rather than decoding raw
// bytes, so the live path behaves exactly as it did before this interface existed.
type mountedKey struct{ key winreg.Key }

func (m mountedKey) OpenSubkey(path string) (registryKey, bool, error) {
	key, err := winreg.OpenKey(m.key, path, winreg.READ)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return mountedKey{key}, true, nil
}

func (m mountedKey) SubkeyNames() ([]string, error) { return m.key.ReadSubKeyNames(-1) }
func (m mountedKey) ValueNames() ([]string, error)  { return m.key.ReadValueNames(-1) }

func (m mountedKey) StringValue(name string) (string, bool) {
	value, _, err := m.key.GetStringValue(name)
	return value, err == nil
}

func (m mountedKey) StringsValue(name string) ([]string, bool) {
	value, _, err := m.key.GetStringsValue(name)
	return value, err == nil
}

func (m mountedKey) IntegerValue(name string) (uint64, bool) {
	value, _, err := m.key.GetIntegerValue(name)
	return value, err == nil
}

func (m mountedKey) BinaryValue(name string) ([]byte, bool) {
	value, _, err := m.key.GetBinaryValue(name)
	if err != nil || len(value) == 0 {
		return nil, false
	}
	return value, true
}

func (m mountedKey) LastWriteString() string { return registryKeyLastWriteString(m.key) }
func (m mountedKey) Close()                  { m.key.Close() }

// fileKey reads a hive parsed from its file.
type fileKey struct{ key *registryfile.Key }

func (f fileKey) OpenSubkey(path string) (registryKey, bool, error) {
	key, err := f.key.OpenPath(path)
	if err != nil {
		// Absent is the common case and not an error: a hive from one Windows
		// build holds keys another does not.
		if errors.Is(err, registryfile.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return fileKey{key}, true, nil
}

func (f fileKey) SubkeyNames() ([]string, error) { return f.key.SubkeyNames() }
func (f fileKey) ValueNames() ([]string, error)  { return f.key.ValueNames() }

func (f fileKey) StringValue(name string) (string, bool) {
	value, err := f.key.StringValue(name)
	return value, err == nil
}

func (f fileKey) StringsValue(name string) ([]string, bool) {
	value, err := f.key.StringsValue(name)
	return value, err == nil
}

func (f fileKey) IntegerValue(name string) (uint64, bool) {
	value, err := f.key.IntegerValue(name)
	return value, err == nil
}

func (f fileKey) BinaryValue(name string) ([]byte, bool) {
	value, err := f.key.BinaryValue(name)
	if err != nil || len(value) == 0 {
		return nil, false
	}
	return value, true
}

func (f fileKey) LastWriteString() string {
	return formatTime(f.key.LastWrite(), "")
}

func (f fileKey) Close() {}

// openCollectedHive reads a collected hive file and returns its root.
//
// This is the only way an analyzer reaches a collected hive. Mounting one through
// RegLoadAppKeyW cannot be relied on: it rejects a collected SYSTEM outright
// (ERROR_BADDB — an application hive may not contain symbolic links and SYSTEM has
// CurrentControlSet), and refuses a hive whose transaction logs need replaying
// unless the caller is elevated. Reading the file has neither problem and needs no
// privilege.
func openCollectedHive(path string) (registryKey, error) {
	hive, err := registryfile.Open(path)
	if err != nil {
		return nil, err
	}
	root, err := hive.Root()
	if err != nil {
		return nil, err
	}
	return fileKey{root}, nil
}

// openLiveKey wraps a live registry root, e.g. winreg.LOCAL_MACHINE.
func openLiveKey(root winreg.Key, path string) (registryKey, bool, error) {
	return mountedKey{root}.OpenSubkey(path)
}

// registryValueNameSet is the set of a key's value names, for the parsers that ask
// "does this key carry any of these" rather than reading one by name. Names are
// kept as the hive spells them, as the caller's lookups are exact.
func registryValueNameSet(key registryKey) map[string]bool {
	names, err := key.ValueNames()
	if err != nil {
		return map[string]bool{}
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}
