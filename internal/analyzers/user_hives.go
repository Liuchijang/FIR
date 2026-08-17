package analyzers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

type userHiveSource struct {
	Username string
	SID      string
	HivePath string
	HiveName string
	Live     bool
}

// resolveNTUserHiveSources lists the per-user NTUSER.DAT hives to parse: the
// analyzed run's collected copies, and the live registry only when the policy
// allows it.
//
// userassist, recentdocs and runmru each carried this same chain inline. One
// copy is what keeps them agreeing about which artifact a run's output was
// derived from — and it is the one place the live fallback has to be refused for
// an offline run, instead of three.
func resolveNTUserHiveSources(req module.AnalyzeRequest) ([]userHiveSource, error) {
	dir, live, err := resolveArtifactSource(req, "registry")
	if err != nil {
		return nil, err
	}
	if live {
		return liveUserNTUserSources()
	}
	return collectedUserHiveSources(dir, "NTUSER.DAT")
}

func collectedUserHiveSources(dir, hiveName string) ([]userHiveSource, error) {
	usersDir := filepath.Join(dir, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read collected user hive dir: %w", err)
	}

	sources := make([]userHiveSource, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hivePath := filepath.Join(usersDir, entry.Name(), hiveName)
		if _, err := os.Stat(hivePath); err != nil {
			continue
		}
		sources = append(sources, userHiveSource{
			Username: entry.Name(),
			HivePath: hivePath,
			HiveName: hiveName,
		})
	}
	return sources, nil
}

func liveUserNTUserSources() ([]userHiveSource, error) {
	profilesKey, ok, err := openLiveKey(winreg.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`)
	if err != nil {
		return nil, fmt.Errorf("open ProfileList: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("ProfileList is not present")
	}
	defer profilesKey.Close()

	sids, err := profilesKey.SubkeyNames()
	if err != nil {
		return nil, fmt.Errorf("enumerate ProfileList: %w", err)
	}

	sources := make([]userHiveSource, 0, len(sids))
	usersRoot := strings.ToLower(filepath.Clean(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")))
	for _, sid := range sids {
		if strings.HasSuffix(sid, "_Classes") || sid == ".DEFAULT" {
			continue
		}

		profileKey, ok, err := profilesKey.OpenSubkey(sid)
		if err != nil || !ok {
			continue
		}
		profilePath := readRegistryFirstString(profileKey, "ProfileImagePath")
		profileKey.Close()
		if profilePath == "" {
			continue
		}
		expandedProfilePath := expandKnownUserEnv(profilePath)
		if !strings.HasPrefix(strings.ToLower(expandedProfilePath), usersRoot+`\`) {
			continue
		}

		userKey, ok, err := openLiveKey(winreg.USERS, sid)
		if err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				continue
			}
			return nil, fmt.Errorf("open live user hive %s: %w", sid, err)
		}
		if !ok {
			continue
		}
		userKey.Close()

		sources = append(sources, userHiveSource{
			Username: filepath.Base(expandedProfilePath),
			SID:      sid,
			HiveName: "NTUSER.DAT",
			Live:     true,
		})
	}

	return sources, nil
}

// openUserHiveSource opens one user hive: the live HKU subtree for a logged-on
// SID, or the collected NTUSER.DAT parsed from its file.
func openUserHiveSource(source userHiveSource) (registryKey, error) {
	if source.Live {
		key, ok, err := openLiveKey(winreg.USERS, source.SID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("live user hive not found: %s", source.SID)
		}
		return key, nil
	}
	return openCollectedHive(source.HivePath)
}

func expandKnownUserEnv(path string) string {
	replacements := map[string]string{
		"%SystemDrive%": os.Getenv("SystemDrive"),
		"%SystemRoot%":  os.Getenv("SystemRoot"),
		"%systemroot%":  os.Getenv("SystemRoot"),
	}
	for needle, value := range replacements {
		if value != "" {
			path = strings.ReplaceAll(path, needle, value)
		}
	}
	return filepath.Clean(path)
}
