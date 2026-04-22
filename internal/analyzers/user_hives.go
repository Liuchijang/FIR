package analyzers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func collectedUserHiveSources(outputDir, hiveName string) ([]userHiveSource, error) {
	dir, ok := existingModuleDir(outputDir, "registry")
	if !ok {
		return nil, nil
	}

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
	profilesKey, err := winreg.OpenKey(winreg.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, winreg.READ)
	if err != nil {
		return nil, fmt.Errorf("open ProfileList: %w", err)
	}
	defer profilesKey.Close()

	sids, err := profilesKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate ProfileList: %w", err)
	}

	sources := make([]userHiveSource, 0, len(sids))
	usersRoot := strings.ToLower(filepath.Clean(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")))
	for _, sid := range sids {
		if strings.HasSuffix(sid, "_Classes") || sid == ".DEFAULT" {
			continue
		}

		profileKey, err := winreg.OpenKey(profilesKey, sid, winreg.READ)
		if err != nil {
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

		userKey, ok, err := openRegistryKeyOptional(winreg.USERS, sid)
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

func openUserHiveSource(source userHiveSource) (winreg.Key, error) {
	if source.Live {
		key, ok, err := openRegistryKeyOptional(winreg.USERS, source.SID)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("live user hive not found: %s", source.SID)
		}
		return key, nil
	}
	return loadRegistryAppKey(source.HivePath)
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
