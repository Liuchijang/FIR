package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/utils"
	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

type hiveSpec struct {
	name      string
	srcPath   string
	dstPath   string
	root      winreg.Key
	keyPath   string
	relPath   string
	isPrimary bool
}

func collectRegistryDirect(ctx context.Context, outDir string) ([]collector.FileInfo, error) {
	configDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "config")
	sidToProfile, err := loadProfileSIDMap()
	if err != nil {
		return nil, fmt.Errorf("load profile SID map: %w", err)
	}

	specs := []hiveSpec{
		{name: "SYSTEM", srcPath: filepath.Join(configDir, "SYSTEM"), dstPath: filepath.Join(outDir, "SYSTEM"), root: winreg.LOCAL_MACHINE, keyPath: "SYSTEM", relPath: "SYSTEM", isPrimary: true},
		{name: "SOFTWARE", srcPath: filepath.Join(configDir, "SOFTWARE"), dstPath: filepath.Join(outDir, "SOFTWARE"), root: winreg.LOCAL_MACHINE, keyPath: "SOFTWARE", relPath: "SOFTWARE", isPrimary: true},
		{name: "SAM", srcPath: filepath.Join(configDir, "SAM"), dstPath: filepath.Join(outDir, "SAM"), root: winreg.LOCAL_MACHINE, keyPath: "SAM", relPath: "SAM", isPrimary: true},
		{name: "SECURITY", srcPath: filepath.Join(configDir, "SECURITY"), dstPath: filepath.Join(outDir, "SECURITY"), root: winreg.LOCAL_MACHINE, keyPath: "SECURITY", relPath: "SECURITY", isPrimary: true},
		{name: "DEFAULT", srcPath: filepath.Join(configDir, "DEFAULT"), dstPath: filepath.Join(outDir, "DEFAULT"), root: winreg.USERS, keyPath: ".DEFAULT", relPath: "DEFAULT", isPrimary: true},
	}

	for _, suffix := range hiveLogSuffixes[1:] {
		for _, hive := range systemHives {
			name := hive + suffix
			specs = append(specs, hiveSpec{
				name:    name,
				srcPath: filepath.Join(configDir, name),
				dstPath: filepath.Join(outDir, name),
				relPath: name,
			})
		}
	}

	for sid, profileDir := range sidToProfile {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		username := filepath.Base(profileDir)
		userOutDir := filepath.Join(outDir, "users", username)
		if err := os.MkdirAll(userOutDir, 0o755); err != nil {
			return nil, fmt.Errorf("create dir for %s: %w", username, err)
		}

		specs = append(specs, hiveSpec{
			name:      "NTUSER.DAT",
			srcPath:   filepath.Join(profileDir, "NTUSER.DAT"),
			dstPath:   filepath.Join(userOutDir, "NTUSER.DAT"),
			root:      winreg.USERS,
			keyPath:   sid,
			relPath:   filepath.Join("users", username, "NTUSER.DAT"),
			isPrimary: true,
		})
		specs = append(specs, hiveSpec{
			name:      "UsrClass.dat",
			srcPath:   filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
			dstPath:   filepath.Join(userOutDir, "UsrClass.dat"),
			root:      winreg.USERS,
			keyPath:   sid + "_Classes",
			relPath:   filepath.Join("users", username, "UsrClass.dat"),
			isPrimary: true,
		})

		for _, suffix := range hiveLogSuffixes[1:] {
			specs = append(specs,
				hiveSpec{
					name:    "NTUSER.DAT" + suffix,
					srcPath: filepath.Join(profileDir, "NTUSER.DAT"+suffix),
					dstPath: filepath.Join(userOutDir, "NTUSER.DAT"+suffix),
					relPath: filepath.Join("users", username, "NTUSER.DAT"+suffix),
				},
				hiveSpec{
					name:    "UsrClass.dat" + suffix,
					srcPath: filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"+suffix),
					dstPath: filepath.Join(userOutDir, "UsrClass.dat"+suffix),
					relPath: filepath.Join("users", username, "UsrClass.dat"+suffix),
				},
			)
		}
	}

	var files []collector.FileInfo
	var errs []string
	for _, spec := range specs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		fi, err := collectHiveSpec(spec)
		if err != nil {
			if isNotFoundError(err) && !spec.isPrimary {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %v", spec.srcPath, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return files, nil
}

func collectHiveSpec(spec hiveSpec) (collector.FileInfo, error) {
	fi, err := copyRegistryFile(spec)
	if err == nil {
		fi.Path = spec.relPath
		return fi, nil
	}

	if !spec.isPrimary || !isHandleBlockedError(err) {
		return collector.FileInfo{}, err
	}

	fi, saveErr := saveRegistryHive(spec)
	if saveErr != nil {
		return collector.FileInfo{}, fmt.Errorf("%v; registry save fallback failed: %w", err, saveErr)
	}
	fi.Path = spec.relPath
	return fi, nil
}

func copyRegistryFile(spec hiveSpec) (collector.FileInfo, error) {
	fi, err := utils.SafeCopyFile(spec.srcPath, spec.dstPath)
	if err == nil {
		return fi, nil
	}
	return utils.SafeCopyFileBackup(spec.srcPath, spec.dstPath)
}

func saveRegistryHive(spec hiveSpec) (collector.FileInfo, error) {
	if spec.root == 0 || spec.keyPath == "" {
		return collector.FileInfo{}, fmt.Errorf("no registry fallback available")
	}
	if err := utils.SaveRegistryHive(spec.root, spec.keyPath, spec.dstPath); err != nil {
		return collector.FileInfo{}, err
	}

	return utils.FileInfoFromPath(spec.dstPath)
}

func loadProfileSIDMap() (map[string]string, error) {
	profilesKey, err := winreg.OpenKey(winreg.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, winreg.READ)
	if err != nil {
		return nil, err
	}
	defer profilesKey.Close()

	sids, err := profilesKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string)
	usersRoot := strings.ToLower(filepath.Clean(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")))
	for _, sid := range sids {
		key, err := winreg.OpenKey(profilesKey, sid, winreg.READ)
		if err != nil {
			continue
		}

		path, _, err := key.GetStringValue("ProfileImagePath")
		key.Close()
		if err != nil || path == "" {
			continue
		}

		expanded := expandKnownEnv(path)
		if !strings.HasPrefix(strings.ToLower(expanded), usersRoot+`\`) {
			continue
		}
		out[sid] = expanded
	}
	return out, nil
}

func expandKnownEnv(path string) string {
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

func isHandleBlockedError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func isNotFoundError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}
