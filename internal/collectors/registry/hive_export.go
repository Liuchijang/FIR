package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
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

func collectRegistryDirect(ctx context.Context, outDir string) ([]module.FileInfo, []string, error) {
	configDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "config")
	sidToProfile, err := loadProfileSIDMap()
	if err != nil {
		return nil, nil, fmt.Errorf("load profile SID map: %w", err)
	}

	// SECURITY is intentionally not collected here — see the comment on
	// systemHives in registry.go for why it can never succeed as Administrator.
	specs := []hiveSpec{
		{name: "SYSTEM", srcPath: filepath.Join(configDir, "SYSTEM"), dstPath: filepath.Join(outDir, "SYSTEM"), root: winreg.LOCAL_MACHINE, keyPath: "SYSTEM", relPath: "SYSTEM", isPrimary: true},
		{name: "SOFTWARE", srcPath: filepath.Join(configDir, "SOFTWARE"), dstPath: filepath.Join(outDir, "SOFTWARE"), root: winreg.LOCAL_MACHINE, keyPath: "SOFTWARE", relPath: "SOFTWARE", isPrimary: true},
		{name: "SAM", srcPath: filepath.Join(configDir, "SAM"), dstPath: filepath.Join(outDir, "SAM"), root: winreg.LOCAL_MACHINE, keyPath: "SAM", relPath: "SAM", isPrimary: true},
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
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		username := filepath.Base(profileDir)
		userOutDir := filepath.Join(outDir, "users", username)
		if err := os.MkdirAll(userOutDir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("create dir for %s: %w", username, err)
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

	// One pool for the whole batch: the raw fallback below opens a volume handle
	// per drive, and the hives all live on the same one.
	rawPool := &acquisition.RawVolumePool{}
	defer rawPool.Close()

	var files []module.FileInfo
	var errs []string
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		fi, err := collectHiveSpec(spec, rawPool)
		if err != nil {
			// A .LOG1/.LOG2 that is not there has nothing to collect — Windows
			// removes the second log on some configurations — so that stays quiet.
			if isNotFoundError(err) && !spec.isPrimary {
				continue
			}
			// Anything else is reported, transaction logs included. This used to
			// swallow a blocked log entirely: the module returned success with no
			// error and a manifest listing six files, while the four hives' logs
			// were missing and nothing said so. A hive whose pending transactions
			// were never collected cannot be recovered later, which is a gap an
			// analyst has to be told about rather than infer from a file count.
			errs = append(errs, fmt.Sprintf("%s: %v", spec.srcPath, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 && len(errs) > 0 {
		return nil, errs, errors.New(strings.Join(errs, "; "))
	}
	return files, errs, nil
}

func collectHiveSpec(spec hiveSpec, rawPool *acquisition.RawVolumePool) (module.FileInfo, error) {
	if spec.isPrimary && spec.root != 0 && spec.keyPath != "" {
		fi, err := saveRegistryHive(spec)
		if err == nil {
			fi.Path = spec.relPath
			return fi, nil
		}
	}

	fi, err := copyRegistryFile(spec, rawPool)
	if err == nil {
		fi.Path = spec.relPath
		return fi, nil
	}

	if !spec.isPrimary || !isHandleBlockedError(err) {
		return module.FileInfo{}, err
	}

	fi, saveErr := saveRegistryHive(spec)
	if saveErr != nil {
		return module.FileInfo{}, fmt.Errorf("%v; registry save fallback failed: %w", err, saveErr)
	}
	fi.Path = spec.relPath
	return fi, nil
}

// copyRegistryFile copies a hive file, ending at a raw NTFS read.
//
// That last step is what a transaction log needs. The kernel holds .LOG1/.LOG2
// open for the life of the hive with a share mode that refuses another opener, and
// a sharing violation is not something backup semantics can lift — measured: a
// read of the live NTUSER.DAT.LOG1 fails even with FILE_SHARE_READ|WRITE.
// Reading the file's data runs straight off the volume goes around the lock
// entirely, which is how the amcache collector has always got its logs and why
// this collector was the one coming home without them.
//
// Primary hives rarely reach it: RegSaveKey is tried first for them and asks the
// registry for a consistent copy rather than touching the file at all.
func copyRegistryFile(spec hiveSpec, rawPool *acquisition.RawVolumePool) (module.FileInfo, error) {
	fi, err := utils.SafeCopyFile(spec.srcPath, spec.dstPath)
	if err == nil {
		return fi, nil
	}

	fi, backupErr := utils.SafeCopyFileBackup(spec.srcPath, spec.dstPath)
	if backupErr == nil {
		return fi, nil
	}
	if isNotFoundError(backupErr) {
		return module.FileInfo{}, backupErr
	}

	if _, rawErr := rawPool.CopyFile(spec.srcPath, spec.dstPath); rawErr != nil {
		return module.FileInfo{}, fmt.Errorf("%v; raw volume read failed: %w", backupErr, rawErr)
	}
	return utils.FileInfoFromPath(spec.dstPath)
}

func saveRegistryHive(spec hiveSpec) (module.FileInfo, error) {
	if spec.root == 0 || spec.keyPath == "" {
		return module.FileInfo{}, fmt.Errorf("no registry fallback available")
	}
	if err := utils.SaveRegistryHive(spec.root, spec.keyPath, spec.dstPath); err != nil {
		return module.FileInfo{}, err
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

// EstimatedBytes sums the hives this run will copy: the system hives with their
// .LOG1/.LOG2 companions, plus NTUSER.DAT and UsrClass.dat for every profile.
func estimatedRegistryBytes() int64 {
	configDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "config")

	var paths []string
	for _, hive := range systemHives {
		paths = append(paths, filepath.Join(configDir, hive))
		for _, suffix := range hiveLogSuffixes[1:] {
			paths = append(paths, filepath.Join(configDir, hive+suffix))
		}
	}

	sidToProfile, err := loadProfileSIDMap()
	if err == nil {
		for _, profileDir := range sidToProfile {
			paths = append(paths,
				filepath.Join(profileDir, "NTUSER.DAT"),
				filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
			)
			for _, suffix := range hiveLogSuffixes[1:] {
				paths = append(paths,
					filepath.Join(profileDir, "NTUSER.DAT"+suffix),
					filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"+suffix),
				)
			}
		}
	}
	return utils.PathsSize(paths...)
}
