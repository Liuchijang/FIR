// Package browser implements browser-forensics collectors.
package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/utils"
)

const BrowserCollectorName = "browser"

// ChromiumCollectorName is kept as a compatibility alias for existing code.
const ChromiumCollectorName = BrowserCollectorName

const (
	browserFamilyChromium = "chromium"
	browserFamilyFirefox  = "firefox"
)

var chromiumEvidenceFiles = []string{
	"Bookmarks",
	"Cookies",
	"Extension Cookies",
	"Favicons",
	"History",
	"Last Session",
	"Last Tabs",
	"Login Data",
	"Login Data For Account",
	"Preferences",
	"Shortcuts",
	"Top Sites",
	"Visited Links",
	"Web Data",
	filepath.Join("Network", "Cookies"),
}

var chromiumEvidenceDirs = []string{
	"Sessions",
	// Extension Rules and Extension State are LevelDB databases (directories
	// containing CURRENT/MANIFEST/*.ldb files), not single files — copying them
	// as a file fails with ERROR_INVALID_FUNCTION.
	"Extension Rules",
	"Extension State",
}

var firefoxEvidenceFiles = []string{
	"addons.json",
	"cert9.db",
	"compatibility.ini",
	"containers.json",
	"content-prefs.sqlite",
	"content-prefs.sqlite-shm",
	"content-prefs.sqlite-wal",
	"cookies.sqlite",
	"cookies.sqlite-shm",
	"cookies.sqlite-wal",
	"extensions.json",
	"favicons.sqlite",
	"favicons.sqlite-shm",
	"favicons.sqlite-wal",
	"formhistory.sqlite",
	"formhistory.sqlite-shm",
	"formhistory.sqlite-wal",
	"handlers.json",
	"key4.db",
	"logins.json",
	"permissions.sqlite",
	"permissions.sqlite-shm",
	"permissions.sqlite-wal",
	"persdict.dat",
	"places.sqlite",
	"places.sqlite-shm",
	"places.sqlite-wal",
	"prefs.js",
	"search.json.mozlz4",
	"sessionCheckpoints.json",
	"sessionstore.jsonlz4",
	"SiteSecurityServiceState.txt",
	"storage.sqlite",
	"storage.sqlite-shm",
	"storage.sqlite-wal",
}

var firefoxEvidenceDirs = []string{
	"bookmarkbackups",
	"sessionstore-backups",
}

type browserDiscovery struct {
	Browser string
	Family  string
	RelPath string
	Layout  string
}

var browserRoots = []browserDiscovery{
	{
		Browser: "Chrome",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Google", "Chrome", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Edge",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Microsoft", "Edge", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Brave",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Vivaldi",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Vivaldi", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Opera",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Roaming", "Opera Software", "Opera Stable"),
		Layout:  "direct_profile",
	},
	{
		Browser: "Opera GX",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Roaming", "Opera Software", "Opera GX Stable"),
		Layout:  "direct_profile",
	},
	{
		Browser: "Firefox",
		Family:  browserFamilyFirefox,
		RelPath: filepath.Join("AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		Layout:  "firefox_profiles",
	},
}

var browserSelection = struct {
	mu    sync.RWMutex
	paths []string
}{}

func init() { module.RegisterArtifact("browser", &browserCollector{}) }

type browserCollector struct{}

type BrowserProfile struct {
	Browser string
	Family  string
	User    string
	Name    string
	Path    string
}

// ChromiumProfile is kept as a compatibility alias for existing code.
type ChromiumProfile = BrowserProfile

func (c *browserCollector) Name() string { return BrowserCollectorName }
func (c *browserCollector) Description() string {
	return "Collect browser artifacts from Chrome, Edge, Brave, Vivaldi, Firefox, Opera, and Opera GX"
}

func ConfigureProfiles(paths []string) {
	browserSelection.mu.Lock()
	defer browserSelection.mu.Unlock()

	browserSelection.paths = append([]string(nil), paths...)
}

func ConfigureChromiumProfiles(paths []string) {
	ConfigureProfiles(paths)
}

func ResolveProfiles() ([]BrowserProfile, error) {
	return resolveSelectedProfiles()
}

func DiscoverProfiles() ([]BrowserProfile, error) {
	usersRoot := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	entries, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil, fmt.Errorf("read Users directory: %w", err)
	}

	var profiles []BrowserProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		username := entry.Name()
		if isSkippedWindowsProfile(username) {
			continue
		}

		userRoot := filepath.Join(usersRoot, username)
		for _, root := range browserRoots {
			browserRoot := filepath.Join(userRoot, root.RelPath)
			profiles = append(profiles, discoverProfilesForRoot(username, root, browserRoot)...)
		}
	}

	return profiles, nil
}

func DiscoverChromiumProfiles() ([]BrowserProfile, error) {
	return DiscoverProfiles()
}

func (c *browserCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	profiles, err := resolveSelectedProfiles()
	if err != nil {
		return module.CollectResult{Error: err.Error()}
	}

	outDir, err := req.EnsureOutputDir("browser")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create browser output dir: %w", err).Error()}
	}

	// rawCtx is a last-resort read path when a browser file can't be copied
	// through the normal Win32 file APIs (e.g. the browser holds it under a
	// share-mode lock that backup semantics/SeBackupPrivilege cannot bypass —
	// that privilege only bypasses ACL checks, not another process's exclusive
	// lock). Reading the file straight off the volume's $MFT never opens a
	// Win32 handle, so it is immune to any live share-mode lock.
	rawCtx := &acquisition.RawVolumePool{}
	defer rawCtx.Close()

	var allFiles []module.FileInfo
	var errors []string
	for _, profile := range profiles {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		log.Info(fmt.Sprintf("Browser profile selected: %s", profile.Path))
		files, warnings, collectErr := collectProfile(ctx, outDir, profile, rawCtx)
		allFiles = append(allFiles, files...)
		if collectErr != nil {
			errors = append(errors, collectErr.Error())
			log.Warn(collectErr.Error())
			continue
		}
		for _, w := range warnings {
			msg := fmt.Sprintf("%s: %s", profile.Path, w)
			errors = append(errors, msg)
			log.Warn(msg)
		}
	}

	if len(allFiles) == 0 {
		if len(errors) == 0 {
			return module.CollectResult{OutputPath: outDir, Error: "no browser artifacts collected"}
		}
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no browser artifacts collected: %s", strings.Join(errors, "; "))}
	}

	if len(errors) > 0 {
		return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: fmt.Sprintf("collected browser artifacts with %d partial failure(s): %s", len(errors), strings.Join(errors, "; "))}
	}

	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}

func resolveSelectedProfiles() ([]BrowserProfile, error) {
	browserSelection.mu.RLock()
	selected := append([]string(nil), browserSelection.paths...)
	browserSelection.mu.RUnlock()

	if len(selected) == 0 {
		return DiscoverProfiles()
	}

	seen := make(map[string]bool)
	var profiles []BrowserProfile
	for _, path := range selected {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true

		profile, ok := buildProfileFromPath(path)
		if !ok {
			profile = BrowserProfile{
				Browser: "Browser",
				Family:  browserFamilyChromium,
				User:    "unknown",
				Name:    filepath.Base(path),
				Path:    path,
			}
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

func discoverProfilesForRoot(username string, root browserDiscovery, browserRoot string) []BrowserProfile {
	switch root.Layout {
	case "chromium_user_data":
		return discoverChromiumProfilesInUserData(username, root.Browser, browserRoot)
	case "direct_profile":
		return discoverDirectProfile(username, root.Browser, root.Family, browserRoot)
	case "firefox_profiles":
		return discoverFirefoxProfiles(username, root.Browser, browserRoot)
	default:
		return nil
	}
}

func discoverChromiumProfilesInUserData(username, browserName, userDataDir string) []BrowserProfile {
	info, err := os.Stat(userDataDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}

	var profiles []BrowserProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		profileDir := filepath.Join(userDataDir, name)
		if !looksLikeChromiumProfile(profileDir, name) {
			continue
		}

		profiles = append(profiles, BrowserProfile{
			Browser: browserName,
			Family:  browserFamilyChromium,
			User:    username,
			Name:    name,
			Path:    profileDir,
		})
	}

	return profiles
}

func discoverDirectProfile(username, browserName, family, profileDir string) []BrowserProfile {
	info, err := os.Stat(profileDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	return []BrowserProfile{{
		Browser: browserName,
		Family:  family,
		User:    username,
		Name:    filepath.Base(profileDir),
		Path:    profileDir,
	}}
}

func discoverFirefoxProfiles(username, browserName, profilesDir string) []BrowserProfile {
	info, err := os.Stat(profilesDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil
	}

	var profiles []BrowserProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profileDir := filepath.Join(profilesDir, entry.Name())
		profiles = append(profiles, BrowserProfile{
			Browser: browserName,
			Family:  browserFamilyFirefox,
			User:    username,
			Name:    entry.Name(),
			Path:    profileDir,
		})
	}

	return profiles
}

func buildProfileFromPath(path string) (BrowserProfile, bool) {
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(os.PathSeparator))
	if len(parts) < 4 {
		return BrowserProfile{}, false
	}

	userIdx := -1
	for i, part := range parts {
		if strings.EqualFold(part, "Users") && i+1 < len(parts) {
			userIdx = i
			break
		}
	}
	if userIdx == -1 || userIdx+1 >= len(parts) {
		return BrowserProfile{}, false
	}

	user := parts[userIdx+1]
	browser, family := inferBrowserMetadata(clean)
	return BrowserProfile{
		Browser: browser,
		Family:  family,
		User:    user,
		Name:    filepath.Base(clean),
		Path:    clean,
	}, true
}

func inferBrowserMetadata(path string) (browserName, family string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, `\google\chrome\user data\`):
		return "Chrome", browserFamilyChromium
	case strings.Contains(lower, `\microsoft\edge\user data\`):
		return "Edge", browserFamilyChromium
	case strings.Contains(lower, `\bravesoftware\brave-browser\user data\`):
		return "Brave", browserFamilyChromium
	case strings.Contains(lower, `\vivaldi\user data\`):
		return "Vivaldi", browserFamilyChromium
	case strings.Contains(lower, `\opera software\opera gx stable`):
		return "Opera GX", browserFamilyChromium
	case strings.Contains(lower, `\opera software\opera stable`):
		return "Opera", browserFamilyChromium
	case strings.Contains(lower, `\mozilla\firefox\profiles\`):
		return "Firefox", browserFamilyFirefox
	default:
		return "Browser", browserFamilyChromium
	}
}

func isChromiumProfileDir(name string) bool {
	if strings.EqualFold(name, "Default") {
		return true
	}
	if strings.EqualFold(name, "Guest Profile") {
		return true
	}
	if strings.EqualFold(name, "System Profile") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "profile ")
}

func looksLikeChromiumProfile(profileDir, name string) bool {
	if isChromiumProfileDir(name) {
		return true
	}

	markers := []string{
		"Bookmarks",
		"Cookies",
		"History",
		"Preferences",
		"Web Data",
	}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(profileDir, marker)); err == nil {
			return true
		}
	}
	return false
}

func isSkippedWindowsProfile(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "defaultapppool":
		return true
	default:
		return false
	}
}

func collectProfile(ctx context.Context, outDir string, profile BrowserProfile, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, []string, error) {
	switch profile.Family {
	case browserFamilyFirefox:
		return collectFirefoxProfile(ctx, outDir, profile, rawCtx)
	default:
		return collectChromiumProfile(ctx, outDir, profile, rawCtx)
	}
}

func collectChromiumProfile(ctx context.Context, outDir string, profile BrowserProfile, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, []string, error) {
	profileRoot := filepath.Join(
		outDir,
		outputDirName(profile.User),
		outputDirName(profile.Browser),
		outputDirName(profile.Name),
	)
	if err := os.MkdirAll(profileRoot, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create browser profile output dir for %s: %w", profile.Path, err)
	}

	var files []module.FileInfo
	var errors []string

	userDataDir := filepath.Dir(profile.Path)
	localState := filepath.Join(userDataDir, "Local State")
	if fi, err := copyBrowserFile(localState, filepath.Join(profileRoot, "Local State"), "Local State", rawCtx); err == nil {
		files = append(files, fi)
	}

	for _, relPath := range chromiumEvidenceFiles {
		select {
		case <-ctx.Done():
			return files, errors, ctx.Err()
		default:
		}

		src := filepath.Join(profile.Path, relPath)
		dst := filepath.Join(profileRoot, relPath)
		fi, err := copyBrowserFile(src, dst, relPath, rawCtx)
		if err != nil {
			if !os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("%s: %v", relPath, err))
			}
			continue
		}
		files = append(files, fi)
	}

	for _, relDir := range chromiumEvidenceDirs {
		select {
		case <-ctx.Done():
			return files, errors, ctx.Err()
		default:
		}

		srcDir := filepath.Join(profile.Path, relDir)
		dstDir := filepath.Join(profileRoot, relDir)
		dirFiles, err := copyBrowserDir(srcDir, dstDir, relDir, rawCtx)
		if err != nil {
			if !os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("%s: %v", relDir, err))
			}
			continue
		}
		files = append(files, dirFiles...)
	}

	if len(files) == 0 {
		if len(errors) == 0 {
			return nil, nil, fmt.Errorf("no browser artifacts copied from %s", profile.Path)
		}
		return nil, errors, fmt.Errorf("no browser artifacts copied from %s: %s", profile.Path, strings.Join(errors, "; "))
	}

	return files, errors, nil
}

func collectFirefoxProfile(ctx context.Context, outDir string, profile BrowserProfile, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, []string, error) {
	profileRoot := filepath.Join(
		outDir,
		outputDirName(profile.User),
		outputDirName(profile.Browser),
		outputDirName(profile.Name),
	)
	if err := os.MkdirAll(profileRoot, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create firefox profile output dir for %s: %w", profile.Path, err)
	}

	var files []module.FileInfo
	var errors []string

	for _, relPath := range firefoxEvidenceFiles {
		select {
		case <-ctx.Done():
			return files, errors, ctx.Err()
		default:
		}

		src := filepath.Join(profile.Path, relPath)
		dst := filepath.Join(profileRoot, relPath)
		fi, err := copyBrowserFile(src, dst, relPath, rawCtx)
		if err != nil {
			if !os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("%s: %v", relPath, err))
			}
			continue
		}
		files = append(files, fi)
	}

	for _, relDir := range firefoxEvidenceDirs {
		select {
		case <-ctx.Done():
			return files, errors, ctx.Err()
		default:
		}

		srcDir := filepath.Join(profile.Path, relDir)
		dstDir := filepath.Join(profileRoot, relDir)
		dirFiles, err := copyBrowserDir(srcDir, dstDir, relDir, rawCtx)
		if err != nil {
			if !os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("%s: %v", relDir, err))
			}
			continue
		}
		files = append(files, dirFiles...)
	}

	if len(files) == 0 {
		if len(errors) == 0 {
			return nil, nil, fmt.Errorf("no browser artifacts copied from %s", profile.Path)
		}
		return nil, errors, fmt.Errorf("no browser artifacts copied from %s: %s", profile.Path, strings.Join(errors, "; "))
	}

	return files, errors, nil
}

func copyBrowserFile(src, dst, relPath string, rawCtx *acquisition.RawVolumePool) (module.FileInfo, error) {
	if _, err := os.Stat(src); err != nil {
		return module.FileInfo{}, err
	}

	fi, err := utils.SafeCopyFile(src, dst)
	if err == nil {
		fi.Path = relPath
		return fi, nil
	}

	fi, err = utils.SafeCopyFileBackup(src, dst)
	if err == nil {
		fi.Path = relPath
		return fi, nil
	}

	// Both Win32 copy paths failed (likely a share-mode lock — see rawCtx above).
	if rawCtx != nil {
		if _, rawErr := rawCtx.CopyFile(src, dst); rawErr == nil {
			if rawFi, fiErr := utils.FileInfoFromPath(dst); fiErr == nil {
				rawFi.Path = relPath
				return rawFi, nil
			}
		}
	}
	return module.FileInfo{}, err
}

func copyBrowserDir(srcDir, dstDir, relDir string, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, error) {
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", srcDir)
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}

	var files []module.FileInfo
	var copied bool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		src := filepath.Join(srcDir, entry.Name())
		relPath := filepath.Join(relDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		fi, copyErr := copyBrowserFile(src, dst, relPath, rawCtx)
		if copyErr != nil {
			continue
		}
		files = append(files, fi)
		copied = true
	}

	if !copied {
		return nil, fmt.Errorf("no files copied from %s", srcDir)
	}

	return files, nil
}

func outputDirName(name string) string {
	return strings.ReplaceAll(output.SanitizeDirNameForExport(name), " ", "_")
}
