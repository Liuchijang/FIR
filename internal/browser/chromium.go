// Package browser implements browser-forensics collectors.
package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/utils"
)

const ChromiumCollectorName = "browser_chromium"

var chromiumEvidenceFiles = []string{
	"Bookmarks",
	"Cookies",
	"Extension Cookies",
	"Extension Rules",
	"Extension State",
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
}

var chromiumBrowserRoots = []struct {
	Browser string
	RelPath string
}{
	{Browser: "Chrome", RelPath: filepath.Join("AppData", "Local", "Google", "Chrome", "User Data")},
	{Browser: "Edge", RelPath: filepath.Join("AppData", "Local", "Microsoft", "Edge", "User Data")},
	{Browser: "Brave", RelPath: filepath.Join("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")},
	{Browser: "Vivaldi", RelPath: filepath.Join("AppData", "Local", "Vivaldi", "User Data")},
}

var chromiumSelection = struct {
	mu    sync.RWMutex
	paths []string
}{}

func init() { collector.Register(&chromiumCollector{}) }

type chromiumCollector struct{}

type ChromiumProfile struct {
	Browser string
	User    string
	Name    string
	Path    string
}

func (c *chromiumCollector) Name() string     { return ChromiumCollectorName }
func (c *chromiumCollector) Category() string { return "browser" }
func (c *chromiumCollector) Description() string {
	return "Collects Chromium browser forensic artifacts from selected Chrome/Edge/Brave/Vivaldi profiles"
}

func ConfigureChromiumProfiles(paths []string) {
	chromiumSelection.mu.Lock()
	defer chromiumSelection.mu.Unlock()

	chromiumSelection.paths = append([]string(nil), paths...)
}

func DiscoverChromiumProfiles() ([]ChromiumProfile, error) {
	usersRoot := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	entries, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil, fmt.Errorf("read Users directory: %w", err)
	}

	var profiles []ChromiumProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		username := entry.Name()
		if isSkippedWindowsProfile(username) {
			continue
		}

		userRoot := filepath.Join(usersRoot, username)
		for _, root := range chromiumBrowserRoots {
			userDataDir := filepath.Join(userRoot, root.RelPath)
			profiles = append(profiles, discoverProfilesInUserData(username, root.Browser, userDataDir)...)
		}
	}

	return profiles, nil
}

func (c *chromiumCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	profiles, err := resolveSelectedProfiles()
	if err != nil {
		return nil, err
	}

	outDir := filepath.Join(outputDir, "browser", "chromium")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create browser output dir: %w", err)
	}

	var allFiles []collector.FileInfo
	var errors []string
	for _, profile := range profiles {
		select {
		case <-ctx.Done():
			return allFiles, ctx.Err()
		default:
		}

		log.Info(fmt.Sprintf("Browser profile selected: %s", profile.Path))
		files, collectErr := collectChromiumProfile(ctx, outDir, profile)
		allFiles = append(allFiles, files...)
		if collectErr != nil {
			errors = append(errors, collectErr.Error())
			log.Warn(collectErr.Error())
		}
	}

	if len(allFiles) == 0 {
		if len(errors) == 0 {
			return nil, fmt.Errorf("no Chromium browser artifacts collected")
		}
		return nil, fmt.Errorf("no Chromium browser artifacts collected: %s", strings.Join(errors, "; "))
	}

	return allFiles, nil
}

func resolveSelectedProfiles() ([]ChromiumProfile, error) {
	chromiumSelection.mu.RLock()
	selected := append([]string(nil), chromiumSelection.paths...)
	chromiumSelection.mu.RUnlock()

	if len(selected) == 0 {
		return DiscoverChromiumProfiles()
	}

	seen := make(map[string]bool)
	var profiles []ChromiumProfile
	for _, path := range selected {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true

		profile, ok := buildChromiumProfileFromPath(path)
		if !ok {
			profile = ChromiumProfile{
				Browser: "Chromium",
				User:    "unknown",
				Name:    filepath.Base(path),
				Path:    path,
			}
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

func discoverProfilesInUserData(username, browserName, userDataDir string) []ChromiumProfile {
	info, err := os.Stat(userDataDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}

	var profiles []ChromiumProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isChromiumProfileDir(name) {
			continue
		}

		profiles = append(profiles, ChromiumProfile{
			Browser: browserName,
			User:    username,
			Name:    name,
			Path:    filepath.Join(userDataDir, name),
		})
	}

	return profiles
}

func buildChromiumProfileFromPath(path string) (ChromiumProfile, bool) {
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(os.PathSeparator))
	if len(parts) < 7 {
		return ChromiumProfile{}, false
	}

	userIdx := -1
	for i, part := range parts {
		if strings.EqualFold(part, "Users") && i+1 < len(parts) {
			userIdx = i
			break
		}
	}
	if userIdx == -1 || userIdx+1 >= len(parts) {
		return ChromiumProfile{}, false
	}

	user := parts[userIdx+1]
	browser := inferBrowserName(clean)
	return ChromiumProfile{
		Browser: browser,
		User:    user,
		Name:    filepath.Base(clean),
		Path:    clean,
	}, true
}

func inferBrowserName(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, `\google\chrome\user data\`):
		return "Chrome"
	case strings.Contains(lower, `\microsoft\edge\user data\`):
		return "Edge"
	case strings.Contains(lower, `\bravesoftware\brave-browser\user data\`):
		return "Brave"
	case strings.Contains(lower, `\vivaldi\user data\`):
		return "Vivaldi"
	default:
		return "Chromium"
	}
}

func isChromiumProfileDir(name string) bool {
	if strings.EqualFold(name, "Default") {
		return true
	}
	if strings.EqualFold(name, "Guest Profile") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "profile ")
}

func isSkippedWindowsProfile(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "defaultapppool":
		return true
	default:
		return false
	}
}

func collectChromiumProfile(ctx context.Context, outDir string, profile ChromiumProfile) ([]collector.FileInfo, error) {
	profileRoot := filepath.Join(
		outDir,
		outputDirName(profile.User),
		outputDirName(profile.Browser),
		outputDirName(profile.Name),
	)
	if err := os.MkdirAll(profileRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create browser profile output dir for %s: %w", profile.Path, err)
	}

	var files []collector.FileInfo
	var errors []string

	userDataDir := filepath.Dir(profile.Path)
	localState := filepath.Join(userDataDir, "Local State")
	if fi, err := copyBrowserFile(localState, filepath.Join(profileRoot, "Local State"), "Local State"); err == nil {
		files = append(files, fi)
	}

	for _, relPath := range chromiumEvidenceFiles {
		select {
		case <-ctx.Done():
			return files, ctx.Err()
		default:
		}

		src := filepath.Join(profile.Path, relPath)
		dst := filepath.Join(profileRoot, relPath)
		fi, err := copyBrowserFile(src, dst, relPath)
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
			return files, ctx.Err()
		default:
		}

		srcDir := filepath.Join(profile.Path, relDir)
		dstDir := filepath.Join(profileRoot, relDir)
		dirFiles, err := copyBrowserDir(srcDir, dstDir, relDir)
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
			return nil, fmt.Errorf("no browser artifacts copied from %s", profile.Path)
		}
		return nil, fmt.Errorf("no browser artifacts copied from %s: %s", profile.Path, strings.Join(errors, "; "))
	}

	return files, nil
}

func copyBrowserFile(src, dst, relPath string) (collector.FileInfo, error) {
	if _, err := os.Stat(src); err != nil {
		return collector.FileInfo{}, err
	}

	fi, err := utils.SafeCopyFile(src, dst)
	if err != nil {
		fi, err = utils.SafeCopyFileBackup(src, dst)
		if err != nil {
			return collector.FileInfo{}, err
		}
	}
	fi.Path = relPath
	return fi, nil
}

func copyBrowserDir(srcDir, dstDir, relDir string) ([]collector.FileInfo, error) {
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

	var files []collector.FileInfo
	var copied bool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		src := filepath.Join(srcDir, entry.Name())
		relPath := filepath.Join(relDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		fi, copyErr := copyBrowserFile(src, dst, relPath)
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
