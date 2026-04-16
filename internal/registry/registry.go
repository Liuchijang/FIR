// Package registry implements the Windows registry hive collector.
package registry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() { collector.Register(&registryCollector{}) }

type registryCollector struct{}

func (c *registryCollector) Name() string     { return "registry" }
func (c *registryCollector) Category() string { return "registry" }
func (c *registryCollector) Description() string {
	return "Collects Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat)"
}

var systemHives = []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}

func (c *registryCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "registry")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create registry output dir: %w", err)
	}

	var allFiles []collector.FileInfo
	var errors []string
	configDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "config")
	for _, hive := range systemHives {
		select {
		case <-ctx.Done():
			return allFiles, ctx.Err()
		default:
		}
		src := filepath.Join(configDir, hive)
		dst := filepath.Join(outDir, hive)
		fi, err := utils.SafeCopyFile(src, dst)
		if err != nil {
			log.Debug(fmt.Sprintf("Direct copy of %s failed, attempting reg save: %v", hive, err))
			fi, err = saveHiveViaReg(ctx, hive, dst)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", hive, err))
				log.Warn(fmt.Sprintf("Failed to collect registry hive %s: %v", hive, err))
				continue
			}
		}
		allFiles = append(allFiles, fi)
		log.Debug(fmt.Sprintf("Collected registry hive: %s (%d bytes)", hive, fi.Size))
	}

	userFiles, userErrors := collectUserHives(ctx, outDir)
	allFiles = append(allFiles, userFiles...)
	errors = append(errors, userErrors...)
	if len(allFiles) == 0 {
		return nil, fmt.Errorf("no registry hives collected: %s", strings.Join(errors, "; "))
	}
	return allFiles, nil
}

func collectUserHives(ctx context.Context, outDir string) ([]collector.FileInfo, []string) {
	log := logging.G()
	var files []collector.FileInfo
	var errors []string
	usersDir := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("read Users dir: %v", err)}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		select {
		case <-ctx.Done():
			return files, append(errors, "context cancelled")
		default:
		}
		username := entry.Name()
		if username == "Public" || username == "Default" || username == "Default User" || username == "All Users" {
			continue
		}

		profileDir := filepath.Join(usersDir, username)
		userOutDir := filepath.Join(outDir, "users", username)
		if err := os.MkdirAll(userOutDir, 0o755); err != nil {
			errors = append(errors, fmt.Sprintf("create dir for %s: %v", username, err))
			continue
		}

		ntuser := filepath.Join(profileDir, "NTUSER.DAT")
		if _, err := os.Stat(ntuser); err == nil {
			fi, err := copyUserHive(ntuser, filepath.Join(userOutDir, "NTUSER.DAT"))
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s/NTUSER.DAT: %v", username, err))
				log.Debug(fmt.Sprintf("Failed to copy NTUSER.DAT for %s: %v", username, err))
			} else {
				fi.Path = filepath.Join("users", username, "NTUSER.DAT")
				files = append(files, fi)
				log.Debug(fmt.Sprintf("Collected NTUSER.DAT for user: %s", username))
			}
		}

		usrclass := filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
		if _, err := os.Stat(usrclass); err == nil {
			fi, err := copyUserHive(usrclass, filepath.Join(userOutDir, "UsrClass.dat"))
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s/UsrClass.dat: %v", username, err))
				log.Debug(fmt.Sprintf("Failed to copy UsrClass.dat for %s: %v", username, err))
			} else {
				fi.Path = filepath.Join("users", username, "UsrClass.dat")
				files = append(files, fi)
				log.Debug(fmt.Sprintf("Collected UsrClass.dat for user: %s", username))
			}
		}
	}

	return files, errors
}

func copyUserHive(src, dst string) (collector.FileInfo, error) {
	fi, err := utils.SafeCopyFile(src, dst)
	if err == nil {
		return fi, nil
	}
	return utils.SafeCopyFileBackup(src, dst)
}

func saveHiveViaReg(ctx context.Context, hiveName, outputPath string) (collector.FileInfo, error) {
	var regKey string
	switch strings.ToUpper(hiveName) {
	case "SYSTEM":
		regKey = `HKLM\SYSTEM`
	case "SOFTWARE":
		regKey = `HKLM\SOFTWARE`
	case "SAM":
		regKey = `HKLM\SAM`
	case "SECURITY":
		regKey = `HKLM\SECURITY`
	case "DEFAULT":
		regKey = `HKU\.DEFAULT`
	default:
		return collector.FileInfo{}, fmt.Errorf("unknown system hive: %s", hiveName)
	}

	os.Remove(outputPath)
	cmd := exec.CommandContext(ctx, "reg", "save", regKey, outputPath, "/y")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("reg save %s: %w\nOutput: %s", regKey, err, string(out))
	}

	hash, err := utils.HashFile(outputPath)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("hash %s: %w", outputPath, err)
	}
	stat, err := os.Stat(outputPath)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat %s: %w", outputPath, err)
	}
	return collector.FileInfo{Path: filepath.Base(outputPath), SHA256: hash, Size: stat.Size()}, nil
}
