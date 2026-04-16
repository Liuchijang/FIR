package acquisition

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fir/fir/internal/logging"
)

// ShadowCopy represents a Volume Shadow Copy that has been created.
type ShadowCopy struct {
	DevicePath string // e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
	ID         string // Shadow Copy ID for deletion
}

// CreateShadowCopy creates a new VSS shadow copy of the specified volume (e.g., "C:\").
// Returns the shadow copy info and a cleanup function to delete it.
func CreateShadowCopy(ctx context.Context, volume string) (*ShadowCopy, func(), error) {
	log := logging.G()

	if !strings.HasSuffix(volume, `\`) {
		volume += `\`
	}

	log.Debug(fmt.Sprintf("Creating shadow copy for %s", volume))

	// Create shadow copy using vssadmin.
	createCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(createCtx, "vssadmin", "create", "shadow", fmt.Sprintf("/for=%s", volume))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("vssadmin create shadow: %w\nOutput: %s", err, string(output))
	}

	outputStr := string(output)
	log.Debug(fmt.Sprintf("vssadmin output: %s", outputStr))

	// Parse shadow copy device path from output.
	// Expected: "Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN"
	deviceRe := regexp.MustCompile(`Shadow Copy Volume Name:\s*(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)`)
	matches := deviceRe.FindStringSubmatch(outputStr)
	if len(matches) < 2 {
		return nil, nil, fmt.Errorf("failed to parse shadow copy device path from output:\n%s", outputStr)
	}
	devicePath := matches[1]

	// Parse shadow copy ID.
	// Expected: "Shadow Copy ID: {GUID}"
	idRe := regexp.MustCompile(`Shadow Copy ID:\s*(\{[0-9A-Fa-f-]+\})`)
	idMatches := idRe.FindStringSubmatch(outputStr)
	var shadowID string
	if len(idMatches) >= 2 {
		shadowID = idMatches[1]
	}

	sc := &ShadowCopy{
		DevicePath: devicePath,
		ID:         shadowID,
	}

	cleanup := func() {
		DeleteShadowCopy(context.Background(), sc)
	}

	log.Debug(fmt.Sprintf("Shadow copy created: %s (ID: %s)", devicePath, shadowID))
	return sc, cleanup, nil
}

// DeleteShadowCopy deletes a previously created shadow copy.
func DeleteShadowCopy(ctx context.Context, sc *ShadowCopy) {
	log := logging.G()

	if sc.ID == "" {
		log.Warn("Cannot delete shadow copy: no ID available")
		return
	}

	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(deleteCtx, "vssadmin", "delete", "shadows",
		fmt.Sprintf("/shadow=%s", sc.ID), "/quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to delete shadow copy %s: %v\nOutput: %s", sc.ID, err, string(output)))
		return
	}

	log.Debug(fmt.Sprintf("Shadow copy deleted: %s", sc.ID))
}

// ShadowPath returns the UNC path to a file within the shadow copy.
// For example: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM
func (sc *ShadowCopy) ShadowPath(relativePath string) string {
	// Remove leading backslash or drive letter from relative path.
	rel := relativePath
	if len(rel) >= 2 && rel[1] == ':' {
		rel = rel[2:]
	}
	rel = strings.TrimPrefix(rel, `\`)

	return sc.DevicePath + `\` + rel
}
