package acquisition

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fir/fir/internal/logging"
)

// ShadowCopy represents a Volume Shadow Copy that has been created.
type ShadowCopy struct {
	DevicePath string
	ID         string
}

// CreateShadowCopy creates a new VSS shadow copy of the specified volume.
func CreateShadowCopy(ctx context.Context, volume string) (*ShadowCopy, func(), error) {
	log := logging.G()
	if !strings.HasSuffix(volume, `\`) {
		volume += `\`
	}

	log.Debug(fmt.Sprintf("Creating shadow copy for %s", volume))
	createCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	psScript := fmt.Sprintf(`$res = ([WMIClass]'Win32_ShadowCopy').Create('%s','ClientAccessible'); if ($res.ReturnValue -ne 0) { Write-Error ('Create failed: ' + $res.ReturnValue); exit $res.ReturnValue }; $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $res.ShadowID }; if ($null -eq $shadow) { Write-Error 'Shadow copy created but not found'; exit 1 }; Write-Output ($shadow.ID + '|' + $shadow.DeviceObject)`, volume)
	cmd := exec.CommandContext(createCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("powershell Win32_ShadowCopy create: %w\nOutput: %s", err, string(output))
	}

	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("failed to parse shadow copy output: %s", string(output))
	}

	sc := &ShadowCopy{ID: strings.TrimSpace(parts[0]), DevicePath: strings.TrimSpace(parts[1])}
	cleanup := func() { DeleteShadowCopy(context.Background(), sc) }
	log.Debug(fmt.Sprintf("Shadow copy created: %s (ID: %s)", sc.DevicePath, sc.ID))
	return sc, cleanup, nil
}

// DeleteShadowCopy deletes a previously created shadow copy.
func DeleteShadowCopy(ctx context.Context, sc *ShadowCopy) {
	log := logging.G()
	if sc == nil || sc.ID == "" {
		log.Warn("Cannot delete shadow copy: no ID available")
		return
	}

	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	psScript := fmt.Sprintf(`$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq '%s' }; if ($null -eq $shadow) { exit 0 }; $result = $shadow.Delete(); if ($result.ReturnValue -ne 0) { Write-Error ('Delete failed: ' + $result.ReturnValue); exit $result.ReturnValue }`, sc.ID)
	cmd := exec.CommandContext(deleteCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to delete shadow copy %s: %v\nOutput: %s", sc.ID, err, string(output)))
		return
	}
	log.Debug(fmt.Sprintf("Shadow copy deleted: %s", sc.ID))
}

// ShadowPath returns the path to a file within the shadow copy.
func (sc *ShadowCopy) ShadowPath(relativePath string) string {
	rel := relativePath
	if len(rel) >= 2 && rel[1] == ':' {
		rel = rel[2:]
	}
	rel = strings.TrimPrefix(rel, `\`)
	return sc.DevicePath + `\` + rel
}
