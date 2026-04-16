package ntfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fir/fir/internal/acquisition"
	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() {
	collector.Register(&secureCollector{})
}

type secureCollector struct{}

func (c *secureCollector) Name() string        { return "secure_sds" }
func (c *secureCollector) Category() string     { return "ntfs" }
func (c *secureCollector) Description() string {
	return "Collects the $Secure:$SDS (Security Descriptor Stream) via VSS or raw access"
}

func (c *secureCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "ntfs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create NTFS output dir: %w", err)
	}

	outputPath := filepath.Join(outDir, "$Secure_SDS")

	// $Secure:$SDS is an NTFS metafile that cannot be accessed via normal file APIs.
	// Strategy: Create a VSS shadow copy and attempt to read from it,
	// or use raw disk access to read the security descriptor stream.

	// Try VSS approach first.
	sc, cleanup, err := acquisition.CreateShadowCopy(ctx, `C:\`)
	if err != nil {
		log.Debug(fmt.Sprintf("VSS shadow copy creation failed: %v, skipping $Secure:$SDS", err))
		return fmt.Errorf("$Secure:$SDS requires VSS access: %w", err)
	}
	defer cleanup()

	// Try to copy $Secure from the shadow copy.
	// $Secure is an NTFS metafile — even via VSS it may not be directly accessible.
	securePath := sc.ShadowPath(`$Secure`)
	fi, err := utils.SafeCopyFile(securePath, outputPath)
	if err != nil {
		log.Debug(fmt.Sprintf("$Secure copy from VSS failed: %v", err))

		// This is expected — $Secure:$SDS is notoriously difficult to access.
		// Log a warning but don't fail the entire collection.
		log.Warn("$Secure:$SDS collection skipped — metafile not directly accessible")
		return fmt.Errorf("$Secure:$SDS not accessible via VSS: %w", err)
	}

	log.Debug(fmt.Sprintf("$Secure:$SDS collected: %d bytes, SHA256: %s", fi.Size, fi.SHA256))
	return nil
}
