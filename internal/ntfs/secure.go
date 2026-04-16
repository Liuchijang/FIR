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

func init() { collector.Register(&secureCollector{}) }

type secureCollector struct{}

func (c *secureCollector) Name() string     { return "secure_sds" }
func (c *secureCollector) Category() string { return "ntfs" }
func (c *secureCollector) Description() string {
	return "Collects the $Secure:$SDS (Security Descriptor Stream) via VSS snapshot access"
}

func (c *secureCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "ntfs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create NTFS output dir: %w", err)
	}

	outputPath := filepath.Join(outDir, "$Secure_SDS")
	sc, cleanup, err := acquisition.CreateShadowCopy(ctx, `C:\`)
	if err != nil {
		log.Debug(fmt.Sprintf("VSS shadow copy creation failed: %v", err))
		return nil, fmt.Errorf("$Secure:$SDS requires a working snapshot provider: %w", err)
	}
	defer cleanup()

	securePath := sc.ShadowPath(`$Secure`)
	fi, err := utils.SafeCopyFile(securePath, outputPath)
	if err != nil {
		log.Warn("$Secure:$SDS collection skipped: metafile is not directly accessible from the snapshot path")
		return nil, fmt.Errorf("$Secure:$SDS not accessible via snapshot path: %w", err)
	}

	log.Debug(fmt.Sprintf("$Secure:$SDS collected: %d bytes, SHA256: %s", fi.Size, fi.SHA256))
	return []collector.FileInfo{fi}, nil
}
