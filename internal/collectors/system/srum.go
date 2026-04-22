package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.Register(&srumCollector{}) }

type srumCollector struct{}

func (c *srumCollector) Name() string     { return "srum" }
func (c *srumCollector) Category() string { return "system" }
func (c *srumCollector) Description() string {
	return "Collect SRUM"
}

func (c *srumCollector) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "system")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create system output dir: %w", err)
	}

	srumPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "sru", "SRUDB.dat")
	dst := filepath.Join(outDir, "SRUDB.dat")
	fi, err := utils.SafeCopyFile(srumPath, dst)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of SRUDB.dat failed: %v", err))
		fi, err = utils.SafeCopyFileBackup(srumPath, dst)
		if err != nil {
			log.Debug(fmt.Sprintf("Backup-semantics copy of SRUDB.dat failed: %v", err))
			return nil, fmt.Errorf("collect SRUDB.dat via native Windows copy: %w", err)
		}
	}
	return []module.FileInfo{fi}, nil
}
