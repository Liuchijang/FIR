package system

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterArtifact("system", &srumCollector{}) }

type srumCollector struct{}

func (c *srumCollector) Name() string { return "srum" }
func (c *srumCollector) Description() string {
	return "Collect SRUM"
}

func (c *srumCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir("system")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create system output dir: %w", err).Error()}
	}

	srumPath := filepath.Join(platform.SystemRoot(), "System32", "sru", "SRUDB.dat")
	dst := filepath.Join(outDir, "SRUDB.dat")
	fi, err := utils.SafeCopyFile(srumPath, dst)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of SRUDB.dat failed: %v", err))
		fi, err = utils.SafeCopyFileBackup(srumPath, dst)
		if err != nil {
			log.Debug(fmt.Sprintf("Backup-semantics copy of SRUDB.dat failed: %v", err))
			return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("collect SRUDB.dat via native Windows copy: %w", err).Error()}
		}
	}
	return module.CollectResult{Files: []module.FileInfo{fi}, OutputPath: outDir}
}

func (c *srumCollector) EstimatedBytes() int64 {
	return utils.PathsSize(filepath.Join(platform.SystemRoot(), "System32", "sru", "SRUDB.dat"))
}
