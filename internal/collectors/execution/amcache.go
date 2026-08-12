package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterArtifact("execution", &amcacheCollector{}) }

type amcacheCollector struct{}

type amcacheFileSpec struct {
	srcPath    string
	dstPath    string
	relPath    string
	isPrimary  bool
	useHiveAPI bool
}

func (c *amcacheCollector) Name() string { return "amcache" }
func (c *amcacheCollector) Description() string {
	return "Collect Amcache hive + logs"
}

func (c *amcacheCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir("execution")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create execution output dir: %w", err).Error()}
	}

	basePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	specs := []amcacheFileSpec{
		{
			srcPath:    basePath,
			dstPath:    filepath.Join(outDir, "Amcache.hve"),
			relPath:    "Amcache.hve",
			isPrimary:  true,
			useHiveAPI: true,
		},
		{
			srcPath: filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve.LOG1"),
			dstPath: filepath.Join(outDir, "Amcache.hve.LOG1"),
			relPath: "Amcache.hve.LOG1",
		},
		{
			srcPath: filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve.LOG2"),
			dstPath: filepath.Join(outDir, "Amcache.hve.LOG2"),
			relPath: "Amcache.hve.LOG2",
		},
	}

	files := make([]module.FileInfo, 0, len(specs))
	rawPool := &acquisition.RawVolumePool{}
	defer rawPool.Close()
	for _, spec := range specs {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: files, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		log.Debug(fmt.Sprintf("Collecting %s via direct Windows file access", spec.relPath))
		fi, err := collectAmcacheFile(spec, rawPool)
		if err != nil {
			if spec.isPrimary {
				return module.CollectResult{Files: files, OutputPath: outDir, Error: fmt.Errorf("collect %s: %w", spec.relPath, err).Error()}
			}

			log.Debug(fmt.Sprintf("Skipping optional %s: %v", spec.relPath, err))
			continue
		}

		files = append(files, fi)
	}

	return module.CollectResult{Files: files, OutputPath: outDir}
}

func collectAmcacheFile(spec amcacheFileSpec, rawPool *acquisition.RawVolumePool) (module.FileInfo, error) {
	fi, err := utils.SafeCopyFile(spec.srcPath, spec.dstPath)
	if err == nil {
		fi.Path = spec.relPath
		return fi, nil
	}

	fi, err = utils.SafeCopyFileBackup(spec.srcPath, spec.dstPath)
	if err == nil {
		fi.Path = spec.relPath
		return fi, nil
	}

	var fallbackErr error
	if spec.useHiveAPI {
		fallbackErr = collectAmcacheHiveFallback(spec.dstPath, spec.srcPath, rawPool)
	} else {
		_, fallbackErr = rawPool.CopyFile(spec.srcPath, spec.dstPath)
	}
	if fallbackErr != nil {
		return module.FileInfo{}, fmt.Errorf("direct copy failed: %v; fallback failed: %w", err, fallbackErr)
	}

	fi, fileInfoErr := utils.FileInfoFromPath(spec.dstPath)
	if fileInfoErr != nil {
		return module.FileInfo{}, fileInfoErr
	}
	fi.Path = spec.relPath
	return fi, nil
}

func collectAmcacheHiveFallback(dst, src string, rawPool *acquisition.RawVolumePool) error {
	if _, err := saveMountedAmcacheHive(dst); err == nil {
		return nil
	}
	_, err := rawPool.CopyFile(src, dst)
	return err
}

func saveMountedAmcacheHive(dst string) (module.FileInfo, error) {
	if err := utils.SaveRegistryHive(winreg.LOCAL_MACHINE, "AMCACHE", dst); err != nil {
		return module.FileInfo{}, err
	}
	return utils.FileInfoFromPath(dst)
}

func (c *amcacheCollector) EstimatedBytes() int64 {
	base := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	return utils.PathsSize(base, base+".LOG1", base+".LOG2")
}
