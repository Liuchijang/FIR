package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.Register(&amcacheCollector{}) }

type amcacheCollector struct{}

type amcacheFileSpec struct {
	srcPath    string
	dstPath    string
	relPath    string
	isPrimary  bool
	useHiveAPI bool
}

type amcacheRawContext struct {
	vol     *acquisition.RawVolume
	volData *acquisition.NTFSVolumeData
}

func (c *amcacheCollector) Name() string     { return "amcache" }
func (c *amcacheCollector) Category() string { return "execution" }
func (c *amcacheCollector) Description() string {
	return "Collect Amcache hive + logs"
}

func (c *amcacheCollector) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "execution")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create execution output dir: %w", err)
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
	var rawCtx *amcacheRawContext
	defer func() {
		if rawCtx != nil && rawCtx.vol != nil {
			rawCtx.vol.Close()
		}
	}()
	for _, spec := range specs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		log.Debug(fmt.Sprintf("Collecting %s via direct Windows file access", spec.relPath))
		fi, err := collectAmcacheFile(spec, &rawCtx)
		if err != nil {
			if spec.isPrimary {
				return nil, fmt.Errorf("collect %s: %w", spec.relPath, err)
			}

			log.Debug(fmt.Sprintf("Skipping optional %s: %v", spec.relPath, err))
			continue
		}

		files = append(files, fi)
	}

	return files, nil
}

func collectAmcacheFile(spec amcacheFileSpec, rawCtx **amcacheRawContext) (module.FileInfo, error) {
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
		fallbackErr = collectAmcacheHiveFallback(spec.dstPath, spec.srcPath, rawCtx)
	} else {
		fallbackErr = collectAmcacheRawFallback(spec.dstPath, spec.srcPath, rawCtx)
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

func collectAmcacheHiveFallback(dst, src string, rawCtx **amcacheRawContext) error {
	if _, err := saveMountedAmcacheHive(dst); err == nil {
		return nil
	}
	return collectAmcacheRawFallback(dst, src, rawCtx)
}

func collectAmcacheRawFallback(dst, src string, rawCtx **amcacheRawContext) error {
	ctx, err := ensureAmcacheRawContext(rawCtx)
	if err != nil {
		return err
	}
	if _, copyErr := acquisition.CopyFileFromRawPath(ctx.vol, ctx.volData, src, dst); copyErr != nil {
		return copyErr
	}
	return nil
}

func ensureAmcacheRawContext(rawCtx **amcacheRawContext) (*amcacheRawContext, error) {
	if rawCtx != nil && *rawCtx != nil {
		return *rawCtx, nil
	}

	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		return nil, err
	}

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		vol.Close()
		return nil, err
	}

	ctx := &amcacheRawContext{
		vol:     vol,
		volData: volData,
	}
	if rawCtx != nil {
		*rawCtx = ctx
	}
	return ctx, nil
}

func saveMountedAmcacheHive(dst string) (module.FileInfo, error) {
	if err := utils.SaveRegistryHive(winreg.LOCAL_MACHINE, "AMCACHE", dst); err != nil {
		return module.FileInfo{}, err
	}
	return utils.FileInfoFromPath(dst)
}
