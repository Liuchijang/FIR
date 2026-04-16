package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() {
	collector.Register(&srumCollector{})
}

type srumCollector struct{}

func (c *srumCollector) Name() string        { return "srum" }
func (c *srumCollector) Category() string     { return "system" }
func (c *srumCollector) Description() string {
	return "Collects SRUM database (SRUDB.dat) from C:\\Windows\\System32\\sru"
}

func (c *srumCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "system")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create system output dir: %w", err)
	}

	srumPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "sru", "SRUDB.dat")
	dst := filepath.Join(outDir, "SRUDB.dat")

	// SRUDB.dat is typically locked by svchost.exe.
	// Try direct copy first, which may work if SeBackupPrivilege is enabled.
	fi, err := utils.SafeCopyFile(srumPath, dst)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of SRUDB.dat failed: %v", err))

		// Try copying via esentutl (ESE database utility) as fallback.
		fi, err = copySRUMViaEsentutl(ctx, srumPath, dst)
		if err != nil {
			return fmt.Errorf("collect SRUDB.dat: %w", err)
		}
	}

	_ = fi
	return nil
}

// copySRUMViaEsentutl uses esentutl.exe to copy a locked ESE database.
func copySRUMViaEsentutl(ctx context.Context, src, dst string) (collector.FileInfo, error) {
	log := logging.G()

	// esentutl /y <source> /vss /d <dest>
	cmd := exec.CommandContext(ctx, "esentutl.exe", "/y", src, "/vss", "/d", dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug(fmt.Sprintf("esentutl failed: %v, output: %s", err, string(out)))
		return collector.FileInfo{}, fmt.Errorf("esentutl copy SRUDB.dat: %w", err)
	}

	hash, err := utils.HashFile(dst)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("hash SRUDB.dat: %w", err)
	}

	stat, err := os.Stat(dst)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat SRUDB.dat: %w", err)
	}

	return collector.FileInfo{
		Path:   "SRUDB.dat",
		SHA256: hash,
		Size:   stat.Size(),
	}, nil
}
