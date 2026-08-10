package ntfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"golang.org/x/sys/windows"
)

func init() { module.RegisterArtifact("ntfs", &usnJrnlCollector{}) }

const (
	FSCTL_QUERY_USN_JOURNAL = 0x000900F4
	FSCTL_READ_USN_JOURNAL  = 0x000900BB
)

type usnJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readUsnJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

type usnJrnlCollector struct{}

func (c *usnJrnlCollector) Name() string { return "usnjrnl" }
func (c *usnJrnlCollector) Description() string {
	return "Collect $UsnJrnl:$J"
}

func (c *usnJrnlCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir("ntfs")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create NTFS output dir: %w", err).Error()}
	}

	drives, err := acquisition.ListFixedDrives()
	if err != nil {
		log.Debug(fmt.Sprintf("Drive enumeration failed, falling back to C: %v", err))
		drives = []string{"C"}
	}

	var files []module.FileInfo
	var errs []string
	for _, drive := range drives {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: files, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		fi, err := collectUSNJournalForDrive(ctx, log, outDir, drive)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
			log.Debug(fmt.Sprintf("USN journal collection skipped for drive %s: %v", drive, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("no $UsnJrnl:$J collected from any drive (ensure running as Administrator): %s", strings.Join(errs, "; ")).Error()}
	}
	if len(errs) > 0 {
		return module.CollectResult{Files: files, OutputPath: outDir, Error: fmt.Sprintf("collected $UsnJrnl:$J from %d drive(s) with %d failure(s): %s", len(files), len(errs), strings.Join(errs, "; "))}
	}
	return module.CollectResult{Files: files, OutputPath: outDir}
}

func collectUSNJournalForDrive(ctx context.Context, log *logging.Logger, outDir, drive string) (module.FileInfo, error) {
	relName := "$UsnJrnl_J_" + drive
	outputPath := filepath.Join(outDir, relName)

	volPath, err := windows.UTF16PtrFromString(`\\.\` + drive + `:`)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("UTF16: %w", err)
	}
	handle, err := windows.CreateFile(volPath, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("open volume for USN journal: %w", err)
	}
	defer windows.CloseHandle(handle)

	var journalData usnJournalData
	var bytesReturned uint32
	if err := windows.DeviceIoControl(handle, FSCTL_QUERY_USN_JOURNAL, nil, 0, (*byte)(unsafe.Pointer(&journalData)), uint32(unsafe.Sizeof(journalData)), &bytesReturned, nil); err != nil {
		return module.FileInfo{}, fmt.Errorf("query USN journal: %w", err)
	}

	log.Debug(fmt.Sprintf("USN Journal %s: ID=%d, FirstUsn=%d, NextUsn=%d", drive, journalData.UsnJournalID, journalData.FirstUsn, journalData.NextUsn))

	outFile, err := os.Create(outputPath)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("create USN journal output: %w", err)
	}
	defer outFile.Close()

	readData := readUsnJournalData{StartUsn: journalData.FirstUsn, ReasonMask: 0xFFFFFFFF, UsnJournalID: journalData.UsnJournalID}
	buf := make([]byte, 64*1024)
	var totalWritten int64
	// Hash the journal as it streams out: a $UsnJrnl:$J is routinely gigabytes,
	// and re-reading it off the evidence drive just to digest it doubled the I/O.
	digest := sha256.New()
	sink := io.MultiWriter(outFile, digest)

	for {
		select {
		case <-ctx.Done():
			return module.FileInfo{}, ctx.Err()
		default:
		}
		if err := windows.DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL, (*byte)(unsafe.Pointer(&readData)), uint32(unsafe.Sizeof(readData)), &buf[0], uint32(len(buf)), &bytesReturned, nil); err != nil || bytesReturned <= 8 {
			break
		}

		nextUsn := *(*int64)(unsafe.Pointer(&buf[0]))
		n, writeErr := sink.Write(buf[8:bytesReturned])
		if writeErr != nil {
			return module.FileInfo{}, fmt.Errorf("write USN data: %w", writeErr)
		}
		totalWritten += int64(n)
		readData.StartUsn = nextUsn
	}

	hash := hex.EncodeToString(digest.Sum(nil))
	log.Debug(fmt.Sprintf("$UsnJrnl:$J collected for drive %s: %d bytes, SHA256: %s", drive, totalWritten, hash))
	return module.FileInfo{Path: relName, SHA256: hash, Size: totalWritten}, nil
}
