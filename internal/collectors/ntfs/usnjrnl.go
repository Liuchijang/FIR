package ntfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

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
	return collectPerDrive(ctx, req, "$UsnJrnl:$J", collectUSNJournalForDrive)
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

	// readErr records a journal that stopped early. The loop's normal exit is a
	// successful read returning only the 8-byte next-USN header; a failed
	// DeviceIoControl used to exit the same way, so a journal truncated by a
	// mid-read error (a deleted-and-recreated journal, an entry aged out from
	// under the cursor) was written out, hashed, and reported as the complete
	// $J. An analyst reading that file has no way to tell it ends early.
	var readErr error
	for {
		select {
		case <-ctx.Done():
			return module.FileInfo{}, ctx.Err()
		default:
		}
		if err := windows.DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL, (*byte)(unsafe.Pointer(&readData)), uint32(unsafe.Sizeof(readData)), &buf[0], uint32(len(buf)), &bytesReturned, nil); err != nil {
			readErr = fmt.Errorf("read USN journal after %d bytes: %w", totalWritten, err)
			break
		}
		if bytesReturned <= 8 {
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

	if err := outFile.Sync(); err != nil {
		return module.FileInfo{}, fmt.Errorf("sync USN journal output: %w", err)
	}
	// A volume whose journal could not be read at all leaves no artifact behind.
	// The empty file that os.Create already made would otherwise be manifested
	// and hashed as a legitimately empty $J, which reads as "this volume had no
	// recorded activity" rather than "this volume was never read".
	if totalWritten == 0 && readErr != nil {
		outFile.Close()
		os.Remove(outputPath)
		return module.FileInfo{}, readErr
	}

	hash := hex.EncodeToString(digest.Sum(nil))
	log.Debug(fmt.Sprintf("$UsnJrnl:$J collected for drive %s: %d bytes, SHA256: %s", drive, totalWritten, hash))
	// The partial journal is still returned: what was read is evidence, and
	// collectPerDrive keeps a file that arrives with an error while surfacing
	// the error as a warning on the run.
	return module.FileInfo{Path: relName, SHA256: hash, Size: totalWritten}, readErr
}
