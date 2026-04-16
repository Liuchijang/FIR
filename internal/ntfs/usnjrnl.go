package ntfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
	"golang.org/x/sys/windows"
)

func init() {
	collector.Register(&usnJrnlCollector{})
}

// FSCTL codes for USN Journal operations.
const (
	FSCTL_QUERY_USN_JOURNAL = 0x000900F4
	FSCTL_READ_USN_JOURNAL  = 0x000900BB
)

// USN_JOURNAL_DATA_V0 matches the Windows USN_JOURNAL_DATA structure.
type usnJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

// READ_USN_JOURNAL_DATA_V0 is the input structure for FSCTL_READ_USN_JOURNAL.
type readUsnJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

type usnJrnlCollector struct{}

func (c *usnJrnlCollector) Name() string        { return "usnjrnl" }
func (c *usnJrnlCollector) Category() string     { return "ntfs" }
func (c *usnJrnlCollector) Description() string {
	return "Collects the $UsnJrnl:$J (USN Change Journal) via FSCTL"
}

func (c *usnJrnlCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "ntfs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create NTFS output dir: %w", err)
	}

	// Open volume handle.
	volPath, err := windows.UTF16PtrFromString(`\\.\C:`)
	if err != nil {
		return fmt.Errorf("UTF16: %w", err)
	}

	handle, err := windows.CreateFile(
		volPath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("open volume for USN journal: %w", err)
	}
	defer windows.CloseHandle(handle)

	// Query journal info.
	var journalData usnJournalData
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		FSCTL_QUERY_USN_JOURNAL,
		nil,
		0,
		(*byte)(unsafe.Pointer(&journalData)),
		uint32(unsafe.Sizeof(journalData)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return fmt.Errorf("query USN journal: %w", err)
	}

	log.Debug(fmt.Sprintf("USN Journal: ID=%d, FirstUsn=%d, NextUsn=%d",
		journalData.UsnJournalID, journalData.FirstUsn, journalData.NextUsn))

	// Read USN journal entries to file.
	outputPath := filepath.Join(outDir, "$UsnJrnl_J")
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create USN journal output: %w", err)
	}
	defer outFile.Close()

	readData := readUsnJournalData{
		StartUsn:          journalData.FirstUsn,
		ReasonMask:        0xFFFFFFFF, // All reasons.
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		UsnJournalID:      journalData.UsnJournalID,
	}

	buf := make([]byte, 64*1024) // 64KB read buffer.
	var totalWritten int64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err = windows.DeviceIoControl(
			handle,
			FSCTL_READ_USN_JOURNAL,
			(*byte)(unsafe.Pointer(&readData)),
			uint32(unsafe.Sizeof(readData)),
			&buf[0],
			uint32(len(buf)),
			&bytesReturned,
			nil,
		)
		if err != nil {
			// ERROR_HANDLE_EOF or similar means we've read all entries.
			break
		}

		if bytesReturned <= 8 {
			// Only the next USN was returned, no more records.
			break
		}

		// First 8 bytes of output are the next USN to read from.
		nextUsn := *(*int64)(unsafe.Pointer(&buf[0]))

		// Write the USN record data (after the 8-byte header).
		n, writeErr := outFile.Write(buf[8:bytesReturned])
		if writeErr != nil {
			return fmt.Errorf("write USN data: %w", writeErr)
		}
		totalWritten += int64(n)

		readData.StartUsn = nextUsn
	}

	// Hash the output.
	hash, err := utils.HashFile(outputPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash $UsnJrnl: %v", err))
	}

	log.Debug(fmt.Sprintf("$UsnJrnl:$J collected: %d bytes, SHA256: %s", totalWritten, hash))
	return nil
}
