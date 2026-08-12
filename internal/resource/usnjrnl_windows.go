//go:build windows

package resource

import (
	"unsafe"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"golang.org/x/sys/windows"
)

const fsctlQueryUsnJournal = 0x000900F4

// usnJournalDataV0 mirrors USN_JOURNAL_DATA_V0 as returned by FSCTL_QUERY_USN_JOURNAL.
type usnJournalDataV0 struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

// liveUsnJournalSize sums the configured MaximumSize of the USN journal across
// every fixed drive, mirroring what the usnjrnl collector actually reads — it
// walks all fixed drives, not just C.
//
// Querying only C undercounted every multi-volume machine by roughly the number
// of drives. Drives whose journal cannot be queried (not elevated, or the
// journal is disabled) are credited the size of the ones that answered, so a
// single unreadable volume does not silently shrink the estimate. Returns 0
// when nothing could be measured, letting the caller fall back to a flat guess.
func liveUsnJournalSize() int64 {
	drives, err := acquisition.ListFixedDrives()
	if err != nil || len(drives) == 0 {
		drives = []string{"C"}
	}

	var total int64
	measured := 0
	for _, drive := range drives {
		size := usnJournalMaxSize(drive)
		if size <= 0 {
			continue
		}
		total += size
		measured++
	}

	if measured == 0 {
		return 0
	}
	if measured < len(drives) {
		average := total / int64(measured)
		total += average * int64(len(drives)-measured)
	}
	return total
}

func usnJournalMaxSize(drive string) int64 {
	volPath, err := windows.UTF16PtrFromString(`\\.\` + drive + `:`)
	if err != nil {
		return 0
	}

	handle, err := windows.CreateFile(volPath, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)

	var data usnJournalDataV0
	var bytesReturned uint32
	if err := windows.DeviceIoControl(handle, fsctlQueryUsnJournal, nil, 0, (*byte)(unsafe.Pointer(&data)), uint32(unsafe.Sizeof(data)), &bytesReturned, nil); err != nil {
		return 0
	}
	return int64(data.MaximumSize)
}
