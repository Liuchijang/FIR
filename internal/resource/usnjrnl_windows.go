//go:build windows

package resource

import (
	"unsafe"

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

// liveUsnJournalSize returns the configured MaximumSize of the USN journal on
// drive C, used as a proxy for the run's total USN journal footprint (journal
// size is normally similar across drives, and querying just one keeps this
// pre-run estimate cheap). Returns 0 if the journal can't be queried (e.g.
// not elevated, or journal not enabled), letting the caller fall back to a
// flat estimate.
func liveUsnJournalSize() int64 {
	volPath, err := windows.UTF16PtrFromString(`\\.\C:`)
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
