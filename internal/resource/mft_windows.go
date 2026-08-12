//go:build windows

package resource

import "github.com/Liuchijang/Tyto/internal/acquisition"

// mftPerDriveFallback is used only for fixed drives whose $MFT size could not be
// measured directly (e.g. access denied to the raw volume), so a multi-drive
// machine isn't silently undercounted just because one volume was unreadable.
const mftPerDriveFallback = 2 * gb

// liveMFTSize sums the actual $MFT valid data length across every fixed drive,
// mirroring what the mft collector will actually copy (CopyMFTToFile reads
// exactly volData.MFTValidDataLength per drive). This is far more accurate than
// a flat guess, since MFT size scales with how many files a volume holds.
func liveMFTSize() int64 {
	drives, err := acquisition.ListFixedDrives()
	if err != nil || len(drives) == 0 {
		return 0
	}

	var total int64
	measured := 0
	for _, drive := range drives {
		vol, err := acquisition.OpenRawVolume(drive)
		if err != nil {
			continue
		}
		volData, err := vol.GetNTFSVolumeData()
		vol.Close()
		if err != nil {
			continue
		}
		total += int64(volData.MFTValidDataLength)
		measured++
	}

	if measured == 0 {
		// Couldn't open any volume (e.g. not running elevated) — fall back to a
		// flat per-drive estimate so multi-drive machines aren't undercounted.
		return int64(len(drives)) * mftPerDriveFallback
	}
	if measured < len(drives) {
		total += int64(len(drives)-measured) * mftPerDriveFallback
	}
	return total
}
