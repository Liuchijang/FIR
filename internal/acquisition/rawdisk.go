// Package acquisition provides low-level Windows disk and volume access for FIR.
package acquisition

import (
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FSCTL_GET_NTFS_VOLUME_DATA is the IOCTL code to retrieve NTFS volume metadata.
const FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064

// NTFSVolumeData holds key NTFS volume parameters returned by FSCTL_GET_NTFS_VOLUME_DATA.
type NTFSVolumeData struct {
	VolumeSerialNumber       uint64
	NumberSectors            uint64
	TotalClusters            uint64
	FreeClusters             uint64
	TotalReserved            uint64
	BytesPerSector           uint32
	BytesPerCluster          uint32
	BytesPerFileRecordSegment uint32
	ClustersPerFileRecordSegment uint32
	MFTValidDataLength       uint64
	MFTStartLCN              uint64
	MFT2StartLCN             uint64
	MFTZoneStart             uint64
	MFTZoneEnd               uint64
}

// ntfsVolumeDataRaw is the raw Windows structure matching NTFS_VOLUME_DATA_BUFFER.
type ntfsVolumeDataRaw struct {
	VolumeSerialNumber          int64
	NumberSectors               int64
	TotalClusters               int64
	FreeClusters                int64
	TotalReserved               int64
	BytesPerSector              uint32
	BytesPerCluster             uint32
	BytesPerFileRecordSegment   uint32
	ClustersPerFileRecordSegment uint32
	MFTValidDataLength          int64
	MFTStartLCN                 int64
	MFT2StartLCN                int64
	MFTZoneStart                int64
	MFTZoneEnd                  int64
}

// RawVolume provides sector-aligned read access to a raw Windows volume.
type RawVolume struct {
	handle windows.Handle
	sector uint32
}

// OpenRawVolume opens a raw volume handle for the specified drive letter (e.g., "C").
// Requires administrator privileges.
func OpenRawVolume(driveLetter string) (*RawVolume, error) {
	path := fmt.Sprintf(`\\.\%s:`, driveLetter)
	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	handle, err := windows.CreateFile(
		pathW,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFile(%s): %w", path, err)
	}

	return &RawVolume{
		handle: handle,
		sector: 512, // Default sector size, updated by GetNTFSVolumeData.
	}, nil
}

// Close releases the volume handle.
func (v *RawVolume) Close() error {
	return windows.CloseHandle(v.handle)
}

// GetNTFSVolumeData retrieves NTFS metadata including MFT location and cluster sizes.
func (v *RawVolume) GetNTFSVolumeData() (*NTFSVolumeData, error) {
	var raw ntfsVolumeDataRaw
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		v.handle,
		FSCTL_GET_NTFS_VOLUME_DATA,
		nil,
		0,
		(*byte)(unsafe.Pointer(&raw)),
		uint32(unsafe.Sizeof(raw)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("DeviceIoControl(FSCTL_GET_NTFS_VOLUME_DATA): %w", err)
	}

	v.sector = raw.BytesPerSector

	return &NTFSVolumeData{
		VolumeSerialNumber:          uint64(raw.VolumeSerialNumber),
		NumberSectors:               uint64(raw.NumberSectors),
		TotalClusters:               uint64(raw.TotalClusters),
		FreeClusters:                uint64(raw.FreeClusters),
		TotalReserved:               uint64(raw.TotalReserved),
		BytesPerSector:              raw.BytesPerSector,
		BytesPerCluster:             raw.BytesPerCluster,
		BytesPerFileRecordSegment:   raw.BytesPerFileRecordSegment,
		ClustersPerFileRecordSegment: raw.ClustersPerFileRecordSegment,
		MFTValidDataLength:          uint64(raw.MFTValidDataLength),
		MFTStartLCN:                 uint64(raw.MFTStartLCN),
		MFT2StartLCN:                uint64(raw.MFT2StartLCN),
		MFTZoneStart:                uint64(raw.MFTZoneStart),
		MFTZoneEnd:                  uint64(raw.MFTZoneEnd),
	}, nil
}

// ReadAtOffset reads exactly 'size' bytes from the volume at the given byte offset.
// Reads are sector-aligned as required by Windows raw device access.
func (v *RawVolume) ReadAtOffset(offset int64, size int64) ([]byte, error) {
	sectorSize := int64(v.sector)

	// Align offset down to sector boundary.
	alignedOffset := (offset / sectorSize) * sectorSize
	leadingBytes := offset - alignedOffset

	// Align total read size up to sector boundary.
	totalRead := leadingBytes + size
	if totalRead%sectorSize != 0 {
		totalRead = ((totalRead / sectorSize) + 1) * sectorSize
	}

	// Seek to aligned offset.
	_, err := windows.Seek(v.handle, alignedOffset, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("seek to offset %d: %w", alignedOffset, err)
	}

	// Read sector-aligned buffer.
	buf := make([]byte, totalRead)
	var totalBytesRead uint32
	for totalBytesRead < uint32(totalRead) {
		var n uint32
		remaining := uint32(totalRead) - totalBytesRead
		err := windows.ReadFile(v.handle, buf[totalBytesRead:totalBytesRead+remaining], &n, nil)
		if err != nil {
			return nil, fmt.Errorf("ReadFile at offset %d: %w", alignedOffset+int64(totalBytesRead), err)
		}
		if n == 0 {
			break
		}
		totalBytesRead += n
	}

	// Return only the requested slice from within the aligned buffer.
	return buf[leadingBytes : leadingBytes+size], nil
}

// CopyMFTToFile copies the $MFT from the raw volume to the specified output file.
// Uses NTFS volume data to locate and size the MFT.
func (v *RawVolume) CopyMFTToFile(volData *NTFSVolumeData, outputPath string) (int64, error) {
	mftOffset := int64(volData.MFTStartLCN) * int64(volData.BytesPerCluster)
	mftSize := int64(volData.MFTValidDataLength)

	// Seek to MFT start.
	_, err := windows.Seek(v.handle, mftOffset, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("seek to MFT offset %d: %w", mftOffset, err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("create MFT output file: %w", err)
	}
	defer outFile.Close()

	sectorSize := int64(v.sector)
	bufSize := sectorSize * 1024 // Read 512KB chunks (1024 sectors).
	buf := make([]byte, bufSize)

	var totalWritten int64
	remaining := mftSize

	for remaining > 0 {
		readSize := bufSize
		if int64(readSize) > remaining {
			// Round up to sector boundary.
			readSize = ((remaining + sectorSize - 1) / sectorSize) * sectorSize
		}

		var n uint32
		err := windows.ReadFile(v.handle, buf[:readSize], &n, nil)
		if err != nil {
			return totalWritten, fmt.Errorf("read MFT data: %w", err)
		}
		if n == 0 {
			break
		}

		// Write only the valid portion (not padding).
		writeSize := int64(n)
		if writeSize > remaining {
			writeSize = remaining
		}

		written, err := outFile.Write(buf[:writeSize])
		if err != nil {
			return totalWritten, fmt.Errorf("write MFT data: %w", err)
		}
		totalWritten += int64(written)
		remaining -= int64(written)
	}

	return totalWritten, nil
}
