// Package acquisition provides low-level Windows disk and volume access for FIR.
package acquisition

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FSCTL_GET_NTFS_VOLUME_DATA is the IOCTL code to retrieve NTFS volume metadata.
const FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064

// NTFSVolumeData holds key NTFS volume parameters returned by FSCTL_GET_NTFS_VOLUME_DATA.
type NTFSVolumeData struct {
	VolumeSerialNumber           uint64
	NumberSectors                uint64
	TotalClusters                uint64
	FreeClusters                 uint64
	TotalReserved                uint64
	BytesPerSector               uint32
	BytesPerCluster              uint32
	BytesPerFileRecordSegment    uint32
	ClustersPerFileRecordSegment uint32
	MFTValidDataLength           uint64
	MFTStartLCN                  uint64
	MFT2StartLCN                 uint64
	MFTZoneStart                 uint64
	MFTZoneEnd                   uint64
	mftDataRuns                  []DataRun
	mftRealSize                  int64
}

// ntfsVolumeDataRaw is the raw Windows structure matching NTFS_VOLUME_DATA_BUFFER.
type ntfsVolumeDataRaw struct {
	VolumeSerialNumber           int64
	NumberSectors                int64
	TotalClusters                int64
	FreeClusters                 int64
	TotalReserved                int64
	BytesPerSector               uint32
	BytesPerCluster              uint32
	BytesPerFileRecordSegment    uint32
	ClustersPerFileRecordSegment uint32
	MFTValidDataLength           int64
	MFTStartLCN                  int64
	MFT2StartLCN                 int64
	MFTZoneStart                 int64
	MFTZoneEnd                   int64
}

// RawVolume provides sector-aligned read access to a raw Windows volume.
type RawVolume struct {
	handle windows.Handle
	sector uint32
}

type DataRun struct {
	LCN    int64
	Length int64
	Sparse bool
}

type DataAttribute struct {
	Name     string
	StartVCN int64
	RealSize int64
	Runs     []DataRun
}

type FileNameRef struct {
	RecordNumber uint64
	ParentRef    uint64
	Name         string
	IsDirectory  bool
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
		VolumeSerialNumber:           uint64(raw.VolumeSerialNumber),
		NumberSectors:                uint64(raw.NumberSectors),
		TotalClusters:                uint64(raw.TotalClusters),
		FreeClusters:                 uint64(raw.FreeClusters),
		TotalReserved:                uint64(raw.TotalReserved),
		BytesPerSector:               raw.BytesPerSector,
		BytesPerCluster:              raw.BytesPerCluster,
		BytesPerFileRecordSegment:    raw.BytesPerFileRecordSegment,
		ClustersPerFileRecordSegment: raw.ClustersPerFileRecordSegment,
		MFTValidDataLength:           uint64(raw.MFTValidDataLength),
		MFTStartLCN:                  uint64(raw.MFTStartLCN),
		MFT2StartLCN:                 uint64(raw.MFT2StartLCN),
		MFTZoneStart:                 uint64(raw.MFTZoneStart),
		MFTZoneEnd:                   uint64(raw.MFTZoneEnd),
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

func (v *RawVolume) ReadMFTRecord(volData *NTFSVolumeData, recordNumber uint64) ([]byte, error) {
	recordSize := int64(volData.BytesPerFileRecordSegment)
	if recordSize <= 0 {
		return nil, fmt.Errorf("invalid file record size: %d", volData.BytesPerFileRecordSegment)
	}

	if err := v.ensureMFTDataRuns(volData); err != nil {
		return nil, err
	}

	recordOffset := int64(recordNumber) * recordSize
	record, err := v.ReadLogicalFromRuns(volData, volData.mftDataRuns, recordOffset, recordSize)
	if err != nil {
		return nil, fmt.Errorf("read MFT record %d: %w", recordNumber, err)
	}
	if err := applyNTFSFixup(record, int(volData.BytesPerSector)); err != nil {
		return nil, fmt.Errorf("apply fixup record %d: %w", recordNumber, err)
	}
	return record, nil
}

func CopyNamedDataStreamFromMFTRecord(vol *RawVolume, volData *NTFSVolumeData, recordNumber uint64, streamName, outputPath string) (int64, error) {
	attrs, err := collectDataAttributesForRecord(vol, volData, recordNumber, streamName)
	if err != nil {
		return 0, err
	}
	if len(attrs) == 0 {
		return 0, fmt.Errorf("named data stream %s not found", streamName)
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].StartVCN < attrs[j].StartVCN })

	var runs []DataRun
	var realSize int64
	for _, attr := range attrs {
		runs = append(runs, attr.Runs...)
		if attr.RealSize > realSize {
			realSize = attr.RealSize
		}
	}
	return vol.CopyDataRunsToFile(volData, runs, realSize, outputPath)
}

func CopyFileFromRawPath(vol *RawVolume, volData *NTFSVolumeData, path string, outputPath string) (int64, error) {
	recordNumber, err := FindRecordByPath(vol, volData, path)
	if err != nil {
		return 0, err
	}
	attrs, err := collectDataAttributesForRecord(vol, volData, recordNumber, "")
	if err != nil {
		return 0, err
	}
	if len(attrs) == 0 {
		return 0, fmt.Errorf("default data stream not found for %s", path)
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].StartVCN < attrs[j].StartVCN })

	var runs []DataRun
	var realSize int64
	for _, attr := range attrs {
		runs = append(runs, attr.Runs...)
		if attr.RealSize > realSize {
			realSize = attr.RealSize
		}
	}
	return vol.CopyDataRunsToFile(volData, runs, realSize, outputPath)
}

func (v *RawVolume) CopyDataRunsToFile(volData *NTFSVolumeData, runs []DataRun, realSize int64, outputPath string) (int64, error) {
	if err := os.MkdirAll(filepathDir(outputPath), 0o755); err != nil {
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	const chunkSize = 1024 * 1024
	var totalWritten int64
	bytesPerCluster := int64(volData.BytesPerCluster)

	for _, run := range runs {
		runBytes := run.Length * bytesPerCluster
		if remaining := realSize - totalWritten; remaining < runBytes {
			runBytes = remaining
		}
		if runBytes <= 0 {
			break
		}

		if run.Sparse {
			zero := make([]byte, min64(chunkSize, runBytes))
			for written := int64(0); written < runBytes; {
				toWrite := min64(int64(len(zero)), runBytes-written)
				n, err := outFile.Write(zero[:toWrite])
				if err != nil {
					return totalWritten, fmt.Errorf("write sparse run: %w", err)
				}
				written += int64(n)
				totalWritten += int64(n)
			}
			continue
		}

		runOffset := run.LCN * bytesPerCluster
		for consumed := int64(0); consumed < runBytes; {
			toRead := min64(chunkSize, runBytes-consumed)
			buf, err := v.ReadAtOffset(runOffset+consumed, toRead)
			if err != nil {
				return totalWritten, fmt.Errorf("read run at offset %d: %w", runOffset+consumed, err)
			}
			n, err := outFile.Write(buf)
			if err != nil {
				return totalWritten, fmt.Errorf("write output: %w", err)
			}
			consumed += int64(n)
			totalWritten += int64(n)
		}
	}

	return totalWritten, nil
}

func (v *RawVolume) ReadLogicalFromRuns(volData *NTFSVolumeData, runs []DataRun, logicalOffset, size int64) ([]byte, error) {
	if size < 0 || logicalOffset < 0 {
		return nil, fmt.Errorf("invalid logical read request")
	}
	result := make([]byte, size)
	bytesPerCluster := int64(volData.BytesPerCluster)
	runLogicalStart := int64(0)
	written := int64(0)

	for _, run := range runs {
		runBytes := run.Length * bytesPerCluster
		runLogicalEnd := runLogicalStart + runBytes

		if logicalOffset >= runLogicalEnd {
			runLogicalStart = runLogicalEnd
			continue
		}
		if logicalOffset+size <= runLogicalStart {
			break
		}

		segmentStart := max64(logicalOffset, runLogicalStart)
		segmentEnd := min64(logicalOffset+size, runLogicalEnd)
		segmentSize := segmentEnd - segmentStart
		if segmentSize <= 0 {
			runLogicalStart = runLogicalEnd
			continue
		}

		destOffset := segmentStart - logicalOffset
		runOffset := segmentStart - runLogicalStart
		if run.Sparse {
			for i := int64(0); i < segmentSize; i++ {
				result[destOffset+i] = 0
			}
		} else {
			physicalOffset := run.LCN*bytesPerCluster + runOffset
			buf, err := v.ReadAtOffset(physicalOffset, segmentSize)
			if err != nil {
				return nil, err
			}
			copy(result[destOffset:destOffset+segmentSize], buf)
		}

		written += segmentSize
		if written >= size {
			return result, nil
		}
		runLogicalStart = runLogicalEnd
	}

	if written < size {
		return nil, fmt.Errorf("logical read incomplete: requested %d bytes, got %d", size, written)
	}
	return result, nil
}

func (v *RawVolume) ensureMFTDataRuns(volData *NTFSVolumeData) error {
	if len(volData.mftDataRuns) > 0 {
		return nil
	}

	recordSize := int64(volData.BytesPerFileRecordSegment)
	if recordSize <= 0 {
		return fmt.Errorf("invalid file record size: %d", volData.BytesPerFileRecordSegment)
	}

	mftOffset := int64(volData.MFTStartLCN) * int64(volData.BytesPerCluster)
	record0, err := v.ReadAtOffset(mftOffset, recordSize)
	if err != nil {
		return fmt.Errorf("read base MFT record: %w", err)
	}
	if err := applyNTFSFixup(record0, int(volData.BytesPerSector)); err != nil {
		return fmt.Errorf("apply fixup base MFT record: %w", err)
	}

	attrs, err := collectDataAttributesFromRecordWithExtensions(v, volData, record0, 0, "")
	if err != nil {
		return fmt.Errorf("collect MFT data runs: %w", err)
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].StartVCN < attrs[j].StartVCN })

	var runs []DataRun
	var realSize int64
	for _, attr := range attrs {
		runs = append(runs, attr.Runs...)
		if attr.RealSize > realSize {
			realSize = attr.RealSize
		}
	}
	if len(runs) == 0 {
		return fmt.Errorf("no data runs found for $MFT")
	}

	volData.mftDataRuns = runs
	volData.mftRealSize = realSize
	return nil
}

func applyNTFSFixup(record []byte, sectorSize int) error {
	if len(record) < 8 {
		return fmt.Errorf("record too small")
	}
	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))
	if usaOffset <= 0 || usaCount < 2 {
		return fmt.Errorf("invalid update sequence array")
	}
	usaEnd := usaOffset + usaCount*2
	if usaEnd > len(record) {
		return fmt.Errorf("update sequence array out of bounds")
	}

	updateSeq := record[usaOffset : usaOffset+2]
	replacements := record[usaOffset+2 : usaEnd]
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*sectorSize - 2
		replOff := (i - 1) * 2
		if sectorEnd+2 > len(record) || replOff+2 > len(replacements) {
			return fmt.Errorf("fixup index out of bounds")
		}
		if record[sectorEnd] != updateSeq[0] || record[sectorEnd+1] != updateSeq[1] {
			return fmt.Errorf("update sequence mismatch")
		}
		record[sectorEnd] = replacements[replOff]
		record[sectorEnd+1] = replacements[replOff+1]
	}
	return nil
}

func collectDataAttributesForRecord(vol *RawVolume, volData *NTFSVolumeData, recordNumber uint64, streamName string) ([]DataAttribute, error) {
	record, err := vol.ReadMFTRecord(volData, recordNumber)
	if err != nil {
		return nil, err
	}
	return collectDataAttributesFromRecordWithExtensions(vol, volData, record, recordNumber, streamName)
}

func collectDataAttributesFromRecordWithExtensions(vol *RawVolume, volData *NTFSVolumeData, record []byte, recordNumber uint64, streamName string) ([]DataAttribute, error) {
	baseAttrs, attrRefs, err := parseDataAttributes(record)
	if err != nil {
		return nil, err
	}

	var matches []DataAttribute
	for _, attr := range baseAttrs {
		if strings.EqualFold(attr.Name, streamName) {
			matches = append(matches, attr)
		}
	}
	if len(matches) > 0 {
		return matches, nil
	}
	if len(attrRefs) == 0 {
		return nil, fmt.Errorf("named data stream %s not found", streamName)
	}

	seen := map[uint64]struct{}{recordNumber: {}}
	for _, ref := range attrRefs {
		if !strings.EqualFold(ref.Name, streamName) {
			continue
		}
		if _, ok := seen[ref.RecordNumber]; ok {
			continue
		}
		seen[ref.RecordNumber] = struct{}{}

		extRecord, err := vol.ReadMFTRecord(volData, ref.RecordNumber)
		if err != nil {
			return nil, fmt.Errorf("read extension record %d: %w", ref.RecordNumber, err)
		}
		extAttrs, _, err := parseDataAttributes(extRecord)
		if err != nil {
			return nil, fmt.Errorf("parse extension record %d: %w", ref.RecordNumber, err)
		}
		for _, attr := range extAttrs {
			if strings.EqualFold(attr.Name, streamName) {
				matches = append(matches, attr)
			}
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("named data stream %s not found", streamName)
	}
	return matches, nil
}

type attributeListRef struct {
	RecordNumber uint64
	Name         string
}

func parseDataAttributes(record []byte) ([]DataAttribute, []attributeListRef, error) {
	if len(record) < 24 || string(record[:4]) != "FILE" {
		return nil, nil, fmt.Errorf("invalid file record signature")
	}
	attrOff := int(binary.LittleEndian.Uint16(record[20:22]))
	var attrs []DataAttribute
	var attrRefs []attributeListRef
	for attrOff+16 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[attrOff : attrOff+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[attrOff+4 : attrOff+8]))
		if attrLen <= 0 || attrOff+attrLen > len(record) {
			return nil, nil, fmt.Errorf("invalid attribute length")
		}
		attr := record[attrOff : attrOff+attrLen]
		nonResident := attr[8] != 0
		name := attributeName(attr)

		if attrType == 0x80 && nonResident {
			startVCN := int64(binary.LittleEndian.Uint64(attr[16:24]))
			dataRunOff := int(binary.LittleEndian.Uint16(attr[32:34]))
			if dataRunOff <= 0 || dataRunOff >= len(attr) {
				return nil, nil, fmt.Errorf("invalid data run offset")
			}
			realSize := int64(binary.LittleEndian.Uint64(attr[48:56]))
			runs, err := parseDataRuns(attr[dataRunOff:])
			if err != nil {
				return nil, nil, err
			}
			attrs = append(attrs, DataAttribute{
				Name:     name,
				StartVCN: startVCN,
				RealSize: realSize,
				Runs:     runs,
			})
		}

		if attrType == 0x20 && !nonResident {
			contentLen := int(binary.LittleEndian.Uint32(attr[16:20]))
			contentOff := int(binary.LittleEndian.Uint16(attr[20:22]))
			if contentOff <= 0 || contentOff+contentLen > len(attr) {
				return nil, nil, fmt.Errorf("invalid attribute list content")
			}
			refs, err := parseAttributeList(attr[contentOff : contentOff+contentLen])
			if err != nil {
				return nil, nil, err
			}
			attrRefs = append(attrRefs, refs...)
		}
		attrOff += attrLen
	}
	return attrs, attrRefs, nil
}

func parseAttributeList(data []byte) ([]attributeListRef, error) {
	var refs []attributeListRef
	for off := 0; off+26 <= len(data); {
		attrType := binary.LittleEndian.Uint32(data[off : off+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		entryLen := int(binary.LittleEndian.Uint16(data[off+4 : off+6]))
		if entryLen <= 0 || off+entryLen > len(data) {
			return nil, fmt.Errorf("invalid attribute list entry")
		}
		nameLen := int(data[off+6])
		nameOff := int(data[off+7])
		baseRefRaw := binary.LittleEndian.Uint64(data[off+16 : off+24])
		recordNumber := baseRefRaw & 0x0000FFFFFFFFFFFF
		name := ""
		if nameLen > 0 && nameOff > 0 && off+nameOff+nameLen*2 <= len(data) {
			name = windows.UTF16ToString(bytesToUint16(data[off+nameOff : off+nameOff+nameLen*2]))
		}
		if attrType == 0x80 {
			refs = append(refs, attributeListRef{
				RecordNumber: recordNumber,
				Name:         name,
			})
		}
		off += entryLen
	}
	return refs, nil
}

func FindRecordByPath(vol *RawVolume, volData *NTFSVolumeData, path string) (uint64, error) {
	volumePrefix := ""
	if len(path) >= 2 && path[1] == ':' {
		volumePrefix = strings.ToLower(path[:2])
		path = path[2:]
	}
	path = strings.TrimLeft(path, `\/`)
	components := strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
	if len(components) == 0 {
		return 5, nil
	}

	totalRecords := int(volData.MFTValidDataLength / uint64(volData.BytesPerFileRecordSegment))
	wanted := make(map[string]struct{}, len(components))
	for _, component := range components {
		wanted[strings.ToLower(component)] = struct{}{}
	}

	candidates := make(map[string][]FileNameRef)
	for recordNumber := 0; recordNumber < totalRecords; recordNumber++ {
		record, err := vol.ReadMFTRecord(volData, uint64(recordNumber))
		if err != nil || !isRecordInUse(record) {
			continue
		}
		refs, err := parseFileNameRefs(record, uint64(recordNumber))
		if err != nil {
			continue
		}
		for _, ref := range refs {
			lower := strings.ToLower(ref.Name)
			if _, ok := wanted[lower]; ok {
				candidates[lower] = append(candidates[lower], ref)
			}
		}
	}

	parent := uint64(5)
	for idx, component := range components {
		lower := strings.ToLower(component)
		matches := candidates[lower]
		isLast := idx == len(components)-1
		found := false
		for _, ref := range matches {
			if ref.ParentRef != parent {
				continue
			}
			if !isLast && !ref.IsDirectory {
				continue
			}
			parent = ref.RecordNumber
			found = true
			break
		}
		if !found {
			if volumePrefix != "" {
				return 0, fmt.Errorf("path %s:%s not found in MFT", volumePrefix, `\`+strings.Join(components, `\`))
			}
			return 0, fmt.Errorf("path %s not found in MFT", `\`+strings.Join(components, `\`))
		}
	}
	return parent, nil
}

func parseFileNameRefs(record []byte, recordNumber uint64) ([]FileNameRef, error) {
	if len(record) < 24 || string(record[:4]) != "FILE" {
		return nil, fmt.Errorf("invalid file record signature")
	}
	attrOff := int(binary.LittleEndian.Uint16(record[20:22]))
	var refs []FileNameRef
	for attrOff+16 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[attrOff : attrOff+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[attrOff+4 : attrOff+8]))
		if attrLen <= 0 || attrOff+attrLen > len(record) {
			return nil, fmt.Errorf("invalid attribute length")
		}
		attr := record[attrOff : attrOff+attrLen]
		if attrType == 0x30 && attr[8] == 0 {
			contentLen := int(binary.LittleEndian.Uint32(attr[16:20]))
			contentOff := int(binary.LittleEndian.Uint16(attr[20:22]))
			if contentOff <= 0 || contentOff+contentLen > len(attr) || contentLen < 66 {
				attrOff += attrLen
				continue
			}
			content := attr[contentOff : contentOff+contentLen]
			parentRaw := binary.LittleEndian.Uint64(content[0:8])
			parentRef := parentRaw & 0x0000FFFFFFFFFFFF
			flags := binary.LittleEndian.Uint32(content[56:60])
			nameLen := int(content[64])
			if 66+nameLen*2 > len(content) {
				attrOff += attrLen
				continue
			}
			name := windows.UTF16ToString(bytesToUint16(content[66 : 66+nameLen*2]))
			refs = append(refs, FileNameRef{
				RecordNumber: recordNumber,
				ParentRef:    parentRef,
				Name:         name,
				IsDirectory:  flags&0x10000000 != 0,
			})
		}
		attrOff += attrLen
	}
	return refs, nil
}

func isRecordInUse(record []byte) bool {
	if len(record) < 24 || string(record[:4]) != "FILE" {
		return false
	}
	flags := binary.LittleEndian.Uint16(record[22:24])
	return flags&0x0001 != 0
}

func attributeName(attr []byte) string {
	nameLen := int(attr[9])
	nameOff := int(binary.LittleEndian.Uint16(attr[10:12]))
	if nameLen <= 0 || nameOff <= 0 || nameOff+nameLen*2 > len(attr) {
		return ""
	}
	return windows.UTF16ToString(bytesToUint16(attr[nameOff : nameOff+nameLen*2]))
}

func parseDataRuns(data []byte) ([]DataRun, error) {
	var runs []DataRun
	var currentLCN int64

	for i := 0; i < len(data); {
		header := data[i]
		i++
		if header == 0 {
			break
		}

		lenSize := int(header & 0x0F)
		offSize := int(header >> 4)
		if lenSize == 0 || i+lenSize+offSize > len(data) {
			return nil, fmt.Errorf("invalid data run")
		}

		runLen := readSignedLittleEndian(data[i : i+lenSize])
		i += lenSize
		runOff := readSignedLittleEndian(data[i : i+offSize])
		i += offSize

		sparse := offSize == 0
		if !sparse {
			currentLCN += runOff
		}
		runs = append(runs, DataRun{
			LCN:    currentLCN,
			Length: runLen,
			Sparse: sparse,
		})
	}

	return runs, nil
}

func readSignedLittleEndian(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	var value int64
	for i := len(data) - 1; i >= 0; i-- {
		value = (value << 8) | int64(data[i])
	}
	if data[len(data)-1]&0x80 != 0 {
		value -= 1 << (uint(len(data)) * 8)
	}
	return value
}

func bytesToUint16(data []byte) []uint16 {
	out := make([]uint16, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		out[i/2] = binary.LittleEndian.Uint16(data[i : i+2])
	}
	return out
}

func filepathDir(path string) string {
	idx := len(path) - 1
	for idx >= 0 && path[idx] != '\\' && path[idx] != '/' {
		idx--
	}
	if idx <= 0 {
		return "."
	}
	return path[:idx]
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
