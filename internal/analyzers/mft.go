package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
)

const (
	mftRecordSize      = 1024
	ntfsWindowsEpochNs = 116444736000000000
)

const (
	attrTypeStandardInformation = 0x10
	attrTypeFileName            = 0x30
	attrTypeData                = 0x80
)

func init() { module.RegisterAnalyzer(&mftParser{}) }

type mftParser struct{}

type mftRecordRow struct {
	Drive             string
	RecordNumber      uint64
	Sequence          uint16
	HardLinkCount     uint16
	InUse             bool
	IsDirectory       bool
	ParentRef         uint64
	ParentSequence    uint16
	Name              string
	ShortName         string
	NameNamespace     string
	Extension         string
	FullPath          string
	SICreated         string
	SIModified        string
	SIMFTModified     string
	SIAccessed        string
	FNCreated         string
	FNModified        string
	FNMFTModified     string
	FNAccessed        string
	Allocated         int64
	RealSize          int64
	ResidentData      bool
	HasAlternateData  bool
	UnnamedDataStream bool
}

type fileNameAttribute struct {
	ParentRef      uint64
	ParentSequence uint16
	Name           string
	Namespace      byte
	Created        string
	Modified       string
	MFTModified    string
	Accessed       string
	Allocated      int64
	RealSize       int64
	Directory      bool
}

func (c *mftParser) Name() string     { return "mft_parser" }
func (c *mftParser) Category() string { return "ntfs" }
func (c *mftParser) Description() string {
	return "Parse $MFT to full CSV"
}

func (c *mftParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create MFT parser output dir: %w", err))
	}

	var rows []mftRecordRow
	var parseErrs []string
	if dir, ok := existingModuleDir(req.OutputDir, "mft"); ok {
		for _, drive := range collectedMFTDrives(dir) {
			mftPath := filepath.Join(dir, "$MFT_"+drive)
			driveRows, err := parseCollectedMFT(ctx, mftPath)
			if err != nil {
				parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", drive, err))
				continue
			}
			for i := range driveRows {
				driveRows[i].Drive = drive
			}
			rows = append(rows, driveRows...)
		}
		if len(rows) == 0 {
			// Fall back to the legacy single-drive filename for older collection runs.
			if legacyPath := filepath.Join(dir, "$MFT"); fileExists(legacyPath) {
				legacyRows, err := parseCollectedMFT(ctx, legacyPath)
				if err != nil {
					parseErrs = append(parseErrs, fmt.Sprintf("C: %v", err))
				} else {
					for i := range legacyRows {
						legacyRows[i].Drive = "C"
					}
					rows = append(rows, legacyRows...)
				}
			}
		}
	}
	if len(rows) == 0 {
		var err error
		rows, err = parseLiveMFT(ctx)
		if err != nil {
			return analyzerError(outDir, err)
		}
	}
	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no MFT records parsed: %s", strings.Join(parseErrs, "; "))}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Drive != rows[j].Drive {
			return rows[i].Drive < rows[j].Drive
		}
		return rows[i].RecordNumber < rows[j].RecordNumber
	})
	// Only name and parent are needed to resolve paths, so the index is built
	// from those two fields rather than from whole rows.
	links := make(mftLinkIndex, len(rows))
	for _, row := range rows {
		links[mftKey{Drive: row.Drive, Record: row.RecordNumber}] = mftParentLink{
			Name:      row.Name,
			ParentRef: row.ParentRef,
		}
	}

	// Rows go out as they are resolved. Collecting them into a [][]string first
	// meant a third full-size copy of the volume's file table, on top of the
	// records themselves and the index.
	stream, err := newCSVStream(filepath.Join(outDir, "mft_records.csv"), mftCSVHeader)
	if err != nil {
		return analyzerError(outDir, err)
	}
	pathCache := make(map[mftKey]string, len(rows))
	for i := range rows {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return analyzerError(outDir, err)
		}
		rows[i].FullPath = resolveMFTPath(links, pathCache, rows[i].Drive, rows[i].RecordNumber)
		if err := stream.Write(mftCSVRow(rows[i])); err != nil {
			stream.Abort()
			return analyzerError(outDir, err)
		}
	}

	fi, err := stream.Close()
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: []module.FileInfo{fi}, OutputPath: outDir}
}

var mftCSVHeader = []string{
	"Drive",
	"RecordNumber",
	"SequenceNumber",
	"HardLinkCount",
	"IsInUse",
	"IsDirectory",
	"ParentRecordNumber",
	"ParentSequenceNumber",
	"FileName",
	"ShortFileName",
	"NameNamespace",
	"Extension",
	"FullPath",
	"SI_CreatedUTC",
	"SI_ModifiedUTC",
	"SI_MFTModifiedUTC",
	"SI_AccessedUTC",
	"FN_CreatedUTC",
	"FN_ModifiedUTC",
	"FN_MFTModifiedUTC",
	"FN_AccessedUTC",
	"AllocatedSize",
	"RealSize",
	"ResidentData",
	"HasUnnamedData",
	"HasAlternateDataStreams",
}

func mftCSVRow(row mftRecordRow) []string {
	return []string{
		row.Drive,
		strconv.FormatUint(row.RecordNumber, 10),
		strconv.FormatUint(uint64(row.Sequence), 10),
		strconv.FormatUint(uint64(row.HardLinkCount), 10),
		strconv.FormatBool(row.InUse),
		strconv.FormatBool(row.IsDirectory),
		strconv.FormatUint(row.ParentRef, 10),
		strconv.FormatUint(uint64(row.ParentSequence), 10),
		row.Name,
		row.ShortName,
		row.NameNamespace,
		row.Extension,
		row.FullPath,
		row.SICreated,
		row.SIModified,
		row.SIMFTModified,
		row.SIAccessed,
		row.FNCreated,
		row.FNModified,
		row.FNMFTModified,
		row.FNAccessed,
		strconv.FormatInt(row.Allocated, 10),
		strconv.FormatInt(row.RealSize, 10),
		strconv.FormatBool(row.ResidentData),
		strconv.FormatBool(row.UnnamedDataStream),
		strconv.FormatBool(row.HasAlternateData),
	}
}

// parseCollectedMFT reads the artifact in fixed batches instead of slurping it
// whole. A $MFT is routinely several gigabytes, and os.ReadFile made the file
// the single largest allocation in a run — larger than the parsed records it
// was there to produce.
func parseCollectedMFT(ctx context.Context, path string) ([]mftRecordRow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read collected $MFT: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat collected $MFT: %w", err)
	}

	totalRecords := int(info.Size() / mftRecordSize)
	rows := make([]mftRecordRow, 0, totalRecords)

	const batchRecords = 1024
	batch := make([]byte, batchRecords*mftRecordSize)

	for i := 0; i < totalRecords; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		count := min(batchRecords, totalRecords-i)
		if _, err := io.ReadFull(file, batch[:count*mftRecordSize]); err != nil {
			return nil, fmt.Errorf("read collected $MFT: %w", err)
		}

		for j := 0; j < count; j++ {
			record := batch[j*mftRecordSize : (j+1)*mftRecordSize]
			if string(record[:4]) != "FILE" {
				continue
			}
			// applyMFTFixup rewrites the record in place and the parsed row can
			// alias what it is handed, so each record is copied out of the
			// batch buffer before it is reused by the next read.
			record = append([]byte(nil), record...)
			if err := applyMFTFixup(record); err != nil {
				continue
			}

			row, ok, err := parseMFTRecord(record, uint64(i+j))
			if err != nil {
				return nil, err
			}
			if ok {
				rows = append(rows, row)
			}
		}
		i += count
	}

	return rows, nil
}

func parseLiveMFT(ctx context.Context) ([]mftRecordRow, error) {
	drives, err := acquisition.ListFixedDrives()
	if err != nil || len(drives) == 0 {
		drives = []string{"C"}
	}

	var rows []mftRecordRow
	var errs []string
	for _, drive := range drives {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		driveRows, err := parseLiveMFTForDrive(ctx, drive)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
			continue
		}
		rows = append(rows, driveRows...)
	}

	if len(rows) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("live MFT parse failed for all drives: %s", strings.Join(errs, "; "))
	}
	return rows, nil
}

func parseLiveMFTForDrive(ctx context.Context, drive string) ([]mftRecordRow, error) {
	vol, err := acquisition.OpenRawVolume(drive)
	if err != nil {
		return nil, fmt.Errorf("open raw volume for live MFT parse: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return nil, fmt.Errorf("get NTFS volume data: %w", err)
	}

	const liveMFTBatchRecords = 8192
	totalRecords := int(volData.MFTValidDataLength / uint64(volData.BytesPerFileRecordSegment))
	rows := make([]mftRecordRow, 0, totalRecords)

	appendRow := func(record []byte, recordNumber uint64) error {
		if len(record) < 4 || string(record[:4]) != "FILE" {
			return nil
		}
		row, ok, err := parseMFTRecord(record, recordNumber)
		if err != nil {
			return err
		}
		if ok {
			row.Drive = drive
			rows = append(rows, row)
		}
		return nil
	}

	for start := 0; start < totalRecords; start += liveMFTBatchRecords {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		count := liveMFTBatchRecords
		if start+count > totalRecords {
			count = totalRecords - start
		}

		records, err := vol.ReadMFTRecordsBatch(volData, uint64(start), count)
		if err != nil {
			// Fall back to one-at-a-time reads for this batch rather than
			// aborting the whole live parse.
			for i := 0; i < count; i++ {
				recordNumber := uint64(start + i)
				record, err := vol.ReadMFTRecord(volData, recordNumber)
				if err != nil {
					continue
				}
				if err := appendRow(record, recordNumber); err != nil {
					return nil, err
				}
			}
			continue
		}

		for i, record := range records {
			if record == nil {
				continue
			}
			if err := appendRow(record, uint64(start+i)); err != nil {
				return nil, err
			}
		}
	}

	return rows, nil
}

func collectedMFTDrives(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var drives []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if drive, ok := strings.CutPrefix(name, "$MFT_"); ok && drive != "" {
			drives = append(drives, drive)
		}
	}
	sort.Strings(drives)
	return drives
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func applyMFTFixup(record []byte) error {
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

	sectorSize := 512
	if sectors := usaCount - 1; sectors > 0 && len(record)%sectors == 0 {
		sectorSize = len(record) / sectors
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

func parseMFTRecord(record []byte, recordNumber uint64) (mftRecordRow, bool, error) {
	if len(record) < 24 || string(record[:4]) != "FILE" {
		return mftRecordRow{}, false, nil
	}

	row := mftRecordRow{
		RecordNumber:  recordNumber,
		Sequence:      binary.LittleEndian.Uint16(record[16:18]),
		HardLinkCount: binary.LittleEndian.Uint16(record[18:20]),
		InUse:         binary.LittleEndian.Uint16(record[22:24])&0x0001 != 0,
		IsDirectory:   binary.LittleEndian.Uint16(record[22:24])&0x0002 != 0,
	}

	attrOff := int(binary.LittleEndian.Uint16(record[20:22]))
	fileNames := make([]fileNameAttribute, 0, 2)

	for attrOff+16 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[attrOff : attrOff+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[attrOff+4 : attrOff+8]))
		if attrLen <= 0 || attrOff+attrLen > len(record) {
			return mftRecordRow{}, false, fmt.Errorf("invalid attribute length in record %d", recordNumber)
		}

		attr := record[attrOff : attrOff+attrLen]
		nonResident := attr[8] != 0
		attrName := attributeName(attr)

		switch attrType {
		case attrTypeStandardInformation:
			content, ok := residentContent(attr)
			if ok && len(content) >= 32 {
				row.SICreated = ntfsFiletimeString(binary.LittleEndian.Uint64(content[0:8]))
				row.SIModified = ntfsFiletimeString(binary.LittleEndian.Uint64(content[8:16]))
				row.SIMFTModified = ntfsFiletimeString(binary.LittleEndian.Uint64(content[16:24]))
				row.SIAccessed = ntfsFiletimeString(binary.LittleEndian.Uint64(content[24:32]))
			}

		case attrTypeFileName:
			content, ok := residentContent(attr)
			if ok {
				fn, parsed := parseFileNameAttribute(content)
				if parsed {
					fileNames = append(fileNames, fn)
				}
			}

		case attrTypeData:
			if attrName != "" {
				row.HasAlternateData = true
			}
			if attrName == "" {
				row.UnnamedDataStream = true
				if nonResident {
					if len(attr) >= 56 {
						row.Allocated = int64(binary.LittleEndian.Uint64(attr[40:48]))
						row.RealSize = int64(binary.LittleEndian.Uint64(attr[48:56]))
					}
				} else {
					content, ok := residentContent(attr)
					if ok {
						row.ResidentData = true
						row.RealSize = int64(len(content))
						row.Allocated = int64(len(content))
					}
				}
			}
		}

		attrOff += attrLen
	}

	bestFN, shortFN, ok := selectBestFileNames(fileNames)
	if ok {
		row.ParentRef = bestFN.ParentRef
		row.ParentSequence = bestFN.ParentSequence
		row.Name = bestFN.Name
		row.NameNamespace = namespaceLabel(bestFN.Namespace)
		row.FNCreated = bestFN.Created
		row.FNModified = bestFN.Modified
		row.FNMFTModified = bestFN.MFTModified
		row.FNAccessed = bestFN.Accessed
		row.IsDirectory = row.IsDirectory || bestFN.Directory
		if row.Allocated == 0 {
			row.Allocated = bestFN.Allocated
		}
		if row.RealSize == 0 {
			row.RealSize = bestFN.RealSize
		}
		if shortFN.Name != "" && shortFN.Name != bestFN.Name {
			row.ShortName = shortFN.Name
		}
	}

	if row.Name == "" {
		row.Name = fmt.Sprintf("record_%d", recordNumber)
	}
	row.Extension = fileExtension(row.Name, row.IsDirectory)
	return row, true, nil
}

func residentContent(attr []byte) ([]byte, bool) {
	if len(attr) < 24 || attr[8] != 0 {
		return nil, false
	}

	contentLen := int(binary.LittleEndian.Uint32(attr[16:20]))
	contentOff := int(binary.LittleEndian.Uint16(attr[20:22]))
	if contentOff <= 0 || contentOff+contentLen > len(attr) {
		return nil, false
	}
	return attr[contentOff : contentOff+contentLen], true
}

func parseFileNameAttribute(content []byte) (fileNameAttribute, bool) {
	if len(content) < 66 {
		return fileNameAttribute{}, false
	}

	parentRef, parentSeq := parseReference(binary.LittleEndian.Uint64(content[0:8]))
	nameLen := int(content[64])
	if 66+nameLen*2 > len(content) {
		return fileNameAttribute{}, false
	}

	flags := binary.LittleEndian.Uint32(content[56:60])
	return fileNameAttribute{
		ParentRef:      parentRef,
		ParentSequence: parentSeq,
		Name:           utf16LEString(content[66 : 66+nameLen*2]),
		Namespace:      content[65],
		Created:        ntfsFiletimeString(binary.LittleEndian.Uint64(content[8:16])),
		Modified:       ntfsFiletimeString(binary.LittleEndian.Uint64(content[16:24])),
		MFTModified:    ntfsFiletimeString(binary.LittleEndian.Uint64(content[24:32])),
		Accessed:       ntfsFiletimeString(binary.LittleEndian.Uint64(content[32:40])),
		Allocated:      int64(binary.LittleEndian.Uint64(content[40:48])),
		RealSize:       int64(binary.LittleEndian.Uint64(content[48:56])),
		Directory:      flags&0x10000000 != 0,
	}, true
}

func parseReference(raw uint64) (uint64, uint16) {
	return raw & 0x0000FFFFFFFFFFFF, uint16(raw >> 48)
}

func selectBestFileNames(fileNames []fileNameAttribute) (fileNameAttribute, fileNameAttribute, bool) {
	if len(fileNames) == 0 {
		return fileNameAttribute{}, fileNameAttribute{}, false
	}

	sort.SliceStable(fileNames, func(i, j int) bool {
		return namespaceRank(fileNames[i].Namespace) > namespaceRank(fileNames[j].Namespace)
	})

	best := fileNames[0]
	short := fileNameAttribute{}
	for _, fn := range fileNames {
		if fn.Namespace == 2 {
			short = fn
			break
		}
	}
	return best, short, true
}

func namespaceRank(ns byte) int {
	switch ns {
	case 3:
		return 4
	case 1:
		return 3
	case 0:
		return 2
	case 2:
		return 1
	default:
		return 0
	}
}

func namespaceLabel(ns byte) string {
	switch ns {
	case 0:
		return "POSIX"
	case 1:
		return "Win32"
	case 2:
		return "DOS"
	case 3:
		return "Win32+DOS"
	default:
		return fmt.Sprintf("Unknown(%d)", ns)
	}
}

func attributeName(attr []byte) string {
	if len(attr) < 12 {
		return ""
	}
	nameLen := int(attr[9])
	nameOff := int(binary.LittleEndian.Uint16(attr[10:12]))
	if nameLen <= 0 || nameOff <= 0 || nameOff+nameLen*2 > len(attr) {
		return ""
	}
	return utf16LEString(attr[nameOff : nameOff+nameLen*2])
}

func fileExtension(name string, isDirectory bool) string {
	if isDirectory {
		return ""
	}
	ext := filepath.Ext(name)
	if ext == "." {
		return ""
	}
	return strings.ToLower(ext)
}

// mftKey uniquely identifies an MFT record across drives: record numbers are
// only unique within a single volume, so resolving paths across multiple
// collected drives requires scoping every lookup by drive letter as well.
type mftKey struct {
	Drive  string
	Record uint64
}

// mftPathSource supplies the only two fields path resolution needs. It exists
// so each caller can keep the record representation it already has: mft_parser
// holds a compact name/parent index, while usnjrnl_parser needs whole rows for
// enrichment and would otherwise have to carry a second copy of them.
type mftPathSource interface {
	parentLink(key mftKey) (name string, parent uint64, ok bool)
}

// mftParentLink is the compact form. A full mftRecordRow is 27 fields wide, and
// indexing several million of them by value doubled the parser's peak memory
// for the sake of two of those fields.
type mftParentLink struct {
	Name      string
	ParentRef uint64
}

type mftLinkIndex map[mftKey]mftParentLink

func (m mftLinkIndex) parentLink(key mftKey) (string, uint64, bool) {
	link, ok := m[key]
	return link.Name, link.ParentRef, ok
}

type mftRowIndex map[mftKey]mftRecordRow

func (m mftRowIndex) parentLink(key mftKey) (string, uint64, bool) {
	row, ok := m[key]
	return row.Name, row.ParentRef, ok
}

func resolveMFTPath(records mftPathSource, cache map[mftKey]string, drive string, recordNumber uint64) string {
	key := mftKey{Drive: drive, Record: recordNumber}
	if cached, ok := cache[key]; ok {
		return cached
	}

	name, parentRef, ok := records.parentLink(key)
	if !ok {
		return fmt.Sprintf(`\record_%d`, recordNumber)
	}
	// Seed the cache before descending so a cyclic parent chain in a corrupt $MFT
	// terminates instead of recursing until the stack overflows. The real path
	// overwrites this below.
	cache[key] = fmt.Sprintf(`\record_%d`, recordNumber)
	if recordNumber == 5 {
		cache[key] = `\`
		return `\`
	}
	if parentRef == 0 || parentRef == recordNumber {
		path := `\` + name
		cache[key] = path
		return path
	}

	parent := resolveMFTPath(records, cache, drive, parentRef)
	if parent == `\` {
		cache[key] = parent + name
		return parent + name
	}
	path := strings.TrimRight(parent, `\`) + `\` + name
	cache[key] = path
	return path
}

func utf16LEString(data []byte) string {
	values := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		value := binary.LittleEndian.Uint16(data[i : i+2])
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return string(utf16.Decode(values))
}

func ntfsFiletimeString(value uint64) string {
	if value == 0 || value < ntfsWindowsEpochNs {
		return ""
	}
	unix100ns := int64(value - ntfsWindowsEpochNs)
	return time.Unix(0, unix100ns*100).UTC().Format(time.RFC3339)
}
