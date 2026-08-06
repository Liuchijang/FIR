package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
	"golang.org/x/sys/windows"
)

func init() { module.RegisterAnalyzer(&usnJrnlParser{}) }

const (
	fsctlQueryUsnJournal = 0x000900F4
	fsctlReadUsnJournal  = 0x000900BB
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

type usnJrnlParser struct{}

func (c *usnJrnlParser) Name() string     { return "usnjrnl_parser" }
func (c *usnJrnlParser) Category() string { return "ntfs" }
func (c *usnJrnlParser) Description() string {
	return "Parse USN, enrich with MFT if selected"
}

func (c *usnJrnlParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create USN parser output dir: %w", err))
	}

	sources, sourceErrs := readUSNJournalSources(ctx, req.OutputDir)

	recordMap, pathCache, enriched, err := loadMFTForUSN(ctx, req)
	if err != nil {
		return analyzerError(outDir, err)
	}

	var header []string
	var rows [][]string
	var parseErrs []string
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		h, driveRows, _, _, err := parseUSNJournalRows(src.data, src.drive, recordMap, pathCache, enriched)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", src.drive, err))
			continue
		}
		header = h
		for _, row := range driveRows {
			rows = append(rows, append([]string{src.drive}, row...))
		}
	}
	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no USN records parsed: %s", strings.Join(append(sourceErrs, parseErrs...), "; "))}
	}
	header = append([]string{"Drive"}, header...)

	recordsName := "usnjrnl_records.csv"
	if enriched {
		recordsName = "usnjrnl_mft_enriched.csv"
	}
	recordsInfo, err := writeCSV(filepath.Join(outDir, recordsName), header, rows)
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: []module.FileInfo{recordsInfo}, OutputPath: outDir}
}

type usnJournalSource struct {
	drive string
	data  []byte
}

// readUSNJournalSources loads $UsnJrnl:$J for every drive it can, preferring
// already-collected $UsnJrnl_J_<drive> files, falling back to the legacy
// single-drive filename, and finally to a live read across every fixed drive.
func readUSNJournalSources(ctx context.Context, outputDir string) ([]usnJournalSource, []string) {
	var sources []usnJournalSource
	var errs []string

	if dir, ok := existingModuleDir(outputDir, "usnjrnl"); ok {
		for _, drive := range collectedUSNJournalDrives(dir) {
			path := filepath.Join(dir, "$UsnJrnl_J_"+drive)
			data, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
				continue
			}
			sources = append(sources, usnJournalSource{drive: drive, data: data})
		}
		if len(sources) == 0 {
			if legacyPath := filepath.Join(dir, "$UsnJrnl_J"); fileExists(legacyPath) {
				data, err := os.ReadFile(legacyPath)
				if err != nil {
					errs = append(errs, fmt.Sprintf("C: %v", err))
				} else {
					sources = append(sources, usnJournalSource{drive: "C", data: data})
				}
			}
		}
	}

	if len(sources) == 0 {
		drives, err := acquisition.ListFixedDrives()
		if err != nil || len(drives) == 0 {
			drives = []string{"C"}
		}
		for _, drive := range drives {
			data, err := readLiveUSNJournal(ctx, drive)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
				continue
			}
			sources = append(sources, usnJournalSource{drive: drive, data: data})
		}
	}

	return sources, errs
}

func collectedUSNJournalDrives(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var drives []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if drive, ok := strings.CutPrefix(entry.Name(), "$UsnJrnl_J_"); ok && drive != "" {
			drives = append(drives, drive)
		}
	}
	sort.Strings(drives)
	return drives
}

func readLiveUSNJournal(ctx context.Context, drive string) ([]byte, error) {
	volPath, err := windows.UTF16PtrFromString(`\\.\` + drive + `:`)
	if err != nil {
		return nil, fmt.Errorf("UTF16: %w", err)
	}

	handle, err := windows.CreateFile(volPath, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open volume for USN journal: %w", err)
	}
	defer windows.CloseHandle(handle)

	var journalData usnJournalData
	var bytesReturned uint32
	err = windows.DeviceIoControl(handle, fsctlQueryUsnJournal, nil, 0, (*byte)(unsafe.Pointer(&journalData)), uint32(unsafe.Sizeof(journalData)), &bytesReturned, nil)
	if err != nil {
		return nil, fmt.Errorf("query USN journal: %w", err)
	}

	readData := readUsnJournalData{
		StartUsn:     journalData.FirstUsn,
		ReasonMask:   0xFFFFFFFF,
		UsnJournalID: journalData.UsnJournalID,
	}
	buf := make([]byte, 64*1024)
	payload := make([]byte, 0, 4*1024*1024)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		err = windows.DeviceIoControl(handle, fsctlReadUsnJournal, (*byte)(unsafe.Pointer(&readData)), uint32(unsafe.Sizeof(readData)), &buf[0], uint32(len(buf)), &bytesReturned, nil)
		if err != nil || bytesReturned <= 8 {
			break
		}

		nextUsn := *(*int64)(unsafe.Pointer(&buf[0]))
		payload = append(payload, buf[8:bytesReturned]...)
		readData.StartUsn = nextUsn
	}

	if len(payload) == 0 {
		return nil, fmt.Errorf("live USN journal returned no records")
	}
	return payload, nil
}

func loadMFTForUSN(ctx context.Context, req module.AnalyzeRequest) (mftRowIndex, map[mftKey]string, bool, error) {
	outputDir := req.OutputDir
	shouldEnrich := req.IsSelected("mft") || req.IsSelected("mft_parser")
	if !shouldEnrich {
		return nil, nil, false, nil
	}

	var rows []mftRecordRow
	var parseErrs []string
	if dir, ok := existingModuleDir(outputDir, "mft"); ok {
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
			return nil, nil, false, fmt.Errorf("parse live $MFT for USN enrichment: %w", err)
		}
	}
	if len(rows) == 0 {
		return nil, nil, false, fmt.Errorf("no MFT records available for USN enrichment: %s", strings.Join(parseErrs, "; "))
	}

	// Whole rows, not just parent links: USN enrichment copies name, extension
	// and flags out of the matching MFT record.
	recordMap := make(mftRowIndex, len(rows))
	for _, row := range rows {
		recordMap[mftKey{Drive: row.Drive, Record: row.RecordNumber}] = row
	}
	return recordMap, make(map[mftKey]string, len(recordMap)), true, nil
}

func parseUSNJournalRows(data []byte, drive string, recordMap mftRowIndex, pathCache map[mftKey]string, enriched bool) ([]string, [][]string, int, int, error) {
	header := []string{
		"RecordOffset",
		"RecordLength",
		"MajorVersion",
		"MinorVersion",
		"TimestampUTC",
		"USN",
		"FileReferenceNumber",
		"FileSequenceNumber",
		"ParentReferenceNumber",
		"ParentSequenceNumber",
		"FileName",
		"Reason",
		"ReasonHex",
		"SourceInfo",
		"SourceInfoHex",
		"SecurityId",
		"FileAttributes",
		"FileAttributesHex",
	}
	if enriched {
		header = append(header,
			"ParentPath",
			"FullPath",
			"MFTName",
			"MFTExtension",
			"MFTIsInUse",
			"MFTIsDirectory",
			"MFTAllocatedSize",
			"MFTRealSize",
			"MFT_SI_CreatedUTC",
			"MFT_SI_ModifiedUTC",
			"MFT_SI_MFTModifiedUTC",
			"MFT_SI_AccessedUTC",
			"MFT_FN_CreatedUTC",
			"MFT_FN_ModifiedUTC",
			"MFT_FN_MFTModifiedUTC",
			"MFT_FN_AccessedUTC",
		)
	}

	rows := make([][]string, 0, 1024)
	offset := 0
	parsedCount := 0
	unsupportedCount := 0

	for offset+8 <= len(data) {
		chunkEnd := offset + 16
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}
		if allZero(data[offset:chunkEnd]) {
			break
		}

		recordLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if recordLen <= 8 || offset+recordLen > len(data) {
			return nil, nil, 0, 0, fmt.Errorf("invalid USN record length %d at offset %d", recordLen, offset)
		}

		major := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		minor := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		record := data[offset : offset+recordLen]

		switch major {
		case 2:
			row, ok := parseUSNRecordV2(record, uint64(offset), drive, recordMap, pathCache, enriched)
			if ok {
				rows = append(rows, row)
				parsedCount++
			}
		case 3:
			row, ok := parseUSNRecordV3(record, uint64(offset), enriched)
			if ok {
				rows = append(rows, row)
				parsedCount++
			}
		default:
			_ = minor
			unsupportedCount++
		}

		offset += recordLen
	}

	return header, rows, parsedCount, unsupportedCount, nil
}

func parseUSNRecordV2(record []byte, recordOffset uint64, drive string, recordMap mftRowIndex, pathCache map[mftKey]string, enriched bool) ([]string, bool) {
	if len(record) < 60 {
		return nil, false
	}

	nameLen := int(binary.LittleEndian.Uint16(record[56:58]))
	nameOff := int(binary.LittleEndian.Uint16(record[58:60]))
	if nameOff <= 0 || nameOff+nameLen > len(record) {
		return nil, false
	}

	fileRefRaw := binary.LittleEndian.Uint64(record[8:16])
	parentRefRaw := binary.LittleEndian.Uint64(record[16:24])
	fileRef, fileSeq := parseReference(fileRefRaw)
	parentRef, parentSeq := parseReference(parentRefRaw)
	usn := int64(binary.LittleEndian.Uint64(record[24:32]))
	reason := binary.LittleEndian.Uint32(record[40:44])
	sourceInfo := binary.LittleEndian.Uint32(record[44:48])
	securityID := binary.LittleEndian.Uint32(record[48:52])
	fileAttrs := binary.LittleEndian.Uint32(record[52:56])
	fileName := utf16LEString(record[nameOff : nameOff+nameLen])

	row := []string{
		fmt.Sprintf("%d", recordOffset),
		fmt.Sprintf("%d", len(record)),
		"2",
		fmt.Sprintf("%d", binary.LittleEndian.Uint16(record[6:8])),
		ntfsFiletimeString(binary.LittleEndian.Uint64(record[32:40])),
		fmt.Sprintf("%d", usn),
		fmt.Sprintf("%d", fileRef),
		fmt.Sprintf("%d", fileSeq),
		fmt.Sprintf("%d", parentRef),
		fmt.Sprintf("%d", parentSeq),
		fileName,
		usnReasonString(reason),
		fmt.Sprintf("0x%08X", reason),
		usnSourceInfoString(sourceInfo),
		fmt.Sprintf("0x%08X", sourceInfo),
		fmt.Sprintf("%d", securityID),
		fileAttributesString(fileAttrs),
		fmt.Sprintf("0x%08X", fileAttrs),
	}

	if !enriched {
		return row, true
	}

	parentPath := ""
	fullPath := ""
	mftRow := mftRecordRow{}
	if len(recordMap) > 0 {
		if _, ok := recordMap[mftKey{Drive: drive, Record: parentRef}]; ok {
			parentPath = resolveMFTPath(recordMap, pathCache, drive, parentRef)
		}
		if existing, ok := recordMap[mftKey{Drive: drive, Record: fileRef}]; ok {
			mftRow = existing
			fullPath = resolveMFTPath(recordMap, pathCache, drive, fileRef)
		}
	}
	if fullPath == "" && parentPath != "" {
		fullPath = strings.TrimRight(parentPath, `\`) + `\` + fileName
	}

	row = append(row,
		parentPath,
		fullPath,
		mftRow.Name,
		mftRow.Extension,
		fmt.Sprintf("%t", mftRow.InUse),
		fmt.Sprintf("%t", mftRow.IsDirectory),
		fmt.Sprintf("%d", mftRow.Allocated),
		fmt.Sprintf("%d", mftRow.RealSize),
		mftRow.SICreated,
		mftRow.SIModified,
		mftRow.SIMFTModified,
		mftRow.SIAccessed,
		mftRow.FNCreated,
		mftRow.FNModified,
		mftRow.FNMFTModified,
		mftRow.FNAccessed,
	)
	return row, true
}

func parseUSNRecordV3(record []byte, recordOffset uint64, enriched bool) ([]string, bool) {
	if len(record) < 76 {
		return nil, false
	}

	nameLen := int(binary.LittleEndian.Uint16(record[72:74]))
	nameOff := int(binary.LittleEndian.Uint16(record[74:76]))
	if nameOff <= 0 || nameOff+nameLen > len(record) {
		return nil, false
	}

	usn := int64(binary.LittleEndian.Uint64(record[40:48]))
	reason := binary.LittleEndian.Uint32(record[56:60])
	sourceInfo := binary.LittleEndian.Uint32(record[60:64])
	securityID := binary.LittleEndian.Uint32(record[64:68])
	fileAttrs := binary.LittleEndian.Uint32(record[68:72])
	fileName := utf16LEString(record[nameOff : nameOff+nameLen])

	row := []string{
		fmt.Sprintf("%d", recordOffset),
		fmt.Sprintf("%d", len(record)),
		"3",
		fmt.Sprintf("%d", binary.LittleEndian.Uint16(record[6:8])),
		ntfsFiletimeString(binary.LittleEndian.Uint64(record[48:56])),
		fmt.Sprintf("%d", usn),
		bytesToHex(record[8:24]),
		"",
		bytesToHex(record[24:40]),
		"",
		fileName,
		usnReasonString(reason),
		fmt.Sprintf("0x%08X", reason),
		usnSourceInfoString(sourceInfo),
		fmt.Sprintf("0x%08X", sourceInfo),
		fmt.Sprintf("%d", securityID),
		fileAttributesString(fileAttrs),
		fmt.Sprintf("0x%08X", fileAttrs),
	}

	if enriched {
		row = append(row, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
	}
	return row, true
}

var usnReasonFlags = []maskFlag[uint32]{
	{0x00000001, "DATA_OVERWRITE"},
	{0x00000002, "DATA_EXTEND"},
	{0x00000004, "DATA_TRUNCATION"},
	{0x00000010, "NAMED_DATA_OVERWRITE"},
	{0x00000020, "NAMED_DATA_EXTEND"},
	{0x00000040, "NAMED_DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"},
	{0x00000200, "FILE_DELETE"},
	{0x00000400, "EA_CHANGE"},
	{0x00000800, "SECURITY_CHANGE"},
	{0x00001000, "RENAME_OLD_NAME"},
	{0x00002000, "RENAME_NEW_NAME"},
	{0x00004000, "INDEXABLE_CHANGE"},
	{0x00008000, "BASIC_INFO_CHANGE"},
	{0x00010000, "HARD_LINK_CHANGE"},
	{0x00020000, "COMPRESSION_CHANGE"},
	{0x00040000, "ENCRYPTION_CHANGE"},
	{0x00080000, "OBJECT_ID_CHANGE"},
	{0x00100000, "REPARSE_POINT_CHANGE"},
	{0x00200000, "STREAM_CHANGE"},
	{0x00400000, "TRANSACTED_CHANGE"},
	{0x00800000, "INTEGRITY_CHANGE"},
	{0x80000000, "CLOSE"},
}

func usnReasonString(mask uint32) string { return maskString(mask, usnReasonFlags) }

var usnSourceInfoFlags = []maskFlag[uint32]{
	{0x00000001, "DATA_MANAGEMENT"},
	{0x00000002, "AUXILIARY_DATA"},
	{0x00000004, "REPLICATION_MANAGEMENT"},
}

func usnSourceInfoString(mask uint32) string { return maskString(mask, usnSourceInfoFlags) }

var fileAttributesFlags = []maskFlag[uint32]{
	{0x00000001, "READONLY"},
	{0x00000002, "HIDDEN"},
	{0x00000004, "SYSTEM"},
	{0x00000010, "DIRECTORY"},
	{0x00000020, "ARCHIVE"},
	{0x00000040, "DEVICE"},
	{0x00000080, "NORMAL"},
	{0x00000100, "TEMPORARY"},
	{0x00000200, "SPARSE_FILE"},
	{0x00000400, "REPARSE_POINT"},
	{0x00000800, "COMPRESSED"},
	{0x00001000, "OFFLINE"},
	{0x00002000, "NOT_CONTENT_INDEXED"},
	{0x00004000, "ENCRYPTED"},
	{0x00008000, "INTEGRITY_STREAM"},
	{0x00010000, "VIRTUAL"},
	{0x00020000, "NO_SCRUB_DATA"},
}

func fileAttributesString(mask uint32) string { return maskString(mask, fileAttributesFlags) }

func bytesToHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	for i, value := range data {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fmt.Sprintf("%02X", value))
	}
	return b.String()
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
