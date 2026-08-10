package analyzers

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/ntfs"
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

	recordMap, pathCache, enriched, err := loadMFTForUSN(ctx, req)
	if err != nil {
		return analyzerError(outDir, err)
	}

	recordsName := "usnjrnl_records.csv"
	if enriched {
		recordsName = "usnjrnl_mft_enriched.csv"
	}
	// Rows stream out as they are parsed. A $UsnJrnl:$J is a volume-sized
	// artifact whose CSV runs several times the size of the binary it came from
	// (see analyzerOutputRatios), and holding every row as [][]string before the
	// first byte reached disk put that whole expansion in memory on top of the
	// journal itself and the MFT index the enrichment needs.
	stream, err := newCSVStream(filepath.Join(outDir, recordsName), usnCSVHeader(enriched))
	if err != nil {
		return analyzerError(outDir, err)
	}

	writer := usnStreamWriter{
		stream:    stream,
		recordMap: recordMap,
		pathCache: pathCache,
		enriched:  enriched,
	}

	var errs []string
	loaded, rows := 0, 0
	for _, src := range collectedUSNJournalSources(req.OutputDir) {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return analyzerError(outDir, err)
		}
		if err := writer.run(src, &loaded, &rows); err != nil {
			if streamFailed(err) {
				stream.Abort()
				return analyzerError(outDir, err)
			}
			errs = append(errs, fmt.Sprintf("%s: %v", src.drive, err))
		}
	}
	// The live journals are read only when no collected one could be opened,
	// which is the same rule the eagerly-loading version applied.
	if loaded == 0 {
		for _, src := range liveUSNJournalSources(ctx) {
			if err := ctx.Err(); err != nil {
				stream.Abort()
				return analyzerError(outDir, err)
			}
			if err := writer.run(src, &loaded, &rows); err != nil {
				if streamFailed(err) {
					stream.Abort()
					return analyzerError(outDir, err)
				}
				errs = append(errs, fmt.Sprintf("%s: %v", src.drive, err))
			}
		}
	}

	if rows == 0 {
		stream.Abort()
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no USN records parsed: %s", strings.Join(errs, "; "))}
	}

	recordsInfo, err := stream.Close()
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: []module.FileInfo{recordsInfo}, OutputPath: outDir}
}

// usnJournalSource names a journal and how to read it. Loading is deferred so a
// multi-drive run holds one journal in memory at a time instead of all of them.
type usnJournalSource struct {
	drive string
	load  func() ([]byte, error)
}

// collectedUSNJournalSources lists this run's collected journals, preferring the
// per-drive filenames and falling back to the legacy single-drive one.
func collectedUSNJournalSources(outputDir string) []usnJournalSource {
	dir, ok := existingModuleDir(outputDir, "usnjrnl")
	if !ok {
		return nil
	}

	var sources []usnJournalSource
	for _, drive := range collectedUSNJournalDrives(dir) {
		path := filepath.Join(dir, "$UsnJrnl_J_"+drive)
		sources = append(sources, usnJournalSource{
			drive: drive,
			load:  func() ([]byte, error) { return os.ReadFile(path) },
		})
	}
	if len(sources) == 0 {
		if legacyPath := filepath.Join(dir, "$UsnJrnl_J"); fileExists(legacyPath) {
			sources = append(sources, usnJournalSource{
				drive: "C",
				load:  func() ([]byte, error) { return os.ReadFile(legacyPath) },
			})
		}
	}
	return sources
}

func liveUSNJournalSources(ctx context.Context) []usnJournalSource {
	drives, err := acquisition.ListFixedDrives()
	if err != nil || len(drives) == 0 {
		drives = []string{"C"}
	}

	sources := make([]usnJournalSource, 0, len(drives))
	for _, drive := range drives {
		sources = append(sources, usnJournalSource{
			drive: drive,
			load:  func() ([]byte, error) { return readLiveUSNJournal(ctx, drive) },
		})
	}
	return sources
}

// usnStreamWriter turns one journal into CSV rows on the open stream.
type usnStreamWriter struct {
	stream    *csvStream
	recordMap mftRowIndex
	pathCache map[mftKey]string
	enriched  bool
}

// run loads one source and appends its rows. loaded counts journals that could
// be read at all — the live fallback keys off it — and rows counts what reached
// the CSV. A journal that loads but does not parse leaves both untouched beyond
// its load, exactly as the discarded per-drive row slice used to.
func (w usnStreamWriter) run(src usnJournalSource, loaded, rows *int) error {
	data, err := src.load()
	if err != nil {
		return err
	}
	*loaded++

	written, err := w.write(data, src.drive)
	*rows += written
	return err
}

func (w usnStreamWriter) write(data []byte, drive string) (int, error) {
	// The whole buffer is validated before a single row is emitted. A malformed
	// record length means the offsets past it are guesses, and a drive that
	// fails this check has always contributed nothing rather than a prefix —
	// streaming must not turn that into a half-written volume.
	if err := walkUSNRecords(data, nil); err != nil {
		return 0, err
	}

	written := 0
	var writeErr error
	_ = walkUSNRecords(data, func(record []byte, offset int, major uint16) {
		if writeErr != nil {
			return
		}
		var row []string
		var ok bool
		switch major {
		case 2:
			row, ok = parseUSNRecordV2(record, uint64(offset), drive, w.recordMap, w.pathCache, w.enriched)
		case 3:
			row, ok = parseUSNRecordV3(record, uint64(offset), w.enriched)
		}
		if !ok {
			return
		}
		if err := w.stream.Write(append([]string{drive}, row...)); err != nil {
			writeErr = errStreamWrite{err}
			return
		}
		written++
	})
	return written, writeErr
}

// errStreamWrite marks a failure of the CSV itself rather than of one journal.
// The first kind is fatal — the output file is already compromised — while the
// second only costs that drive its rows.
type errStreamWrite struct{ err error }

func (e errStreamWrite) Error() string { return e.err.Error() }
func (e errStreamWrite) Unwrap() error { return e.err }

func streamFailed(err error) bool {
	var target errStreamWrite
	return errors.As(err, &target)
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

	rows, parseErrs, err := loadMFTRows(ctx, outputDir)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse live $MFT for USN enrichment: %w", err)
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

// usnCSVHeader is the column list for a journal CSV. Enrichment appends the
// joined-in MFT columns; parseUSNRecordV3 pads the same width with empty values
// because a V3 record carries 128-bit file references that do not index the MFT
// row map.
func usnCSVHeader(enriched bool) []string {
	header := []string{
		"Drive",
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
	return header
}

// walkUSNRecords iterates a $UsnJrnl:$J buffer, calling visit for each record.
// A nil visit validates the record chain without producing anything, which is
// how the writer checks a whole journal before committing any of it to the CSV.
//
// The zero check is the journal's own end marker: $J is a sparse file whose
// unwritten head reads back as zeros, so the first all-zero record header is
// the end of the data rather than a corrupt record.
func walkUSNRecords(data []byte, visit func(record []byte, offset int, major uint16)) error {
	for offset := 0; offset+8 <= len(data); {
		if allZero(data[offset:min(offset+16, len(data))]) {
			return nil
		}

		recordLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if recordLen <= 8 || offset+recordLen > len(data) {
			return fmt.Errorf("invalid USN record length %d at offset %d", recordLen, offset)
		}
		if visit != nil {
			visit(data[offset:offset+recordLen], offset, binary.LittleEndian.Uint16(data[offset+4:offset+6]))
		}
		offset += recordLen
	}
	return nil
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
	fileName := ntfs.UTF16String(record[nameOff : nameOff+nameLen])

	// strconv rather than fmt for the plain integers: this runs once per journal
	// record, and a busy volume's $J holds millions of them.
	row := []string{
		strconv.FormatUint(recordOffset, 10),
		strconv.Itoa(len(record)),
		"2",
		strconv.FormatUint(uint64(binary.LittleEndian.Uint16(record[6:8])), 10),
		formatFiletime(binary.LittleEndian.Uint64(record[32:40]), ""),
		strconv.FormatInt(usn, 10),
		strconv.FormatUint(fileRef, 10),
		strconv.FormatUint(uint64(fileSeq), 10),
		strconv.FormatUint(parentRef, 10),
		strconv.FormatUint(uint64(parentSeq), 10),
		fileName,
		usnReasonString(reason),
		hexMask(reason),
		usnSourceInfoString(sourceInfo),
		hexMask(sourceInfo),
		strconv.FormatUint(uint64(securityID), 10),
		fileAttributesString(fileAttrs),
		hexMask(fileAttrs),
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
		strconv.FormatBool(mftRow.InUse),
		strconv.FormatBool(mftRow.IsDirectory),
		strconv.FormatInt(mftRow.Allocated, 10),
		strconv.FormatInt(mftRow.RealSize, 10),
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
	fileName := ntfs.UTF16String(record[nameOff : nameOff+nameLen])

	row := []string{
		strconv.FormatUint(recordOffset, 10),
		strconv.Itoa(len(record)),
		"3",
		strconv.FormatUint(uint64(binary.LittleEndian.Uint16(record[6:8])), 10),
		formatFiletime(binary.LittleEndian.Uint64(record[48:56]), ""),
		strconv.FormatInt(usn, 10),
		bytesToHex(record[8:24]),
		"",
		bytesToHex(record[24:40]),
		"",
		fileName,
		usnReasonString(reason),
		hexMask(reason),
		usnSourceInfoString(sourceInfo),
		hexMask(sourceInfo),
		strconv.FormatUint(uint64(securityID), 10),
		fileAttributesString(fileAttrs),
		hexMask(fileAttrs),
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

const hexDigits = "0123456789ABCDEF"

// hexMask renders a 32-bit flag word as the CSV's 0xXXXXXXXX form. It is one of
// the per-record hot paths, so it builds the eleven bytes directly rather than
// going through fmt's format parser for every USN record on the volume.
func hexMask(value uint32) string {
	out := []byte("0x00000000")
	for i := 0; i < 8; i++ {
		out[len(out)-1-i] = hexDigits[(value>>(4*i))&0xF]
	}
	return string(out)
}

// bytesToHex renders the 128-bit file references a V3 record carries, as
// space-separated uppercase pairs.
func bytesToHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	out := make([]byte, 0, len(data)*3-1)
	for i, value := range data {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexDigits[value>>4], hexDigits[value&0xF])
	}
	return string(out)
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
