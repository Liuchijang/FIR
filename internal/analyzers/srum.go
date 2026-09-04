package analyzers

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
	"github.com/Velocidex/ordereddict"
	ese "www.velocidex.com/golang/go-ese/parser"
)

func init() { module.RegisterAnalyzer(&srumParser{}) }

type srumParser struct{ offlineCapable }

func (c *srumParser) Name() string     { return "srum_parser" }
func (c *srumParser) Category() string { return "system" }
func (c *srumParser) Description() string {
	return "Parse SRUM, enrich with registry if selected"
}

// srumDatabaseName is the file the collector writes and the name the live
// database has on disk.
const srumDatabaseName = "SRUDB.dat"

func (c *srumParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create SRUM parser output dir: %w", err))
	}

	dbPath, cleanup, err := resolveSRUMDatabase(req, outDir)
	if err != nil {
		if errors.Is(err, errNoCollectedSource) {
			return skippedNoSource(outDir, "collected "+srumDatabaseName)
		}
		return analyzerError(outDir, err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	file, err := os.Open(dbPath)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("open %s: %w", srumDatabaseName, err))
	}
	defer file.Close()

	// The ESE reader walks the B-tree straight off the file and never replays a
	// transaction log, which is what lets it read the copy a live collection made
	// while the SRUM service still had the database open.
	eseCtx, err := ese.NewESEContext(file)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("read ESE header of %s: %w", srumDatabaseName, err))
	}
	catalog, err := ese.ReadCatalog(eseCtx)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("read ESE catalog of %s: %w", srumDatabaseName, err))
	}

	ids, err := loadSRUMIDMap(catalog)
	if err != nil {
		// Without the ID map every AppId and UserId stays a bare integer. That is
		// a degraded export rather than no export, so the tables are still
		// written and the failure is surfaced as a warning.
		ids = nil
	}
	idMapErr := err

	// Unconditional, unlike usnjrnl_parser's $MFT enrichment: that one is gated
	// on the collector being selected because parsing a live $MFT costs minutes,
	// whereas reading WlanSvc's profile list is a handful of registry opens. The
	// collected SOFTWARE hive is preferred and the live one is the fallback.
	exporter := srumExporter{
		catalog:   catalog,
		ids:       ids,
		wlan:      loadSRUMWLANProfiles(req),
		providers: loadSRUMProviderNames(req),
	}

	var files []module.FileInfo
	var errs []string
	if idMapErr != nil {
		errs = append(errs, idMapErr.Error())
	}
	for _, table := range srumProviderTables(catalog) {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		fi, rows, err := exporter.export(ctx, outDir, table)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", table, err))
			continue
		}
		if rows == 0 {
			// An empty provider table is normal — a desktop reports no battery
			// usage — and an empty CSV in the output is noise, not evidence.
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no SRUM tables parsed: %s", strings.Join(errs, "; "))}
	}
	result := module.AnalyzeResult{Files: files, OutputPath: outDir}
	if len(errs) > 0 {
		result.Error = fmt.Sprintf("parsed %d SRUM table(s) with %d failure(s): %s", len(files), len(errs), strings.Join(errs, "; "))
	}
	return result
}

// resolveSRUMDatabase prefers this run's collected SRUDB.dat and otherwise
// stages a copy of the live one.
//
// The live database cannot simply be opened: the SRUM service holds it without
// sharing writes, so a read needs the same copy fallbacks the collector uses.
// The staged copy goes under the analyzer's own output directory rather than the
// machine's temp directory, because the subject volume is evidence.
func resolveSRUMDatabase(req module.AnalyzeRequest, outDir string) (string, func(), error) {
	dir, live, err := resolveArtifactSource(req, "srum")
	if err != nil {
		return "", nil, err
	}
	if !live {
		collected := filepath.Join(dir, srumDatabaseName)
		if _, err := os.Stat(collected); err != nil {
			return "", nil, errNoCollectedSource
		}
		return collected, nil, nil
	}

	livePath := filepath.Join(platform.SystemRoot(), "System32", "sru", srumDatabaseName)
	if _, err := os.Stat(livePath); err != nil {
		return "", nil, fmt.Errorf("no collected %s and no live database: %w", srumDatabaseName, err)
	}

	stageDir, err := os.MkdirTemp(outDir, "srum-stage-")
	if err != nil {
		return "", nil, fmt.Errorf("create SRUM staging dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stageDir) }

	staged := filepath.Join(stageDir, srumDatabaseName)
	if _, err := utils.SafeCopyFile(livePath, staged); err == nil {
		return staged, cleanup, nil
	}
	if _, err := utils.SafeCopyFileBackup(livePath, staged); err == nil {
		return staged, cleanup, nil
	}
	cleanup()
	return "", nil, fmt.Errorf("stage live %s: the SRUM service holds it open and neither copy path succeeded", srumDatabaseName)
}

// srumProviderTables lists the data-provider tables in a stable order. ESE
// bookkeeping and the ID map are excluded; anything else is exported even when
// its GUID is unrecognised.
func srumProviderTables(catalog *ese.Catalog) []string {
	var tables []string
	for _, name := range catalog.Tables.Keys() {
		if srumInternalTables[name] {
			continue
		}
		tables = append(tables, name)
	}
	sort.Strings(tables)
	return tables
}

type srumExporter struct {
	catalog *ese.Catalog
	ids     srumIDMap
	wlan    srumWLANProfiles
	// providers names the tables this file does not name itself, read from
	// Windows' own SRUM registration.
	providers map[string]string
}

// export writes one provider table and reports how many rows it held.
func (e srumExporter) export(ctx context.Context, outDir, table string) (module.FileInfo, int, error) {
	columns, err := srumTableColumns(e.catalog, table)
	if err != nil {
		return module.FileInfo{}, 0, err
	}

	// The header comes from the catalog, not from the first row. Tagged columns
	// are absent from rows that never set them, so a header derived from row one
	// would shift every later row's values into the wrong columns.
	computed := srumComputedColumns[strings.ToUpper(table)]
	header := make([]string, 0, len(columns)+8)
	for _, column := range columns {
		header = append(header, srumColumnHeader(column))
		header = append(header, srumDerivedColumns(column)...)
	}
	for _, extra := range computed {
		header = append(header, extra.name)
	}

	path := filepath.Join(outDir, srumTableFileName(table, e.providers))
	stream, err := newCSVStream(path, header)
	if err != nil {
		return module.FileInfo{}, 0, err
	}

	rows := 0
	var writeErr error
	walkErr := e.catalog.DumpTable(table, func(row *ordereddict.Dict) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		record := make([]string, 0, len(header))
		for _, column := range columns {
			value, _ := row.Get(column)
			record = append(record, srumFormatValue(column, value))
			record = append(record, e.deriveValues(column, row)...)
		}
		for _, extra := range computed {
			record = append(record, extra.compute(row))
		}
		if err := stream.Write(record); err != nil {
			writeErr = err
			return err
		}
		rows++
		return nil
	})
	if writeErr != nil {
		stream.Abort()
		return module.FileInfo{}, 0, writeErr
	}
	if walkErr != nil {
		stream.Abort()
		return module.FileInfo{}, 0, walkErr
	}
	if rows == 0 {
		stream.Abort()
		return module.FileInfo{}, 0, nil
	}

	fi, err := stream.Close()
	if err != nil {
		return module.FileInfo{}, 0, err
	}
	return fi, rows, nil
}

// srumDerivedColumns names the resolved companion each translatable column gets.
//
// The raw value is kept alongside it rather than replaced: the integer is what
// the artifact actually contains, and an analyst has to be able to see it to
// verify the resolution or to correlate against another tool's output.
func srumDerivedColumns(column string) []string {
	switch column {
	case "AppId":
		return []string{"AppIdResolved"}
	case "UserId":
		return []string{"UserIdResolved"}
	case "InterfaceLuid":
		return []string{"InterfaceType"}
	case "L2ProfileId":
		return []string{"L2ProfileName"}
	}
	if srumSecondsColumns[column] {
		return []string{srumColumnHeader(column) + "Duration"}
	}
	return nil
}

// srumComputedColumn is a value derived from several columns of the same row,
// appended after the table's own columns.
type srumComputedColumn struct {
	name    string
	compute func(row *ordereddict.Dict) string
}

// srumComputedColumns are the joins an analyst would otherwise do by hand.
//
// srum-dump supplies both as Excel formulas; in this run's workbook the stop-time
// formula evaluated to 00:00:00 for every row, so the value is computed here
// instead of being emitted as a spreadsheet expression a CSV cannot carry anyway.
var srumComputedColumns = map[string][]srumComputedColumn{
	srumNetworkDataUsageTable: {
		{name: "TotalBytes", compute: srumTotalBytes},
	},
	srumNetworkConnectivityable: {
		{name: "ConnectStopTimeUTC", compute: srumConnectStopTime},
	},
}

// srumTotalBytes is the sent-plus-received figure the network table is almost
// always sorted on.
func srumTotalBytes(row *ordereddict.Dict) string {
	sent, sentOK := srumUint64(row, "BytesSent")
	received, receivedOK := srumUint64(row, "BytesRecvd")
	if !sentOK && !receivedOK {
		return ""
	}
	return strconv.FormatUint(sent+received, 10)
}

// srumConnectStopTime is when a network session ended: SRUM records only its
// start and how long it lasted, so "was this machine on that network at time T"
// cannot be answered from the raw columns without this addition.
func srumConnectStopTime(row *ordereddict.Dict) string {
	start, ok := srumUint64(row, "ConnectStartTime")
	if !ok || start < windowsEpoch100ns {
		return ""
	}
	seconds, ok := srumInt32(row, "ConnectedTime")
	if !ok || seconds < 0 {
		return ""
	}
	// FILETIME ticks are 100ns, so a second is 10,000,000 of them.
	return formatFiletime(start+uint64(seconds)*10_000_000, "")
}

// srumDurationValue renders a seconds count as a duration.
//
// A present zero renders as "0s" rather than blank: an empty cell means the value
// was absent everywhere else in Tyto's output, and a counter that really is zero
// is a different statement from one that was never recorded.
func srumDurationValue(row *ordereddict.Dict, column string) string {
	seconds, ok := srumInt32(row, column)
	if !ok || seconds < 0 {
		return ""
	}
	return (time.Duration(seconds) * time.Second).String()
}

func (e srumExporter) deriveValues(column string, row *ordereddict.Dict) []string {
	switch column {
	case "AppId", "UserId":
		id, ok := srumInt32(row, column)
		if !ok {
			return []string{""}
		}
		return []string{e.ids.resolve(id)}
	case "InterfaceLuid":
		luid, ok := srumUint64(row, column)
		if !ok || luid == 0 {
			return []string{""}
		}
		return []string{srumInterfaceType(luid)}
	case "L2ProfileId":
		id, ok := srumInt32(row, column)
		if !ok {
			return []string{""}
		}
		return []string{e.wlan.resolve(id)}
	}
	if srumSecondsColumns[column] {
		return []string{srumDurationValue(row, column)}
	}
	return nil
}

// ESE reserves a fixed-width slot for every fixed column of a row even when the
// column is NULL, and marks which ones are NULL in a bit array after the fixed
// data. The reader this analyzer uses does not consult that bit array, so a NULL
// fixed column comes back as whatever bytes occupy its slot — which in SRUM is
// 0x2A fill.
//
// Left alone, the App Timeline table exports 3038287259199220266 for every
// counter an application never touched: 1.19 million cells on the host this was
// found on, including AudioInTimeline for 40,047 of 40,050 rows. An analyst
// summing NetworkBytesRaw would get astronomical nonsense and no hint that the
// underlying value was absent.
//
// Only the 4- and 8-byte widths are filtered. 0x2A2A2A2A2A2A2A2A is 3.0e18 and
// 0x2A2A2A2A is 7.1e8 in columns that count seconds — both absurd as
// measurements, and neither occurs once in the other 176,659 rows of a real
// database. The 1- and 2-byte equivalents (42 and 10794) are entirely plausible
// counter values and are deliberately left alone.
const (
	eseNullFill64 = uint64(0x2A2A2A2A2A2A2A2A)
	eseNullFill32 = uint64(0x2A2A2A2A)
)

// srumFormatValue renders one cell. Timestamps go through the shared analyzer
// helpers so a SRUM CSV can be joined on time against every other analyzer's
// output.
func srumFormatValue(column string, value any) string {
	if value == nil {
		return ""
	}
	// A timestamp column never falls through to the numeric cases below. It used
	// to whenever the ESE type was not the one expected, and the cell then held
	// the raw tick count under a UTC header — unusable to anything that types the
	// column, and indistinguishable from a byte count to anything that does not.
	if srumTimestampColumn(column) {
		return srumFormatTimestamp(value)
	}

	switch typed := value.(type) {
	case time.Time:
		return formatTime(typed, "")
	case string:
		return typed
	case []byte:
		return hex.EncodeToString(typed)
	case bool:
		return strconv.FormatBool(typed)
	case uint8:
		return strconv.FormatUint(uint64(typed), 10)
	case uint16:
		return strconv.FormatUint(uint64(typed), 10)
	case uint32:
		if uint64(typed) == eseNullFill32 {
			return ""
		}
		return strconv.FormatUint(uint64(typed), 10)
	case uint64:
		if typed == eseNullFill64 {
			return ""
		}
		return strconv.FormatUint(typed, 10)
	case int8:
		return strconv.FormatInt(int64(typed), 10)
	case int16:
		return strconv.FormatInt(int64(typed), 10)
	case int32:
		if uint64(uint32(typed)) == eseNullFill32 {
			return ""
		}
		return strconv.FormatInt(int64(typed), 10)
	case int64:
		if uint64(typed) == eseNullFill64 {
			return ""
		}
		return strconv.FormatInt(typed, 10)
	case int:
		return strconv.Itoa(typed)
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// srumFormatTimestamp renders a cell bound for a UTC column. The reader hands
// back a decoded time.Time for an ESE DateTime column and the underlying integer
// for the FILETIME ones, so both have to be accepted; anything else is a column
// whose storage this code has misread, and an empty cell says so honestly.
func srumFormatTimestamp(value any) string {
	switch typed := value.(type) {
	case time.Time:
		return formatTime(typed, "")
	case uint64:
		if typed == eseNullFill64 {
			return ""
		}
		return formatFiletime(typed, "")
	case int64:
		if typed <= 0 || uint64(typed) == eseNullFill64 {
			return ""
		}
		return formatFiletime(uint64(typed), "")
	default:
		return ""
	}
}

func srumTableColumns(catalog *ese.Catalog, table string) ([]string, error) {
	entry, ok := catalog.Tables.Get(table)
	if !ok {
		return nil, fmt.Errorf("table not present in catalog")
	}
	spec, ok := entry.(*ese.Table)
	if !ok {
		return nil, fmt.Errorf("unexpected catalog entry type %T", entry)
	}
	columns := make([]string, 0, len(spec.Columns))
	for _, column := range spec.Columns {
		columns = append(columns, column.Name)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("table has no columns")
	}
	return columns, nil
}
