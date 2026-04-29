package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterAnalyzer(&shimCacheParser{}) }

type shimCacheParser struct{}

type shimCacheSource struct {
	ControlSet  string
	Data        []byte
	FormatPath  string
	RegistryKey string
}

type shimCacheRow struct {
	LastModifiedUTC string
	LastUpdateUTC   string
	Path            string
	FileSize        string
	ExecFlag        string
	ControlSet      string
	Format          string
	EntryPosition   int
}

const (
	shimNotAvailable = "N/A"

	shimMagicNt52 = 0xbadc0ffe
	shimMagicNt61 = 0xbadc0fee
	shimMagicXP32 = 0xdeadbeef

	shimStatsWin8           = 0x80
	shimStatsWin10          = 0x30
	shimStatsWin10Cu        = 0x34
	shimTagWin8      string = "00ts"
	shimTagWin81     string = "10ts"
	shimTagWin10     string = "10ts"
)

func (c *shimCacheParser) Name() string     { return "shimcache_parser" }
func (c *shimCacheParser) Category() string { return "registry" }
func (c *shimCacheParser) Description() string {
	return "Parse ShimCache"
}

func (c *shimCacheParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir := req.AnalyzerDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "Analyzer", c.Name())
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create shimcache parser output dir: %w", err).Error()}
	}

	sources, err := loadShimCacheSources(req.OutputDir)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no ShimCache sources found in collected SYSTEM hive or live registry"}
	}

	rows := make([]shimCacheRow, 0, 1024)
	seen := make(map[string]bool)
	var parseErrors []string
	for _, source := range sources {
		select {
		case <-ctx.Done():
			return module.AnalyzeResult{OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		data := source.Data
		if len(data) == 0 {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: empty source data", source.RegistryKey))
			continue
		}

		parsed, err := parseShimCache(data, source)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: parse %v", source.RegistryKey, err))
			continue
		}
		for _, row := range parsed {
			row = normalizeShimCacheRow(row)
			key := strings.Join([]string{
				row.LastModifiedUTC,
				row.LastUpdateUTC,
				strings.ToLower(row.Path),
				row.FileSize,
				row.ExecFlag,
			}, "|")
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		if len(parseErrors) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no ShimCache entries parsed: %s", strings.Join(parseErrors, "; "))}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: "no ShimCache entries parsed"}
	}

	outCSV := filepath.Join(outDir, "shimcache_entries.csv")
	csvRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		csvRows = append(csvRows, []string{
			row.LastModifiedUTC,
			row.LastUpdateUTC,
			row.Path,
			row.FileSize,
			row.ExecFlag,
			row.ControlSet,
			row.Format,
			fmt.Sprintf("%d", row.EntryPosition),
		})
	}
	if err := writeCSVFile(outCSV, []string{
		"LastModifiedUTC",
		"LastUpdateUTC",
		"Path",
		"FileSize",
		"ExecFlag",
		"ControlSet",
		"Format",
		"EntryPosition",
	}, csvRows); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}

	fi, err := utils.FileInfoFromPath(outCSV)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: []module.FileInfo{fi}, OutputPath: outDir}
}

func loadShimCacheSources(outputDir string) ([]shimCacheSource, error) {
	var collectedErr error
	if dir, ok := existingModuleDir(outputDir, "registry"); ok {
		collected := filepath.Join(dir, "SYSTEM")
		if _, err := os.Stat(collected); err == nil {
			sources, err := loadShimCacheSourcesFromHive(collected)
			if err == nil {
				return sources, nil
			}
			collectedErr = err
		}
	}
	sources, liveErr := loadLiveShimCacheSources()
	if liveErr != nil {
		if collectedErr != nil {
			return nil, fmt.Errorf("load collected SYSTEM hive: %v; load live SYSTEM hive: %w", collectedErr, liveErr)
		}
		return nil, liveErr
	}
	return sources, nil
}

func loadLiveShimCacheSources() ([]shimCacheSource, error) {
	systemKey, ok, err := openRegistryKeyOptional(winreg.LOCAL_MACHINE, `SYSTEM`)
	if err != nil {
		return nil, fmt.Errorf("open live SYSTEM hive: %w", err)
	}
	if !ok {
		return nil, nil
	}
	defer systemKey.Close()
	return loadShimCacheSourcesFromRoot(systemKey, `HKEY_LOCAL_MACHINE\SYSTEM`)
}

func loadShimCacheSourcesFromHive(hivePath string) ([]shimCacheSource, error) {
	root, err := loadRegistryAppKey(hivePath)
	if err != nil {
		return nil, fmt.Errorf("load SYSTEM hive app key: %w", err)
	}
	defer root.Close()
	return loadShimCacheSourcesFromRoot(root, `SYSTEM`)
}

func loadShimCacheSourcesFromRoot(root winreg.Key, registryPrefix string) ([]shimCacheSource, error) {
	controlSets, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate control sets: %w", err)
	}

	targets := []struct {
		pathSuffix string
		format     string
	}{
		{pathSuffix: `Control\Session Manager\AppCompatCache`, format: "AppCompatCache"},
		{pathSuffix: `Control\Session Manager\AppCompatibility`, format: "AppCompatibility"},
	}

	sources := make([]shimCacheSource, 0, len(controlSets))
	for _, controlSet := range controlSets {
		if !isControlSetName(controlSet) {
			continue
		}
		for _, target := range targets {
			keyPath := controlSet + `\` + target.pathSuffix
			key, ok, err := openRegistryKeyOptional(root, keyPath)
			if err != nil {
				return nil, fmt.Errorf("open ShimCache key %s: %w", keyPath, err)
			}
			if !ok {
				continue
			}

			value, ok := readRegistryBinaryValue(key, "AppCompatCache")
			key.Close()
			if !ok {
				continue
			}

			sources = append(sources, shimCacheSource{
				ControlSet:  controlSet,
				Data:        append([]byte(nil), value...),
				FormatPath:  target.format,
				RegistryKey: registryPrefix + `\` + keyPath,
			})
		}
	}
	return sources, nil
}

func isControlSetName(name string) bool {
	if !strings.HasPrefix(name, "ControlSet") || len(name) != len("ControlSet000") {
		return false
	}
	for _, ch := range name[len("ControlSet"):] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func parseShimCache(data []byte, source shimCacheSource) ([]shimCacheRow, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("shimcache data too small")
	}

	if len(data) > shimStatsWin10Cu+4 && string(data[shimStatsWin10Cu:shimStatsWin10Cu+4]) == shimTagWin10 {
		return parseWin10ShimEntries(data, shimStatsWin10Cu, "Windows10+", source), nil
	}
	if len(data) > shimStatsWin10+4 && string(data[shimStatsWin10:shimStatsWin10+4]) == shimTagWin10 {
		return parseWin10ShimEntries(data, shimStatsWin10, "Windows10", source), nil
	}
	if len(data) > shimStatsWin8+4 && string(data[shimStatsWin8:shimStatsWin8+4]) == shimTagWin81 {
		return parseWin8ShimEntries(data, shimStatsWin8, "Windows8.1", source), nil
	}
	if len(data) > shimStatsWin8+4 && string(data[shimStatsWin8:shimStatsWin8+4]) == shimTagWin8 {
		return parseWin8ShimEntries(data, shimStatsWin8, "Windows8", source), nil
	}

	magic := binary.LittleEndian.Uint32(data[:4])
	switch magic {
	case shimMagicNt61:
		rows32, score32 := parseLegacyNt61Entries(data, true, source)
		rows64, score64 := parseLegacyNt61Entries(data, false, source)
		if score64 > score32 {
			return rows64, nil
		}
		return rows32, nil
	case shimMagicNt52:
		rows32, score32 := parseLegacyNt52Entries(data, true, source)
		rows64, score64 := parseLegacyNt52Entries(data, false, source)
		if score64 > score32 {
			return rows64, nil
		}
		return rows32, nil
	case shimMagicXP32:
		return nil, fmt.Errorf("Windows XP ShimCache format is not supported yet")
	default:
		return nil, fmt.Errorf("unrecognized ShimCache format magic 0x%08x", magic)
	}
}

func parseWin10ShimEntries(data []byte, statsSize int, format string, source shimCacheSource) []shimCacheRow {
	cacheData := data[statsSize:]
	rows := make([]shimCacheRow, 0, 128)
	offset := 0
	position := 0

	for offset+12 <= len(cacheData) {
		tag := string(cacheData[offset : offset+4])
		if tag != shimTagWin10 {
			break
		}

		entryLen := int(binary.LittleEndian.Uint32(cacheData[offset+8 : offset+12]))
		if entryLen <= 0 || offset+12+entryLen > len(cacheData) {
			break
		}

		entry := cacheData[offset+12 : offset+12+entryLen]
		if len(entry) < 14 {
			break
		}

		pathLen := int(binary.LittleEndian.Uint16(entry[0:2]))
		if 2+pathLen+12 > len(entry) {
			break
		}

		path := utf16LEString(entry[2 : 2+pathLen])
		cursor := 2 + pathLen
		lastModified := filetimeUint64String(binary.LittleEndian.Uint64(entry[cursor : cursor+8]))
		cursor += 8

		if cursor+4 > len(entry) {
			break
		}
		dataLen := int(binary.LittleEndian.Uint32(entry[cursor : cursor+4]))
		cursor += 4
		if cursor+dataLen > len(entry) {
			break
		}

		rows = append(rows, shimCacheRow{
			LastModifiedUTC: lastModified,
			LastUpdateUTC:   shimNotAvailable,
			Path:            strings.ReplaceAll(path, `\??\`, ""),
			FileSize:        shimNotAvailable,
			ExecFlag:        shimNotAvailable,
			ControlSet:      source.ControlSet,
			Format:          format,
			EntryPosition:   position,
		})

		position++
		offset += 12 + entryLen
	}

	return rows
}

func parseWin8ShimEntries(data []byte, statsSize int, format string, source shimCacheSource) []shimCacheRow {
	cacheData := data[statsSize:]
	rows := make([]shimCacheRow, 0, 128)
	offset := 0
	position := 0

	for offset+12 <= len(cacheData) {
		tag := string(cacheData[offset : offset+4])
		if tag != shimTagWin8 && tag != shimTagWin81 {
			break
		}

		entryLen := int(binary.LittleEndian.Uint32(cacheData[offset+8 : offset+12]))
		if entryLen <= 0 || offset+12+entryLen > len(cacheData) {
			break
		}

		entry := cacheData[offset+12 : offset+12+entryLen]
		if len(entry) < 4 {
			break
		}

		pathLen := int(binary.LittleEndian.Uint16(entry[0:2]))
		if 2+pathLen+2 > len(entry) {
			break
		}

		path := utf16LEString(entry[2 : 2+pathLen])
		cursor := 2 + pathLen
		packageLen := int(binary.LittleEndian.Uint16(entry[cursor : cursor+2]))
		cursor += 2
		if cursor+packageLen+20 > len(entry) {
			break
		}

		cursor += packageLen
		flags := binary.LittleEndian.Uint32(entry[cursor : cursor+4])
		cursor += 8 // flags + unknown
		lastModified := filetimePartsString(
			binary.LittleEndian.Uint32(entry[cursor:cursor+4]),
			binary.LittleEndian.Uint32(entry[cursor+4:cursor+8]),
		)

		rows = append(rows, shimCacheRow{
			LastModifiedUTC: lastModified,
			LastUpdateUTC:   shimNotAvailable,
			Path:            strings.ReplaceAll(path, `\??\`, ""),
			FileSize:        shimNotAvailable,
			ExecFlag:        boolString(flags&0x2 == 0x2),
			ControlSet:      source.ControlSet,
			Format:          format,
			EntryPosition:   position,
		})

		position++
		offset += 12 + entryLen
	}

	return rows
}

func parseLegacyNt61Entries(data []byte, is32Bit bool, source shimCacheSource) ([]shimCacheRow, int) {
	const headerSize = 0x80

	entrySize := 0x30
	if is32Bit {
		entrySize = 0x20
	}
	if len(data) < headerSize+entrySize {
		return nil, 0
	}

	count := int(binary.LittleEndian.Uint32(data[4:8]))
	rows := make([]shimCacheRow, 0, count)
	score := 0

	for i := 0; i < count; i++ {
		start := headerSize + i*entrySize
		if start+entrySize > len(data) {
			break
		}

		entry := data[start : start+entrySize]
		var pathLen int
		var pathOff int
		var low, high, flags uint32

		if is32Bit {
			pathLen = int(binary.LittleEndian.Uint16(entry[0:2]))
			pathOff = int(binary.LittleEndian.Uint32(entry[4:8]))
			low = binary.LittleEndian.Uint32(entry[8:12])
			high = binary.LittleEndian.Uint32(entry[12:16])
			flags = binary.LittleEndian.Uint32(entry[16:20])
		} else {
			pathLen = int(binary.LittleEndian.Uint16(entry[0:2]))
			pathOff = int(binary.LittleEndian.Uint64(entry[8:16]))
			low = binary.LittleEndian.Uint32(entry[16:20])
			high = binary.LittleEndian.Uint32(entry[20:24])
			flags = binary.LittleEndian.Uint32(entry[24:28])
		}

		path, ok := readUTF16Path(data, pathOff, pathLen)
		if !ok {
			continue
		}
		score++

		rows = append(rows, shimCacheRow{
			LastModifiedUTC: filetimePartsString(low, high),
			LastUpdateUTC:   shimNotAvailable,
			Path:            strings.ReplaceAll(path, `\??\`, ""),
			FileSize:        shimNotAvailable,
			ExecFlag:        boolString(flags&0x2 == 0x2),
			ControlSet:      source.ControlSet,
			Format:          ternary(is32Bit, "Windows7-32", "Windows7-64"),
			EntryPosition:   i,
		})
	}

	return rows, score
}

func parseLegacyNt52Entries(data []byte, is32Bit bool, source shimCacheSource) ([]shimCacheRow, int) {
	const headerSize = 0x08

	entrySize := 0x20
	if is32Bit {
		entrySize = 0x18
	}
	if len(data) < headerSize+entrySize {
		return nil, 0
	}

	count := int(binary.LittleEndian.Uint32(data[4:8]))
	rows := make([]shimCacheRow, 0, count)
	score := 0
	sizeLike := 0
	flagLike := 0

	type candidate struct {
		lastMod string
		path    string
		sizeLo  uint32
		sizeHi  uint32
	}
	candidates := make([]candidate, 0, count)

	for i := 0; i < count; i++ {
		start := headerSize + i*entrySize
		if start+entrySize > len(data) {
			break
		}

		entry := data[start : start+entrySize]
		var pathLen int
		var pathOff int
		var low, high, sizeLo, sizeHi uint32

		if is32Bit {
			pathLen = int(binary.LittleEndian.Uint16(entry[0:2]))
			pathOff = int(binary.LittleEndian.Uint32(entry[4:8]))
			low = binary.LittleEndian.Uint32(entry[8:12])
			high = binary.LittleEndian.Uint32(entry[12:16])
			sizeLo = binary.LittleEndian.Uint32(entry[16:20])
			sizeHi = binary.LittleEndian.Uint32(entry[20:24])
		} else {
			pathLen = int(binary.LittleEndian.Uint16(entry[0:2]))
			pathOff = int(binary.LittleEndian.Uint64(entry[8:16]))
			low = binary.LittleEndian.Uint32(entry[16:20])
			high = binary.LittleEndian.Uint32(entry[20:24])
			sizeLo = binary.LittleEndian.Uint32(entry[24:28])
			sizeHi = binary.LittleEndian.Uint32(entry[28:32])
		}

		path, ok := readUTF16Path(data, pathOff, pathLen)
		if !ok {
			continue
		}
		score++
		if sizeHi != 0 || sizeLo > 3 {
			sizeLike++
		} else {
			flagLike++
		}

		candidates = append(candidates, candidate{
			lastMod: filetimePartsString(low, high),
			path:    strings.ReplaceAll(path, `\??\`, ""),
			sizeLo:  sizeLo,
			sizeHi:  sizeHi,
		})
	}

	useFileSize := sizeLike > flagLike
	for i, item := range candidates {
		row := shimCacheRow{
			LastModifiedUTC: item.lastMod,
			LastUpdateUTC:   shimNotAvailable,
			Path:            item.path,
			FileSize:        shimNotAvailable,
			ExecFlag:        shimNotAvailable,
			ControlSet:      source.ControlSet,
			Format:          ternary(is32Bit, "Vista/2003-32", "Vista/2003-64"),
			EntryPosition:   i,
		}
		if useFileSize {
			size := (uint64(item.sizeHi) << 32) | uint64(item.sizeLo)
			row.FileSize = fmt.Sprintf("%d", size)
		} else {
			row.ExecFlag = boolString(item.sizeLo&0x2 == 0x2)
		}
		rows = append(rows, row)
	}

	return rows, score
}

func readUTF16Path(data []byte, off, length int) (string, bool) {
	if length <= 0 || off < 0 || off+length > len(data) {
		return "", false
	}
	return utf16LEString(data[off : off+length]), true
}

func filetimePartsString(low, high uint32) string {
	return filetimeUint64String((uint64(high) << 32) | uint64(low))
}

func filetimeUint64String(value uint64) string {
	if value == 0 {
		return shimNotAvailable
	}
	const windowsEpoch = 116444736000000000
	if value < windowsEpoch {
		return shimNotAvailable
	}
	unix100ns := int64(value - windowsEpoch)
	return time.Unix(0, unix100ns*100).UTC().Format("2006-01-02 15:04:05")
}

func boolString(value bool) string {
	if value {
		return "True"
	}
	return "False"
}

func ternary(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func normalizeShimCacheRow(row shimCacheRow) shimCacheRow {
	row.LastModifiedUTC = shimValueOrNA(row.LastModifiedUTC)
	row.LastUpdateUTC = shimValueOrNA(row.LastUpdateUTC)
	row.Path = shimValueOrNA(row.Path)
	row.FileSize = shimValueOrNA(row.FileSize)
	row.ExecFlag = shimValueOrNA(row.ExecFlag)
	row.ControlSet = shimValueOrNA(row.ControlSet)
	row.Format = shimValueOrNA(row.Format)
	return row
}

func shimValueOrNA(value string) string {
	if strings.TrimSpace(value) == "" {
		return shimNotAvailable
	}
	return value
}
