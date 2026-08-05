package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterAnalyzer(&recentDocsParser{}) }

type recentDocsParser struct{}

type recentDocsRow struct {
	Username              string
	HiveSource            string
	KeyPath               string
	Extension             string
	ValueName             string
	MRUPosition           string
	EntryName             string
	KeyLastWriteTimestamp string
}

func (c *recentDocsParser) Name() string     { return "recentdocs_parser" }
func (c *recentDocsParser) Category() string { return "registry" }
func (c *recentDocsParser) Description() string {
	return "Parse RecentDocs"
}

func (c *recentDocsParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create recentdocs output dir: %w", err).Error()}
	}

	sources, err := collectedUserHiveSources(req.OutputDir, "NTUSER.DAT")
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	if len(sources) == 0 {
		sources, err = liveUserNTUserSources()
		if err != nil {
			return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
		}
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no NTUSER.DAT sources found in collected registry output or live registry"}
	}

	rows := make([]recentDocsRow, 0, 256)
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
		}

		root, err := openUserHiveSource(source)
		if err != nil {
			continue
		}
		sourceRows, err := parseRecentDocsFromRoot(root, source)
		root.Close()
		if err != nil {
			continue
		}
		rows = append(rows, sourceRows...)
	}

	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no RecentDocs entries parsed"}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Username == rows[j].Username {
			if rows[i].KeyPath == rows[j].KeyPath {
				if rows[i].MRUPosition == rows[j].MRUPosition {
					return rows[i].ValueName < rows[j].ValueName
				}
				return rows[i].MRUPosition < rows[j].MRUPosition
			}
			return rows[i].KeyPath < rows[j].KeyPath
		}
		return rows[i].Username < rows[j].Username
	})

	outCSV := filepath.Join(outDir, "recentdocs_entries.csv")
	csvRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		csvRows = append(csvRows, []string{
			row.Username,
			row.HiveSource,
			row.KeyPath,
			row.Extension,
			row.ValueName,
			row.MRUPosition,
			row.EntryName,
			row.KeyLastWriteTimestamp,
		})
	}
	if err := writeCSVFile(outCSV, []string{
		"Username",
		"HiveSource",
		"KeyPath",
		"Extension",
		"ValueName",
		"MRUPosition",
		"EntryName",
		"KeyLastWriteTimestamp",
	}, csvRows); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}

	fi, err := utils.FileInfoFromPath(outCSV)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: []module.FileInfo{fi}, OutputPath: outDir}
}

func parseRecentDocsFromRoot(root winreg.Key, source userHiveSource) ([]recentDocsRow, error) {
	key, ok, err := openRegistryKeyOptional(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer key.Close()

	rows := make([]recentDocsRow, 0, 128)
	if err := walkRecentDocsKey(key, `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`, source, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func walkRecentDocsKey(key winreg.Key, keyPath string, source userHiveSource, rows *[]recentDocsRow) error {
	mruPositions := parseMRUListEx(key)
	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, valueName := range valueNames {
			if strings.EqualFold(valueName, "MRUListEx") || strings.EqualFold(valueName, "MRUList") {
				continue
			}

			entryName := readRecentDocsEntry(key, valueName)
			if entryName == "" {
				continue
			}

			*rows = append(*rows, recentDocsRow{
				Username:              source.Username,
				HiveSource:            ternary(source.Live, "LiveNTUSER", source.HiveName),
				KeyPath:               keyPath,
				Extension:             filepath.Base(keyPath),
				ValueName:             valueName,
				MRUPosition:           mruPositionString(mruPositions, valueName),
				EntryName:             entryName,
				KeyLastWriteTimestamp: registryKeyLastWriteString(key),
			})
		}
	}

	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	for _, name := range subKeys {
		subKey, err := winreg.OpenKey(key, name, winreg.READ)
		if err != nil {
			continue
		}
		nextPath := keyPath + `\` + name
		if err := walkRecentDocsKey(subKey, nextPath, source, rows); err != nil {
			subKey.Close()
			return err
		}
		subKey.Close()
	}
	return nil
}

func parseMRUListEx(key winreg.Key) map[string]int {
	data, ok := readRegistryBinaryValue(key, "MRUListEx")
	if !ok || len(data) < 4 {
		return map[string]int{}
	}

	positions := make(map[string]int)
	order := 0
	for offset := 0; offset+4 <= len(data); offset += 4 {
		value := binary.LittleEndian.Uint32(data[offset : offset+4])
		if value == 0xFFFFFFFF {
			break
		}
		positions[strconv.FormatUint(uint64(value), 10)] = order
		order++
	}
	return positions
}

func mruPositionString(positions map[string]int, valueName string) string {
	if pos, ok := positions[valueName]; ok {
		return strconv.Itoa(pos)
	}
	return ""
}

func readRecentDocsEntry(key winreg.Key, valueName string) string {
	if data, ok := readRegistryBinaryValue(key, valueName); ok {
		return decodeRecentDocsBinary(data)
	}
	return readRegistryFirstString(key, valueName)
}

func decodeRecentDocsBinary(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	for end := 2; end <= len(data); end += 2 {
		if end+1 < len(data) && data[end] == 0 && data[end+1] == 0 {
			return utf16LEString(data[:end])
		}
	}
	return utf16LEString(data)
}
