package analyzers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterAnalyzer(&runMRUParser{}) }

type runMRUParser struct{ offlineCapable }

type runMRURow struct {
	Username              string
	HiveSource            string
	KeyPath               string
	ValueName             string
	MRUPosition           int
	HasMRUPosition        bool
	Command               string
	MRUList               string
	KeyLastWriteTimestamp string
}

func (c *runMRUParser) Name() string     { return "runmru_parser" }
func (c *runMRUParser) Category() string { return "registry" }
func (c *runMRUParser) Description() string {
	return "Parse RunMRU"
}

func (c *runMRUParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create runmru output dir: %w", err))
	}

	sources, err := resolveNTUserHiveSources(req)
	if err != nil {
		if errors.Is(err, errNoCollectedSource) {
			return skippedNoSource(outDir, "collected NTUSER.DAT hives")
		}
		return analyzerError(outDir, err)
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no NTUSER.DAT sources found in collected registry output or live registry"}
	}

	rows := make([]runMRURow, 0, 128)
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		hive, err := openUserHiveSource(source)
		if err != nil {
			continue
		}
		sourceRows, err := parseRunMRUFromRoot(hive, source)
		hive.Close()
		if err != nil {
			continue
		}
		rows = append(rows, sourceRows...)
	}

	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no RunMRU entries parsed"}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Username == rows[j].Username {
			if rows[i].HasMRUPosition != rows[j].HasMRUPosition {
				return rows[i].HasMRUPosition
			}
			if rows[i].MRUPosition != rows[j].MRUPosition {
				return rows[i].MRUPosition < rows[j].MRUPosition
			}
			return rows[i].ValueName < rows[j].ValueName
		}
		return rows[i].Username < rows[j].Username
	})

	csvRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		mruPosition := ""
		if row.HasMRUPosition {
			mruPosition = fmt.Sprintf("%d", row.MRUPosition)
		}
		csvRows = append(csvRows, []string{
			row.Username,
			row.HiveSource,
			row.KeyPath,
			row.ValueName,
			mruPosition,
			row.Command,
			row.MRUList,
			row.KeyLastWriteTimestamp,
		})
	}
	return csvResult(outDir, "runmru_entries.csv", []string{
		"Username",
		"HiveSource",
		"KeyPath",
		"ValueName",
		"MRUPosition",
		"Command",
		"MRUList",
		"KeyLastWriteTimestamp",
	}, csvRows)
}

func parseRunMRUFromRoot(root registryKey, source userHiveSource) ([]runMRURow, error) {
	const keyPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

	key, ok, err := root.OpenSubkey(keyPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer key.Close()

	mruList := readRegistryFirstString(key, "MRUList")
	mruPositions := parseRunMRUList(mruList)
	keyLastWrite := key.LastWriteString()

	valueNames, err := key.ValueNames()
	if err != nil {
		return nil, fmt.Errorf("enumerate RunMRU values: %w", err)
	}

	rows := make([]runMRURow, 0, len(valueNames))
	for _, valueName := range valueNames {
		if valueName == "" || strings.EqualFold(valueName, "MRUList") {
			continue
		}

		command := readRunMRUCommand(key, valueName)
		if command == "" {
			continue
		}

		position, ok := mruPositions[valueName]
		rows = append(rows, runMRURow{
			Username:              source.Username,
			HiveSource:            ternary(source.Live, "LiveNTUSER", source.HiveName),
			KeyPath:               keyPath,
			ValueName:             valueName,
			MRUPosition:           position,
			HasMRUPosition:        ok,
			Command:               command,
			MRUList:               mruList,
			KeyLastWriteTimestamp: keyLastWrite,
		})
	}

	return rows, nil
}

func parseRunMRUList(value string) map[string]int {
	positions := make(map[string]int)
	for idx, ch := range strings.TrimSpace(value) {
		positions[string(ch)] = idx
	}
	return positions
}

func readRunMRUCommand(key registryKey, valueName string) string {
	if value := readRegistryFirstString(key, valueName); value != "" {
		return normalizeRunMRUCommand(value)
	}
	if data, ok := readRegistryBinaryValue(key, valueName); ok {
		return normalizeRunMRUCommand(decodeRecentDocsBinary(data))
	}
	return ""
}

func normalizeRunMRUCommand(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimRightFunc(value, func(r rune) bool {
		return r >= 0 && r < 0x20
	})
	return strings.TrimSpace(value)
}
