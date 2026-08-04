package analyzers

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterAnalyzer(&runMRUParser{}) }

type runMRUParser struct{}

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
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create runmru output dir: %w", err).Error()}
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

	rows := make([]runMRURow, 0, 128)
	for _, source := range sources {
		select {
		case <-ctx.Done():
			return module.AnalyzeResult{OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		root, err := openUserHiveSource(source)
		if err != nil {
			continue
		}
		sourceRows, err := parseRunMRUFromRoot(root, source)
		root.Close()
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

	outCSV := filepath.Join(outDir, "runmru_entries.csv")
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
	if err := writeCSVFile(outCSV, []string{
		"Username",
		"HiveSource",
		"KeyPath",
		"ValueName",
		"MRUPosition",
		"Command",
		"MRUList",
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

func parseRunMRUFromRoot(root winreg.Key, source userHiveSource) ([]runMRURow, error) {
	const keyPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

	key, ok, err := openRegistryKeyOptional(root, keyPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer key.Close()

	mruList := readRegistryFirstString(key, "MRUList")
	mruPositions := parseRunMRUList(mruList)
	keyLastWrite := registryKeyLastWriteString(key)

	valueNames, err := key.ReadValueNames(-1)
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

func readRunMRUCommand(key winreg.Key, valueName string) string {
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
