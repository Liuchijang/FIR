package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterAnalyzer(&userAssistParser{}) }

type userAssistParser struct{}

type userAssistRow struct {
	Username              string
	HiveSource            string
	GUID                  string
	ValueName             string
	DecodedValue          string
	RunCount              string
	FocusCount            string
	FocusTimeMS           string
	LastExecutedUTC       string
	KeyLastWriteTimestamp string
	Format                string
}

func (c *userAssistParser) Name() string     { return "userassist_parser" }
func (c *userAssistParser) Category() string { return "registry" }
func (c *userAssistParser) Description() string {
	return "Parse UserAssist"
}

func (c *userAssistParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create userassist output dir: %w", err))
	}

	sources, err := collectedUserHiveSources(req.OutputDir, "NTUSER.DAT")
	if err != nil {
		return analyzerError(outDir, err)
	}
	if len(sources) == 0 {
		sources, err = liveUserNTUserSources()
		if err != nil {
			return analyzerError(outDir, err)
		}
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no NTUSER.DAT sources found in collected registry output or live registry"}
	}

	rows := make([]userAssistRow, 0, 256)
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		root, err := openUserHiveSource(source)
		if err != nil {
			continue
		}
		sourceRows, err := parseUserAssistFromRoot(root, source)
		root.Close()
		if err != nil {
			continue
		}
		rows = append(rows, sourceRows...)
	}

	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no UserAssist entries parsed"}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Username == rows[j].Username {
			if rows[i].GUID == rows[j].GUID {
				return rows[i].DecodedValue < rows[j].DecodedValue
			}
			return rows[i].GUID < rows[j].GUID
		}
		return rows[i].Username < rows[j].Username
	})

	csvRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		csvRows = append(csvRows, []string{
			row.Username,
			row.HiveSource,
			row.GUID,
			row.ValueName,
			row.DecodedValue,
			row.RunCount,
			row.FocusCount,
			row.FocusTimeMS,
			row.LastExecutedUTC,
			row.KeyLastWriteTimestamp,
			row.Format,
		})
	}
	return csvResult(outDir, "userassist_entries.csv", []string{
		"Username",
		"HiveSource",
		"GUID",
		"ValueName",
		"DecodedValue",
		"RunCount",
		"FocusCount",
		"FocusTimeMS",
		"LastExecutedUTC",
		"KeyLastWriteTimestamp",
		"Format",
	}, csvRows)
}

func parseUserAssistFromRoot(root winreg.Key, source userHiveSource) ([]userAssistRow, error) {
	baseKey, ok, err := openRegistryKeyOptional(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer baseKey.Close()

	guidNames, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate UserAssist GUIDs: %w", err)
	}

	rows := make([]userAssistRow, 0, 128)
	for _, guidName := range guidNames {
		guidKey, err := winreg.OpenKey(baseKey, guidName, winreg.READ)
		if err != nil {
			continue
		}
		countKey, ok, err := openRegistryKeyOptional(guidKey, "Count")
		guidKey.Close()
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		valueNames, err := countKey.ReadValueNames(-1)
		if err != nil {
			countKey.Close()
			continue
		}
		keyLastWrite := registryKeyLastWriteString(countKey)
		for _, valueName := range valueNames {
			if valueName == "" {
				continue
			}
			data, ok := readRegistryBinaryValue(countKey, valueName)
			if !ok {
				continue
			}
			runCount, focusCount, focusTimeMS, lastExec, format := parseUserAssistValue(data)
			rows = append(rows, userAssistRow{
				Username:              source.Username,
				HiveSource:            ternary(source.Live, "LiveNTUSER", source.HiveName),
				GUID:                  guidName,
				ValueName:             valueName,
				DecodedValue:          decodeROT13(valueName),
				RunCount:              runCount,
				FocusCount:            focusCount,
				FocusTimeMS:           focusTimeMS,
				LastExecutedUTC:       lastExec,
				KeyLastWriteTimestamp: keyLastWrite,
				Format:                format,
			})
		}
		countKey.Close()
	}

	return rows, nil
}

func parseUserAssistValue(data []byte) (runCount, focusCount, focusTimeMS, lastExecutedUTC, format string) {
	switch {
	case len(data) >= 68:
		runCount = uint32DecimalString(binary.LittleEndian.Uint32(data[4:8]))
		focusCount = uint32DecimalString(binary.LittleEndian.Uint32(data[8:12]))
		focusTimeMS = uint32DecimalString(binary.LittleEndian.Uint32(data[12:16]))
		lastExecutedUTC = formatFiletime(binary.LittleEndian.Uint64(data[60:68]), "")
		format = "Vista+"
	case len(data) >= 16:
		count := binary.LittleEndian.Uint32(data[4:8])
		if count >= 5 {
			count -= 5
		}
		runCount = uint32DecimalString(count)
		lastExecutedUTC = formatFiletime(binary.LittleEndian.Uint64(data[8:16]), "")
		format = "XP"
	default:
		format = fmt.Sprintf("Unknown(%d)", len(data))
	}

	if runCount == "" {
		runCount = "0"
	}
	if focusCount == "" {
		focusCount = "0"
	}
	if focusTimeMS == "" {
		focusTimeMS = "0"
	}
	// LastExecutedUTC stays blank when the entry has no FILETIME. It used to read
	// "N/A", which a consumer that binds the column to a date type rejects the
	// whole file over — see the timestamp invariant in common.go. 41 of the 123
	// rows on one host carried it.
	return runCount, focusCount, focusTimeMS, lastExecutedUTC, format
}

func decodeROT13(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			out.WriteRune('a' + ((ch - 'a' + 13) % 26))
		case ch >= 'A' && ch <= 'Z':
			out.WriteRune('A' + ((ch - 'A' + 13) % 26))
		default:
			out.WriteRune(ch)
		}
	}
	return out.String()
}

func uint32DecimalString(value uint32) string {
	return fmt.Sprintf("%d", value)
}
