package analyzers

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
)

func requiredModuleDir(outputDir, name string) (string, error) {
	c, err := module.Get(name)
	if err != nil {
		return "", err
	}
	return module.ModuleDir(outputDir, c), nil
}

func existingModuleDir(outputDir, name string) (string, bool) {
	dir, err := requiredModuleDir(outputDir, name)
	if err != nil {
		return "", false
	}
	if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
		return dir, true
	}
	return "", false
}

func writeCSVFile(path string, header []string, rows [][]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create csv dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return fmt.Errorf("write utf-8 bom: %w", err)
	}

	w := csv.NewWriter(f)
	if err := w.Write(sanitizeCSVRow(header)); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, row := range rows {
		if err := w.Write(sanitizeCSVRow(row)); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}

	return nil
}

func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, value := range row {
		out[i] = sanitizeCSVValue(value)
	}
	return out
}

func sanitizeCSVValue(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return strings.TrimSpace(value)
}

// maskFlag pairs a bit with its name. Flag tables are package-level so a
// million-record USN journal does not reallocate them per record.
type maskFlag[T ~uint16 | ~uint32] struct {
	value T
	name  string
}

func maskString[T ~uint16 | ~uint32](mask T, flags []maskFlag[T]) string {
	var names []string
	for _, flag := range flags {
		if mask&flag.value != 0 {
			names = append(names, flag.name)
		}
	}
	return strings.Join(names, "|")
}
