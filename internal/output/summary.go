package output

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
)

var (
	failureHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("204"))
)

type SummaryReport struct {
	Hostname            string
	OS                  string
	Architecture        string
	Version             string
	OutputDir           string
	StartedAt           time.Time
	FinishedAt          time.Time
	TotalDuration       time.Duration
	TimeoutPerCollector time.Duration
	Concurrency         int
	CollectorsTotal     int
	SuccessCount        int
	FailureCount        int
	Results             []collector.Result
}

func NewSummaryReport(outputDir string, startedAt time.Time, totalDuration time.Duration, timeout time.Duration, concurrency int, results []collector.Result) SummaryReport {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UNKNOWN"
	}

	successCount := 0
	failureCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	return SummaryReport{
		Hostname:            hostname,
		OS:                  runtime.GOOS,
		Architecture:        runtime.GOARCH,
		Version:             Version,
		OutputDir:           outputDir,
		StartedAt:           startedAt,
		FinishedAt:          startedAt.Add(totalDuration),
		TotalDuration:       totalDuration,
		TimeoutPerCollector: timeout,
		Concurrency:         concurrency,
		CollectorsTotal:     len(results),
		SuccessCount:        successCount,
		FailureCount:        failureCount,
		Results:             results,
	}
}

func (r SummaryReport) Render() string {
	infoRows := [][]string{
		{"Host", r.Hostname},
		{"Collector version", r.Version},
		{"Platform", fmt.Sprintf("%s/%s", r.OS, r.Architecture)},
		{"Started", r.StartedAt.Format(time.RFC3339)},
		{"Finished", r.FinishedAt.Format(time.RFC3339)},
		{"Output", r.OutputDir},
		{"Collectors", fmt.Sprintf("%d", r.CollectorsTotal)},
		{"Succeeded", fmt.Sprintf("%d", r.SuccessCount)},
		{"Failed", fmt.Sprintf("%d", r.FailureCount)},
		{"Concurrency", fmt.Sprintf("%d", r.Concurrency)},
		{"Timeout per collector", r.TimeoutPerCollector.String()},
		{"Total duration", formatDuration(r.TotalDuration)},
	}

	tableRows := make([][]string, 0, len(r.Results))
	for _, result := range r.Results {
		status := "FAILED"
		if result.Success {
			status = "SUCCESS"
		}

		errorText := "-"
		if result.Error != "" {
			errorText = sanitizeCell(result.Error)
		}

		tableRows = append(tableRows, []string{
			result.Category,
			result.CollectorName,
			status,
			fmt.Sprintf("%d", len(result.FilesCollected)),
			formatBytes(totalSize(result.FilesCollected)),
			formatDuration(result.Duration),
			errorText,
		})
	}

	var b strings.Builder
	b.WriteString("Collection Summary\n")
	b.WriteString(strings.Repeat("=", 18))
	b.WriteString("\n\n")
	b.WriteString(renderTable([]string{"Field", "Value"}, infoRows))
	b.WriteString("\n\n")
	b.WriteString(renderTable(
		[]string{"Category", "Module", "Status", "Files", "Size", "Duration", "Error"},
		tableRows,
	))
	b.WriteString("\n")

	return b.String()
}

func (r SummaryReport) FailedResults() []collector.Result {
	var failed []collector.Result
	for _, result := range r.Results {
		if !result.Success {
			failed = append(failed, result)
		}
	}
	return failed
}

func (r SummaryReport) RenderTerminal(width int) string {
	width = maxInt(width, 12)

	var b strings.Builder
	b.WriteString("Collection Summary\n")
	b.WriteString(strings.Repeat("=", minInt(width, len("Collection Summary"))))
	b.WriteString("\n\n")
	b.WriteString(renderTerminalInfoTable(r, width))
	b.WriteString("\n\n")
	b.WriteString(renderTerminalModulesTable(r.Results, width))

	failed := r.FailedResults()
	if len(failed) > 0 {
		b.WriteString("\n\nFailure Details\n")
		b.WriteString(strings.Repeat("-", minInt(width, len("Failure Details"))))
		b.WriteString("\n")
		for _, result := range failed {
			header := fmt.Sprintf("! [%s] %s duration=%s", result.Category, result.CollectorName, formatDuration(result.Duration))
			b.WriteString(failureHeaderStyle.Render(trimToWidth(header, width)))
			b.WriteString("\n")
			b.WriteString(wrapText("error: "+sanitizeCell(result.Error), maxInt(12, width-2), "  "))
			b.WriteString("\n")
		}
	}

	return lipgloss.NewStyle().Width(width).Render(strings.TrimRight(b.String(), "\n"))
}

func WriteSummary(outputDir string, report SummaryReport) error {
	summaryPath := filepath.Join(outputDir, "summary.txt")
	if err := os.WriteFile(summaryPath, []byte(report.Render()), 0o644); err != nil {
		return fmt.Errorf("write summary.txt: %w", err)
	}
	return nil
}

func renderTable(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for idx, header := range headers {
		widths[idx] = len(header)
	}

	for _, row := range rows {
		for idx := range headers {
			value := ""
			if idx < len(row) {
				value = sanitizeCell(row[idx])
			}
			if len(value) > widths[idx] {
				widths[idx] = len(value)
			}
		}
	}

	return renderFixedWidthTable(headers, widths, rows)
}

func renderTerminalInfoTable(report SummaryReport, width int) string {
	rows := [][]string{
		{"Host", report.Hostname},
		{"Collector version", report.Version},
		{"Platform", fmt.Sprintf("%s/%s", report.OS, report.Architecture)},
		{"Started", report.StartedAt.Format(time.RFC3339)},
		{"Finished", report.FinishedAt.Format(time.RFC3339)},
		{"Output", report.OutputDir},
		{"Collectors", fmt.Sprintf("%d", report.CollectorsTotal)},
		{"Succeeded", fmt.Sprintf("%d", report.SuccessCount)},
		{"Failed", fmt.Sprintf("%d", report.FailureCount)},
		{"Concurrency", fmt.Sprintf("%d", report.Concurrency)},
		{"Timeout per collector", report.TimeoutPerCollector.String()},
		{"Total duration", formatDuration(report.TotalDuration)},
	}

	if width < 23 {
		compactRows := make([][]string, 0, len(rows))
		for _, row := range rows {
			compactRows = append(compactRows, []string{row[0] + ": " + row[1]})
		}
		return renderFixedWidthTable([]string{"Info"}, []int{maxInt(1, width-4)}, compactRows)
	}

	fieldWidth := clampInt((width-7)/3, 6, 18)
	valueWidth := maxInt(10, width-7-fieldWidth)
	return renderFixedWidthTable([]string{"Field", "Value"}, []int{fieldWidth, valueWidth}, rows)
}

func renderTerminalModulesTable(results []collector.Result, width int) string {
	switch {
	case width >= 95:
		rows := make([][]string, 0, len(results))
		errorWidth := maxInt(16, width-tableWidth([]int{16, 10, 8, 5, 10, 8, 0}))
		for _, result := range results {
			rows = append(rows, []string{
				result.Category,
				result.CollectorName,
				resultStatus(result),
				fmt.Sprintf("%d", len(result.FilesCollected)),
				formatBytes(totalSize(result.FilesCollected)),
				formatDuration(result.Duration),
				resultError(result),
			})
		}
		return renderFixedWidthTable(
			[]string{"Category", "Module", "Status", "Files", "Size", "Duration", "Error"},
			[]int{10, 16, 8, 5, 10, 8, errorWidth},
			rows,
		)

	case width >= 76:
		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				result.Category,
				result.CollectorName,
				resultStatus(result),
				fmt.Sprintf("%d", len(result.FilesCollected)),
				formatBytes(totalSize(result.FilesCollected)),
				formatDuration(result.Duration),
			})
		}
		return renderFixedWidthTable(
			[]string{"Category", "Module", "Status", "Files", "Size", "Duration"},
			[]int{10, 16, 8, 5, 10, maxInt(8, width-tableWidth([]int{10, 16, 8, 5, 10, 0}))},
			rows,
		)

	case width >= 54:
		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				fmt.Sprintf("[%s] %s", result.Category, result.CollectorName),
				resultStatus(result),
				fmt.Sprintf("%d", len(result.FilesCollected)),
				formatDuration(result.Duration),
			})
		}
		return renderFixedWidthTable(
			[]string{"Collector", "Status", "Files", "Duration"},
			[]int{16, 10, 7, maxInt(8, width-tableWidth([]int{16, 10, 7, 0}))},
			rows,
		)

	case width >= 38:
		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				fmt.Sprintf("[%s] %s", result.Category, result.CollectorName),
				resultStatus(result),
				formatDuration(result.Duration),
			})
		}
		return renderFixedWidthTable(
			[]string{"Collector", "Status", "Duration"},
			[]int{12, 8, maxInt(8, width-tableWidth([]int{12, 8, 0}))},
			rows,
		)

	default:
		if width < 23 {
			rows := make([][]string, 0, len(results))
			for _, result := range results {
				rows = append(rows, []string{
					fmt.Sprintf("[%s] %s %s", result.Category, result.CollectorName, resultStatus(result)),
				})
			}
			return renderFixedWidthTable(
				[]string{"Collector"},
				[]int{maxInt(1, width-4)},
				rows,
			)
		}

		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				fmt.Sprintf("[%s] %s", result.Category, result.CollectorName),
				resultStatus(result),
			})
		}
		return renderFixedWidthTable(
			[]string{"Collector", "Status"},
			[]int{8, maxInt(8, width-tableWidth([]int{8, 0}))},
			rows,
		)
	}
}

func resultStatus(result collector.Result) string {
	if result.Success {
		return "SUCCESS"
	}
	return "FAILED"
}

func resultError(result collector.Result) string {
	if result.Error == "" {
		return "-"
	}
	return sanitizeCell(result.Error)
}

func renderFixedWidthTable(headers []string, widths []int, rows [][]string) string {
	var b strings.Builder
	border := tableBorder(widths)
	b.WriteString(border)
	b.WriteString("\n")
	b.WriteString(tableRowFixed(headers, widths))
	b.WriteString("\n")
	b.WriteString(border)
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(tableRowFixed(row, widths))
		b.WriteString("\n")
	}
	b.WriteString(border)
	return b.String()
}

func tableBorder(widths []int) string {
	var b strings.Builder
	b.WriteString("+")
	for _, width := range widths {
		b.WriteString(strings.Repeat("-", width+2))
		b.WriteString("+")
	}
	return b.String()
}

func tableRowFixed(values []string, widths []int) string {
	var b strings.Builder
	b.WriteString("|")
	for idx, width := range widths {
		value := ""
		if idx < len(values) {
			value = trimToWidth(sanitizeCell(values[idx]), width)
		}
		padding := width - lipgloss.Width(value)
		if padding < 0 {
			padding = 0
		}
		b.WriteString(" ")
		b.WriteString(value)
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" |")
	}
	return b.String()
}

func tableWidth(widths []int) int {
	total := 1
	for _, width := range widths {
		total += width + 3
	}
	return total
}

func sanitizeCell(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func totalSize(files []collector.FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func formatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func wrapText(value string, width int, indent string) string {
	value = sanitizeCell(value)
	if width <= len(indent)+8 {
		return indent + value
	}

	contentWidth := width - len(indent)
	words := strings.Fields(wordwrap.String(value, contentWidth))
	if len(words) == 0 {
		return indent
	}

	var lines []string
	current := ""
	for _, word := range words {
		for lipgloss.Width(word) > contentWidth {
			chunk := trimToWidth(word, contentWidth)
			chunk = strings.TrimSuffix(chunk, "...")
			if chunk == "" {
				break
			}
			if current != "" {
				lines = append(lines, indent+current)
				current = ""
			}
			lines = append(lines, indent+chunk)
			runes := []rune(word)
			word = string(runes[len([]rune(chunk)):])
		}

		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if lipgloss.Width(candidate) <= contentWidth {
			current = candidate
			continue
		}
		if current != "" {
			lines = append(lines, indent+current)
		}
		current = word
	}

	if current != "" {
		lines = append(lines, indent+current)
	}

	return strings.Join(lines, "\n")
}

func trimToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}

	suffix := "..."
	if width <= len(suffix) {
		return strings.Repeat(".", width)
	}

	runes := []rune(value)
	for len(runes) > 0 && lipgloss.Width(string(runes)+suffix) > width {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 {
		return suffix
	}
	return string(runes) + suffix
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
