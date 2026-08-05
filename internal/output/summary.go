package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/platform"
	"github.com/Liuchijang/FIR/internal/resource"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
)

// Terminal styles below deliberately reuse the interactive TUI's palette (see
// internal/tui): 175 for errors, 182 for success, 246 for borders, 218 for section
// titles. RenderTerminal draws inside the TUI's rounded panel, so a table drawn in
// unrelated colors reads as a second, foreign UI pasted into the panel. Only the
// RenderTerminal path uses these — Render() must stay plain so summary.txt on disk
// never contains ANSI escapes.
var (
	failureHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("175"))
	warningHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("221"))
	terminalTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("218"))
	tableBorderStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
	tableHeaderStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	successCellStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("182"))
	failureCellStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("175"))
	skippedCellStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("221"))
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
	SkippedCount        int
	Results             []module.Result
}

func NewSummaryReport(outputDir string, startedAt time.Time, totalDuration time.Duration, timeout time.Duration, concurrency int, results []module.Result) SummaryReport {
	host := platform.DetectHost()

	successCount := 0
	failureCount := 0
	skippedCount := 0
	for _, result := range results {
		switch {
		case result.Skipped:
			skippedCount++
		case result.Success:
			successCount++
		default:
			failureCount++
		}
	}

	return SummaryReport{
		Hostname:            host.Hostname,
		OS:                  host.OS,
		Architecture:        host.Architecture,
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
		SkippedCount:        skippedCount,
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
		{"Skipped", fmt.Sprintf("%d", r.SkippedCount)},
		{"Concurrency", fmt.Sprintf("%d", r.Concurrency)},
		{"Timeout per collector", formatTimeout(r.TimeoutPerCollector)},
		{"Total duration", formatDuration(r.TotalDuration)},
	}

	tableRows := make([][]string, 0, len(r.Results))
	for _, result := range r.Results {
		tableRows = append(tableRows, []string{
			result.Category,
			result.CollectorName,
			resultStatus(result),
			fmt.Sprintf("%d", len(result.FilesCollected)),
			resource.FormatBytes(module.TotalSize(result.FilesCollected)),
			formatDuration(result.Duration),
			resultErrorBrief(result, 48),
		})
	}

	var b strings.Builder
	b.WriteString("Collection Summary\n")
	b.WriteString(strings.Repeat("=", 18))
	b.WriteString("\n\n")
	b.WriteString(renderFixedWidthTable(
		[]string{"Field", "Value"},
		[]int{23, 33},
		infoRows,
	))
	b.WriteString("\n\n")
	b.WriteString(renderFixedWidthTable(
		[]string{"Category", "Module", "Status", "Files", "Size", "Duration", "Error"},
		[]int{10, 16, 8, 5, 10, 8, 48},
		tableRows,
	))
	failed := r.FailedResults()
	if len(failed) > 0 {
		b.WriteString("\n\nFailure Details\n")
		b.WriteString(strings.Repeat("-", len("Failure Details")))
		b.WriteString("\n")
		for _, result := range failed {
			b.WriteString(fmt.Sprintf("! [%s] %s duration=%s\n", result.Category, result.CollectorName, formatDuration(result.Duration)))
			b.WriteString(wrapText("error: "+sanitizeCell(result.Error), 118, "  "))
			b.WriteString("\n")
		}
	}
	warnings := r.WarningResults()
	if len(warnings) > 0 {
		b.WriteString("\n\nWarnings (succeeded with partial errors)\n")
		b.WriteString(strings.Repeat("-", len("Warnings (succeeded with partial errors)")))
		b.WriteString("\n")
		for _, result := range warnings {
			b.WriteString(fmt.Sprintf("* [%s] %s duration=%s\n", result.Category, result.CollectorName, formatDuration(result.Duration)))
			b.WriteString(wrapText("warning: "+sanitizeCell(result.Error), 118, "  "))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	return b.String()
}

func (r SummaryReport) FailedResults() []module.Result {
	var failed []module.Result
	for _, result := range r.Results {
		if !result.Success {
			failed = append(failed, result)
		}
	}
	return failed
}

// WarningResults returns modules that finished successfully (some files were
// collected) but still reported an error — e.g. a registry collector that
// captured most hives but couldn't read one of them.
func (r SummaryReport) WarningResults() []module.Result {
	var warnings []module.Result
	for _, result := range r.Results {
		if result.Success && result.Error != "" {
			warnings = append(warnings, result)
		}
	}
	return warnings
}

func (r SummaryReport) RenderTerminal(width int) string {
	width = max(width, 12)

	// No "Collection Summary" heading here: the TUI already renders that phase title
	// directly above this viewport (see CollectionProgressModel.bodyHeaderLines), so
	// repeating it inside the content printed the same words twice in two styles.
	var b strings.Builder
	b.WriteString(renderTerminalInfoTable(r, width))
	b.WriteString("\n\n")
	b.WriteString(renderTerminalModulesTable(r.Results, width))

	failed := r.FailedResults()
	if len(failed) > 0 {
		b.WriteString("\n\n")
		b.WriteString(terminalTitleStyle.Render(trimToWidth("Failure Details", width)))
		b.WriteString("\n")
		for _, result := range failed {
			header := fmt.Sprintf("! [%s] %s duration=%s", result.Category, result.CollectorName, formatDuration(result.Duration))
			b.WriteString(failureHeaderStyle.Render(trimToWidth(header, width)))
			b.WriteString("\n")
			b.WriteString(wrapText("error: "+sanitizeCell(result.Error), max(12, width-2), "  "))
			b.WriteString("\n")
		}
	}

	warnings := r.WarningResults()
	if len(warnings) > 0 {
		b.WriteString("\n\n")
		b.WriteString(terminalTitleStyle.Render(trimToWidth("Warnings (succeeded with partial errors)", width)))
		b.WriteString("\n")
		for _, result := range warnings {
			header := fmt.Sprintf("* [%s] %s duration=%s", result.Category, result.CollectorName, formatDuration(result.Duration))
			b.WriteString(warningHeaderStyle.Render(trimToWidth(header, width)))
			b.WriteString("\n")
			b.WriteString(wrapText("warning: "+sanitizeCell(result.Error), max(12, width-2), "  "))
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
		{"Skipped", fmt.Sprintf("%d", report.SkippedCount)},
		{"Concurrency", fmt.Sprintf("%d", report.Concurrency)},
		{"Timeout per collector", formatTimeout(report.TimeoutPerCollector)},
		{"Total duration", formatDuration(report.TotalDuration)},
	}

	if width < 23 {
		compactRows := make([][]string, 0, len(rows))
		for _, row := range rows {
			compactRows = append(compactRows, []string{row[0] + ": " + row[1]})
		}
		return renderStyledTable([]string{"Info"}, []int{max(1, width-4)}, compactRows, -1)
	}

	fieldWidth := min(max((width-7)/3, 6), 18)
	valueWidth := max(10, width-7-fieldWidth)
	return renderStyledTable([]string{"Field", "Value"}, []int{fieldWidth, valueWidth}, rows, -1)
}

func renderTerminalModulesTable(results []module.Result, width int) string {
	switch {
	case width >= 95:
		rows := make([][]string, 0, len(results))
		errorWidth := max(16, width-tableWidth([]int{16, 10, 8, 5, 10, 8, 0}))
		for _, result := range results {
			rows = append(rows, []string{
				result.Category,
				result.CollectorName,
				resultStatus(result),
				fmt.Sprintf("%d", len(result.FilesCollected)),
				resource.FormatBytes(module.TotalSize(result.FilesCollected)),
				formatDuration(result.Duration),
				resultError(result),
			})
		}
		return renderStyledTable(
			[]string{"Category", "Module", "Status", "Files", "Size", "Duration", "Error"},
			[]int{10, 16, 8, 5, 10, 8, errorWidth},
			rows,
			2,
		)

	case width >= 76:
		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				result.Category,
				result.CollectorName,
				resultStatus(result),
				fmt.Sprintf("%d", len(result.FilesCollected)),
				resource.FormatBytes(module.TotalSize(result.FilesCollected)),
				formatDuration(result.Duration),
			})
		}
		return renderStyledTable(
			[]string{"Category", "Module", "Status", "Files", "Size", "Duration"},
			[]int{10, 16, 8, 5, 10, max(8, width-tableWidth([]int{10, 16, 8, 5, 10, 0}))},
			rows,
			2,
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
		return renderStyledTable(
			[]string{"Collector", "Status", "Files", "Duration"},
			[]int{16, 10, 7, max(8, width-tableWidth([]int{16, 10, 7, 0}))},
			rows,
			1,
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
		return renderStyledTable(
			[]string{"Collector", "Status", "Duration"},
			[]int{12, 8, max(8, width-tableWidth([]int{12, 8, 0}))},
			rows,
			1,
		)

	default:
		if width < 23 {
			rows := make([][]string, 0, len(results))
			for _, result := range results {
				rows = append(rows, []string{
					fmt.Sprintf("[%s] %s %s", result.Category, result.CollectorName, resultStatus(result)),
				})
			}
			return renderStyledTable(
				[]string{"Collector"},
				[]int{max(1, width-4)},
				rows,
				-1,
			)
		}

		rows := make([][]string, 0, len(results))
		for _, result := range results {
			rows = append(rows, []string{
				fmt.Sprintf("[%s] %s", result.Category, result.CollectorName),
				resultStatus(result),
			})
		}
		return renderStyledTable(
			[]string{"Collector", "Status"},
			[]int{8, max(8, width-tableWidth([]int{8, 0}))},
			rows,
			1,
		)
	}
}

func resultStatus(result module.Result) string {
	if result.Status != "" {
		return strings.ToUpper(result.Status)
	}
	if result.Skipped {
		return "SKIPPED"
	}
	if result.Success {
		return "SUCCESS"
	}
	return "FAILED"
}

func resultError(result module.Result) string {
	if result.Error == "" {
		return "-"
	}
	return sanitizeCell(result.Error)
}

func resultErrorBrief(result module.Result, width int) string {
	if result.Error == "" {
		return "-"
	}
	return trimToWidth(sanitizeCell(result.Error), width)
}

// renderStyledTable draws the same fixed-width ASCII table as renderFixedWidthTable, but
// tints the borders and header row to the TUI palette and colors the cells in statusCol
// using the same status colors the live progress list uses — so a module's SUCCESS/FAILED
// row keeps its color when collection finishes instead of turning plain white. Styles are
// applied after each cell is trimmed and padded, so the ANSI escapes can never disturb
// column alignment. Pass statusCol < 0 to disable cell coloring.
func renderStyledTable(headers []string, widths []int, rows [][]string, statusCol int) string {
	plain := func(int, string) lipgloss.Style { return lipgloss.NewStyle() }
	cellStyle := plain
	if statusCol >= 0 {
		cellStyle = func(col int, value string) lipgloss.Style {
			if col == statusCol {
				return statusCellStyle(value)
			}
			return lipgloss.NewStyle()
		}
	}

	var b strings.Builder
	border := tableBorderStyle.Render(tableBorder(widths))
	b.WriteString(border)
	b.WriteString("\n")
	b.WriteString(styledTableRow(headers, widths, func(int, string) lipgloss.Style { return tableHeaderStyle }))
	b.WriteString("\n")
	b.WriteString(border)
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(styledTableRow(row, widths, cellStyle))
		b.WriteString("\n")
	}
	b.WriteString(border)
	return b.String()
}

func styledTableRow(values []string, widths []int, style func(col int, value string) lipgloss.Style) string {
	var b strings.Builder
	pipe := tableBorderStyle.Render("|")
	b.WriteString(pipe)
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
		b.WriteString(style(idx, value).Render(value))
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" ")
		b.WriteString(pipe)
	}
	return b.String()
}

func statusCellStyle(value string) lipgloss.Style {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "SUCCESS":
		return successCellStyle
	case "FAILED":
		return failureCellStyle
	case "SKIPPED":
		return skippedCellStyle
	default:
		return lipgloss.NewStyle()
	}
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

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func formatTimeout(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
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
