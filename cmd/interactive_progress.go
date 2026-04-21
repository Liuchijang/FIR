package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/tui"
)

type collectorStatus string

const (
	statusWaiting collectorStatus = "WAITING"
	statusRunning collectorStatus = "RUNNING"
	statusSuccess collectorStatus = "SUCCESS"
	statusFailed  collectorStatus = "FAILED"
)

type progressRow struct {
	name     string
	category string
	status   collectorStatus
	result   *module.Result
}

type outputReadyMsg struct {
	path string
}

type collectorStartedMsg struct {
	index int
}

type collectorFinishedMsg struct {
	index  int
	result module.Result
}

type collectionFinishedMsg struct {
	report output.SummaryReport
	err    error
}

type progressSizePollMsg struct {
	width  int
	height int
}

type collectionProgressModel struct {
	spinner  spinner.Model
	viewport viewport.Model
	updates  chan tea.Msg

	collectors  []module.Module
	rows        []progressRow
	outputDir   string
	report      *output.SummaryReport
	err         error
	completed   bool
	concurrency int
	width       int
	height      int
}

var safePinkSpinnerCmd = spinner.Spinner{
	Frames: []string{"|", "/", "-", "\\"},
	FPS:    time.Second / 10,
}

func runInteractiveCollection(collectors []module.Module) error {
	updates := make(chan tea.Msg)
	console.SyncBufferToWindow()
	model := newCollectionProgressModel(collectors, updates)
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	finalModel, err := program.Run()
	if err != nil {
		return err
	}

	finished, ok := finalModel.(collectionProgressModel)
	if !ok {
		return fmt.Errorf("unexpected collection progress model type: %T", finalModel)
	}
	if finished.err != nil {
		return finished.err
	}
	return nil
}

func newCollectionProgressModel(collectors []module.Module, updates chan tea.Msg) collectionProgressModel {
	spin := spinner.New()
	if console.LikelyExplorerLaunch() {
		spin.Spinner = safePinkSpinnerCmd
	} else {
		spin.Spinner = spinner.Dot
	}
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	rows := make([]progressRow, 0, len(collectors))
	for _, col := range collectors {
		rows = append(rows, progressRow{
			name:     col.Name(),
			category: col.Category(),
			status:   statusWaiting,
		})
	}

	return collectionProgressModel{
		spinner:     spin,
		viewport:    viewport.New(0, 0),
		updates:     updates,
		collectors:  collectors,
		rows:        rows,
		concurrency: concurrencyFlag,
	}
}

func (m collectionProgressModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		startCollectionCmd(m.collectors, m.updates),
		waitForCollectionUpdate(m.updates),
		pollProgressTerminalSizeCmd(),
	)
}

func (m collectionProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sizeChanged := false
		if msg.Width > 0 {
			sizeChanged = sizeChanged || msg.Width != m.width
			m.width = msg.Width
		}
		if msg.Height > 0 {
			sizeChanged = sizeChanged || msg.Height != m.height
			m.height = msg.Height
		}
		console.SyncBufferToWindow()
		m.syncViewport()
		if sizeChanged {
			return m, tea.ClearScreen
		}
		return m, nil

	case progressSizePollMsg:
		sizeChanged := false
		if msg.width > 0 {
			sizeChanged = sizeChanged || msg.width != m.width
			m.width = msg.width
		}
		if msg.height > 0 {
			sizeChanged = sizeChanged || msg.height != m.height
			m.height = msg.height
		}
		console.SyncBufferToWindow()
		m.syncViewport()
		if sizeChanged {
			return m, tea.Batch(tea.ClearScreen, pollProgressTerminalSizeCmd())
		}
		return m, pollProgressTerminalSizeCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "q", "esc", "ctrl+c":
			if m.completed {
				return m, tea.Quit
			}
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
		}

		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case tea.MouseMsg:
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		m.syncViewport()
		return m, cmd

	case outputReadyMsg:
		m.outputDir = msg.path
		m.syncViewport()
		return m, waitForCollectionUpdate(m.updates)

	case collectorStartedMsg:
		if msg.index >= 0 && msg.index < len(m.rows) {
			m.rows[msg.index].status = statusRunning
		}
		m.syncViewport()
		return m, waitForCollectionUpdate(m.updates)

	case collectorFinishedMsg:
		if msg.index >= 0 && msg.index < len(m.rows) {
			m.rows[msg.index].result = &msg.result
			if msg.result.Success {
				m.rows[msg.index].status = statusSuccess
			} else {
				m.rows[msg.index].status = statusFailed
			}
		}
		m.syncViewport()
		return m, waitForCollectionUpdate(m.updates)

	case collectionFinishedMsg:
		m.completed = true
		m.err = msg.err
		if msg.err == nil {
			m.report = &msg.report
		}
		m.syncViewport()
		return m, nil
	}

	return m, nil
}

func (m collectionProgressModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "\nLoading..."
	}

	header := m.headerView()
	body := m.viewport.View()
	if strings.TrimSpace(body) == "" {
		return header
	}
	return strings.Join([]string{header, "", body}, "\n")
}

func (m collectionProgressModel) headerView() string {
	width := maxCmd(1, m.width)
	lines := []string{m.bannerView(width), ""}

	if m.completed {
		if m.err != nil {
			lines = append(lines,
				subtleStyleCmd.Render(trimToWidthCmd("Status: FAILED", width)),
				titleStyleCmd.Render(trimToWidthCmd("Collection Failed", width)),
				errorStyleCmd.Render(trimToWidthCmd(sanitizeErrorCmd(m.err.Error()), width)),
			)
		} else {
			lines = append(lines,
				subtleStyleCmd.Render(trimToWidthCmd(
					fmt.Sprintf("Status: COMPLETE  |  Output: %s", emptyFallbackCmd(m.outputDir, "-")),
					width,
				)),
				titleStyleCmd.Render(trimToWidthCmd("Collection Summary", width)),
			)
		}
	} else {
		lines = append(lines,
			titleStyleCmd.Render(trimToWidthCmd("Collecting Artifacts", width)),
		)
	}

	return strings.Join(lines, "\n")
}

func (m collectionProgressModel) bannerView(width int) string {
	content := tui.BannerContent{
		Version:  output.Version,
		Subtitle: "Interactive collection runner",
	}

	if m.completed {
		content.CenterTitle = "Summary"
		content.CenterLines = []string{
			"Review collection results",
			"Inspect failure details",
			"Close with enter, esc, or q",
		}
		content.RightTitle = "Navigation"
		content.RightLines = []string{
			"mouse/up-down scroll",
			"pgup/pgdn fast scroll",
			"g/G jump top/bottom",
			"enter    exit",
			"esc/q    exit",
		}
	} else {
		content.CenterTitle = "Collection"
		content.CenterLines = []string{
			trimToWidthCmd(m.statusLine(), maxCmd(12, width/3)),
			"Monitor module progress",
			"Wait for collection summary",
		}
		content.RightTitle = "Navigation"
		content.RightLines = []string{
			"mouse/up-down scroll",
			"pgup/pgdn fast scroll",
			"g/G jump top/bottom",
			"ctrl+c   abort",
		}
	}

	return tui.RenderAppBanner(width, content)
}

func (m collectionProgressModel) renderRunningContent(width int) string {
	lines := make([]string, 0, len(m.rows)*2+2)
	for _, row := range m.rows {
		lines = append(lines, m.renderProgressRow(row, width))
	}
	return strings.Join(lines, "\n")
}

func (m collectionProgressModel) renderProgressRow(row progressRow, width int) string {
	statusText := string(row.status)
	statusWidth := 12
	switch row.status {
	case statusRunning:
		statusText = fmt.Sprintf("%s %s", m.spinner.View(), row.status)
	case statusSuccess:
		statusText = successStyleCmd.Render("[OK] " + statusText)
	case statusFailed:
		statusText = errorStyleCmd.Render("[-] " + statusText)
	case statusWaiting:
		statusText = subtleStyleCmd.Render("... " + statusText)
	}

	if width < 32 {
		return trimToWidthCmd(
			fmt.Sprintf("%s [%s] %s", statusText, row.category, row.name),
			width,
		)
	}

	categoryWidth := clampCmd(width/8, 8, 14)
	nameWidth := clampCmd(width/5, 10, 24)

	category := trimToWidthCmd("["+row.category+"]", categoryWidth)
	name := trimToWidthCmd(row.name, nameWidth)

	line := strings.Join([]string{
		padVisibleWidthCmd(statusText, statusWidth),
		padVisibleWidthCmd(category, categoryWidth),
		padVisibleWidthCmd(name, nameWidth),
	}, " ")
	if row.result == nil {
		return trimToWidthCmd(line, width)
	}

	details := sanitizeErrorCmd(m.progressDetails(row))
	detailWidth := width - lipgloss.Width(line) - 2
	if detailWidth <= 4 {
		return trimToWidthCmd(line, width)
	}

	return line + "  " + subtleStyleCmd.Render(trimToWidthCmd(details, detailWidth))
}

func (m collectionProgressModel) progressDetails(row progressRow) string {
	if row.result == nil {
		return ""
	}
	if row.result.Success {
		return fmt.Sprintf(
			"files=%d  size=%s  duration=%s",
			len(row.result.FilesCollected),
			formatBytesCmd(totalSizeCmd(row.result.FilesCollected)),
			row.result.Duration.Round(100*time.Millisecond).String(),
		)
	}
	return fmt.Sprintf(
		"duration=%s  error=%s",
		row.result.Duration.Round(100*time.Millisecond).String(),
		sanitizeErrorCmd(row.result.Error),
	)
}

func (m collectionProgressModel) statusLine() string {
	running := 0
	waiting := 0
	done := 0
	for _, row := range m.rows {
		switch row.status {
		case statusRunning:
			running++
		case statusWaiting:
			waiting++
		default:
			done++
		}
	}

	parts := []string{
		fmt.Sprintf("%s Running: %d", m.spinner.View(), running),
		fmt.Sprintf("Waiting: %d", waiting),
		fmt.Sprintf("Finished: %d/%d", done, len(m.rows)),
		fmt.Sprintf("Concurrency: %d", m.concurrency),
	}
	return strings.Join(parts, "  |  ")
}

func startCollectionCmd(collectors []module.Module, updates chan<- tea.Msg) tea.Cmd {
	return func() tea.Msg {
		go func() {
			report, err := executeCollectionWithOptions(collectors, collectionOptions{
				SilentConsole: true,
				Callbacks: collectionCallbacks{
					OnOutputReady: func(path string) {
						updates <- outputReadyMsg{path: path}
					},
					OnModuleStart: func(index int, _ module.Module) {
						updates <- collectorStartedMsg{index: index}
					},
					OnModuleFinish: func(index int, result module.Result) {
						updates <- collectorFinishedMsg{index: index, result: result}
					},
				},
			})
			updates <- collectionFinishedMsg{report: report, err: err}
			close(updates)
		}()
		return nil
	}
}

func waitForCollectionUpdate(updates <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-updates
		if !ok {
			return nil
		}
		return msg
	}
}

var (
	titleStyleCmd   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87"))
	subtleStyleCmd  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	successStyleCmd = lipgloss.NewStyle().Foreground(lipgloss.Color("79"))
	errorStyleCmd   = lipgloss.NewStyle().Foreground(lipgloss.Color("204"))
)

func sanitizeErrorCmd(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func emptyFallbackCmd(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (m *collectionProgressModel) syncViewport() {
	if m.width == 0 || m.height == 0 {
		return
	}

	m.viewport.Width = maxCmd(1, m.width)

	headerHeight := lipgloss.Height(m.headerView())
	m.viewport.Height = maxCmd(1, m.height-headerHeight-1)

	if m.completed {
		if m.err != nil {
			m.viewport.SetContent("")
			return
		}
		if m.report != nil {
			m.viewport.SetContent(m.report.RenderTerminal(m.viewport.Width))
		}
		return
	}

	m.viewport.SetContent(m.renderRunningContent(m.viewport.Width))
}

func trimToWidthCmd(value string, width int) string {
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

func padVisibleWidthCmd(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func clampCmd(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxCmd(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func totalSizeCmd(files []module.FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

func formatBytesCmd(size int64) string {
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

func pollProgressTerminalSizeCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg {
		width, height, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return nil
		}
		return progressSizePollMsg{width: width, height: height}
	})
}
