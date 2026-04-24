package tui

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
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

type OutputReadyMsg struct {
	Path string
}

type CollectorStartedMsg struct {
	Index int
}

type CollectorFinishedMsg struct {
	Index  int
	Result module.Result
}

type CollectionFinishedMsg struct {
	Report output.SummaryReport
	Err    error
}

type progressKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding
	Help     key.Binding
	Abort    key.Binding
	Close    key.Binding
}

func newProgressKeyMap(completed bool) progressKeyMap {
	keys := progressKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/↓", "scroll up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("down/j", "scroll down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "b"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "f", " "),
			key.WithHelp("pgdn", "page down"),
		),
		Top: key.NewBinding(
			key.WithKeys("g", "home"),
			key.WithHelp("g", "top"),
		),
		Bottom: key.NewBinding(
			key.WithKeys("G", "end"),
			key.WithHelp("G", "bottom"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "toggle help"),
		),
		Abort: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", "abort"),
		),
		Close: key.NewBinding(
			key.WithKeys("enter", "q", "esc", "ctrl+c"),
			key.WithHelp("enter", "close"),
		),
	}
	if completed {
		keys.Abort.SetEnabled(false)
	} else {
		keys.Close.SetEnabled(false)
	}
	return keys
}

func (k progressKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.PageDown, k.Help, k.Abort, k.Close}
}

func (k progressKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PageUp, k.PageDown},
		{k.Top, k.Bottom, k.Help, k.Abort, k.Close},
	}
}

type CollectionProgressModel struct {
	spinner  spinner.Model
	help     help.Model
	viewport viewport.Model

	rows        []progressRow
	outputDir   string
	report      *output.SummaryReport
	err         error
	completed   bool
	concurrency int
	width       int
	height      int
}

func NewCollectionProgressModel(collectors []module.Module, concurrency int) CollectionProgressModel {
	spin := spinner.New()
	if console.LikelyExplorerLaunch() {
		spin.Spinner = safePinkSpinner
	} else {
		spin.Spinner = spinner.Dot
	}
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("217")).Bold(true)

	rows := make([]progressRow, 0, len(collectors))
	for _, col := range collectors {
		rows = append(rows, progressRow{
			name:     col.Name(),
			category: col.Category(),
			status:   statusWaiting,
		})
	}

	return CollectionProgressModel{
		spinner:     spin,
		help:        help.New(),
		viewport:    viewport.New(0, 0),
		rows:        rows,
		concurrency: concurrency,
	}
}

func (m CollectionProgressModel) RunError() error {
	return m.err
}

func (m CollectionProgressModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		PollTerminalSizeCmd(),
	)
}

func (m CollectionProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sizeChanged := false
		if msg.Width > 0 {
			sizeChanged = sizeChanged || msg.Width != m.width
			m.width = msg.Width
			m.help.Width = msg.Width
		}
		if msg.Height > 0 {
			sizeChanged = sizeChanged || msg.Height != m.height
			m.height = msg.Height
		}
		m.syncViewport()
		if sizeChanged {
			return m, tea.Batch(tea.ClearScreen, PollTerminalSizeCmd())
		}
		return m, PollTerminalSizeCmd()

	case tea.KeyMsg:
		keys := m.keyMap()
		switch {
		case key.Matches(msg, keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			m.syncViewport()
			return m, nil
		case m.completed && key.Matches(msg, keys.Close):
			return m, tea.Quit
		case !m.completed && key.Matches(msg, keys.Abort):
			return m, tea.Quit
		}

		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case tea.MouseMsg:
		switch {
		case msg.Button == tea.MouseButtonWheelUp || msg.Type == tea.MouseWheelUp:
			m.viewport.LineUp(3)
			return m, nil
		case msg.Button == tea.MouseButtonWheelDown || msg.Type == tea.MouseWheelDown:
			m.viewport.LineDown(3)
			return m, nil
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		m.syncViewport()
		return m, cmd

	case OutputReadyMsg:
		m.outputDir = msg.Path
		m.syncViewport()
		return m, nil

	case CollectorStartedMsg:
		if msg.Index >= 0 && msg.Index < len(m.rows) {
			m.rows[msg.Index].status = statusRunning
		}
		m.syncViewport()
		return m, nil

	case CollectorFinishedMsg:
		if msg.Index >= 0 && msg.Index < len(m.rows) {
			m.rows[msg.Index].result = &msg.Result
			if msg.Result.Success {
				m.rows[msg.Index].status = statusSuccess
			} else {
				m.rows[msg.Index].status = statusFailed
			}
		}
		m.syncViewport()
		return m, nil

	case CollectionFinishedMsg:
		m.completed = true
		m.err = msg.Err
		if msg.Err == nil {
			m.report = &msg.Report
		}
		m.syncViewport()
		return m, nil
	}

	return m, nil
}

func (m CollectionProgressModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "\nLoading..."
	}

	width, height := m.rootSize()
	header := m.headerViewWithWidth(width)
	footer := m.footerViewWithWidth(width)
	bodyHeight := maxInt(3, height-lipgloss.Height(header)-lipgloss.Height(footer))
	body := m.bodyView(width, bodyHeight)
	screen := lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
	screen = PadViewport(screen, width, height)
	return lipgloss.NewStyle().
		Padding(progressMarginY, progressMarginX).
		Render(screen)
}

func (m CollectionProgressModel) headerViewWithWidth(width int) string {
	innerWidth := maxInt(10, width-panelBoxStyle.GetHorizontalFrameSize())
	leftWidth, rightWidth := BannerColumnWidths(innerWidth)

	leftLogo := BannerLogoLines()
	rightLines := []string{
		"Machine Info",
		RenderBannerInfoRow("Host", MachineHostname(), rightWidth, progressBannerLabelStyle, progressBannerValueStyle),
		RenderBannerInfoRow("Platform", runtime.GOOS+"/"+runtime.GOARCH, rightWidth, progressBannerLabelStyle, progressBannerValueStyle),
		RenderBannerInfoRow("Phase", m.collectionPhaseTitle(), rightWidth, progressBannerLabelStyle, progressBannerValueStyle),
		RenderBannerInfoRow("State", m.bannerStateSummary(), rightWidth, progressBannerLabelStyle, progressBannerValueStyle),
	}

	left := lipgloss.NewStyle().
		Width(leftWidth).
		Align(lipgloss.Left, lipgloss.Top).
		Render(strings.Join([]string{
			titleStyle.Render(trimToWidth(leftLogo[0], leftWidth)),
			titleStyle.Render(trimToWidth(leftLogo[1], leftWidth)),
			titleStyle.Render(trimToWidth(leftLogo[2], leftWidth)),
			bannerTitleStyle.Render(trimToWidth("FIR v"+output.Version, leftWidth)),
			lipgloss.NewStyle().Bold(true).Render(trimToWidth("Freedom Incident Response", leftWidth)),
			bannerMutedStyle.Render(trimToWidth("Interactive collection runner", leftWidth)),
		}, "\n"))

	right := lipgloss.NewStyle().
		Width(rightWidth).
		Align(lipgloss.Left, lipgloss.Top).
		Render(renderProgressBannerLines(rightLines, rightWidth))

	row := lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", BannerColumnGap), right)
	return panelBoxStyle.
		Width(maxInt(1, width-2)).
		Height(6).
		Render(row)
}

func (m CollectionProgressModel) footerViewWithWidth(width int) string {
	width = maxInt(1, width)
	helpWidth := maxInt(1, width-footerBarStyle.GetHorizontalFrameSize())

	helpModel := m.help
	helpModel.Width = helpWidth

	lines := make([]string, 0, 2)
	if hint := m.footerHint(); hint != "" {
		lines = append(lines, subtleStyle.Render(trimToWidth(hint, helpWidth)))
	}
	if helpView := helpModel.View(m.keyMap()); helpView != "" {
		lines = append(lines, helpView)
	}
	innerWidth := maxInt(1, width-footerBarStyle.GetHorizontalFrameSize())
	return footerBarStyle.Width(innerWidth).Render(strings.Join(lines, "\n"))
}

func (m CollectionProgressModel) bodyView(width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	innerWidth := maxInt(1, width-panelBoxStyle.GetHorizontalFrameSize())
	innerHeight := maxInt(1, height-panelBoxStyle.GetVerticalFrameSize())
	content := PadViewport(m.bodyContent(innerWidth, innerHeight), innerWidth, innerHeight)
	return panelBoxStyle.
		Width(maxInt(1, width-2)).
		Height(maxInt(1, height-2)).
		Render(content)
}

func (m CollectionProgressModel) bodyContent(width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}

	lines := m.bodyHeaderLines(width)
	availableRows := maxInt(0, height-len(lines))
	if availableRows <= 0 {
		if height < len(lines) {
			return strings.Join(lines[:height], "\n")
		}
		return strings.Join(lines, "\n")
	}

	content := m.viewport.View()
	if strings.TrimSpace(content) != "" {
		lines = append(lines, content)
	}

	return strings.Join(lines, "\n")
}

func (m CollectionProgressModel) bodyHeaderLines(width int) []string {
	lines := []string{
		titleStyle.Render(trimToWidth(m.collectionPhaseTitle(), width)),
	}

	if m.completed {
		if m.err != nil {
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("175")).Render(trimToWidth(progressSanitizeError(m.err.Error()), width)))
		} else {
			lines = append(lines, subtleStyle.Render(trimToWidth(
				fmt.Sprintf("Output: %s", progressEmptyFallback(m.outputDir, "-")),
				width,
			)))
		}
	}

	lines = append(lines, "")
	return lines
}

func (m CollectionProgressModel) collectionPhaseTitle() string {
	if m.completed {
		if m.err != nil {
			return "Collection Failed"
		}
		return "Collection Summary"
	}
	return "Collecting Artifacts"
}

func (m CollectionProgressModel) renderRunningContent(width int) string {
	lines := make([]string, 0, len(m.rows)*2+2)
	for _, row := range m.rows {
		lines = append(lines, m.renderProgressRow(row, width))
	}
	return strings.Join(lines, "\n")
}

func (m CollectionProgressModel) renderProgressRow(row progressRow, width int) string {
	statusText := string(row.status)
	statusWidth := 12
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("182"))
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("175"))
	switch row.status {
	case statusRunning:
		statusText = fmt.Sprintf("%s %s", m.spinner.View(), row.status)
	case statusSuccess:
		statusText = successStyle.Render("[OK] " + statusText)
	case statusFailed:
		statusText = errorStyle.Render("[-] " + statusText)
	case statusWaiting:
		statusText = subtleStyle.Render("... " + statusText)
	}

	if width < 32 {
		return trimToWidth(
			fmt.Sprintf("%s [%s] %s", statusText, row.category, row.name),
			width,
		)
	}

	categoryWidth := clampInt(width/8, 8, 14)
	nameWidth := clampInt(width/5, 10, 24)
	category := trimToWidth("["+row.category+"]", categoryWidth)
	name := trimToWidth(row.name, nameWidth)

	line := strings.Join([]string{
		progressPadVisibleWidth(statusText, statusWidth),
		progressPadVisibleWidth(category, categoryWidth),
		progressPadVisibleWidth(name, nameWidth),
	}, " ")
	if row.result == nil {
		return trimToWidth(line, width)
	}

	details := progressSanitizeError(m.progressDetails(row))
	detailWidth := width - lipgloss.Width(line) - 2
	if detailWidth <= 4 {
		return trimToWidth(line, width)
	}

	return line + "  " + subtleStyle.Render(trimToWidth(details, detailWidth))
}

func (m CollectionProgressModel) progressDetails(row progressRow) string {
	if row.result == nil {
		return ""
	}
	if row.result.Success {
		return fmt.Sprintf(
			"files=%d  size=%s  duration=%s",
			len(row.result.FilesCollected),
			progressFormatBytes(progressTotalSize(row.result.FilesCollected)),
			row.result.Duration.Round(100*time.Millisecond).String(),
		)
	}
	return fmt.Sprintf(
		"duration=%s  error=%s",
		row.result.Duration.Round(100*time.Millisecond).String(),
		progressSanitizeError(row.result.Error),
	)
}

func (m CollectionProgressModel) statusLine() string {
	running, waiting, done := m.statusCounts()
	parts := []string{
		fmt.Sprintf("%s Running: %d", m.spinner.View(), running),
		fmt.Sprintf("Waiting: %d", waiting),
		fmt.Sprintf("Finished: %d/%d", done, len(m.rows)),
		fmt.Sprintf("Concurrency: %d", m.concurrency),
	}
	return strings.Join(parts, "  |  ")
}

func (m *CollectionProgressModel) syncViewport() {
	if m.width == 0 || m.height == 0 {
		return
	}

	width, height := m.rootSize()
	header := m.headerViewWithWidth(width)
	footer := m.footerViewWithWidth(width)
	bodyHeight := maxInt(3, height-lipgloss.Height(header)-lipgloss.Height(footer))
	innerWidth := maxInt(1, width-panelBoxStyle.GetHorizontalFrameSize())
	innerHeight := maxInt(1, bodyHeight-panelBoxStyle.GetVerticalFrameSize())
	bodyHeaderHeight := lipgloss.Height(strings.Join(m.bodyHeaderLines(innerWidth), "\n"))
	m.viewport.Width = maxInt(1, innerWidth)
	m.viewport.Height = maxInt(1, innerHeight-bodyHeaderHeight)

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

func (m CollectionProgressModel) rootSize() (int, int) {
	return RootViewportSize(m.width, m.height, progressMarginX, progressMarginY)
}

func renderProgressBannerLines(lines []string, width int) string {
	if len(lines) == 0 {
		return ""
	}

	rendered := make([]string, 0, len(lines))
	for idx, line := range lines {
		line = trimToWidth(line, width)
		if idx == 0 {
			rendered = append(rendered, bannerTitleStyle.Render(line))
			continue
		}
		rendered = append(rendered, line)
	}
	return strings.Join(rendered, "\n")
}

func (m CollectionProgressModel) bannerStateSummary() string {
	if m.completed {
		if m.err != nil {
			return "Failed"
		}
		if m.report != nil {
			return fmt.Sprintf(
				"Succeeded: %d | Failed: %d | Total: %d | Concurrency: %d",
				m.report.SuccessCount,
				m.report.FailureCount,
				m.report.CollectorsTotal,
				m.report.Concurrency,
			)
		}
		return "Completed"
	}
	return m.statusLine()
}

func (m CollectionProgressModel) statusCounts() (running, waiting, done int) {
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
	return running, waiting, done
}

func (m CollectionProgressModel) keyMap() progressKeyMap {
	return newProgressKeyMap(m.completed)
}

func (m CollectionProgressModel) footerHint() string {
	if m.completed {
		if m.err != nil {
			return "Collection stopped with an error. Review the message above, then close this screen."
		}
		if m.report != nil {
			return fmt.Sprintf("Completed: %d succeeded, %d failed. Scroll to inspect the rendered summary report.", m.report.SuccessCount, m.report.FailureCount)
		}
		return "Collection completed. Close this screen when you are done reviewing the output."
	}
	return fmt.Sprintf("Live progress is streamed from running modules. %d collectors loaded with concurrency=%d.", len(m.rows), m.concurrency)
}

const (
	progressMarginX = 2
	progressMarginY = 1
)

var (
	progressBannerLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)
	progressBannerValueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true)
)

func progressSanitizeError(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func progressEmptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func progressPadVisibleWidth(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func progressTotalSize(files []module.FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

func progressFormatBytes(size int64) string {
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
