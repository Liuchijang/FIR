package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/resource"
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
			key.WithHelp(verticalKeysHelp(), "scroll"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
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
		{k.Up, k.PageUp, k.PageDown},
		{k.Top, k.Bottom, k.Help, k.Abort, k.Close},
	}
}

type CollectionProgressModel struct {
	spinner  spinner.Model
	help     help.Model
	viewport viewport.Model

	rows      []progressRow
	outputDir string
	report    *output.SummaryReport
	err       error
	completed bool
	aborting  bool
	workers   string
	width     int
	height    int
}

func NewCollectionProgressModel(collectors []module.Module, workers string) CollectionProgressModel {
	spin := newAdaptiveSpinner()
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("217")).Bold(true)

	rows := make([]progressRow, 0, len(collectors))
	for _, col := range collectors {
		rows = append(rows, progressRow{
			name:     col.Name(),
			category: col.Category(),
			status:   statusWaiting,
		})
	}

	m := CollectionProgressModel{
		spinner:  spin,
		help:     newAdaptiveHelp(),
		viewport: viewport.New(0, 0),
		rows:     rows,
		workers:  workers,
		width:    100,
		height:   28,
	}
	m.syncViewport()
	return m
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
			// Cancellation is signalled to the running collection via the outer model's
			// context.CancelFunc. Do not quit here: collection.Run still needs to write the
			// manifest/summary, compress the output, and remove the raw directory. Quitting
			// immediately would exit the process mid-cleanup, corrupting the evidence archive.
			// The screen stays up until CollectionFinishedMsg arrives and sets m.completed.
			m.aborting = true
			m.syncViewport()
			return m, nil
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
		// The viewport keeps whatever scroll offset the progress list ended on, and the
		// summary report that replaces it is much taller — without this the summary opens
		// part-way down, hiding the info table's first rows. Reset here rather than in
		// syncViewport, which runs on every spinner tick and would fight the user's scrolling.
		m.viewport.GotoTop()
		return m, nil
	}

	return m, nil
}

func (m CollectionProgressModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return "Loading..."
	}
	width, height := chromeSize(m.width, m.height)
	header, footer := m.chromeHeaderFooter(width)
	body := chromePanel(width, chromeBodyHeight(height, header, footer), m.bodyContent)
	return chromeFrame(width, height, header, body, footer)
}

func (m CollectionProgressModel) chromeHeaderFooter(width int) (string, string) {
	footer := chromeFooter(width, m.footerHint(), m.keyMap(), m.help)
	_, height := chromeSize(m.width, m.height)
	header := chromeHeader(width, height-lipgloss.Height(footer), "Interactive collection runner", [][2]string{
		{"Host", MachineHostname()},
		{"Platform", MachinePlatform()},
		{"Phase", m.collectionPhaseTitle()},
		{"State", m.bannerStateSummary()},
	})
	return header, footer
}

func (m CollectionProgressModel) bodyContent(width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}

	lines := m.bodyHeaderLines(width, height)
	if height-len(lines) <= 0 {
		return strings.Join(lines[:min(len(lines), height)], "\n")
	}

	content := m.viewport.View()
	if strings.TrimSpace(content) != "" {
		lines = append(lines, content)
	}

	return strings.Join(lines, "\n")
}

// bodyHeaderLines returns nothing when height leaves no room for both the header
// and rows: the phase title is already in the banner, so under pressure the rows win.
func (m CollectionProgressModel) bodyHeaderLines(width, height int) []string {
	if height < bodyChromeRows+2 {
		return nil
	}

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
	if m.aborting {
		return "Aborting Collection..."
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

	categoryWidth := min(max(width/8, 8), 14)
	nameWidth := min(max(width/5, 10), 24)
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
		details := fmt.Sprintf(
			"files=%d  size=%s  duration=%s",
			len(row.result.FilesCollected),
			resource.FormatBytes(module.TotalSize(row.result.FilesCollected)),
			row.result.Duration.Round(100*time.Millisecond).String(),
		)
		if row.result.Error != "" {
			details += "  warning=" + progressSanitizeError(row.result.Error)
		}
		return details
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
		fmt.Sprintf("Workers: %s", m.workers),
	}
	return strings.Join(parts, "  |  ")
}

func (m *CollectionProgressModel) syncViewport() {
	if m.width == 0 || m.height == 0 {
		return
	}

	width, height := chromeSize(m.width, m.height)
	header, footer := m.chromeHeaderFooter(width)
	bodyHeight := chromeBodyHeight(height, header, footer)
	innerWidth := max(1, width-panelBoxStyle.GetHorizontalFrameSize())
	innerHeight := max(1, bodyHeight-panelBoxStyle.GetVerticalFrameSize())
	bodyHeaderHeight := len(m.bodyHeaderLines(innerWidth, innerHeight))
	m.viewport.Width = max(1, innerWidth)
	m.viewport.Height = max(1, innerHeight-bodyHeaderHeight)

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

func (m CollectionProgressModel) bannerStateSummary() string {
	if m.completed {
		if m.err != nil {
			return "Failed"
		}
		if m.report != nil {
			return fmt.Sprintf(
				"Succeeded: %d | Failed: %d | Total: %d | Workers: %s",
				m.report.SuccessCount,
				m.report.FailureCount,
				m.report.CollectorsTotal,
				m.report.Workers,
			)
		}
		return "Completed"
	}
	if m.aborting {
		return "Aborting..."
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
	if m.aborting {
		return "Aborting: waiting for in-progress modules and archive cleanup to finish before exiting."
	}
	return fmt.Sprintf("Live progress is streamed from running modules. %d modules loaded, %s.", len(m.rows), m.workers)
}

const (
	progressMarginX = 2
	progressMarginY = 1
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
