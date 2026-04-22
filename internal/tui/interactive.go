// Package tui implements FIR's interactive Bubble Tea interface.
package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/Liuchijang/FIR/internal/collectors/browser"
	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
)

type phase int

const (
	phaseCollectors phase = iota
	phaseLoadingProfiles
	phaseProfiles
	phaseLoadingEventLogs
	phaseEventLogs
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87"))
	subtleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	cursorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("79"))

	categoryStyles = map[string]lipgloss.Style{
		"memory":    lipgloss.NewStyle().Foreground(lipgloss.Color("204")),
		"ntfs":      lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		"execution": lipgloss.NewStyle().Foreground(lipgloss.Color("79")),
		"eventlog":  lipgloss.NewStyle().Foreground(lipgloss.Color("75")),
		"live":      lipgloss.NewStyle().Foreground(lipgloss.Color("221")),
		"registry":  lipgloss.NewStyle().Foreground(lipgloss.Color("111")),
		"system":    lipgloss.NewStyle().Foreground(lipgloss.Color("176")),
		"browser":   lipgloss.NewStyle().Foreground(lipgloss.Color("117")),
	}

	safePinkSpinner = spinner.Spinner{
		Frames: []string{"|", "/", "-", "\\"},
		FPS:    time.Second / 10,
	}
)

type moduleOption struct {
	module module.Module
	mode   string
	title  string
	detail string
}

type profileOption struct {
	profile browser.ChromiumProfile
	title   string
	detail  string
}

type eventLogOption struct {
	name   string
	title  string
	detail string
}

type profilesLoadedMsg struct {
	profiles []browser.ChromiumProfile
	err      error
}

type eventLogsLoadedMsg struct {
	logs []eventlogpkg.EventLogFile
	err  error
}

type sizePollMsg struct {
	width  int
	height int
}

type menuModel struct {
	spinner spinner.Model
	width   int
	height  int

	phase phase

	modules            []moduleOption
	selectedCollectors map[int]bool
	collectorCursor    int

	profiles         []profileOption
	selectedProfiles map[int]bool
	profileCursor    int

	eventLogs         []eventLogOption
	selectedEventLogs map[int]bool
	eventLogCursor    int

	status    string
	cancelled bool
}

func RunInteractiveMenu() ([]module.Module, error) {
	browser.ConfigureChromiumProfiles(nil)
	eventlogpkg.ConfigureSelectedLogs(nil)
	console.SyncBufferToWindow()

	model := newMenuModel()
	program := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := program.Run()
	if err != nil {
		return nil, err
	}

	finished, ok := finalModel.(menuModel)
	if !ok {
		return nil, fmt.Errorf("unexpected interactive model type: %T", finalModel)
	}
	if finished.cancelled {
		return nil, nil
	}

	selected := finished.moduleResults()
	if len(selected) == 0 {
		return nil, nil
	}
	if finished.needsBrowserProfiles() {
		paths := finished.profileResults()
		if len(paths) == 0 {
			return nil, fmt.Errorf("browser module selected but no profile paths were chosen")
		}
		browser.ConfigureChromiumProfiles(paths)
	}
	if finished.needsEventLogSelection() {
		names := finished.eventLogResults()
		if len(names) == 0 {
			return nil, fmt.Errorf("eventlog parser selected but no EVTX files were chosen")
		}
		eventlogpkg.ConfigureSelectedLogs(names)
	}

	return selected, nil
}

func newMenuModel() menuModel {
	spin := spinner.New()
	if console.LikelyExplorerLaunch() {
		spin.Spinner = safePinkSpinner
	} else {
		spin.Spinner = spinner.Dot
	}
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	var options []moduleOption
	for _, mode := range module.Modes() {
		for _, m := range module.GetByMode(mode) {
			options = append(options, moduleOption{
				module: m,
				mode:   mode,
				title:  fmt.Sprintf("[%s] %s", m.Category(), m.Name()),
				detail: shortMenuDescription(m.Description()),
			})
		}
	}

	return menuModel{
		spinner:            spin,
		width:              100,
		height:             28,
		phase:              phaseCollectors,
		modules:            options,
		selectedCollectors: make(map[int]bool),
		selectedProfiles:   make(map[int]bool),
		selectedEventLogs:  make(map[int]bool),
		status:             "Select modules, then press enter to continue.",
	}
}

func (m menuModel) Init() tea.Cmd {
	return pollTerminalSizeCmd()
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		if sizeChanged {
			return m, tea.ClearScreen
		}
		return m, nil

	case sizePollMsg:
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
		if sizeChanged {
			return m, tea.Batch(tea.ClearScreen, pollTerminalSizeCmd())
		}
		return m, pollTerminalSizeCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.cancelled = true
			return m, tea.Quit
		}

		switch m.phase {
		case phaseCollectors:
			return m.updateCollectors(msg)
		case phaseLoadingProfiles:
			if msg.String() == "esc" {
				m.phase = phaseCollectors
				m.status = "Profile loading cancelled. Review modules or press enter again."
				return m, nil
			}
		case phaseProfiles:
			return m.updateProfiles(msg)
		case phaseLoadingEventLogs:
			if msg.String() == "esc" {
				m.phase = phaseCollectors
				m.status = "EVTX discovery cancelled. Review modules or press enter again."
				return m, nil
			}
		case phaseEventLogs:
			return m.updateEventLogs(msg)
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.phase == phaseLoadingProfiles || m.phase == phaseLoadingEventLogs {
			return m, cmd
		}
		return m, nil

	case profilesLoadedMsg:
		if m.phase != phaseLoadingProfiles {
			return m, nil
		}
		if msg.err != nil {
			m.phase = phaseCollectors
			m.status = fmt.Sprintf("Failed to discover Chromium profiles: %v", msg.err)
			return m, nil
		}
		if len(msg.profiles) == 0 {
			m.phase = phaseCollectors
			m.status = "No Chromium profiles found on this system."
			return m, nil
		}

		sort.Slice(msg.profiles, func(i, j int) bool {
			if msg.profiles[i].User == msg.profiles[j].User {
				if msg.profiles[i].Browser == msg.profiles[j].Browser {
					return msg.profiles[i].Name < msg.profiles[j].Name
				}
				return msg.profiles[i].Browser < msg.profiles[j].Browser
			}
			return msg.profiles[i].User < msg.profiles[j].User
		})

		m.phase = phaseProfiles
		m.profileCursor = 0
		m.profiles = make([]profileOption, 0, len(msg.profiles))
		m.selectedProfiles = make(map[int]bool, len(msg.profiles))
		for idx, profile := range msg.profiles {
			m.profiles = append(m.profiles, profileOption{
				profile: profile,
				title:   fmt.Sprintf("[%s] %s | %s", profile.User, profile.Browser, profile.Name),
				detail:  profile.Path,
			})
			m.selectedProfiles[idx] = false
		}
		m.status = "Review browser profiles, then press enter to continue."
		return m, nil

	case eventLogsLoadedMsg:
		if m.phase != phaseLoadingEventLogs {
			return m, nil
		}
		if msg.err != nil {
			m.phase = phaseCollectors
			m.status = fmt.Sprintf("Failed to discover EVTX files: %v", msg.err)
			return m, nil
		}
		if len(msg.logs) == 0 {
			m.phase = phaseCollectors
			m.status = "No EVTX files found on this system."
			return m, nil
		}

		m.phase = phaseEventLogs
		m.eventLogCursor = 0
		m.eventLogs = make([]eventLogOption, 0, len(msg.logs))
		m.selectedEventLogs = make(map[int]bool, len(msg.logs))
		for idx, logFile := range msg.logs {
			m.eventLogs = append(m.eventLogs, eventLogOption{
				name:   logFile.Name,
				title:  logFile.Name,
				detail: "",
			})
			m.selectedEventLogs[idx] = false
		}
		m.status = "Review EVTX files, then press enter to continue."
		return m, nil
	}

	return m, nil
}

func (m menuModel) updateCollectors(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.collectorCursor > 0 {
			m.collectorCursor--
		}
	case "down", "j":
		if m.collectorCursor < len(m.modules)-1 {
			m.collectorCursor++
		}
	case " ":
		if len(m.modules) > 0 {
			m.selectedCollectors[m.collectorCursor] = !m.selectedCollectors[m.collectorCursor]
			m.status = fmt.Sprintf("%d modules selected.", len(m.moduleResults()))
		}
	case "a":
		allSelected := len(m.modules) > 0
		for idx := range m.modules {
			if !m.selectedCollectors[idx] {
				allSelected = false
				break
			}
		}
		for idx := range m.modules {
			m.selectedCollectors[idx] = !allSelected
		}
		if allSelected {
			m.status = "Module selection cleared."
		} else {
			m.status = fmt.Sprintf("Selected all %d modules.", len(m.modules))
		}
	case "enter":
		if len(m.moduleResults()) == 0 {
			m.status = "Select at least one module."
			return m, nil
		}
		if m.needsBrowserProfiles() {
			m.phase = phaseLoadingProfiles
			m.status = "Discovering Chromium profiles..."
			return m, tea.Batch(m.spinner.Tick, discoverProfilesCmd())
		}
		if m.needsEventLogSelection() {
			m.phase = phaseLoadingEventLogs
			m.status = "Discovering EVTX files..."
			return m, tea.Batch(m.spinner.Tick, discoverEventLogsCmd())
		}
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) updateProfiles(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.profileCursor > 0 {
			m.profileCursor--
		}
	case "down", "j":
		if m.profileCursor < len(m.profiles)-1 {
			m.profileCursor++
		}
	case " ":
		if len(m.profiles) > 0 {
			m.selectedProfiles[m.profileCursor] = !m.selectedProfiles[m.profileCursor]
			m.status = fmt.Sprintf("%d browser profiles selected.", len(m.profileResults()))
		}
	case "a":
		allSelected := len(m.profiles) > 0
		for idx := range m.profiles {
			if !m.selectedProfiles[idx] {
				allSelected = false
				break
			}
		}
		for idx := range m.profiles {
			m.selectedProfiles[idx] = !allSelected
		}
		if allSelected {
			m.status = "Browser profile selection cleared."
		} else {
			m.status = fmt.Sprintf("Selected all %d browser profiles.", len(m.profiles))
		}
	case "esc":
		m.phase = phaseCollectors
		m.status = fmt.Sprintf("%d modules selected.", len(m.moduleResults()))
	case "enter":
		if len(m.profileResults()) == 0 {
			m.status = "Select at least one browser profile."
			return m, nil
		}
		if m.needsEventLogSelection() {
			m.phase = phaseLoadingEventLogs
			m.status = "Discovering EVTX files..."
			return m, tea.Batch(m.spinner.Tick, discoverEventLogsCmd())
		}
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) updateEventLogs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.eventLogCursor > 0 {
			m.eventLogCursor--
		}
	case "down", "j":
		if m.eventLogCursor < len(m.eventLogs)-1 {
			m.eventLogCursor++
		}
	case " ":
		if len(m.eventLogs) > 0 {
			m.selectedEventLogs[m.eventLogCursor] = !m.selectedEventLogs[m.eventLogCursor]
			m.status = fmt.Sprintf("%d EVTX files selected.", len(m.eventLogResults()))
		}
	case "a":
		allSelected := len(m.eventLogs) > 0
		for idx := range m.eventLogs {
			if !m.selectedEventLogs[idx] {
				allSelected = false
				break
			}
		}
		for idx := range m.eventLogs {
			m.selectedEventLogs[idx] = !allSelected
		}
		if allSelected {
			m.status = "EVTX selection cleared."
		} else {
			m.status = fmt.Sprintf("Selected all %d EVTX files.", len(m.eventLogs))
		}
	case "esc":
		m.phase = phaseCollectors
		m.status = fmt.Sprintf("%d modules selected.", len(m.moduleResults()))
	case "enter":
		if len(m.eventLogResults()) == 0 {
			m.status = "Select at least one EVTX file."
			return m, nil
		}
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) View() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	width = maxInt(24, width)
	height := m.height
	if height <= 0 {
		height = 24
	}

	header := m.headerView(width)
	layout := MeasureScreenLayout(width, height, header)
	body := m.bodyView(width, layout.ContentHeight)
	return RenderScreen(layout, header, body)
}

func (m menuModel) headerView(width int) string {
	sections := []string{
		m.bannerView(width),
		"",
		titleStyle.Render("Module Selection"),
		subtleStyle.Render(wrapMessage(m.status, width)),
		helpStyle.Render(wrapMessage("Controls: up/down move, space toggle, a select all, enter continue, esc/q quit.", width)),
	}
	return strings.Join(sections, "\n")
}

func (m menuModel) renderCollectors(width, height int) string {
	titleWidth := m.collectorTitleWidth(width)
	lines := make([]string, 0, len(m.modules)+4)
	lineByCollector := make([]int, len(m.modules))
	lastMode := ""
	for idx := range m.modules {
		item := m.modules[idx]
		if item.mode != lastMode {
			if lastMode != "" {
				lines = append(lines, "")
			}
			lines = append(lines, titleStyle.Render(module.ModeDirName(item.mode)))
			lastMode = item.mode
		}
		lineByCollector[idx] = len(lines)
		lines = append(lines, renderSelectableRow(
			idx == m.collectorCursor,
			m.selectedCollectors[idx],
			item.title,
			item.detail,
			item.module.Category(),
			width,
			titleWidth,
		))
	}
	return m.renderWindowedLines(lines, lineByCollector, m.collectorCursor, m.bodyRowsAvailable(height))
}

func (m menuModel) renderLoadingProfiles(width, _ int) string {
	lines := []string{
		fmt.Sprintf("%s Discovering Chromium profiles...", m.spinner.View()),
		"",
		wrapMessage("Press esc to return to collector selection.", width),
	}
	return strings.Join(lines, "\n")
}

func (m menuModel) renderProfiles(width, height int) string {
	titleWidth := m.profileTitleWidth(width)
	return m.renderWindowedOptions(len(m.profiles), m.profileCursor, m.bodyRowsAvailable(height), func(idx int) string {
		return renderSelectableRow(
			idx == m.profileCursor,
			m.selectedProfiles[idx],
			m.profiles[idx].title,
			m.profiles[idx].detail,
			"browser",
			width,
			titleWidth,
		)
	})
}

func (m menuModel) renderLoadingEventLogs(width, _ int) string {
	lines := []string{
		fmt.Sprintf("%s Discovering EVTX files...", m.spinner.View()),
		"",
		wrapMessage("Press esc to return to module selection.", width),
	}
	return strings.Join(lines, "\n")
}

func (m menuModel) renderEventLogs(width, height int) string {
	titleWidth := m.columnTitleWidth(width, width)
	return m.renderWindowedOptions(len(m.eventLogs), m.eventLogCursor, m.bodyRowsAvailable(height), func(idx int) string {
		return renderSelectableRow(
			idx == m.eventLogCursor,
			m.selectedEventLogs[idx],
			m.eventLogs[idx].title,
			m.eventLogs[idx].detail,
			"eventlog",
			width,
			titleWidth,
		)
	})
}

func (m menuModel) collectorTitleWidth(width int) int {
	maxWidth := 0
	for _, item := range m.modules {
		itemWidth := lipgloss.Width(item.title)
		if itemWidth > maxWidth {
			maxWidth = itemWidth
		}
	}
	return m.columnTitleWidth(width, maxWidth)
}

func (m menuModel) profileTitleWidth(width int) int {
	maxWidth := 0
	for _, item := range m.profiles {
		itemWidth := lipgloss.Width(item.title)
		if itemWidth > maxWidth {
			maxWidth = itemWidth
		}
	}
	return m.columnTitleWidth(width, maxWidth)
}

func (m menuModel) columnTitleWidth(width, longestTitle int) int {
	available := maxInt(1, width-7)
	minWidth := 18
	if available < minWidth {
		minWidth = maxInt(8, available/2)
	}
	maxWidth := available - 2
	if maxWidth < minWidth {
		maxWidth = minWidth
	}
	preferred := longestTitle + 2
	if preferred > (available*9)/10 {
		preferred = (available * 9) / 10
	}
	if preferred < minWidth {
		preferred = minWidth
	}
	return clampInt(preferred, minWidth, maxWidth)
}

func (m menuModel) renderOptions(total int, render func(int) string) string {
	lines := make([]string, 0, total)
	for idx := 0; idx < total; idx++ {
		lines = append(lines, render(idx))
	}
	return strings.Join(lines, "\n")
}

func (m menuModel) renderWindowedOptions(total, cursor, visibleRows int, render func(int) string) string {
	if total == 0 {
		return ""
	}
	if visibleRows <= 0 {
		return ""
	}
	if visibleRows >= total {
		return m.renderOptions(total, render)
	}

	start := cursor - visibleRows/2
	if start < 0 {
		start = 0
	}
	end := start + visibleRows
	if end > total {
		end = total
		start = maxInt(0, end-visibleRows)
	}

	lines := make([]string, 0, end-start+2)
	if start > 0 {
		lines = append(lines, subtleStyle.Render(fmt.Sprintf("... %d items above ...", start)))
	}
	for idx := start; idx < end; idx++ {
		lines = append(lines, render(idx))
	}
	if end < total {
		lines = append(lines, subtleStyle.Render(fmt.Sprintf("... %d items below ...", total-end)))
	}
	return strings.Join(lines, "\n")
}

func (m menuModel) renderWindowedLines(lines []string, lineByItem []int, cursor, visibleRows int) string {
	total := len(lines)
	if total == 0 {
		return ""
	}
	if visibleRows <= 0 {
		return ""
	}
	if visibleRows >= total {
		return strings.Join(lines, "\n")
	}

	cursorLine := 0
	if cursor >= 0 && cursor < len(lineByItem) {
		cursorLine = lineByItem[cursor]
	}

	start := cursorLine - visibleRows/2
	if start < 0 {
		start = 0
	}
	end := start + visibleRows
	if end > total {
		end = total
		start = maxInt(0, end-visibleRows)
	}

	window := make([]string, 0, end-start+2)
	if start > 0 {
		window = append(window, subtleStyle.Render(fmt.Sprintf("... %d lines above ...", start)))
	}
	window = append(window, lines[start:end]...)
	if end < total {
		window = append(window, subtleStyle.Render(fmt.Sprintf("... %d lines below ...", total-end)))
	}
	return strings.Join(window, "\n")
}

func (m menuModel) bodyRowsAvailable(height int) int {
	if height < 0 {
		return 0
	}
	return height
}

func renderSelectableRow(cursor, selected bool, title, detail, category string, width, titleWidth int) string {
	cursorText := " "
	if cursor {
		cursorText = cursorStyle.Render(">")
	}

	check := "[ ]"
	checkStyle := lipgloss.NewStyle()
	if selected {
		check = "[x]"
		checkStyle = selectedStyle
	}

	style, ok := categoryStyles[category]
	if !ok {
		style = lipgloss.NewStyle()
	}

	prefix := fmt.Sprintf("%s %s ", cursorText, checkStyle.Render(check))
	available := maxInt(1, width-lipgloss.Width(prefix))
	if available < 16 {
		return prefix + style.Render(trimToWidth(title, available))
	}

	if strings.TrimSpace(detail) == "" {
		return prefix + style.Render(trimToWidth(title, available))
	}

	if titleWidth > available-5 {
		titleWidth = maxInt(8, (available*2)/3)
	}
	if titleWidth < 8 {
		titleWidth = 8
	}

	titleText := padRight(trimToWidth(title, titleWidth), titleWidth)
	row := prefix + style.Render(titleText)

	detailWidth := available - titleWidth - 1
	if detailWidth > 4 && detail != "" {
		row += " " + subtleStyle.Render("-- "+trimToWidth(detail, detailWidth-3))
	}
	return row
}

func shortMenuDescription(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 44 {
		return value
	}
	return strings.TrimSpace(value[:41]) + "..."
}

func (m menuModel) bodyView(width, height int) string {
	switch m.phase {
	case phaseCollectors:
		return m.renderCollectors(width, height)
	case phaseLoadingProfiles:
		return m.renderLoadingProfiles(width, height)
	case phaseProfiles:
		return m.renderProfiles(width, height)
	case phaseLoadingEventLogs:
		return m.renderLoadingEventLogs(width, height)
	case phaseEventLogs:
		return m.renderEventLogs(width, height)
	default:
		return ""
	}
}

func (m menuModel) bannerView(width int) string {
	return RenderAppBanner(width, BannerContent{
		Version:     output.Version,
		Subtitle:    "Interactive module launcher",
		CenterTitle: "Welcome",
		CenterLines: []string{"Choose modules", "Review browser profiles", "Run collection"},
		RightTitle:  "Controls",
		RightLines:  []string{"up/down  move", "space    toggle", "a        all", "enter    continue", "esc/q    quit"},
	})
}

func (m menuModel) moduleResults() []module.Module {
	var selected []module.Module
	for idx, item := range m.modules {
		if m.selectedCollectors[idx] {
			selected = append(selected, item.module)
		}
	}
	return selected
}

func (m menuModel) profileResults() []string {
	var selected []string
	for idx, item := range m.profiles {
		if m.selectedProfiles[idx] {
			selected = append(selected, item.profile.Path)
		}
	}
	return selected
}

func (m menuModel) eventLogResults() []string {
	var selected []string
	for idx, item := range m.eventLogs {
		if m.selectedEventLogs[idx] {
			selected = append(selected, item.name)
		}
	}
	return selected
}

func (m menuModel) needsBrowserProfiles() bool {
	for _, mod := range m.moduleResults() {
		if mod.Name() == browser.ChromiumCollectorName {
			return true
		}
	}
	return false
}

func (m menuModel) needsEventLogSelection() bool {
	for _, mod := range m.moduleResults() {
		if mod.Name() == "eventlog_parser" {
			return true
		}
	}
	return false
}

func discoverProfilesCmd() tea.Cmd {
	return func() tea.Msg {
		profiles, err := browser.DiscoverChromiumProfiles()
		return profilesLoadedMsg{profiles: profiles, err: err}
	}
}

func discoverEventLogsCmd() tea.Cmd {
	return func() tea.Msg {
		logs, err := eventlogpkg.DiscoverAvailableLogs()
		return eventLogsLoadedMsg{logs: logs, err: err}
	}
}

func pollTerminalSizeCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg {
		width, height, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return nil
		}
		return sizePollMsg{width: width, height: height}
	})
}

func padRight(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}
