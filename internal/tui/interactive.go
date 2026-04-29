// Package tui implements FIR's interactive Bubble Tea interface.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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
	titleStyle         = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("218"))
	subtleStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	helpStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	selectedStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("218"))
	menuItemStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	focusedRowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color("175"))
	focusedDetailStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color("175"))
	focusedCursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color("175")).Bold(true)
	focusedCheckStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color("175")).Bold(true)
	menuFooterStyle    = FooterBarStyle()
	boxBorderStyle     = PanelBoxStyle()

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

type menuKeyMap struct {
	Up        key.Binding
	Down      key.Binding
	PageUp    key.Binding
	PageDown  key.Binding
	Top       key.Binding
	Bottom    key.Binding
	Toggle    key.Binding
	ToggleAll key.Binding
	Continue  key.Binding
	Back      key.Binding
	Help      key.Binding
	Quit      key.Binding
}

func newMenuKeyMap() menuKeyMap {
	return menuKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("up/k", "move"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("down/j", "move"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "b"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "f"),
			key.WithHelp("pgdn", "page down"),
		),
		Top: key.NewBinding(
			key.WithKeys("home", "g"),
			key.WithHelp("g/home", "top"),
		),
		Bottom: key.NewBinding(
			key.WithKeys("end", "G"),
			key.WithHelp("G/end", "bottom"),
		),
		Toggle: key.NewBinding(
			key.WithKeys(" "),
			key.WithHelp("space", "toggle"),
		),
		ToggleAll: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "all on/off"),
		),
		Continue: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "continue"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "toggle help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

func (k menuKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.PageDown, k.Toggle, k.Help, k.Quit}
}

func (k menuKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PageUp, k.PageDown, k.Top, k.Bottom},
		{k.Toggle, k.ToggleAll},
		{k.Continue, k.Back, k.Help, k.Quit},
	}
}

type menuModel struct {
	spinner spinner.Model
	help    help.Model
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
	completed bool
}

func RunInteractiveMenu() ([]module.Module, error) {
	browser.ConfigureProfiles(nil)
	eventlogpkg.ConfigureSelectedLogs(nil)

	model := newMenuModel()
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())
	finalModel, err := program.Run()
	if err != nil {
		return nil, err
	}

	finished, ok := finalModel.(menuModel)
	if !ok {
		return nil, fmt.Errorf("unexpected interactive model type: %T", finalModel)
	}
	selected, cancelled, err := resolveMenuResults(finished)
	if err != nil {
		return nil, err
	}
	if cancelled {
		return nil, nil
	}
	return selected, nil
}

func NewInteractiveMenuTeaModel() tea.Model {
	browser.ConfigureProfiles(nil)
	eventlogpkg.ConfigureSelectedLogs(nil)
	return newMenuModel()
}

func InteractiveMenuFinished(model tea.Model) (done bool, modules []module.Module, cancelled bool, err error) {
	finished, ok := model.(menuModel)
	if !ok {
		return false, nil, false, fmt.Errorf("unexpected interactive model type: %T", model)
	}
	if !finished.completed && !finished.cancelled {
		return false, nil, false, nil
	}
	modules, cancelled, err = resolveMenuResults(finished)
	return true, modules, cancelled, err
}

func resolveMenuResults(finished menuModel) ([]module.Module, bool, error) {
	if finished.cancelled {
		return nil, true, nil
	}

	selected := finished.moduleResults()
	if len(selected) == 0 {
		return nil, false, nil
	}
	if finished.needsBrowserProfiles() {
		paths := finished.profileResults()
		if len(paths) == 0 {
			return nil, false, fmt.Errorf("browser module selected but no profile paths were chosen")
		}
		browser.ConfigureProfiles(paths)
	}
	if finished.needsEventLogSelection() {
		names := finished.eventLogResults()
		if len(names) == 0 {
			return nil, false, fmt.Errorf("eventlog parser selected but no EVTX files were chosen")
		}
		eventlogpkg.ConfigureSelectedLogs(names)
	}

	return selected, false, nil
}

func newMenuModel() menuModel {
	spin := spinner.New()
	if console.LikelyExplorerLaunch() {
		spin.Spinner = safePinkSpinner
	} else {
		spin.Spinner = spinner.Dot
	}
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("217")).Bold(true)

	var options []moduleOption
	for _, mode := range module.Modes() {
		for _, m := range module.GetByMode(mode) {
			options = append(options, moduleOption{
				module: m,
				mode:   mode,
				title:  fmt.Sprintf("[%s] %s", m.Category(), m.Name()),
				detail: strings.TrimSpace(m.Description()),
			})
		}
	}

	return menuModel{
		spinner:            spin,
		help:               help.New(),
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
	return PollTerminalSizeCmd()
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		if sizeChanged {
			return m, tea.Batch(tea.ClearScreen, PollTerminalSizeCmd())
		}
		return m, PollTerminalSizeCmd()

	case tea.KeyMsg:
		keys := m.keyMap()
		switch {
		case key.Matches(msg, keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			return m, nil
		case key.Matches(msg, keys.Quit):
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

	case tea.MouseMsg:
		return m.updateMouse(msg)

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
			m.status = fmt.Sprintf("Failed to discover browser profiles: %v", msg.err)
			return m, nil
		}
		if len(msg.profiles) == 0 {
			m.phase = phaseCollectors
			m.status = "No browser profiles found on this system."
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
	case "esc":
		m.cancelled = true
		return m, tea.Quit
	case "up", "k":
		m.collectorCursor = moveCursorUp(m.collectorCursor, 1)
	case "down", "j":
		m.collectorCursor = moveCursorDown(m.collectorCursor, len(m.modules), 1)
	case "pgup", "b":
		m.collectorCursor = moveCursorUp(m.collectorCursor, pageStep(m.height))
	case "pgdown", "f":
		m.collectorCursor = moveCursorDown(m.collectorCursor, len(m.modules), pageStep(m.height))
	case "home", "g":
		m.collectorCursor = 0
	case "end", "G":
		m.collectorCursor = maxInt(0, len(m.modules)-1)
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
			m.status = "Discovering browser profiles..."
			return m, tea.Batch(m.spinner.Tick, discoverProfilesCmd())
		}
		if m.needsEventLogSelection() {
			m.phase = phaseLoadingEventLogs
			m.status = "Discovering EVTX files..."
			return m, tea.Batch(m.spinner.Tick, discoverEventLogsCmd())
		}
		m.completed = true
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) updateProfiles(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.profileCursor = moveCursorUp(m.profileCursor, 1)
	case "down", "j":
		m.profileCursor = moveCursorDown(m.profileCursor, len(m.profiles), 1)
	case "pgup", "b":
		m.profileCursor = moveCursorUp(m.profileCursor, pageStep(m.height))
	case "pgdown", "f":
		m.profileCursor = moveCursorDown(m.profileCursor, len(m.profiles), pageStep(m.height))
	case "home", "g":
		m.profileCursor = 0
	case "end", "G":
		m.profileCursor = maxInt(0, len(m.profiles)-1)
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
		m.completed = true
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) updateEventLogs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.eventLogCursor = moveCursorUp(m.eventLogCursor, 1)
	case "down", "j":
		m.eventLogCursor = moveCursorDown(m.eventLogCursor, len(m.eventLogs), 1)
	case "pgup", "b":
		m.eventLogCursor = moveCursorUp(m.eventLogCursor, pageStep(m.height))
	case "pgdown", "f":
		m.eventLogCursor = moveCursorDown(m.eventLogCursor, len(m.eventLogs), pageStep(m.height))
	case "home", "g":
		m.eventLogCursor = 0
	case "end", "G":
		m.eventLogCursor = maxInt(0, len(m.eventLogs)-1)
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
		if m.needsBrowserProfiles() {
			m.phase = phaseProfiles
			m.status = fmt.Sprintf("%d browser profiles selected.", len(m.profileResults()))
			return m, nil
		}
		m.phase = phaseCollectors
		m.status = fmt.Sprintf("%d modules selected.", len(m.moduleResults()))
	case "enter":
		if len(m.eventLogResults()) == 0 {
			m.status = "Select at least one EVTX file."
			return m, nil
		}
		m.completed = true
		return m, tea.Quit
	}

	return m, nil
}

func (m menuModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return "Loading..."
	}

	marginX := 2
	marginY := 1
	width, height := RootViewportSize(m.width, m.height, marginX, marginY)

	header := m.headerView(width)
	footer := m.footerView(width)
	bodyHeight := maxInt(3, height-lipgloss.Height(header)-lipgloss.Height(footer))
	body := m.bodyView(width, bodyHeight)

	ui := lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
	ui = PadViewport(ui, width, height)

	return lipgloss.NewStyle().
		Padding(marginY, marginX).
		Render(ui)
}

func (m menuModel) headerView(width int) string {
	innerWidth := maxInt(10, width-boxBorderStyle.GetHorizontalFrameSize())
	leftWidth, rightWidth := BannerColumnWidths(innerWidth)

	leftLogo := BannerLogoLines()
	rightLines := []string{
		"Machine Info",
		RenderBannerInfoRow("Host", MachineHostname(), rightWidth, menuItemStyle, bannerMutedStyle),
		RenderBannerInfoRow("Platform", MachinePlatform(), rightWidth, menuItemStyle, bannerMutedStyle),
		RenderBannerInfoRow("Phase", m.screenTitle(), rightWidth, menuItemStyle, bannerMutedStyle),
	}

	left := lipgloss.NewStyle().
		Width(leftWidth).
		Align(lipgloss.Left, lipgloss.Top).
		Render(strings.Join([]string{
			bannerLogoStyle.Render(trimToWidth(leftLogo[0], leftWidth)),
			bannerLogoStyle.Render(trimToWidth(leftLogo[1], leftWidth)),
			bannerLogoStyle.Render(trimToWidth(leftLogo[2], leftWidth)),
			bannerTitleStyle.Render(trimToWidth("FIR v"+output.Version, leftWidth)),
			lipgloss.NewStyle().Bold(true).Render(trimToWidth("Freedom Incident Response", leftWidth)),
			bannerMutedStyle.Render(trimToWidth("Interactive module launcher", leftWidth)),
		}, "\n"))

	right := lipgloss.NewStyle().
		Width(rightWidth).
		Align(lipgloss.Left, lipgloss.Top).
		Render(strings.Join([]string{
			bannerTitleStyle.Render(trimToWidth(rightLines[0], rightWidth)),
			trimToWidth(rightLines[1], rightWidth),
			trimToWidth(rightLines[2], rightWidth),
			trimToWidth(rightLines[3], rightWidth),
		}, "\n"))

	row := lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", BannerColumnGap), right)

	return boxBorderStyle.
		Width(maxInt(1, width-2)).
		Height(6).
		Render(row)
}

func (m menuModel) footerView(width int) string {
	innerWidth := maxInt(1, width-menuFooterStyle.GetHorizontalFrameSize())
	statusLine := subtleStyle.Render(trimToWidth(m.status, innerWidth))
	helpLine := helpStyle.Render(trimToWidth(m.help.View(newMenuKeyMap()), innerWidth))
	return menuFooterStyle.
		Width(innerWidth).
		Render(strings.Join([]string{statusLine, helpLine}, "\n"))
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
		fmt.Sprintf("%s Discovering browser profiles...", m.spinner.View()),
		"",
		trimToWidth("Scanning detected browser data roots and enumerating available profiles.", width),
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
		trimToWidth("Enumerating EVTX candidates so the parser only targets files you explicitly choose.", width),
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
	cursorTextStyle := lipgloss.NewStyle()
	if cursor {
		cursorTextStyle = focusedCursorStyle
		cursorText = ">"
	}

	check := "[ ]"
	checkStyle := lipgloss.NewStyle()
	itemStyle := menuItemStyle
	detailStyle := subtleStyle
	if selected {
		check = "[x]"
		checkStyle = selectedStyle
		itemStyle = selectedStyle
	}
	if cursor {
		checkStyle = focusedCheckStyle
		itemStyle = focusedRowStyle
		detailStyle = focusedDetailStyle
	}

	prefix := fmt.Sprintf("%s %s ", cursorTextStyle.Render(cursorText), checkStyle.Render(check))
	available := maxInt(1, width-lipgloss.Width(prefix))
	if available < 16 {
		return prefix + itemStyle.Render(trimToWidth(title, available))
	}

	if strings.TrimSpace(detail) == "" {
		return prefix + itemStyle.Render(trimToWidth(title, available))
	}

	if titleWidth > available-5 {
		titleWidth = maxInt(8, (available*2)/3)
	}
	if titleWidth < 8 {
		titleWidth = 8
	}

	titleText := trimToWidth(title, titleWidth)
	titlePadding := titleWidth - lipgloss.Width(titleText)
	if titlePadding < 0 {
		titlePadding = 0
	}
	row := prefix + itemStyle.Render(titleText) + strings.Repeat(" ", titlePadding)

	detailWidth := available - titleWidth - 1
	if detailWidth > 4 && detail != "" {
		row += " " + detailStyle.Render("-- "+trimToWidth(detail, detailWidth-3))
	}
	return row
}

func (m menuModel) bodyView(width, height int) string {
	if height <= 0 {
		return ""
	}

	innerWidth := maxInt(1, width-boxBorderStyle.GetHorizontalFrameSize())
	innerHeight := maxInt(1, height-boxBorderStyle.GetVerticalFrameSize())
	content := PadViewport(m.bodyContent(innerWidth, innerHeight), innerWidth, innerHeight)
	return boxBorderStyle.
		Width(maxInt(1, width-2)).
		Height(maxInt(1, height-2)).
		Render(content)
}

func (m menuModel) bodyContent(width, height int) string {
	if height <= 0 || width <= 0 {
		return ""
	}

	lines := []string{
		titleStyle.Render(trimToWidth(m.screenTitle(), width)),
		subtleStyle.Render(trimToWidth(m.status, width)),
		"",
	}

	availableRows := maxInt(0, height-len(lines))
	if availableRows <= 0 {
		if height < len(lines) {
			return strings.Join(lines[:height], "\n")
		}
		return strings.Join(lines, "\n")
	}

	var content string
	switch m.phase {
	case phaseLoadingProfiles:
		content = m.renderLoadingProfiles(width, availableRows)
	case phaseProfiles:
		content = m.renderProfiles(width, availableRows)
	case phaseLoadingEventLogs:
		content = m.renderLoadingEventLogs(width, availableRows)
	case phaseEventLogs:
		content = m.renderEventLogs(width, availableRows)
	default:
		content = m.renderCollectors(width, availableRows)
	}

	if strings.TrimSpace(content) != "" {
		lines = append(lines, content)
	}

	return strings.Join(lines, "\n")
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
		if mod.Category() == "browser" {
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
		profiles, err := browser.DiscoverProfiles()
		return profilesLoadedMsg{profiles: profiles, err: err}
	}
}

func discoverEventLogsCmd() tea.Cmd {
	return func() tea.Msg {
		logs, err := eventlogpkg.DiscoverAvailableLogs()
		return eventLogsLoadedMsg{logs: logs, err: err}
	}
}

func moveCursorUp(cursor, step int) int {
	if step < 1 {
		step = 1
	}
	cursor -= step
	if cursor < 0 {
		return 0
	}
	return cursor
}

func moveCursorDown(cursor, total, step int) int {
	if total <= 0 {
		return 0
	}
	if step < 1 {
		step = 1
	}
	cursor += step
	maxCursor := total - 1
	if cursor > maxCursor {
		return maxCursor
	}
	return cursor
}

func pageStep(height int) int {
	step := height / 3
	if step < 5 {
		return 5
	}
	return step
}

func (m menuModel) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	step := 3
	switch {
	case msg.Button == tea.MouseButtonWheelUp || msg.Type == tea.MouseWheelUp:
		switch m.phase {
		case phaseCollectors:
			m.collectorCursor = moveCursorUp(m.collectorCursor, step)
		case phaseProfiles:
			m.profileCursor = moveCursorUp(m.profileCursor, step)
		case phaseEventLogs:
			m.eventLogCursor = moveCursorUp(m.eventLogCursor, step)
		}
	case msg.Button == tea.MouseButtonWheelDown || msg.Type == tea.MouseWheelDown:
		switch m.phase {
		case phaseCollectors:
			m.collectorCursor = moveCursorDown(m.collectorCursor, len(m.modules), step)
		case phaseProfiles:
			m.profileCursor = moveCursorDown(m.profileCursor, len(m.profiles), step)
		case phaseEventLogs:
			m.eventLogCursor = moveCursorDown(m.eventLogCursor, len(m.eventLogs), step)
		}
	}
	return m, nil
}

func (m menuModel) keyMap() menuKeyMap {
	keys := newMenuKeyMap()
	switch m.phase {
	case phaseCollectors:
		keys.Back.SetEnabled(false)
	case phaseLoadingProfiles, phaseLoadingEventLogs:
		keys.Up.SetEnabled(false)
		keys.Down.SetEnabled(false)
		keys.Toggle.SetEnabled(false)
		keys.ToggleAll.SetEnabled(false)
		keys.Continue.SetEnabled(false)
	case phaseProfiles, phaseEventLogs:
		// All bindings remain enabled.
	default:
		keys.Back.SetEnabled(false)
	}
	return keys
}

func (m menuModel) screenTitle() string {
	switch m.phase {
	case phaseLoadingProfiles:
		return "Loading Browser Profiles"
	case phaseProfiles:
		return "Browser Profile Selection"
	case phaseLoadingEventLogs:
		return "Loading EVTX Files"
	case phaseEventLogs:
		return "EVTX File Selection"
	default:
		return "Module Selection"
	}
}
