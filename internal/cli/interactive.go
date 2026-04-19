// Package cli implements the interactive Bubble Tea interface for FIR.
package cli

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

	"github.com/Liuchijang/FIR/internal/browser"
	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/ui"
)

type phase int

const (
	phaseCollectors phase = iota
	phaseLoadingProfiles
	phaseProfiles
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

type collectorOption struct {
	collector collector.Collector
	title     string
	detail    string
}

type profileOption struct {
	profile browser.ChromiumProfile
	title   string
	detail  string
}

type profilesLoadedMsg struct {
	profiles []browser.ChromiumProfile
	err      error
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

	collectors         []collectorOption
	selectedCollectors map[int]bool
	collectorCursor    int

	profiles         []profileOption
	selectedProfiles map[int]bool
	profileCursor    int

	status    string
	cancelled bool
}

func RunInteractiveMenu() ([]collector.Collector, error) {
	browser.ConfigureChromiumProfiles(nil)
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

	selected := finished.collectorResults()
	if len(selected) == 0 {
		return nil, nil
	}
	if finished.needsBrowserProfiles() {
		paths := finished.profileResults()
		if len(paths) == 0 {
			return nil, fmt.Errorf("browser collector selected but no profile paths were chosen")
		}
		browser.ConfigureChromiumProfiles(paths)
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

	var options []collectorOption
	for _, category := range collector.Categories() {
		for _, c := range collector.GetByCategory(category) {
			options = append(options, collectorOption{
				collector: c,
				title:     fmt.Sprintf("[%s] %s", c.Category(), c.Name()),
				detail:    c.Description(),
			})
		}
	}

	return menuModel{
		spinner:            spin,
		width:              100,
		height:             28,
		phase:              phaseCollectors,
		collectors:         options,
		selectedCollectors: make(map[int]bool),
		selectedProfiles:   make(map[int]bool),
		status:             "Select collectors, then press enter to continue.",
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
				m.status = "Profile loading cancelled. Review collectors or press enter again."
				return m, nil
			}
		case phaseProfiles:
			return m.updateProfiles(msg)
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.phase == phaseLoadingProfiles {
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
			m.selectedProfiles[idx] = true
		}
		m.status = "Review browser profiles, then press enter to start collection."
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
		if m.collectorCursor < len(m.collectors)-1 {
			m.collectorCursor++
		}
	case " ":
		if len(m.collectors) > 0 {
			m.selectedCollectors[m.collectorCursor] = !m.selectedCollectors[m.collectorCursor]
			m.status = fmt.Sprintf("%d collectors selected.", len(m.collectorResults()))
		}
	case "a":
		allSelected := len(m.collectors) > 0
		for idx := range m.collectors {
			if !m.selectedCollectors[idx] {
				allSelected = false
				break
			}
		}
		for idx := range m.collectors {
			m.selectedCollectors[idx] = !allSelected
		}
		if allSelected {
			m.status = "Collector selection cleared."
		} else {
			m.status = fmt.Sprintf("Selected all %d collectors.", len(m.collectors))
		}
	case "enter":
		if len(m.collectorResults()) == 0 {
			m.status = "Select at least one collector."
			return m, nil
		}
		if m.needsBrowserProfiles() {
			m.phase = phaseLoadingProfiles
			m.status = "Discovering Chromium profiles..."
			return m, tea.Batch(m.spinner.Tick, discoverProfilesCmd())
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
		m.status = fmt.Sprintf("%d collectors selected.", len(m.collectorResults()))
	case "enter":
		if len(m.profileResults()) == 0 {
			m.status = "Select at least one browser profile."
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
	sections := []string{
		m.bannerView(width),
		"",
		titleStyle.Render("Artifact Selection"),
		subtleStyle.Render(wrapMessage(m.status, width)),
		helpStyle.Render(wrapMessage("Controls: up/down move, space toggle, a select all, enter continue, esc/q quit.", width)),
		"",
		m.bodyView(width, m.height),
	}
	return strings.Join(sections, "\n")
}

func (m menuModel) renderCollectors(width, _ int) string {
	titleWidth := m.collectorTitleWidth(width)
	return m.renderOptions(len(m.collectors), func(idx int) string {
		return renderSelectableRow(
			idx == m.collectorCursor,
			m.selectedCollectors[idx],
			m.collectors[idx].title,
			m.collectors[idx].detail,
			m.collectors[idx].collector.Category(),
			width,
			titleWidth,
		)
	})
}

func (m menuModel) renderLoadingProfiles(width, _ int) string {
	lines := []string{
		fmt.Sprintf("%s Discovering Chromium profiles...", m.spinner.View()),
		"",
		wrapMessage("Press esc to return to collector selection.", width),
	}
	return strings.Join(lines, "\n")
}

func (m menuModel) renderProfiles(width, _ int) string {
	titleWidth := m.profileTitleWidth(width)
	return m.renderOptions(len(m.profiles), func(idx int) string {
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

func (m menuModel) collectorTitleWidth(width int) int {
	maxWidth := 0
	for _, item := range m.collectors {
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
	maxWidth := available - 8
	if maxWidth < minWidth {
		maxWidth = minWidth
	}
	preferred := longestTitle + 2
	if preferred > available/2 {
		preferred = available / 2
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

	if titleWidth > available-5 {
		titleWidth = maxInt(8, available/2)
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

func (m menuModel) bodyView(width, height int) string {
	switch m.phase {
	case phaseCollectors:
		return m.renderCollectors(width, height)
	case phaseLoadingProfiles:
		return m.renderLoadingProfiles(width, height)
	case phaseProfiles:
		return m.renderProfiles(width, height)
	default:
		return ""
	}
}

func (m menuModel) bannerView(width int) string {
	return ui.RenderAppBanner(width, ui.BannerContent{
		Version:     output.Version,
		Subtitle:    "Interactive collector launcher",
		CenterTitle: "Welcome",
		CenterLines: []string{"Choose collectors", "Review browser profiles", "Run collection"},
		RightTitle:  "Controls",
		RightLines:  []string{"up/down  move", "space    toggle", "a        all", "enter    continue", "esc/q    quit"},
	})
}

func wrapMessage(value string, width int) string {
	if width <= 0 || lipgloss.Width(value) <= width {
		return value
	}

	words := strings.Fields(value)
	if len(words) == 0 {
		return value
	}

	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		candidate := current + " " + word
		if lipgloss.Width(candidate) <= width {
			current = candidate
			continue
		}
		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
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

func (m menuModel) collectorResults() []collector.Collector {
	var selected []collector.Collector
	for idx, item := range m.collectors {
		if m.selectedCollectors[idx] {
			selected = append(selected, item.collector)
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

func (m menuModel) needsBrowserProfiles() bool {
	for _, col := range m.collectorResults() {
		if col.Name() == browser.ChromiumCollectorName {
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
