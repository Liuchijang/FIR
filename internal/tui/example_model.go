package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	exampleTooSmallWidth    = 28
	exampleTooSmallHeight   = 8
	exampleMinModulesHeight = 5
)

var (
	exampleContentStyle = lipgloss.NewStyle()
	exampleStatusStyle  = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				Padding(0, 1)
	exampleModulesStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("238")).
				Padding(0, 1)
	exampleFooterStyle = lipgloss.NewStyle().
				BorderTop(true).
				BorderForeground(lipgloss.Color("238")).
				Padding(0, 1)
	exampleTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87"))
	exampleMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

// ExampleModel is a compileable Bubble Tea model showing a fixed header and
// responsive scrollable content area that fully recomposes on resize.
type ExampleModel struct {
	viewport viewport.Model
	root     RootLayout

	width  int
	height int

	headerHeight  int
	footerHeight  int
	contentWidth  int
	contentHeight int
	statusHeight  int
	modulesHeight int

	records []string
}

// NewResizeExampleModel returns a standalone demo model that can be used to
// validate resize behavior with long content.
func NewResizeExampleModel() ExampleModel {
	model := ExampleModel{
		viewport: viewport.New(0, 0),
		width:    80,
		height:   24,
		records:  exampleRecords(),
	}
	model.recalculateLayout()
	model.resizeChildComponents()
	return model
}

func (m ExampleModel) Init() tea.Cmd {
	return nil
}

func (m ExampleModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	finalize := func(cmd tea.Cmd) (tea.Model, tea.Cmd) {
		m.recalculateLayout()
		m.resizeChildComponents()
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sizeChanged := m.handleWindowResize(msg)
		if sizeChanged {
			return finalize(tea.ClearScreen)
		}
		return finalize(nil)

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return finalize(tea.Quit)
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return finalize(cmd)

	case tea.MouseMsg:
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return finalize(cmd)
	}

	return finalize(nil)
}

func (m ExampleModel) View() string {
	return RenderRootLayout(m.root, m.headerView(), m.contentView(), m.footerView())
}

func (m *ExampleModel) handleWindowResize(msg tea.WindowSizeMsg) bool {
	sizeChanged := false
	if msg.Width > 0 {
		sizeChanged = sizeChanged || msg.Width != m.width
		m.width = msg.Width
	}
	if msg.Height > 0 {
		sizeChanged = sizeChanged || msg.Height != m.height
		m.height = msg.Height
	}
	return sizeChanged
}

func (m *ExampleModel) recalculateLayout() {
	header := m.headerView()
	footer := m.footerView()
	layout := MeasureRootLayout(m.width, m.height, header, footer)

	m.root = layout
	m.headerHeight = layout.HeaderHeight
	m.footerHeight = layout.FooterHeight
	m.contentWidth, m.contentHeight = AvailableContentSize(layout, exampleContentStyle)

	if m.contentWidth < exampleTooSmallWidth || m.contentHeight < exampleTooSmallHeight {
		m.statusHeight = 0
		m.modulesHeight = maxInt(0, m.contentHeight)
		return
	}

	statusWidth, _ := AvailableSize(m.contentWidth, m.contentHeight, exampleStatusStyle)
	statusBodyHeight := lipgloss.Height(m.renderStatusBody(maxInt(1, statusWidth)))
	statusPaneHeight := statusBodyHeight + exampleStatusStyle.GetVerticalFrameSize()
	maxStatusHeight := maxInt(0, m.contentHeight-exampleMinModulesHeight)
	if maxStatusHeight == 0 {
		m.statusHeight = 0
		m.modulesHeight = maxInt(0, m.contentHeight)
		return
	}

	m.statusHeight = clampInt(statusPaneHeight, exampleStatusStyle.GetVerticalFrameSize()+1, maxStatusHeight)
	m.modulesHeight = maxInt(0, m.contentHeight-m.statusHeight)
}

func (m *ExampleModel) resizeChildComponents() {
	modulesWidth, modulesHeight := AvailableSize(m.contentWidth, m.modulesHeight, exampleModulesStyle)
	m.viewport.Width = maxInt(0, modulesWidth)
	m.viewport.Height = maxInt(0, modulesHeight)
	m.viewport.SetContent(m.renderModulesBody(maxInt(1, modulesWidth)))
	m.viewport.SetYOffset(m.viewport.YOffset)
}

func (m ExampleModel) headerView() string {
	width := maxInt(1, m.width)
	lines := []string{
		RenderAppBanner(width, BannerContent{
			Version:     "demo",
			Subtitle:    "Resize-safe Bubble Tea layout example",
			CenterTitle: "Layout",
			CenterLines: []string{"Fixed header", "Responsive content", "Deterministic reflow"},
			RightTitle:  "Controls",
			RightLines:  []string{"mouse/up-down scroll", "pgup/pgdn fast scroll", "g/G jump", "q exit"},
		}),
		"",
		exampleTitleStyle.Render("Resize Demo"),
		exampleMutedStyle.Render("This sample keeps the banner fixed at the top while the body fully recomposes on every resize."),
	}
	return strings.Join(lines, "\n")
}

func (m ExampleModel) statusView() string {
	if m.contentWidth <= 0 || m.statusHeight <= 0 {
		return ""
	}
	usableWidth, usableHeight := AvailableSize(m.contentWidth, m.statusHeight, exampleStatusStyle)
	body := RenderSection(usableWidth, usableHeight, m.renderStatusBody(maxInt(1, usableWidth)))
	return exampleStatusStyle.
		Width(m.contentWidth).
		Height(m.statusHeight).
		MaxWidth(m.contentWidth).
		MaxHeight(m.statusHeight).
		Render(body)
}

func (m ExampleModel) modulesView() string {
	if m.contentWidth <= 0 || m.modulesHeight <= 0 {
		return ""
	}
	usableWidth, usableHeight := AvailableSize(m.contentWidth, m.modulesHeight, exampleModulesStyle)
	body := RenderSection(usableWidth, usableHeight, m.viewport.View())
	return exampleModulesStyle.
		Width(m.contentWidth).
		Height(m.modulesHeight).
		MaxWidth(m.contentWidth).
		MaxHeight(m.modulesHeight).
		Render(body)
}

func (m ExampleModel) footerView() string {
	width := maxInt(1, m.width)
	content := exampleMutedStyle.Render(wrapExample(
		"Controls: mouse/up-down scroll, pgup/pgdn fast scroll, g/G jump, q exit. Only the content pane scrolls; the header stays fixed.",
		maxInt(1, width-exampleFooterStyle.GetHorizontalFrameSize()),
	))
	return exampleFooterStyle.Width(width).Render(content)
}

func (m ExampleModel) contentView() string {
	if m.contentWidth <= 0 || m.contentHeight <= 0 {
		return ""
	}
	if m.contentWidth < exampleTooSmallWidth || m.contentHeight < exampleTooSmallHeight {
		return RenderSection(m.contentWidth, m.contentHeight, exampleMutedStyle.Render(
			wrapExample("Terminal too small. Enlarge the window to keep the fixed header, status pane, and scrollable content visible together.", maxInt(1, m.contentWidth)),
		))
	}

	sections := make([]string, 0, 2)
	if status := m.statusView(); status != "" {
		sections = append(sections, status)
	}
	if modules := m.modulesView(); modules != "" {
		sections = append(sections, modules)
	}
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m ExampleModel) renderStatusBody(width int) string {
	lines := []string{
		exampleTitleStyle.Render(trimToWidth("Layout State", width)),
		fmt.Sprintf("Terminal: %dx%d", m.width, m.height),
		fmt.Sprintf("Header/Footer: %d/%d", m.headerHeight, m.footerHeight),
		fmt.Sprintf("Content: %dx%d", m.contentWidth, m.contentHeight),
		fmt.Sprintf("Status/Modules: %d/%d rows", m.statusHeight, m.modulesHeight),
	}
	return strings.Join(lines, "\n")
}

func (m ExampleModel) renderModulesBody(width int) string {
	if width <= 0 {
		return ""
	}

	lines := make([]string, 0, len(m.records)*2)
	for _, record := range m.records {
		lines = append(lines, trimToWidth(record, width))
	}
	return strings.Join(lines, "\n")
}

func exampleRecords() []string {
	lines := make([]string, 0, 40)
	for idx := 1; idx <= 40; idx++ {
		lines = append(lines,
			fmt.Sprintf("[%02d] Module selection row with enough detail to force reflow when the terminal becomes narrow.", idx),
			fmt.Sprintf("     Example status detail for row %02d: files=%d duration=%ds output=C:/cases/demo/module-%02d/report.txt", idx, idx*3, idx+2, idx),
		)
	}
	return lines
}

func wrapExample(value string, width int) string {
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
