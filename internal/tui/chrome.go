package tui

import (
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/platform"
	"github.com/charmbracelet/bubbles/help"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const BannerColumnGap = 3

// Mirrors the +---+ summary tables so panels and tables read as one system.
var asciiPanelBorder = lipgloss.Border{
	Top:         "-",
	Bottom:      "-",
	Left:        "|",
	Right:       "|",
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
}

func adaptivePanelBorder() lipgloss.Border {
	if console.SupportsUnicodeGlyphs() {
		return lipgloss.RoundedBorder()
	}
	return asciiPanelBorder
}

var (
	panelBoxStyle = lipgloss.NewStyle().
			Border(adaptivePanelBorder()).
			BorderForeground(lipgloss.Color("246")).
			Padding(0, 1)
	// NOTE: BorderTop(true) without a BorderStyle is a no-op in lipgloss, so this footer
	// has never actually drawn a separator line. Left as-is deliberately — adding one now
	// would change both screens' layout, which is a design call, not a consistency fix.
	footerBarStyle = lipgloss.NewStyle().
			BorderTop(true).
			BorderForeground(lipgloss.Color("246")).
			Padding(0, 1)
	bannerLogoLines = []string{
		"|-----||   O    |----\\\\",
		"|    --| |----| |   x  <|'",
		"|__|--'  |____| |__|\\\\__/",
	}
)

func verticalKeysHelp() string {
	if console.SupportsUnicodeGlyphs() {
		return "↑/↓/k/j"
	}
	return "up/dn/k/j"
}

// bubbles defaults to " • " and "…", which legacy conhost renders as '?'.
func newAdaptiveHelp() help.Model {
	model := help.New()
	if !console.SupportsUnicodeGlyphs() {
		model.ShortSeparator = " | "
		model.Ellipsis = "..."
	}
	return model
}

func PanelBoxStyle() lipgloss.Style {
	return panelBoxStyle
}

func FooterBarStyle() lipgloss.Style {
	return footerBarStyle
}

func BannerLogoLines() []string {
	return append([]string(nil), bannerLogoLines...)
}

func BannerColumnWidths(innerWidth int) (int, int) {
	const (
		fixedLeftWidth = 31
		minLeftWidth   = 24
		minRightWidth  = 24
	)

	if innerWidth <= 0 {
		return 0, 0
	}
	if innerWidth >= fixedLeftWidth+BannerColumnGap+minRightWidth {
		return fixedLeftWidth, innerWidth - fixedLeftWidth - BannerColumnGap
	}

	leftWidth := max(minLeftWidth, (innerWidth-BannerColumnGap)/2)
	rightWidth := max(10, innerWidth-leftWidth-BannerColumnGap)
	if leftWidth+BannerColumnGap+rightWidth > innerWidth {
		leftWidth = max(10, (innerWidth-BannerColumnGap)/2)
		rightWidth = max(10, innerWidth-leftWidth-BannerColumnGap)
	}
	return leftWidth, rightWidth
}

func MachineHostname() string {
	return platform.DetectHost().Hostname
}

func MachinePlatform() string {
	host := platform.DetectHost()
	return host.OS + "/" + host.Architecture
}

func RenderBannerInfoRow(label, value string, width int, labelStyle, valueStyle lipgloss.Style) string {
	if width <= 0 {
		return ""
	}

	labelWidth := 10
	if labelWidth > width-4 {
		labelWidth = max(1, width/3)
	}

	labelText := trimToWidth(label, labelWidth)
	labelPadding := labelWidth - lipgloss.Width(labelText)
	if labelPadding < 0 {
		labelPadding = 0
	}

	valueWidth := max(1, width-labelWidth-1)
	valueText := trimToWidth(value, valueWidth)

	return labelStyle.Render(labelText) +
		strings.Repeat(" ", labelPadding) + " " +
		valueStyle.Render("-- "+trimToWidth(valueText, max(1, valueWidth-3)))
}

func PadViewport(value string, width, height int) string {
	return padToViewport(value, width, height)
}

func RootViewportSize(totalWidth, totalHeight, marginX, marginY int) (int, int) {
	return max(20, totalWidth-marginX*2-1), max(10, totalHeight-marginY*2-1)
}

func PollTerminalSizeCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg {
		console.SyncBufferToWindow()
		width, height, ok := console.CurrentSize()
		if !ok {
			return nil
		}
		return tea.WindowSizeMsg{Width: width, Height: height}
	})
}

const (
	chromeMarginX = 2
	chromeMarginY = 1
	chromeHeaderH = 6
)

// chromeSize is the drawable area inside the root margins.
func chromeSize(termWidth, termHeight int) (int, int) {
	return RootViewportSize(termWidth, termHeight, chromeMarginX, chromeMarginY)
}

// chromeHeader draws the banner panel: logo and subtitle on the left, labelled
// machine-info rows on the right.
func chromeHeader(width int, subtitle string, info [][2]string) string {
	innerWidth := max(10, width-panelBoxStyle.GetHorizontalFrameSize())
	leftWidth, rightWidth := BannerColumnWidths(innerWidth)

	logo := BannerLogoLines()
	leftLines := []string{
		bannerLogoStyle.Render(trimToWidth(logo[0], leftWidth)),
		bannerLogoStyle.Render(trimToWidth(logo[1], leftWidth)),
		bannerLogoStyle.Render(trimToWidth(logo[2], leftWidth)),
		bannerTitleStyle.Render(trimToWidth("FIR v"+output.Version, leftWidth)),
		lipgloss.NewStyle().Bold(true).Render(trimToWidth("Freedom Incident Response", leftWidth)),
		bannerMutedStyle.Render(trimToWidth(subtitle, leftWidth)),
	}

	rightLines := make([]string, 0, len(info)+1)
	rightLines = append(rightLines, bannerTitleStyle.Render(trimToWidth("Machine Info", rightWidth)))
	for _, row := range info {
		rightLines = append(rightLines, RenderBannerInfoRow(row[0], row[1], rightWidth, menuItemStyle, bannerMutedStyle))
	}

	column := func(w int, lines []string) string {
		return lipgloss.NewStyle().Width(w).Align(lipgloss.Left, lipgloss.Top).Render(strings.Join(lines, "\n"))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		column(leftWidth, leftLines),
		strings.Repeat(" ", BannerColumnGap),
		column(rightWidth, rightLines),
	)
	return panelBoxStyle.Width(max(1, width-2)).Height(chromeHeaderH).Render(row)
}

// chromeFooter draws the status line above the key help, omitting either if empty.
func chromeFooter(width int, status string, keys help.KeyMap, model help.Model) string {
	innerWidth := max(1, width-footerBarStyle.GetHorizontalFrameSize())
	model.Width = innerWidth

	lines := make([]string, 0, 2)
	if status != "" {
		lines = append(lines, subtleStyle.Render(trimToWidth(status, innerWidth)))
	}
	if view := model.View(keys); view != "" {
		lines = append(lines, helpStyle.Render(trimToWidth(view, innerWidth)))
	}
	return footerBarStyle.Width(innerWidth).Render(strings.Join(lines, "\n"))
}

// chromePanel wraps body content in the bordered panel, padded to fill it.
func chromePanel(width, height int, render func(width, height int) string) string {
	if height <= 0 {
		return ""
	}
	innerWidth := max(1, width-panelBoxStyle.GetHorizontalFrameSize())
	innerHeight := max(1, height-panelBoxStyle.GetVerticalFrameSize())
	content := padToViewport(render(innerWidth, innerHeight), innerWidth, innerHeight)
	return panelBoxStyle.Width(max(1, width-2)).Height(max(1, height-2)).Render(content)
}

// chromeBodyHeight is the panel height left once the header and footer are placed.
func chromeBodyHeight(height int, header, footer string) int {
	return max(3, height-lipgloss.Height(header)-lipgloss.Height(footer))
}

// chromeFrame stacks the three panels and applies the root margin.
func chromeFrame(width, height int, header, body, footer string) string {
	ui := padToViewport(lipgloss.JoinVertical(lipgloss.Left, header, body, footer), width, height)
	return lipgloss.NewStyle().Padding(chromeMarginY, chromeMarginX).Render(ui)
}

// chromeApplySize folds a WindowSizeMsg into width/height, reporting whether the
// terminal actually changed size.
func chromeApplySize(msg tea.WindowSizeMsg, width, height *int) bool {
	changed := false
	if msg.Width > 0 {
		changed = changed || msg.Width != *width
		*width = msg.Width
	}
	if msg.Height > 0 {
		changed = changed || msg.Height != *height
		*height = msg.Height
	}
	return changed
}
