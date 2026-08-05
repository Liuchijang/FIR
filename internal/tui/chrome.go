package tui

import (
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/console"
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
