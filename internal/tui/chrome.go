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

// asciiPanelBorder mirrors the +---+ frame the summary tables draw, so when the rounded
// border is unavailable the panels and the tables inside them read as one visual system.
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

// adaptivePanelBorder picks the rounded border only on consoles that can actually render
// its U+256D-U+2570 corner glyphs. Legacy conhost substitutes '?' for glyphs its font
// lacks, which turned every panel corner into a literal '?'. Same idea as
// newAdaptiveSpinner, applied to the frame instead of the spinner.
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

// verticalKeysHelp labels the up/down bindings, dropping the U+2191/U+2193 arrows on
// consoles whose fonts render them as '?'. Both key maps share it so the footer help reads
// the same on the selection and collection screens.
func verticalKeysHelp() string {
	if console.SupportsUnicodeGlyphs() {
		return "↑/↓/k/j"
	}
	return "up/dn/k/j"
}

// newAdaptiveHelp builds the footer help model with separators the console can actually
// draw: bubbles defaults to " • " (U+2022) and "…" (U+2026), both of which legacy conhost
// renders as '?'.
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

	leftWidth := maxInt(minLeftWidth, (innerWidth-BannerColumnGap)/2)
	rightWidth := maxInt(10, innerWidth-leftWidth-BannerColumnGap)
	if leftWidth+BannerColumnGap+rightWidth > innerWidth {
		leftWidth = maxInt(10, (innerWidth-BannerColumnGap)/2)
		rightWidth = maxInt(10, innerWidth-leftWidth-BannerColumnGap)
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
		labelWidth = maxInt(1, width/3)
	}

	labelText := trimToWidth(label, labelWidth)
	labelPadding := labelWidth - lipgloss.Width(labelText)
	if labelPadding < 0 {
		labelPadding = 0
	}

	valueWidth := maxInt(1, width-labelWidth-1)
	valueText := trimToWidth(value, valueWidth)

	return labelStyle.Render(labelText) +
		strings.Repeat(" ", labelPadding) + " " +
		valueStyle.Render("-- "+trimToWidth(valueText, maxInt(1, valueWidth-3)))
}

func PadViewport(value string, width, height int) string {
	return padToViewport(value, width, height)
}

func RootViewportSize(totalWidth, totalHeight, marginX, marginY int) (int, int) {
	return maxInt(20, totalWidth-marginX*2-1), maxInt(10, totalHeight-marginY*2-1)
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
