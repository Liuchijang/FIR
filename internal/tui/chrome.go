package tui

import (
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/platform"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const BannerColumnGap = 3

var (
	panelBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("246")).
			Padding(0, 1)
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
