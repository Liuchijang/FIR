package tui

import (
	"strings"
	"time"

	"github.com/Liuchijang/Tyto/internal/console"
	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/platform"
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
	// A perched owl, for Tyto — the barn owl genus. ASCII only, because legacy
	// conhost draws anything else as '?' (see console.SupportsUnicodeGlyphs).
	bannerOwlLines = []string{
		`  ,_,`,
		` (o,o)`,
		` /)_)`,
	}
)

// bannerStars is the night sky to the right of the owl, at fixed offsets.
//
// Fixed rather than randomised because chromeHeader re-renders on every keypress:
// a starfield that moved between frames would read as the screen glitching, not as
// decoration. Ordered by column within each row — BannerMarkLines fills the gaps
// left to right and would misplace a star listed out of order.
//
// Tone is per star rather than per glyph. Keying it off '.' versus '*' would only
// recolour the shape that is already there, and the two colours would fall into
// the same regular pattern the fixed offsets are trying to avoid.
var bannerStars = []struct {
	row, col int
	glyph    rune
	tone     lipgloss.Style
}{
	{0, 14, '.', bannerStarPink}, {0, 21, '*', bannerStarWhite}, {0, 28, '.', bannerStarWhite},
	{1, 10, '*', bannerStarPink}, {1, 18, '.', bannerStarWhite}, {1, 26, '.', bannerStarPink},
	{2, 15, '.', bannerStarWhite}, {2, 23, '*', bannerStarPink}, {2, 29, '.', bannerStarWhite},
}

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

// BannerMarkLines renders the owl and its night sky, styled and sized to fit
// width.
//
// A star past width is dropped rather than clipped, so the mark degrades by
// losing its outermost stars instead of being cut mid-glyph and given an
// ellipsis — the left banner column shrinks from 31 to 24 on a narrow terminal.
//
// The two tones are composed here rather than by the caller: trimToWidth slices
// runes, so it would cut an ANSI escape in half. Nothing downstream needs to trim
// these, because every line is built to fit.
func BannerMarkLines(width int) []string {
	lines := make([]string, len(bannerOwlLines))
	for i, owl := range bannerOwlLines {
		var sky strings.Builder
		// column tracks where the next write lands, so each star is styled on its
		// own and the gaps between them stay unstyled.
		column := len(owl)
		for _, star := range bannerStars {
			// Keep at least one column between the owl and its nearest star.
			if star.row != i || star.col >= width || star.col <= len(owl) {
				continue
			}
			sky.WriteString(strings.Repeat(" ", star.col-column))
			sky.WriteString(star.tone.Render(string(star.glyph)))
			column = star.col + 1
		}
		lines[i] = bannerLogoStyle.Render(owl) + sky.String()
	}
	return lines
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
	// Five rows: owl (3) + version + tagline on the left, and "Machine Info" plus
	// at most four info rows on the right. Both columns land on five exactly, so
	// a sixth would be blank in every screen and cost the body a row.
	chromeHeaderH = 5
	// chromeMinBodyRows is the panel height the banner must leave behind. Below it
	// the banner is collapsed to one line: a fixed 8-row banner on a short terminal
	// starved the body until no selectable rows were drawn at all.
	chromeMinBodyRows = 8
	// bodyChromeRows is the title/status/blank block a body panel prepends.
	bodyChromeRows = 3
)

// chromeSize is the drawable area inside the root margins.
func chromeSize(termWidth, termHeight int) (int, int) {
	return RootViewportSize(termWidth, termHeight, chromeMarginX, chromeMarginY)
}

// chromeHeader draws the banner panel: the mark on the left, labelled
// machine-info rows on the right. budget is the height available for the header and
// the body together; when the banner would not leave chromeMinBodyRows behind it
// collapses to a single line so the body keeps its rows.
func chromeHeader(width, budget int, info [][2]string) string {
	if budget < chromeHeaderH+panelBoxStyle.GetVerticalFrameSize()+chromeMinBodyRows {
		return chromeCompactHeader(width, info)
	}

	innerWidth := max(10, width-panelBoxStyle.GetHorizontalFrameSize())
	leftWidth, rightWidth := BannerColumnWidths(innerWidth)

	mark := BannerMarkLines(leftWidth)
	leftLines := []string{
		mark[0],
		mark[1],
		mark[2],
		bannerTitleStyle.Render(trimToWidth("Tyto v"+output.Version, leftWidth)),
		lipgloss.NewStyle().Bold(true).Render(trimToWidth("Windows DFIR triage", leftWidth)),
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

// chromeCompactHeader is the one-line banner for short terminals: version, host and
// the last info row, which is the phase or run state.
func chromeCompactHeader(width int, info [][2]string) string {
	innerWidth := max(10, width-panelBoxStyle.GetHorizontalFrameSize())

	parts := []string{bannerTitleStyle.Render("Tyto v" + output.Version)}
	if len(info) > 0 {
		parts = append(parts, menuItemStyle.Render(info[0][1]))
	}
	if len(info) > 1 {
		parts = append(parts, bannerMutedStyle.Render(info[len(info)-1][1]))
	}

	line := strings.Join(parts, bannerMutedStyle.Render("  |  "))
	if lipgloss.Width(line) > innerWidth {
		line = trimToWidth(line, innerWidth)
	}
	return panelBoxStyle.Width(max(1, width-2)).Height(1).Render(line)
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
