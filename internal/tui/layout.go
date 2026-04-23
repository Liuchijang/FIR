package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ScreenLayout stores the measured terminal layout for a fixed header and
// responsive content area.
type RootLayout struct {
	TotalWidth    int
	TotalHeight   int
	HeaderHeight  int
	FooterHeight  int
	ContentHeight int
}

// MeasureRootLayout calculates fixed header/footer heights from their rendered
// output and reserves the remaining rows for the main content area.
func MeasureRootLayout(totalWidth, totalHeight int, header, footer string) RootLayout {
	width := maxInt(0, totalWidth)
	height := maxInt(0, totalHeight)
	headerHeight := lipgloss.Height(trimTrailingNewlines(header))
	headerHeight = clampInt(headerHeight, 0, height)
	footerHeight := lipgloss.Height(trimTrailingNewlines(footer))
	footerHeight = clampInt(footerHeight, 0, maxInt(0, height-headerHeight))

	return RootLayout{
		TotalWidth:    width,
		TotalHeight:   height,
		HeaderHeight:  headerHeight,
		FooterHeight:  footerHeight,
		ContentHeight: maxInt(0, height-headerHeight-footerHeight),
	}
}

// AvailableContentSize returns the usable size for the content area after
// subtracting any border, margin, or padding applied by the content style.
func AvailableContentSize(layout RootLayout, style lipgloss.Style) (int, int) {
	return AvailableSize(layout.TotalWidth, layout.ContentHeight, style)
}

// AvailableSize returns the usable width and height after subtracting the
// frame size of a lipgloss style.
func AvailableSize(totalWidth, totalHeight int, style lipgloss.Style) (int, int) {
	usableWidth := maxInt(0, totalWidth-style.GetHorizontalFrameSize())
	usableHeight := maxInt(0, totalHeight-style.GetVerticalFrameSize())
	return usableWidth, usableHeight
}

// RenderRootLayout joins the fixed header, responsive content, and fixed
// footer into a stable full-height terminal frame.
func RenderRootLayout(layout RootLayout, header, content, footer string) string {
	header = trimTrailingNewlines(header)
	content = trimTrailingNewlines(content)
	footer = trimTrailingNewlines(footer)

	sections := make([]string, 0, 3)
	if layout.HeaderHeight > 0 && header != "" {
		sections = append(sections, RenderSection(layout.TotalWidth, layout.HeaderHeight, header))
	}
	if layout.ContentHeight > 0 {
		sections = append(sections, RenderSection(layout.TotalWidth, layout.ContentHeight, content))
	}
	if layout.FooterHeight > 0 && footer != "" {
		sections = append(sections, RenderSection(layout.TotalWidth, layout.FooterHeight, footer))
	}

	screen := ""
	if len(sections) > 0 {
		screen = lipgloss.JoinVertical(lipgloss.Left, sections...)
	}

	screen = trimToHeight(screen, layout.TotalHeight)
	return padToViewport(screen, layout.TotalWidth, layout.TotalHeight)
}

// RenderSection clamps a section to its assigned viewport and pads any missing
// rows so old terminal content cannot bleed through after a resize.
func RenderSection(width, height int, content string) string {
	if height <= 0 {
		return ""
	}
	if width <= 0 {
		return padToViewport("", width, height)
	}

	content = trimToHeight(trimTrailingNewlines(content), height)
	rendered := lipgloss.NewStyle().
		Width(width).
		MaxWidth(width).
		Height(height).
		MaxHeight(height).
		Render(content)

	return padToViewport(trimToHeight(rendered, height), width, height)
}

func trimTrailingNewlines(value string) string {
	return strings.TrimRight(value, "\n")
}

func trimToHeight(value string, height int) string {
	if height <= 0 || strings.TrimSpace(value) == "" {
		return ""
	}

	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	if len(lines) <= height {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:height], "\n")
}

func padToViewport(value string, width, height int) string {
	if height <= 0 {
		return value
	}

	contentHeight := lipgloss.Height(value)
	lines := make([]string, 0, maxInt(contentHeight, height))
	if value != "" {
		for _, line := range strings.Split(value, "\n") {
			lines = append(lines, padLineToWidth(line, width))
		}
	}

	if contentHeight >= height {
		return strings.Join(lines, "\n")
	}

	padding := height - contentHeight
	blank := padLineToWidth("", width)
	for idx := 0; idx < padding; idx++ {
		lines = append(lines, blank)
	}
	return strings.Join(lines, "\n")
}

func padLineToWidth(value string, width int) string {
	if width <= 0 {
		return value
	}
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func clampInt(value, minValue, maxValue int) int {
	if maxValue < minValue {
		maxValue = minValue
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
