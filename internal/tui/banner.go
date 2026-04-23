package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type BannerContent struct {
	Version     string
	Subtitle    string
	CenterTitle string
	CenterLines []string
}

var (
	bannerBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("246"))
	bannerTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("218")).Bold(true)
	bannerMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	bannerLogoStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("217"))
)

func RenderAppBanner(width int, content BannerContent) string {
	if width <= 0 {
		width = 80
	}

	version := content.Version
	if version == "" {
		version = "dev"
	}

	borderWidth := bannerBorderStyle.GetHorizontalFrameSize()
	innerWidth := maxInt(1, width-borderWidth)
	contentWidth := maxInt(1, innerWidth-2)

	subtitle := content.Subtitle
	if subtitle == "" {
		subtitle = "Interactive module launcher"
	}

	if width < 72 {
		lines := []string{
			bannerLogoStyle.Render(renderLogo(maxInt(10, contentWidth))),
			"",
			bannerTitleStyle.Render("FIR v" + version),
			trimToWidth("Freedom Incident Response", contentWidth),
			bannerMutedStyle.Render(trimToWidth(subtitle, contentWidth)),
		}
		box := lipgloss.NewStyle().
			Width(contentWidth).
			Padding(0, 1).
			Render(strings.Join(lines, "\n"))
		return bannerBorderStyle.Render(box)
	}

	panelGap := 1
	available := innerWidth - panelGap
	if available < 24 {
		available = innerWidth
	}

	leftWidth := maxInt(16, (available*34)/100)
	centerWidth := maxInt(12, available-leftWidth)
	if leftWidth+centerWidth > available {
		leftWidth = maxInt(10, available/3)
		centerWidth = maxInt(8, available-leftWidth)
	}

	left := strings.Join([]string{
		bannerTitleStyle.Render("FIR v" + version),
		trimToWidth("Freedom Incident Response", leftWidth),
		bannerMutedStyle.Render(trimToWidth(subtitle, leftWidth)),
	}, "\n")

	center := strings.Join(buildPanel(centerWidth, content.CenterTitle, content.CenterLines), "\n")
	logo := bannerLogoStyle.Render(renderLogo(maxInt(10, leftWidth)))
	left = strings.Join([]string{logo, "", left}, "\n")

	panelStyle := lipgloss.NewStyle().Padding(0, 0)
	rowParts := []string{
		panelStyle.Width(leftWidth).Render(left),
		lipgloss.NewStyle().Padding(0, 1).Width(centerWidth).Render(center),
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, rowParts...)
	box := lipgloss.NewStyle().Width(innerWidth).Render(row)
	return bannerBorderStyle.Render(box)
}

func buildPanel(width int, title string, lines []string) []string {
	if title == "" && len(lines) == 0 {
		return nil
	}

	panel := make([]string, 0, len(lines)+1)
	if title != "" {
		panel = append(panel, bannerTitleStyle.Render(trimToWidth(title, width)))
	}
	for _, line := range lines {
		panel = append(panel, bannerMutedStyle.Render(trimToWidth(line, width)))
	}
	return panel
}

func renderLogo(width int) string {
	lines := []string{
		"  |-----||   O    |----\\\\",
		"  |    --| |----| |   x  <|'",
		"  |__|--'  |____| |__|\\\\__/",
	}
	for idx := range lines {
		lines[idx] = trimToWidth(lines[idx], width)
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
