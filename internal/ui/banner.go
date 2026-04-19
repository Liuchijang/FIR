package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type BannerContent struct {
	Version     string
	Subtitle    string
	CenterTitle string
	CenterLines []string
	RightTitle  string
	RightLines  []string
}

var (
	bannerBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("240"))
	bannerTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	bannerMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	bannerLogoStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
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
		subtitle = "Interactive collector launcher"
	}

	if width < 72 {
		lines := []string{
			bannerLogoStyle.Render(renderLogo(maxInt(10, contentWidth))),
			"",
			bannerTitleStyle.Render("FIR v" + version),
			wrapMessage("Freedom Incident Response", contentWidth),
			bannerMutedStyle.Render(wrapMessage(subtitle, contentWidth)),
		}
		box := lipgloss.NewStyle().
			Width(contentWidth).
			Padding(0, 1).
			Render(strings.Join(lines, "\n"))
		return bannerBorderStyle.Render(box)
	}

	panelGap := 2
	available := innerWidth - panelGap*2
	if available < 30 {
		available = innerWidth
	}

	leftWidth := maxInt(18, available/3)
	midWidth := maxInt(16, available/3)
	rightWidth := maxInt(18, available-leftWidth-midWidth)
	totalWidth := leftWidth + midWidth + rightWidth
	if totalWidth > available {
		overflow := totalWidth - available
		if rightWidth-overflow >= 12 {
			rightWidth -= overflow
		} else if midWidth-overflow >= 12 {
			midWidth -= overflow
		} else {
			leftWidth = maxInt(12, leftWidth-overflow)
		}
	}

	left := strings.Join([]string{
		bannerTitleStyle.Render("FIR v" + version),
		wrapMessage("Freedom Incident Response", leftWidth),
		bannerMutedStyle.Render(wrapMessage(subtitle, leftWidth)),
	}, "\n")

	center := strings.Join(buildPanel(content.CenterTitle, content.CenterLines), "\n")
	right := strings.Join(buildPanel(content.RightTitle, content.RightLines), "\n")

	logo := bannerLogoStyle.Render(renderLogo(maxInt(10, leftWidth)))
	left = strings.Join([]string{logo, "", left}, "\n")

	panelStyle := lipgloss.NewStyle().Padding(0, 1)
	row := lipgloss.JoinHorizontal(
		lipgloss.Top,
		panelStyle.Width(leftWidth).Render(left),
		panelStyle.Width(midWidth).Render(center),
		panelStyle.Width(rightWidth).Render(right),
	)
	box := lipgloss.NewStyle().Width(innerWidth).Render(row)
	return bannerBorderStyle.Render(box)
}

func buildPanel(title string, lines []string) []string {
	if title == "" && len(lines) == 0 {
		return nil
	}

	panel := make([]string, 0, len(lines)+1)
	if title != "" {
		panel = append(panel, bannerTitleStyle.Render(title))
	}
	for _, line := range lines {
		panel = append(panel, bannerMutedStyle.Render(line))
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
