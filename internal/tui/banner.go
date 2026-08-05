package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	bannerTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("218")).Bold(true)
	bannerMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	bannerLogoStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("217"))
)

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
