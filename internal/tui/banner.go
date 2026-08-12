package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	// The owl and the wordmark under it share one colour so the banner reads as a
	// single mark. Defined once rather than repeated per style, because two
	// literals a line apart is how they drifted to 217 and 218 in the first place.
	bannerAccent = lipgloss.Color("218")

	bannerTitleStyle = lipgloss.NewStyle().Foreground(bannerAccent).Bold(true)
	bannerMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	bannerLogoStyle  = lipgloss.NewStyle().Bold(true).Foreground(bannerAccent)

	// The night sky is two tones. Neither is bold, so the owl stays the one bold
	// thing in the banner even where a star shares its colour.
	bannerStarWhite = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	bannerStarPink  = lipgloss.NewStyle().Foreground(bannerAccent)
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
