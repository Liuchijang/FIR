package tui

import (
	"strings"

	"github.com/Liuchijang/Tyto/internal/output"
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

// RenderCommandBanner is the banner the flag-driven commands print before a run.
//
// It reuses the interactive mark rather than drawing a second one, so the two
// front doors of the tool cannot drift apart. subtitle names what is about to
// happen — the flag path has no header row to carry that the way the TUI does.
//
// No box and no fixed width: this goes to a stderr that may be a pipe or a log
// file, where a bordered panel sized to a guessed terminal width is noise.
func RenderCommandBanner(subtitle string) string {
	mark := BannerMarkLines(bannerCommandWidth)

	lines := make([]string, 0, len(mark)+1)
	lines = append(lines, mark...)
	title := bannerTitleStyle.Render("Tyto v" + output.Version)
	if subtitle != "" {
		title += bannerMutedStyle.Render("  |  ") + bannerMutedStyle.Render(subtitle)
	}
	lines = append(lines, title)
	return strings.Join(lines, "\n")
}

// bannerCommandWidth keeps a couple of stars around the owl without assuming a
// terminal width, since the output may not be going to a terminal at all.
const bannerCommandWidth = 31

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
