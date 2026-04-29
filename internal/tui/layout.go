package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/truncate"
)

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
		return strings.Join(lines[:height], "\n")
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
	if padding < 0 {
		return truncate.String(value, uint(width))
	}
	if padding == 0 {
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

func clampInt64(value, minValue, maxValue int64) int64 {
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
