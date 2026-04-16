// Package cli implements the interactive menu-driven interface for FIR.
package cli

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fir/fir/internal/collector"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// CategoryDisplay maps internal category names to display-friendly names and icons.
var CategoryDisplay = map[string]struct {
	Icon string
	Name string
}{
	"memory":    {Icon: "🔴", Name: "Memory (RAM)"},
	"ntfs":      {Icon: "🟠", Name: "NTFS Artifacts"},
	"execution": {Icon: "🟡", Name: "Execution Artifacts"},
	"eventlog":  {Icon: "🟢", Name: "Windows Event Logs"},
	"registry":  {Icon: "🔵", Name: "Registry Hives"},
	"system":    {Icon: "🟣", Name: "System Activity"},
}

// RunInteractiveMenu presents the interactive collector selection menu.
// Returns the list of selected collectors.
func RunInteractiveMenu() ([]collector.Collector, error) {
	fmt.Fprintf(os.Stderr, "\n%s%s", colorCyan, colorBold)
	fmt.Fprintf(os.Stderr, "  ╔═══════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "  ║       Artifact Selection Menu         ║\n")
	fmt.Fprintf(os.Stderr, "  ╚═══════════════════════════════════════╝%s\n\n", colorReset)

	categories := collector.Categories()

	var options []string
	optionToCollector := make(map[string]collector.Collector)
	var defaultOptions []string

	// Build the options list grouped by category
	for _, cat := range categories {
		catCollectors := collector.GetByCategory(cat)
		for _, c := range catCollectors {
			display, ok := CategoryDisplay[cat]
			if !ok {
				display = struct{ Icon, Name string }{Icon: "⚪", Name: cat}
			}
			
			opt := fmt.Sprintf("%s [%s] %s  -- %s", display.Icon, cat, c.Name(), c.Description())
			options = append(options, opt)
			optionToCollector[opt] = c
			
			// Optional: we can pre-select non-memory artifacts by default, or let user pick freely.
			// Currently leaving 'defaultOptions' empty so user selects what they want.
		}
	}

	prompt := &survey.MultiSelect{
		Message:  "Select artifacts to collect:",
		Options:  options,
		Default:  defaultOptions,
		PageSize: 15,
	}

	var selectedOptions []string
	err := survey.AskOne(prompt, &selectedOptions, survey.WithIcons(func(icons *survey.IconSet) {
		icons.MarkedOption.Text = "[x]"
		icons.UnmarkedOption.Text = "[ ]"
	}))
	
	if err != nil {
		return nil, fmt.Errorf("interactive prompt aborted")
	}

	if len(selectedOptions) == 0 {
		return nil, nil // Let the caller handle empty selection
	}

	var selected []collector.Collector
	for _, opt := range selectedOptions {
		selected = append(selected, optionToCollector[opt])
	}

	fmt.Fprintf(os.Stderr, "\n%sSelected collectors:%s\n", colorBold, colorReset)
	for _, c := range selected {
		fmt.Fprintf(os.Stderr, "  %s✓%s %s (%s)\n", colorGreen, colorReset, c.Name(), c.Category())
	}
	fmt.Fprintf(os.Stderr, "\n")

	return selected, nil
}
