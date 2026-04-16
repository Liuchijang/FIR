// Package cli implements the interactive menu-driven interface for FIR.
package cli

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fir/fir/internal/collector"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBlue   = "\033[34m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorPurple = "\033[35m"
	colorBold   = "\033[1m"
)

var CategoryDisplay = map[string]struct {
	Color string
}{
	"memory":    {Color: colorRed},
	"ntfs":      {Color: colorYellow},
	"execution": {Color: colorGreen},
	"eventlog":  {Color: colorCyan},
	"registry":  {Color: colorBlue},
	"system":    {Color: colorPurple},
}

func RunInteractiveMenu() ([]collector.Collector, error) {
	fmt.Fprintf(os.Stderr, "\n%s%sArtifact Selection Menu%s\n\n", colorCyan, colorBold, colorReset)

	categories := collector.Categories()
	var options []string
	optionToCollector := make(map[string]collector.Collector)
	var defaultOptions []string

	for _, cat := range categories {
		catCollectors := collector.GetByCategory(cat)
		display, ok := CategoryDisplay[cat]
		if !ok {
			display = struct{ Color string }{Color: colorCyan}
		}
		for _, c := range catCollectors {
			header := fmt.Sprintf("%s%s[%s]%s", display.Color, colorBold, cat, colorReset)
			opt := fmt.Sprintf("%s %s  -- %s", header, c.Name(), c.Description())
			options = append(options, opt)
			optionToCollector[opt] = c
		}
	}

	prompt := &survey.MultiSelect{Message: "Select artifacts to collect:", Options: options, Default: defaultOptions, PageSize: 15}
	var selectedOptions []string
	err := survey.AskOne(prompt, &selectedOptions, survey.WithIcons(func(icons *survey.IconSet) {
		icons.MarkedOption.Text = "[x]"
		icons.UnmarkedOption.Text = "[ ]"
	}))
	if err != nil {
		return nil, fmt.Errorf("interactive prompt aborted")
	}
	if len(selectedOptions) == 0 {
		return nil, nil
	}

	var selected []collector.Collector
	for _, opt := range selectedOptions {
		selected = append(selected, optionToCollector[opt])
	}

	fmt.Fprintf(os.Stderr, "\n%sSelected collectors:%s\n", colorBold, colorReset)
	for _, c := range selected {
		fmt.Fprintf(os.Stderr, "  %s[OK]%s %s (%s)\n", colorGreen, colorReset, c.Name(), c.Category())
	}
	fmt.Fprintf(os.Stderr, "\n")
	return selected, nil
}
