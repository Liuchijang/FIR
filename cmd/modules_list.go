package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/spf13/cobra"
)

// artifactListKeyword is what --artifact takes to print the module list instead
// of running anything.
const artifactListKeyword = "list"

// requestsModuleList reports whether this invocation only wants the module list.
//
// Read through the flag set rather than the package variables, so it answers for
// whichever command was invoked without knowing which one that is.
func requestsModuleList(cmd *cobra.Command) bool {
	value, err := cmd.Flags().GetString("artifact")
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(value), artifactListKeyword)
}

// printModuleList writes every module with its category and what it does.
//
// The detailed half of the pair: moduleCategoryHelp shows which names belong to
// which category, this shows what each name is for. Both read the registry rather
// than a hand-written list — the help text used to carry a copy of every module
// name, which drifts the moment a module is added and does so silently, because
// nothing checks prose against the registry.
func printModuleList(w io.Writer) {
	tab := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, mode := range module.Modes() {
		mods := module.GetByMode(mode)
		if len(mods) == 0 {
			continue
		}
		fmt.Fprintf(tab, "\n%s modules:\n", strings.ToUpper(mode[:1])+mode[1:])
		for _, mod := range mods {
			fmt.Fprintf(tab, "  %s\t%s\t%s\n", mod.Name(), mod.Category(), strings.TrimSpace(mod.Description()))
		}
	}

	tab.Flush()
	fmt.Fprintf(w, "\nA category name selects every module in it; 'all' selects them all.\n")
}

// moduleCategoryHelp renders every category with the modules in it — the compact
// form the command help carries.
//
// One row per category covers both lists at once: the row label is a valid
// --artifact value and so is every name in it, so nine lines say what the old
// help spent two hand-maintained paragraphs on. Descriptions and the
// collector/analyzer split are left to --artifact list, which is where someone
// who wants them will look.
func moduleCategoryHelp() string {
	var out strings.Builder
	out.WriteString("Modules by category (any name or category works with --artifact;\n")
	out.WriteString("'all' selects every module, 'list' prints them with descriptions):\n")

	tab := tabwriter.NewWriter(&out, 0, 0, 2, ' ', 0)
	for _, category := range moduleCategories() {
		names := make([]string, 0, 6)
		for _, mod := range module.GetByCategory(category) {
			names = append(names, mod.Name())
		}
		fmt.Fprintf(tab, "  %s\t%s\n", category, strings.Join(names, ", "))
	}
	tab.Flush()
	return out.String()
}

func moduleCategories() []string {
	seen := make(map[string]bool)
	var categories []string
	for _, mod := range module.All() {
		if seen[mod.Category()] {
			continue
		}
		seen[mod.Category()] = true
		categories = append(categories, mod.Category())
	}
	sort.Strings(categories)
	return categories
}
