package collection

import (
	"fmt"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
)

// ResolveModules converts a comma-separated artifact string to registered modules.
func ResolveModules(artifactStr string) ([]module.Module, error) {
	names := strings.Split(artifactStr, ",")
	var result []module.Module
	seen := make(map[string]bool)

	for _, name := range names {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		if name == "browser_chromium" {
			name = "browser"
		}

		if name == "all" {
			return module.All(), nil
		}

		categoryModules := module.GetByCategory(name)
		if len(categoryModules) > 0 {
			for _, mod := range categoryModules {
				if !seen[mod.Name()] {
					result = append(result, mod)
					seen[mod.Name()] = true
				}
			}
			continue
		}

		mod, err := module.Get(name)
		if err != nil {
			return nil, fmt.Errorf("unknown artifact or category: %s\nUse 'fir collect --help' to see available artifacts", name)
		}
		if !seen[mod.Name()] {
			result = append(result, mod)
			seen[mod.Name()] = true
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no modules resolved from: %s", artifactStr)
	}
	return result, nil
}
