package module

import (
	"fmt"
	"sort"
	"sync"
)

// registry is the global module registry. Modules self-register via init().
var registry = &collectorRegistry{
	collectors: make(map[string]Module),
}

var activeRun = struct {
	mu      sync.RWMutex
	modules map[string]bool
}{
	modules: make(map[string]bool),
}

// collectorRegistry provides thread-safe registration and lookup of modules.
type collectorRegistry struct {
	mu         sync.RWMutex
	collectors map[string]Module
}

// Register adds a module to the global registry.
// It panics if a module with the same name is already registered,
// ensuring no silent overwrites during init().
func Register(m Module) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	name := m.Name()
	if _, exists := registry.collectors[name]; exists {
		panic(fmt.Sprintf("module already registered: %s", name))
	}
	registry.collectors[name] = m
}

// Get returns a module by name, or an error if not found.
func Get(name string) (Module, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	c, ok := registry.collectors[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return c, nil
}

// GetByCategory returns all modules belonging to the specified category.
func GetByCategory(category string) []Module {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var result []Module
	for _, m := range registry.collectors {
		if m.Category() == category {
			result = append(result, m)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})
	return result
}

// GetByMode returns all modules belonging to the specified mode.
func GetByMode(mode string) []Module {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var result []Module
	for _, m := range registry.collectors {
		if ModeOf(m) == mode {
			result = append(result, m)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category() == result[j].Category() {
			return result[i].Name() < result[j].Name()
		}
		return result[i].Category() < result[j].Category()
	})
	return result
}

// All returns all registered modules, sorted by category then name.
func All() []Module {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	result := make([]Module, 0, len(registry.collectors))
	for _, m := range registry.collectors {
		result = append(result, m)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category() == result[j].Category() {
			return result[i].Name() < result[j].Name()
		}
		return result[i].Category() < result[j].Category()
	})
	return result
}

// Categories returns a sorted, deduplicated list of all registered categories.
func Categories() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	seen := make(map[string]bool)
	for _, m := range registry.collectors {
		seen[m.Category()] = true
	}

	cats := make([]string, 0, len(seen))
	for cat := range seen {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	return cats
}

// Modes returns the known mode order for interactive and CLI displays.
func Modes() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	seenCollector := false
	seenAnalyzer := false
	for _, m := range registry.collectors {
		switch ModeOf(m) {
		case ModeAnalyzer:
			seenAnalyzer = true
		default:
			seenCollector = true
		}
	}

	var modes []string
	if seenCollector {
		modes = append(modes, ModeCollector)
	}
	if seenAnalyzer {
		modes = append(modes, ModeAnalyzer)
	}
	return modes
}

// Names returns a sorted list of all registered module names.
func Names() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]string, 0, len(registry.collectors))
	for name := range registry.collectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SetActiveRunModules stores the modules selected for the current run so that
// modules can make small coordination decisions without changing the public
// module contract.
func SetActiveRunModules(modules []Module) {
	activeRun.mu.Lock()
	defer activeRun.mu.Unlock()

	activeRun.modules = make(map[string]bool, len(modules))
	for _, mod := range modules {
		activeRun.modules[mod.Name()] = true
	}
}

// ClearActiveRunModules clears the current run selection state.
func ClearActiveRunModules() {
	activeRun.mu.Lock()
	defer activeRun.mu.Unlock()

	activeRun.modules = make(map[string]bool)
}

// IsSelected reports whether the named module is part of the current run.
func IsSelected(name string) bool {
	activeRun.mu.RLock()
	defer activeRun.mu.RUnlock()

	return activeRun.modules[name]
}
