package module

import (
	"fmt"
	"sort"
	"sync"
)

var registry = &collectorRegistry{
	collectors: make(map[string]Module),
}

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

func Get(name string) (Module, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	c, ok := registry.collectors[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return c, nil
}

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
