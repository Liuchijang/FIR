package collector

import (
	"fmt"
	"sort"
	"sync"
)

// registry is the global collector registry. Collectors self-register via init().
var registry = &collectorRegistry{
	collectors: make(map[string]Collector),
}

// collectorRegistry provides thread-safe registration and lookup of collectors.
type collectorRegistry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
}

// Register adds a collector to the global registry.
// It panics if a collector with the same name is already registered,
// ensuring no silent overwrites during init().
func Register(c Collector) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	name := c.Name()
	if _, exists := registry.collectors[name]; exists {
		panic(fmt.Sprintf("collector already registered: %s", name))
	}
	registry.collectors[name] = c
}

// Get returns a collector by name, or an error if not found.
func Get(name string) (Collector, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	c, ok := registry.collectors[name]
	if !ok {
		return nil, fmt.Errorf("collector not found: %s", name)
	}
	return c, nil
}

// GetByCategory returns all collectors belonging to the specified category.
func GetByCategory(category string) []Collector {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var result []Collector
	for _, c := range registry.collectors {
		if c.Category() == category {
			result = append(result, c)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})
	return result
}

// All returns all registered collectors, sorted by category then name.
func All() []Collector {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	result := make([]Collector, 0, len(registry.collectors))
	for _, c := range registry.collectors {
		result = append(result, c)
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
	for _, c := range registry.collectors {
		seen[c.Category()] = true
	}

	cats := make([]string, 0, len(seen))
	for cat := range seen {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	return cats
}

// Names returns a sorted list of all registered collector names.
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
