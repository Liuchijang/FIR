package collection

import (
	"context"
	"strings"
	"testing"

	"github.com/Liuchijang/FIR/internal/module"
)

type resolverModule struct {
	name     string
	category string
}

func (m resolverModule) Name() string        { return m.name }
func (m resolverModule) Category() string    { return m.category }
func (m resolverModule) Description() string { return "resolver test module" }
func (m resolverModule) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	return nil, nil
}

func TestResolveModulesByNameCategoryAllAndAlias(t *testing.T) {
	registerResolverModule("resolve_alpha", "resolve_category")
	registerResolverModule("resolve_beta", "resolve_category")
	registerResolverModule("browser", "resolve_browser")

	byName, err := ResolveModules("resolve_alpha, resolve_beta, resolve_alpha")
	if err != nil {
		t.Fatalf("ResolveModules(name) error = %v", err)
	}
	if got := moduleNames(byName); strings.Join(got, ",") != "resolve_alpha,resolve_beta" {
		t.Fatalf("ResolveModules(name) = %v, want resolve_alpha,resolve_beta", got)
	}

	byCategory, err := ResolveModules("resolve_category")
	if err != nil {
		t.Fatalf("ResolveModules(category) error = %v", err)
	}
	if got := moduleNames(byCategory); strings.Join(got, ",") != "resolve_alpha,resolve_beta" {
		t.Fatalf("ResolveModules(category) = %v, want resolve_alpha,resolve_beta", got)
	}

	alias, err := ResolveModules("browser_chromium")
	if err != nil {
		t.Fatalf("ResolveModules(alias) error = %v", err)
	}
	if got := moduleNames(alias); strings.Join(got, ",") != "browser" {
		t.Fatalf("ResolveModules(alias) = %v, want browser", got)
	}

	all, err := ResolveModules("all")
	if err != nil {
		t.Fatalf("ResolveModules(all) error = %v", err)
	}
	if len(all) < 3 {
		t.Fatalf("ResolveModules(all) len = %d, want at least 3", len(all))
	}
}

func TestResolveModulesUnknown(t *testing.T) {
	_, err := ResolveModules("definitely_missing_module")
	if err == nil {
		t.Fatalf("ResolveModules(unknown) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unknown artifact or category") {
		t.Fatalf("ResolveModules(unknown) error = %q", err)
	}
}

func moduleNames(modules []module.Module) []string {
	names := make([]string, 0, len(modules))
	for _, mod := range modules {
		names = append(names, mod.Name())
	}
	return names
}

func registerResolverModule(name, category string) {
	if _, err := module.Get(name); err == nil {
		return
	}
	module.Register(resolverModule{name: name, category: category})
}
