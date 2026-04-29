package cmd

import (
	"time"

	"github.com/Liuchijang/FIR/internal/collection"
)

type runtimeConfig struct {
	OutputBaseDir string
	Verbose       bool
	Timeout       time.Duration
	Concurrency   int
}

func runtimeConfigFromFlags() runtimeConfig {
	cfg := runtimeConfig{
		OutputBaseDir: outputDir,
		Verbose:       verbose,
		Timeout:       timeoutFlag,
		Concurrency:   concurrencyFlag,
	}
	return cfg.normalized()
}

func (c runtimeConfig) normalized() runtimeConfig {
	if c.OutputBaseDir == "" {
		c.OutputBaseDir = "."
	}
	if c.Timeout <= 0 {
		c.Timeout = collection.DefaultTimeout
	}
	if c.Concurrency <= 0 {
		c.Concurrency = collection.DefaultConcurrency
	}
	return c
}

func (c runtimeConfig) CollectionOptions(silentConsole bool, callbacks collection.Callbacks) collection.Options {
	c = c.normalized()
	return collection.Options{
		OutputBaseDir: c.OutputBaseDir,
		Verbose:       c.Verbose,
		Timeout:       c.Timeout,
		Concurrency:   c.Concurrency,
		SilentConsole: silentConsole,
		Callbacks:     callbacks,
	}
}
