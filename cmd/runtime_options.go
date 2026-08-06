package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Liuchijang/FIR/internal/collection"
	"github.com/Liuchijang/FIR/internal/resource"
)

type runtimeConfig struct {
	OutputBaseDir string
	Verbose       bool
	Timeout       time.Duration
	Resources     resource.Config
}

func runtimeConfigFromFlags() runtimeConfig {
	cfg := runtimeConfig{
		OutputBaseDir: outputDir,
		Verbose:       verbose,
		Timeout:       timeoutFlag,
		Resources: resource.Config{
			CPULimitPercent: cpuLimitFlag,
			DiskIOLimitBps:  diskIOBytesFlag,
			Compress:        compressFlag,
		},
	}
	return cfg.normalized()
}

func (c runtimeConfig) normalized() runtimeConfig {
	if c.OutputBaseDir == "" {
		c.OutputBaseDir = "."
	}
	c.Resources = c.Resources.Normalized().ResolveWorkers(c.OutputBaseDir)
	return c
}

func (c runtimeConfig) CollectionOptions(silentConsole bool, callbacks collection.Callbacks) collection.Options {
	c = c.normalized()
	return collection.Options{
		OutputBaseDir: c.OutputBaseDir,
		Verbose:       c.Verbose,
		Timeout:       c.Timeout,
		Resources:     c.Resources,
		SilentConsole: silentConsole,
		Callbacks:     callbacks,
	}
}

func parseByteSize(value string) (int64, error) {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "" {
		return 0, nil
	}
	multiplier := int64(1)
	for _, suffix := range []struct {
		text string
		mul  int64
	}{
		{"GB", 1024 * 1024 * 1024},
		{"G", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"M", 1024 * 1024},
		{"KB", 1024},
		{"K", 1024},
	} {
		if strings.HasSuffix(value, suffix.text) {
			multiplier = suffix.mul
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix.text))
			break
		}
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", value)
	}
	return int64(number * float64(multiplier)), nil
}
