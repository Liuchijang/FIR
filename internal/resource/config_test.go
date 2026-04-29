package resource

import "testing"

func TestConfigNormalizedClampsResourceLimits(t *testing.T) {
	cfg := Config{
		CPULimitPercent: 100,
		RAMCapBytes:     64 * 1024 * 1024 * 1024,
		Workers:         128,
		DiskIOLimitBps:  1024 * 1024 * 1024,
		Compress:        true,
	}.Normalized()

	if cfg.CPULimitPercent != MaxCPULimitPercent {
		t.Fatalf("CPULimitPercent = %d, want %d", cfg.CPULimitPercent, MaxCPULimitPercent)
	}
	if cfg.Workers > HardWorkersMax {
		t.Fatalf("Workers = %d, want <= %d", cfg.Workers, HardWorkersMax)
	}
	if cfg.RAMCapBytes > HardRAMCapMax {
		t.Fatalf("RAMCapBytes = %d, want <= %d", cfg.RAMCapBytes, HardRAMCapMax)
	}
	if cfg.DiskIOLimitBps != MaxDiskIOLimitBps {
		t.Fatalf("DiskIOLimitBps = %d, want %d", cfg.DiskIOLimitBps, MaxDiskIOLimitBps)
	}
}

func TestConfigNormalizedClampsMinimums(t *testing.T) {
	cfg := Config{
		CPULimitPercent: 1,
		RAMCapBytes:     1,
		Workers:         1,
		DiskIOLimitBps:  1,
		Compress:        true,
	}.Normalized()

	if cfg.CPULimitPercent != MinCPULimitPercent {
		t.Fatalf("CPULimitPercent = %d, want %d", cfg.CPULimitPercent, MinCPULimitPercent)
	}
	if cfg.RAMCapBytes != MinRAMCapBytes {
		t.Fatalf("RAMCapBytes = %d, want %d", cfg.RAMCapBytes, MinRAMCapBytes)
	}
	if cfg.Workers != MinWorkers {
		t.Fatalf("Workers = %d, want %d", cfg.Workers, MinWorkers)
	}
	if cfg.DiskIOLimitBps != MinDiskIOLimitBps {
		t.Fatalf("DiskIOLimitBps = %d, want %d", cfg.DiskIOLimitBps, MinDiskIOLimitBps)
	}
}
