package resource

const (
	DefaultCPULimitPercent = 60
	DefaultDiskIOLimitBps  = 80 * 1024 * 1024
	DefaultCompress        = true

	MinCPULimitPercent = 10
	MaxCPULimitPercent = 80
	MinRAMCapBytes     = 512 * 1024 * 1024
	FallbackRAMCapMax  = 4 * 1024 * 1024 * 1024
	HardRAMCapMax      = 8 * 1024 * 1024 * 1024
	MinWorkers         = 1
	HardWorkersMax     = 16
	MinDiskIOLimitBps  = 10 * 1024 * 1024
	MaxDiskIOLimitBps  = 250 * 1024 * 1024
)

type Config struct {
	CPULimitPercent int   `json:"cpu_limit_percent"`
	RAMCapBytes     int64 `json:"ram_cap_bytes"`
	Workers         int   `json:"workers"`
	DiskIOLimitBps  int64 `json:"disk_io_limit_bps"`
	Compress        bool  `json:"compress"`
}

func DefaultConfig() Config {
	host := DetectHostResources()
	return SuggestConfig(host)
}

func SuggestConfig(host HostResources) Config {
	workers := host.CPUCores / 2
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}

	ramCap := int64(2 * 1024 * 1024 * 1024)
	if host.TotalRAMBytes > 0 {
		switch {
		case host.TotalRAMBytes <= 8*1024*1024*1024:
			ramCap = 1 * 1024 * 1024 * 1024
		case host.TotalRAMBytes >= 32*1024*1024*1024:
			ramCap = 4 * 1024 * 1024 * 1024
		}
	}

	return Config{
		CPULimitPercent: DefaultCPULimitPercent,
		RAMCapBytes:     ramCap,
		Workers:         workers,
		DiskIOLimitBps:  DefaultDiskIOLimitBps,
		Compress:        DefaultCompress,
	}
}

func (c Config) Normalized() Config {
	host := DetectHostResources()
	defaults := SuggestConfig(host)
	if c.CPULimitPercent <= 0 {
		c.CPULimitPercent = defaults.CPULimitPercent
	}
	c.CPULimitPercent = clampInt(c.CPULimitPercent, MinCPULimitPercent, MaxCPULimitPercent)

	if c.RAMCapBytes <= 0 {
		c.RAMCapBytes = defaults.RAMCapBytes
	}
	c.RAMCapBytes = clampInt64(c.RAMCapBytes, MinRAMCapBytes, MaxRAMCapBytes(host))

	if c.Workers <= 0 {
		c.Workers = defaults.Workers
	}
	c.Workers = clampInt(c.Workers, MinWorkers, MaxWorkers(host))

	if c.DiskIOLimitBps <= 0 {
		c.DiskIOLimitBps = defaults.DiskIOLimitBps
	}
	c.DiskIOLimitBps = clampInt64(c.DiskIOLimitBps, MinDiskIOLimitBps, MaxDiskIOLimitBps)
	return c
}

func (c Config) IsZero() bool {
	return c.CPULimitPercent == 0 &&
		c.RAMCapBytes == 0 &&
		c.Workers == 0 &&
		c.DiskIOLimitBps == 0 &&
		!c.Compress
}

func MaxWorkers(host HostResources) int {
	maxWorkers := host.CPUCores
	if maxWorkers <= 0 {
		maxWorkers = HardWorkersMax
	}
	if maxWorkers > HardWorkersMax {
		maxWorkers = HardWorkersMax
	}
	if maxWorkers < MinWorkers {
		return MinWorkers
	}
	return maxWorkers
}

func MaxRAMCapBytes(host HostResources) int64 {
	if host.TotalRAMBytes <= 0 {
		return FallbackRAMCapMax
	}
	max := host.TotalRAMBytes / 2
	if max > HardRAMCapMax {
		max = HardRAMCapMax
	}
	if max < MinRAMCapBytes {
		return MinRAMCapBytes
	}
	return max
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampInt64(value, minValue, maxValue int64) int64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
