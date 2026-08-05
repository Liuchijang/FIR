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
	const gb = 1024 * 1024 * 1024

	ramCap := int64(2 * gb)
	if host.TotalRAMBytes > 0 {
		switch {
		case host.TotalRAMBytes <= 8*gb:
			ramCap = 1 * gb
		case host.TotalRAMBytes >= 32*gb:
			ramCap = 4 * gb
		}
	}

	return Config{
		CPULimitPercent: DefaultCPULimitPercent,
		RAMCapBytes:     ramCap,
		Workers:         min(max(host.CPUCores/2, 2), 8),
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
	c.CPULimitPercent = min(max(c.CPULimitPercent, MinCPULimitPercent), MaxCPULimitPercent)

	if c.RAMCapBytes <= 0 {
		c.RAMCapBytes = defaults.RAMCapBytes
	}
	c.RAMCapBytes = min(max(c.RAMCapBytes, MinRAMCapBytes), MaxRAMCapBytes(host))

	if c.Workers <= 0 {
		c.Workers = defaults.Workers
	}
	c.Workers = min(max(c.Workers, MinWorkers), MaxWorkers(host))

	if c.DiskIOLimitBps <= 0 {
		c.DiskIOLimitBps = defaults.DiskIOLimitBps
	}
	c.DiskIOLimitBps = min(max(c.DiskIOLimitBps, MinDiskIOLimitBps), MaxDiskIOLimitBps)
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
	cores := host.CPUCores
	if cores <= 0 {
		cores = HardWorkersMax
	}
	return min(max(cores, MinWorkers), HardWorkersMax)
}

func MaxRAMCapBytes(host HostResources) int64 {
	if host.TotalRAMBytes <= 0 {
		return FallbackRAMCapMax
	}
	return min(max(host.TotalRAMBytes/2, MinRAMCapBytes), HardRAMCapMax)
}
