package resource

import "fmt"

const (
	DefaultCPULimitPercent = 60
	// DefaultDiskIOLimitBps is zero: unthrottled. Measured on a real host, the
	// previous 80 MiB/s default cost 49 seconds on a 126-second run (+63%) for
	// protection that only matters when collecting from a live production
	// server. That is the minority case, and it is exactly when an operator
	// would set --disk-io deliberately.
	DefaultDiskIOLimitBps = 0
	DefaultCompress       = true

	MinCPULimitPercent = 10
	MaxCPULimitPercent = 80
	MinWorkers         = 1
	// MinDiskIOLimitBps is the floor for a budget that was actually asked for.
	// Zero stays zero and means no budget at all.
	MinDiskIOLimitBps = 1 * 1024 * 1024
)

const (
	// analyzerPeakBytes is the working set to assume per concurrent analyzer.
	// mft_parser holds the parsed record table, a name/parent index and a path
	// cache for a whole volume before it can emit a row, so its peak scales
	// with the artifact. There is no RAM cap any more — the soft one that used
	// to be here never prevented an allocation — so this divisor is what stands
	// between a multi-GB volume and the machine's swap file.
	analyzerPeakBytes = 2 * 1024 * 1024 * 1024
	// analyzerMemoryHeadroomPct leaves room for the rest of the machine. The
	// host is usually a live system under investigation, not a spare box.
	analyzerMemoryHeadroomPct = 70
)

type Config struct {
	CPULimitPercent int   `json:"cpu_limit_percent"`
	DiskIOLimitBps  int64 `json:"disk_io_limit_bps"`
	Compress        bool  `json:"compress"`

	// CollectorWorkers and AnalyzerWorkers are the counts the runner dispatches
	// with. There is no way to override them: the right degree of parallelism
	// depends on the storage behind the run, which an operator cannot see from
	// the command line and which the wrong answer to makes collection slower,
	// not faster. They are recorded in the manifest with the reasoning, so a
	// run stays auditable even though the numbers were chosen per machine.
	CollectorWorkers int    `json:"collector_workers"`
	AnalyzerWorkers  int    `json:"analyzer_workers"`
	WorkersRationale string `json:"workers_rationale,omitempty"`

	// CPULimitMechanism and DiskIOMechanism record how each cap was enforced.
	// They matter for interpreting a run afterwards: the CPU fallback leaves
	// winpmem and the PowerShell-hosted parsers uncapped, and a host without
	// storage rate control runs unthrottled however the budget was set.
	CPULimitMechanism string `json:"cpu_limit_mechanism,omitempty"`
	DiskIOMechanism   string `json:"disk_io_mechanism,omitempty"`
}

func DefaultConfig() Config {
	return SuggestConfig()
}

// SuggestConfig returns the starting configuration for a run.
//
// None of these three depend on the host: the CPU cap is a share of whatever
// cores exist, the disk budget is opt-in, and compression is a policy choice.
// Worker counts are the host-dependent part and are left at zero here, because
// they also depend on where the output lands; ResolveWorkers fills them in once
// that is known.
func SuggestConfig() Config {
	return Config{
		CPULimitPercent: DefaultCPULimitPercent,
		DiskIOLimitBps:  DefaultDiskIOLimitBps,
		Compress:        DefaultCompress,
	}
}

func (c Config) Normalized() Config {
	defaults := SuggestConfig()
	if c.CPULimitPercent <= 0 {
		c.CPULimitPercent = defaults.CPULimitPercent
	}
	c.CPULimitPercent = min(max(c.CPULimitPercent, MinCPULimitPercent), MaxCPULimitPercent)

	// A budget is opt-in, so zero is a meaningful value rather than something to
	// fill in with a default. There is no upper clamp: the cap is enforced by
	// the kernel against real device traffic, and an operator asking for more
	// than the hardware can do simply gets the hardware's speed.
	if c.DiskIOLimitBps < 0 {
		c.DiskIOLimitBps = 0
	}
	if c.DiskIOLimitBps > 0 {
		c.DiskIOLimitBps = max(c.DiskIOLimitBps, MinDiskIOLimitBps)
	}
	return c
}

// ResolveWorkers derives the per-batch worker counts for a run whose output
// lands in outputBaseDir, and records why they were chosen.
func (c Config) ResolveWorkers(outputBaseDir string) Config {
	host := DetectHostResources()
	storage := SurveyStorage(outputBaseDir)

	c.CollectorWorkers = suggestCollectorWorkers(host, storage)
	c.AnalyzerWorkers = suggestAnalyzerWorkers(host)
	c.WorkersRationale = fmt.Sprintf("%d cores, %s free RAM, %s",
		max(host.CPUCores, 1), FormatBytes(host.AvailableRAMBytes), storage.Rationale())
	return c
}

// WorkerSummary renders the resolved counts for the summary table and the
// progress footer.
func (c Config) WorkerSummary() string {
	return fmt.Sprintf("%d collect / %d analyze", c.CollectorWorkers, c.AnalyzerWorkers)
}

// suggestCollectorWorkers derives collection concurrency from the machine's
// actual storage topology.
//
// A collector is a pipe: it reads from a source drive and writes to the
// evidence drive. Two independent limits apply, and the tighter one governs:
//
//   - Reads spread across every distinct physical drive involved, so a machine
//     with several spindles genuinely serves several readers at once.
//   - Writes all funnel through the one evidence device, so its tolerance caps
//     the whole batch no matter how many source drives there are.
//
// Nothing here is a fixed ceiling. On a single spinning disk it lands at 1-4;
// on a workstation reading NVMe and writing NVMe it lands at core count.
func suggestCollectorWorkers(host HostResources, storage StorageSurvey) int {
	cores := host.CPUCores
	if cores <= 0 {
		cores = 1
	}

	workers := min(storage.ReadStreams(), storage.WriteStreams())
	// Each stream also hashes while it copies, so a stream needs a core to run
	// on; past that, extra workers only queue behind the CPU.
	workers = min(workers, cores)
	return max(workers, MinWorkers)
}

// suggestAnalyzerWorkers derives analysis concurrency from cores and free
// memory. Analysis reads artifacts already on disk, so storage topology does
// not bound it — the parsers' working set does.
func suggestAnalyzerWorkers(host HostResources) int {
	cores := host.CPUCores
	if cores <= 0 {
		cores = 1
	}

	workers := cores
	if host.AvailableRAMBytes > 0 {
		usable := host.AvailableRAMBytes * analyzerMemoryHeadroomPct / 100
		workers = min(workers, int(usable/analyzerPeakBytes))
	}
	return max(workers, MinWorkers)
}

func (c Config) IsZero() bool {
	return c.CPULimitPercent == 0 &&
		c.DiskIOLimitBps == 0 &&
		!c.Compress
}
