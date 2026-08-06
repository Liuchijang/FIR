package resource

import "runtime"

type HostResources struct {
	CPUCores      int   `json:"cpu_cores"`
	TotalRAMBytes int64 `json:"total_ram_bytes"`
	// AvailableRAMBytes is what the machine can hand out right now. The
	// analyzers size their working set from the artifact they parse, so this —
	// not total RAM — is what bounds how many may run at once.
	AvailableRAMBytes int64 `json:"available_ram_bytes"`
}

func DetectHostResources() HostResources {
	total, available := detectRAMBytes()
	return HostResources{
		CPUCores:          runtime.NumCPU(),
		TotalRAMBytes:     total,
		AvailableRAMBytes: available,
	}
}
