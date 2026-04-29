package resource

import "runtime"

type HostResources struct {
	CPUCores      int   `json:"cpu_cores"`
	TotalRAMBytes int64 `json:"total_ram_bytes"`
}

func DetectHostResources() HostResources {
	return HostResources{
		CPUCores:      runtime.NumCPU(),
		TotalRAMBytes: detectTotalRAMBytes(),
	}
}
