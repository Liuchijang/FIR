package platform

import (
	"os"
	"runtime"
)

type HostInfo struct {
	Hostname     string
	OS           string
	Architecture string
}

func DetectHost() HostInfo {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "UNKNOWN"
	}
	return HostInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
}
