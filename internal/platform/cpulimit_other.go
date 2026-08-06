//go:build !windows

package platform

func limitCPU(percent int) (string, func()) {
	return CPUMechanismGOMAXPROCS, limitGOMAXPROCS(percent)
}
