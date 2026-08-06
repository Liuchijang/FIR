package platform

import "runtime"

// CPU limit mechanisms, reported back to the caller so a run records how the
// cap was actually enforced rather than only what was asked for.
const (
	// CPUMechanismJobObject caps the whole process tree through the Windows
	// scheduler, so child processes are covered too.
	CPUMechanismJobObject = "job-object"
	// CPUMechanismGOMAXPROCS only bounds goroutines running Go code. Child
	// processes and blocking syscalls escape it.
	CPUMechanismGOMAXPROCS = "gomaxprocs"
	// CPUMechanismNone means no cap was requested.
	CPUMechanismNone = "none"
)

// LimitCPU caps CPU usage to percent and returns the mechanism that was used
// plus a func that lifts the cap.
//
// A percent of 100 or more is not a limit, and anything at or below zero means
// no cap was asked for; both are no-ops.
func LimitCPU(percent int) (mechanism string, restore func()) {
	if percent <= 0 || percent >= 100 {
		return CPUMechanismNone, func() {}
	}
	return limitCPU(percent)
}

// limitGOMAXPROCS is the portable fallback: it only reaches goroutines running
// Go code, which for a collector run is the smaller half of the work.
func limitGOMAXPROCS(percent int) func() {
	previous := runtime.GOMAXPROCS(0)
	// Round up, so asking for 60% on a 2-core host does not silently deliver 50%.
	procs := (previous*percent + 99) / 100
	if procs < 1 {
		procs = 1
	}
	runtime.GOMAXPROCS(procs)
	return func() { runtime.GOMAXPROCS(previous) }
}
