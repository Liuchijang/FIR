package platform

// Disk I/O limit mechanisms, reported back so a run records how the budget was
// actually enforced.
const (
	// DiskMechanismJobObject throttles the whole process tree through the
	// Windows storage scheduler, child processes included.
	DiskMechanismJobObject = "job-object"
	// DiskMechanismNone means no budget was requested, or the host could not
	// install one.
	DiskMechanismNone = "none"
)

// LimitDiskIO caps disk bandwidth for this process and everything it spawns to
// bytesPerSecond, returning the mechanism used and a func that lifts the cap.
//
// Unlike the Go-side token bucket this replaces, the limit is enforced by the
// kernel against real device traffic. That closes the gap that made the old
// budget unable to deliver what it promised: winpmem writing a memory image and
// the PowerShell-hosted analyzers reading event logs both live in child
// processes, and no amount of instrumenting Go call sites could reach them.
//
// Zero or negative means no limit.
func LimitDiskIO(bytesPerSecond int64) (mechanism string, restore func()) {
	if bytesPerSecond <= 0 {
		return DiskMechanismNone, func() {}
	}
	return limitDiskIO(bytesPerSecond)
}
