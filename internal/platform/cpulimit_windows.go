//go:build windows

package platform

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobObjectCPURateControlEnable turns on rate control for a job.
//
// JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP is deliberately not set. Without it the
// cap binds when something else wants the CPU and the job may exceed it while
// the machine is otherwise idle, which is the behaviour a triage tool wants:
// stay out of the way on a busy production server, but do not artificially
// stretch an acquisition on a quiet one. A longer run is not free — it widens
// the window over which the artifacts being collected keep changing.
const jobObjectCPURateControlEnable = 0x1

// cpuRateScale converts a percentage into the CpuRate unit, which is cycles
// per 10,000 rather than per 100.
const cpuRateScale = 100

// jobObjectCPURateControlInformation mirrors
// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION. Rate overlays a union whose other
// members (Weight, and a MinRate/MaxRate pair) are unused here.
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	Rate         uint32
}

var (
	jobOnce   sync.Once
	jobHandle windows.Handle
	jobErr    error
)

// cpuJob returns the process-wide job object, creating it on first use.
//
// The handle is kept for the lifetime of the process on purpose. A process can
// never leave a job once assigned, so there is nothing to undo and re-creating
// per run would only add a second nested job. Keeping it means a later run can
// still adjust the rate.
func cpuJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		handle, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		// Note the limits deliberately left unset: without
		// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, dropping this handle cannot take
		// the collection down with it.
		if err := windows.AssignProcessToJobObject(handle, windows.CurrentProcess()); err != nil {
			windows.CloseHandle(handle)
			jobErr = err
			return
		}
		jobHandle = handle
	})
	return jobHandle, jobErr
}

// limitCPU caps the process and everything it spawns.
//
// Child processes inherit the job automatically, which is the entire point:
// winpmem and the PowerShell-hosted event log parser do the heaviest CPU work
// in a run and GOMAXPROCS cannot touch either of them.
func limitCPU(percent int) (string, func()) {
	job, err := cpuJob()
	if err != nil {
		// Assignment can fail when the process already sits in a job that
		// forbids nesting. Falling back keeps a partial cap rather than none.
		return CPUMechanismGOMAXPROCS, limitGOMAXPROCS(percent)
	}
	if err := setCPURate(job, uint32(percent)*cpuRateScale); err != nil {
		return CPUMechanismGOMAXPROCS, limitGOMAXPROCS(percent)
	}
	return CPUMechanismJobObject, func() { clearCPURate(job) }
}

func setCPURate(job windows.Handle, rate uint32) error {
	info := jobObjectCPURateControlInformation{
		ControlFlags: jobObjectCPURateControlEnable,
		Rate:         rate,
	}
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return err
}

// clearCPURate lifts the cap. The process stays in the job — it has to, there
// is no way out — so this is what "restore" can actually mean here.
func clearCPURate(job windows.Handle) {
	info := jobObjectCPURateControlInformation{}
	windows.SetInformationJobObject(
		job,
		windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}
