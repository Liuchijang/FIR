//go:build windows

package platform

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobObjectIoRateControlEnable turns on storage rate control for a job.
const jobObjectIoRateControlEnable = 0x1

// jobIoRateControlInformation mirrors JOBOBJECT_IO_RATE_CONTROL_INFORMATION.
// A nil VolumeName applies the limit to every volume the job touches, which is
// what a run writing evidence to a second drive needs.
type jobIoRateControlInformation struct {
	MaxIops         int64
	MaxBandwidth    int64
	ReservationIops int64
	VolumeName      *uint16
	BaseIoSize      uint32
	ControlFlags    uint32
}

var (
	modkernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procSetIoRateControlJobObj = modkernel32.NewProc("SetIoRateControlInformationJobObject")
)

// limitDiskIO installs a bandwidth cap on the process-wide job object.
//
// Measured on Windows 10: an 8 MiB/s cap held both volumes to 7.9-8.0 MiB/s,
// and a spawned PowerShell process writing 32 MiB went from 302ms to 4.03s —
// the child is inside the cap, which is the whole point of using the job.
func limitDiskIO(bytesPerSecond int64) (string, func()) {
	job, err := cpuJob()
	if err != nil {
		return DiskMechanismNone, func() {}
	}
	if err := setIoRate(job, bytesPerSecond); err != nil {
		// Storage rate control needs a volume that supports it. Report honestly
		// rather than pretending a budget is in force.
		return DiskMechanismNone, func() {}
	}
	return DiskMechanismJobObject, func() { setIoRate(job, 0) }
}

// setIoRate applies bytesPerSecond to the job, or lifts the cap when zero.
func setIoRate(job windows.Handle, bytesPerSecond int64) error {
	info := jobIoRateControlInformation{}
	if bytesPerSecond > 0 {
		info.MaxBandwidth = bytesPerSecond
		info.ControlFlags = jobObjectIoRateControlEnable
	}

	// Returns the number of volume records written; zero means failure.
	ret, _, err := procSetIoRateControlJobObj.Call(
		uintptr(job),
		uintptr(unsafe.Pointer(&info)),
	)
	if ret == 0 {
		return err
	}
	return nil
}
