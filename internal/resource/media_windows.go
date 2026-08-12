//go:build windows

package resource

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"golang.org/x/sys/windows"
)

const (
	ioctlStorageQueryProperty       = 0x002D1400
	ioctlVolumeGetVolumeDiskExtents = 0x00560000

	propertyStandardQuery            = 0
	storageDeviceProperty            = 0
	storageDeviceSeekPenaltyProperty = 7

	// maxProbedExtents bounds the spanned-volume walk. A volume striped across
	// more disks than this is vanishingly rare on a triage target, and the
	// first few extents already answer the only question being asked.
	maxProbedExtents = 8

	// deviceDescriptorBuffer must hold STORAGE_DEVICE_DESCRIPTOR plus the
	// variable-length vendor/product strings that follow it.
	deviceDescriptorBuffer = 1024
	// busTypeOffset is where STORAGE_BUS_TYPE sits inside that descriptor.
	busTypeOffset = 28
	// commandQueueingOffset is the BOOLEAN reporting queue support.
	commandQueueingOffset = 11
)

// storagePropertyQuery mirrors STORAGE_PROPERTY_QUERY.
type storagePropertyQuery struct {
	PropertyID           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// deviceSeekPenaltyDescriptor mirrors DEVICE_SEEK_PENALTY_DESCRIPTOR.
type deviceSeekPenaltyDescriptor struct {
	Version           uint32
	Size              uint32
	IncursSeekPenalty uint8
	_                 [3]byte
}

// diskExtent mirrors DISK_EXTENT.
type diskExtent struct {
	DiskNumber     uint32
	_              uint32
	StartingOffset int64
	ExtentLength   int64
}

// volumeDiskExtents mirrors VOLUME_DISK_EXTENTS with room for a few extents.
type volumeDiskExtents struct {
	NumberOfDiskExtents uint32
	_                   uint32
	Extents             [maxProbedExtents]diskExtent
}

var (
	deviceCacheMu sync.Mutex
	deviceCache   = map[uint32]StorageDevice{}
	volumeCacheMu sync.Mutex
	volumeCache   = map[string][]uint32{}
)

// SurveyStorage builds the device inventory a run's parallelism is derived
// from: the drive behind the evidence directory, and every distinct physical
// drive the collectors read.
//
// The source side matters as much as the output side. A spinning system drive
// with evidence written to a fast external SSD looks fine from the output alone,
// but mft/usnjrnl/secure_sds still walk the spindle.
func SurveyStorage(outputBaseDir string) StorageSurvey {
	survey := StorageSurvey{Output: outputDevice(outputBaseDir)}

	seen := make(map[uint32]bool)
	for _, drive := range fixedDriveLetters() {
		for _, number := range volumeDiskNumbers(drive) {
			if seen[number] {
				continue
			}
			seen[number] = true
			survey.Sources = append(survey.Sources, describeDevice(number))
		}
	}
	if len(survey.Sources) == 0 {
		// Nothing enumerable — assume the evidence device is also the source,
		// which is the single-disk case and the conservative reading.
		survey.Sources = []StorageDevice{survey.Output}
	}
	return survey
}

// outputDevice returns the most restrictive physical drive behind a path, since
// every write in the run has to pass through all of them.
func outputDevice(path string) StorageDevice {
	numbers := volumeDiskNumbers(volumeRoot(path))
	if len(numbers) == 0 {
		return StorageDevice{Media: MediaUnknown, Bus: BusTypeUnknown}
	}

	worst := describeDevice(numbers[0])
	for _, number := range numbers[1:] {
		candidate := describeDevice(number)
		if candidate.ConcurrentStreams(roleWrite) < worst.ConcurrentStreams(roleWrite) {
			worst = candidate
		}
	}
	return worst
}

func fixedDriveLetters() []string {
	drives, err := acquisition.ListFixedDrives()
	if err != nil {
		return nil
	}
	return drives
}

// DetectMediaKind reports how the storage behind path behaves under concurrent
// access. Kept for callers that only need the coarse answer.
func DetectMediaKind(path string) MediaKind {
	return outputDevice(path).Media
}

// describeDevice probes one physical drive. Results are cached: a device cannot
// change during a run, and the run config screen re-derives on every keypress.
func describeDevice(number uint32) StorageDevice {
	deviceCacheMu.Lock()
	defer deviceCacheMu.Unlock()
	if device, ok := deviceCache[number]; ok {
		return device
	}

	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, number)
	device := StorageDevice{Number: number, Media: MediaUnknown, Bus: BusTypeUnknown}
	device.Media = seekPenaltyOfDevice(path)
	device.Bus, device.CommandQueuing = busOfDevice(path)

	deviceCache[number] = device
	return device
}

// volumeRoot returns the drive letter backing path, or "" when there isn't one
// (a UNC share has no local device to interrogate).
func volumeRoot(path string) string {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	name := filepath.VolumeName(abs)
	if len(name) != 2 || name[1] != ':' {
		return ""
	}
	return strings.ToUpper(name[:1])
}

// volumeDiskNumbers maps a drive letter to the physical drives behind it.
func volumeDiskNumbers(drive string) []uint32 {
	if drive == "" {
		return nil
	}

	volumeCacheMu.Lock()
	defer volumeCacheMu.Unlock()
	if numbers, ok := volumeCache[drive]; ok {
		return numbers
	}

	numbers := queryVolumeDiskNumbers(drive)
	volumeCache[drive] = numbers
	return numbers
}

func queryVolumeDiskNumbers(drive string) []uint32 {
	handle, err := openDevice(`\\.\` + drive + ":")
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)

	var extents volumeDiskExtents
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		ioctlVolumeGetVolumeDiskExtents,
		nil,
		0,
		(*byte)(unsafe.Pointer(&extents)),
		uint32(unsafe.Sizeof(extents)),
		&returned,
		nil,
	); err != nil {
		return nil
	}

	count := min(int(extents.NumberOfDiskExtents), maxProbedExtents)
	seen := make(map[uint32]bool, count)
	numbers := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		number := extents.Extents[i].DiskNumber
		if seen[number] {
			continue
		}
		seen[number] = true
		numbers = append(numbers, number)
	}
	return numbers
}

func seekPenaltyOfDevice(devicePath string) MediaKind {
	handle, err := openDevice(devicePath)
	if err != nil {
		return MediaUnknown
	}
	defer windows.CloseHandle(handle)

	query := storagePropertyQuery{
		PropertyID: storageDeviceSeekPenaltyProperty,
		QueryType:  propertyStandardQuery,
	}
	var descriptor deviceSeekPenaltyDescriptor
	var returned uint32
	err = windows.DeviceIoControl(
		handle,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&query)),
		uint32(unsafe.Sizeof(query)),
		(*byte)(unsafe.Pointer(&descriptor)),
		uint32(unsafe.Sizeof(descriptor)),
		&returned,
		nil,
	)
	// Plenty of USB bridges and virtual disks do not implement this query. An
	// unanswered probe is reported as unknown rather than guessed at.
	if err != nil || returned < uint32(unsafe.Sizeof(descriptor)) {
		return MediaUnknown
	}
	if descriptor.IncursSeekPenalty != 0 {
		return MediaSeekPenalty
	}
	return MediaSolidState
}

// busOfDevice reads the interface the drive is attached to, and whether it
// supports command queuing. Both change how much concurrency is useful: NVMe is
// built around a deep queue, a USB bridge is not, and a device without queuing
// serves one request at a time whatever the medium.
func busOfDevice(devicePath string) (BusType, bool) {
	handle, err := openDevice(devicePath)
	if err != nil {
		return BusTypeUnknown, false
	}
	defer windows.CloseHandle(handle)

	query := storagePropertyQuery{
		PropertyID: storageDeviceProperty,
		QueryType:  propertyStandardQuery,
	}
	buffer := make([]byte, deviceDescriptorBuffer)
	var returned uint32
	err = windows.DeviceIoControl(
		handle,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&query)),
		uint32(unsafe.Sizeof(query)),
		&buffer[0],
		uint32(len(buffer)),
		&returned,
		nil,
	)
	if err != nil || returned < busTypeOffset+4 {
		return BusTypeUnknown, false
	}

	bus := BusType(*(*uint32)(unsafe.Pointer(&buffer[busTypeOffset])))
	queuing := buffer[commandQueueingOffset] != 0
	return bus, queuing
}

// openDevice opens a storage device for metadata queries only. Zero desired
// access is deliberate: these IOCTLs are answered by the device object, and
// asking for GENERIC_READ would make the probe fail without elevation.
func openDevice(devicePath string) (windows.Handle, error) {
	path, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		path,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
}
