package resource

import (
	"fmt"
	"strings"
)

// MediaKind describes how the storage behind a path behaves under concurrent
// access, which is what decides whether parallel collection helps or hurts.
type MediaKind int

const (
	// MediaUnknown means the device did not answer the probe. Callers must not
	// treat it as spinning rust: plenty of healthy USB bridges and virtual
	// disks simply do not implement the query.
	MediaUnknown MediaKind = iota
	// MediaSolidState has no seek penalty, so concurrent reads raise queue
	// depth and throughput with it.
	MediaSolidState
	// MediaSeekPenalty is a spinning disk. Concurrent large sequential reads
	// make the head thrash, so parallelism here is slower than doing one
	// artifact at a time.
	MediaSeekPenalty
)

func (m MediaKind) String() string {
	switch m {
	case MediaSolidState:
		return "ssd"
	case MediaSeekPenalty:
		return "hdd"
	default:
		return "unknown"
	}
}

// BusType mirrors STORAGE_BUS_TYPE. Only the values that change the answer are
// named; everything else falls through to the conservative default.
type BusType uint32

const (
	BusTypeUnknown BusType = 0x00
	BusTypeAta     BusType = 0x03
	BusTypeUSB     BusType = 0x07
	BusTypeRAID    BusType = 0x08
	BusTypeSAS     BusType = 0x0A
	BusTypeSATA    BusType = 0x0B
	BusTypeNVMe    BusType = 0x11
)

func (b BusType) String() string {
	switch b {
	case BusTypeNVMe:
		return "nvme"
	case BusTypeSATA:
		return "sata"
	case BusTypeSAS:
		return "sas"
	case BusTypeUSB:
		return "usb"
	case BusTypeRAID:
		return "raid"
	case BusTypeAta:
		return "ata"
	default:
		return "unknown-bus"
	}
}

// StorageDevice is one physical drive a run will touch.
type StorageDevice struct {
	Number         uint32
	Media          MediaKind
	Bus            BusType
	CommandQueuing bool
}

func (d StorageDevice) String() string {
	queue := ""
	if d.CommandQueuing {
		queue = "+ncq"
	}
	return fmt.Sprintf("%s/%s%s", d.Media, d.Bus, queue)
}

// ioRole distinguishes the two very different concurrency limits a single
// device has.
type ioRole int

const (
	roleRead ioRole = iota
	roleWrite
)

// ConcurrentStreams reports how many simultaneous sequential streams this
// device serves before throughput stops improving.
//
// These numbers describe device physics, not a policy choice: a single head
// cannot serve two sequential readers without seeking between them, while an
// NVMe controller is built around a deep queue and is starved by one stream.
// The per-run answer comes from combining them with the machine's actual device
// inventory in SurveyStorage — that is where the machine-specific part lives.
func (d StorageDevice) ConcurrentStreams(role ioRole) int {
	if d.Media == MediaSeekPenalty {
		if role == roleWrite {
			// Writes are absorbed by the write-back cache and reordered by the
			// elevator before they reach the platter, so writers interleave far
			// better than readers do on the same spindle.
			return 4
		}
		if d.CommandQueuing {
			// NCQ reorders requests, which recovers some of the loss.
			return 2
		}
		return 1
	}

	switch d.Bus {
	case BusTypeNVMe:
		// Deep queues are the entire design point of the interface.
		return 16
	case BusTypeUSB:
		// The bridge, not the flash, is the limit.
		return 4
	case BusTypeSATA, BusTypeSAS, BusTypeRAID:
		if d.CommandQueuing {
			return 8
		}
		return 4
	default:
		return 4
	}
}

// StorageSurvey is the device inventory a run's parallelism is derived from.
type StorageSurvey struct {
	// Output is the most restrictive device behind the evidence directory. All
	// writes funnel through it.
	Output StorageDevice
	// Sources are the distinct physical drives the collectors read. Reads on
	// separate spindles genuinely run in parallel, so these add up.
	Sources []StorageDevice
}

// ReadStreams is how many concurrent readers the source devices support in
// total. Separate physical drives contribute independently.
func (s StorageSurvey) ReadStreams() int {
	total := 0
	for _, device := range s.Sources {
		total += device.ConcurrentStreams(roleRead)
	}
	if total < 1 {
		return 1
	}
	return total
}

// WriteStreams is how many concurrent writers the evidence device supports.
func (s StorageSurvey) WriteStreams() int {
	return max(s.Output.ConcurrentStreams(roleWrite), 1)
}

func (s StorageSurvey) Rationale() string {
	sources := make([]string, 0, len(s.Sources))
	for _, device := range s.Sources {
		sources = append(sources, device.String())
	}
	if len(sources) == 0 {
		sources = append(sources, "no sources probed")
	}
	return fmt.Sprintf("write to %s (%d streams), read from %s (%d streams)",
		s.Output, s.WriteStreams(), strings.Join(sources, "+"), s.ReadStreams())
}
