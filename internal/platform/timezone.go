package platform

import (
	"fmt"
	"time"
)

// TimezoneInfo records the timezone of the machine a run was collected on.
//
// Every timestamp Tyto writes into a CSV is UTC, which is unambiguous but throws
// away something an investigator needs: what the clock on the subject's screen
// said when the event happened. Recording the zone once per run recovers that for
// every row of every CSV, at the cost of three fields.
//
// It matters most where the answer is least available. During a live collection
// the analyst could read the subject's zone off the machine; by the time the run
// is being parsed on a workstation two timezones away, the only remaining record
// of it is whatever the manifest kept.
type TimezoneInfo struct {
	// Name is Windows' own identity for the zone, e.g. "SE Asia Standard Time".
	// It names the region and the DST rules that go with it, which OffsetSeconds
	// alone cannot: +07:00 is Hanoi, Bangkok, Jakarta and Krasnoyarsk. Empty when
	// it could not be read.
	Name string `json:"name,omitempty"`
	// Abbreviation is what Go reports for the zone. On Windows this is an offset
	// spelled as a name ("+07"), which is why Name is read separately.
	Abbreviation string `json:"abbreviation,omitempty"`
	// OffsetSeconds is seconds east of UTC as it stood when the run started, so
	// it already includes DST if DST was in effect at that moment. A run that
	// straddles a DST boundary is not represented by one offset — Name is what
	// survives that, because it carries the rule rather than one evaluation of it.
	OffsetSeconds int `json:"offset_seconds"`
}

// String renders the zone for a human reading summary.txt.
//
// Offset first, name in parentheses after it. summary.txt renders this into a
// fixed 33-column cell that truncates, and the offset is the half that does work
// — it is what converts a UTC row back to the clock the subject was reading —
// while the name only identifies the region. Leading with it means a long zone
// name loses its tail rather than taking the offset down with it. manifest.json
// carries both in full either way.
//
// A nil receiver renders "unknown" rather than nothing: on an analysis run the
// field's absence is a fact about the input, and a blank cell reads as a
// rendering bug instead. Kept short enough to survive the 33-column cell — the
// first version said "not recorded by the analyzed run" and was truncated to
// "unknown (not recorded by the a...", which reads like a crash.
func (t *TimezoneInfo) String() string {
	if t == nil {
		return "unknown (not recorded)"
	}

	offset := t.OffsetSeconds
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	utc := fmt.Sprintf("UTC%s%02d:%02d", sign, offset/3600, (offset%3600)/60)

	if t.Name == "" {
		return utc
	}
	return fmt.Sprintf("%s (%s)", utc, t.Name)
}

// DetectTimezone reports the timezone of the machine this process is running on.
//
// Callers must not use it to describe a machine other than this one. An offline
// analysis run describes the subject, so its manifest takes the zone from the
// analyzed run and leaves the field absent when that run did not record one —
// the analyst's own zone is a different machine's answer, and a wrong offset is
// worse than a missing one because nothing about it looks wrong.
func DetectTimezone() TimezoneInfo {
	abbreviation, offset := time.Now().Zone()
	return TimezoneInfo{
		Name:          timezoneKeyName(),
		Abbreviation:  abbreviation,
		OffsetSeconds: offset,
	}
}
