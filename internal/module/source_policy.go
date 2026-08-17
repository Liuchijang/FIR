package module

import "fmt"

type SourcePolicy string

const (
	// SourcePolicyCollectedThenLive uses collected output when its source collector
	// is selected for the run, and live/fallback sources when it is not selected.
	SourcePolicyCollectedThenLive SourcePolicy = "collected_then_live"

	// SourcePolicyCollectedOnly reads only what the analyzed run actually holds.
	//
	// It exists for the offline workflow: collection runs on the subject machine
	// and analysis runs later on the investigator's. There the live host is a
	// different machine entirely, so falling back to it would write the analyst's
	// own prefetch, registry and event logs into the subject's CSVs with nothing
	// in the output saying so. An analyzer whose artifact is absent reports
	// Skipped instead.
	SourcePolicyCollectedOnly SourcePolicy = "collected_only"
)

func (r CollectRequest) IsSelected(name string) bool {
	return r.SelectedModules[name]
}

func (r AnalyzeRequest) IsSelected(name string) bool {
	return r.SelectedModules[name]
}

// SourceRoot is the run root an analyzer reads collected artifacts from.
//
// It is separate from OutputDir because offline analysis reads one run and
// writes another; for a live run the two are the same directory and SourceDir
// is left empty.
func (r AnalyzeRequest) SourceRoot() string {
	if r.SourceDir != "" {
		return r.SourceDir
	}
	return r.OutputDir
}

// AllowLive reports whether this request may fall back to the live system when
// the analyzed run does not hold the artifact.
func (r AnalyzeRequest) AllowLive() bool {
	return r.SourcePolicy != SourcePolicyCollectedOnly
}

// OfflineAnalyzer is implemented by an analyzer that can run against a
// previously collected run instead of the live host.
//
// Absence means "no" on purpose. An analyzer that only exists as a live query —
// wmi_parser is the remaining one — would otherwise silently describe the
// investigator's own machine in a report labelled with the subject's hostname,
// so offline capability has to be claimed rather than assumed.
type OfflineAnalyzer interface {
	SupportsOffline() bool
}

// SupportsOffline reports whether a module can run in the offline analysis mode.
func SupportsOffline(m Module) bool {
	if offline, ok := m.(OfflineAnalyzer); ok {
		return offline.SupportsOffline()
	}
	return false
}

// LiveOnlyResult is what an analyzer that only exists as a query of the running
// host returns when the policy forbids reading it.
//
// The CLI already keeps these analyzers out of an offline run, so reaching this
// means something selected one directly. It is a skip rather than a refusal to
// start, and it says so in the summary: the alternative is a CSV describing the
// investigator's own machine under the subject's hostname.
func LiveOnlyResult(outDir, name string) AnalyzeResult {
	return AnalyzeResult{
		OutputPath: outDir,
		Skipped:    true,
		Error:      fmt.Sprintf("%s only exists as a live query of the running host", name),
	}
}
