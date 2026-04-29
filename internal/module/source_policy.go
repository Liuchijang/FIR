package module

type SourcePolicy string

const (
	// SourcePolicyCollectedThenLive uses collected output when its source collector
	// is selected for the run, and live/fallback sources when it is not selected.
	SourcePolicyCollectedThenLive SourcePolicy = "collected_then_live"
)

func (r CollectRequest) IsSelected(name string) bool {
	return r.SelectedModules[name]
}

func (r AnalyzeRequest) IsSelected(name string) bool {
	return r.SelectedModules[name]
}
