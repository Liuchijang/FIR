//go:build !windows

package resource

func liveUsnJournalSize() int64 {
	return 0
}
