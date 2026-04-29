//go:build !windows

package resource

func detectTotalRAMBytes() int64 {
	return 0
}
