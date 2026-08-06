//go:build !windows

package resource

func detectRAMBytes() (total, available int64) {
	return 0, 0
}
