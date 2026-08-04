//go:build !windows

package resource

func liveMFTSize() int64 {
	return 0
}
