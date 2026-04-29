//go:build !windows

package resource

import "fmt"

func FreeSpaceBytes(path string) (int64, error) {
	return 0, fmt.Errorf("free space detection is only implemented on Windows")
}
