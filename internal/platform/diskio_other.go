//go:build !windows

package platform

func limitDiskIO(int64) (string, func()) {
	return DiskMechanismNone, func() {}
}
