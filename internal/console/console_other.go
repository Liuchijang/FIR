//go:build !windows

package console

func Ensure() {}

func EnsureInteractive() {}

func PauseBeforeExit() {}

func LikelyExplorerLaunch() bool { return false }

func SyncBufferToWindow() {}
