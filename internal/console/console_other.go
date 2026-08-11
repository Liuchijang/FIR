//go:build !windows

package console

import (
	"os"

	"golang.org/x/term"
)

func Ensure() {}

func EnsureInteractive() {}

func PauseBeforeExit() {}

func SupportsUnicodeGlyphs() bool { return true }

func SyncBufferToWindow() {}

func CurrentSize() (int, int, bool) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return 0, 0, false
	}
	return width, height, true
}
