//go:build windows

package console

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procAllocConsole               = modKernel32.NewProc("AllocConsole")
	procAttachConsole              = modKernel32.NewProc("AttachConsole")
	procFlushConsoleInputBuffer    = modKernel32.NewProc("FlushConsoleInputBuffer")
	procGetConsoleProcessList      = modKernel32.NewProc("GetConsoleProcessList")
	procGetConsoleScreenBufferInfo = modKernel32.NewProc("GetConsoleScreenBufferInfo")
	procGetConsoleWindow           = modKernel32.NewProc("GetConsoleWindow")
	procReadConsoleInputW          = modKernel32.NewProc("ReadConsoleInputW")
	procSetConsoleScreenBufferSize = modKernel32.NewProc("SetConsoleScreenBufferSize")
	procSetConsoleWindowInfo       = modKernel32.NewProc("SetConsoleWindowInfo")
	procSetConsoleCP               = modKernel32.NewProc("SetConsoleCP")
	procSetConsoleOutputCP         = modKernel32.NewProc("SetConsoleOutputCP")
)

const attachParentProcess = ^uint32(0)

const (
	enableProcessedOutput           = 0x0001
	enableVirtualTerminalProcessing = 0x0004
	keyEventType                    = 0x0001
	utf8CodePage                    = 65001
)

type inputRecord struct {
	EventType uint16
	_         uint16
	Event     [16]byte
}

type keyEventRecord struct {
	BKeyDown          int32
	WRepeatCount      uint16
	WVirtualKeyCode   uint16
	WVirtualScanCode  uint16
	UnicodeChar       uint16
	DwControlKeyState uint32
}

type coord struct {
	X int16
	Y int16
}

type smallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type consoleScreenBufferInfo struct {
	DwSize              coord
	DwCursorPosition    coord
	WAttributes         uint16
	SrWindow            smallRect
	DwMaximumWindowSize coord
}

func Ensure() {
	if hasConsoleWindow() || hasUsableStdHandles() {
		enableVirtualTerminal()
		return
	}

	if attachParentConsole() {
		rebindStandardStreams()
		enableVirtualTerminal()
		return
	}

	if allocConsole() {
		rebindStandardStreams()
		enableVirtualTerminal()
		return
	}
}

// EnsureInteractive guarantees the process has real console-backed stdin/stdout/stderr
// before launching an interactive prompt. Explorer launches often provide placeholder
// standard handles that are not attached to a console, which breaks interactive prompts.
func EnsureInteractive() {
	if hasConsoleWindow() && hasInteractiveConsoleHandles() {
		return
	}

	if !hasConsoleWindow() && attachParentConsole() {
		rebindStandardStreams()
		if hasInteractiveConsoleHandles() {
			return
		}
	}

	if !hasConsoleWindow() && allocConsole() {
		rebindStandardStreams()
		return
	}

	if !hasInteractiveConsoleHandles() {
		rebindStandardStreams()
	}

	enableVirtualTerminal()
}

func hasConsoleWindow() bool {
	hwnd, _, _ := procGetConsoleWindow.Call()
	return hwnd != 0
}

func hasUsableStdHandles() bool {
	return isUsableStdHandle(windows.STD_OUTPUT_HANDLE) || isUsableStdHandle(windows.STD_ERROR_HANDLE)
}

func hasInteractiveConsoleHandles() bool {
	return isConsoleHandle(windows.STD_INPUT_HANDLE) &&
		isConsoleHandle(windows.STD_OUTPUT_HANDLE) &&
		isConsoleHandle(windows.STD_ERROR_HANDLE)
}

func isUsableStdHandle(kind uint32) bool {
	handle, err := windows.GetStdHandle(kind)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return false
	}

	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return false
	}

	return fileType != windows.FILE_TYPE_UNKNOWN
}

func isConsoleHandle(kind uint32) bool {
	handle, err := windows.GetStdHandle(kind)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return false
	}

	var mode uint32
	return windows.GetConsoleMode(handle, &mode) == nil
}

func attachParentConsole() bool {
	r1, _, _ := procAttachConsole.Call(uintptr(attachParentProcess))
	return r1 != 0
}

func allocConsole() bool {
	r1, _, _ := procAllocConsole.Call()
	return r1 != 0
}

func rebindStandardStreams() {
	if in, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
		os.Stdin = in
		_ = windows.SetStdHandle(windows.STD_INPUT_HANDLE, windows.Handle(in.Fd()))
	}
	if out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout = out
		_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(out.Fd()))
	}
	if errOut, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stderr = errOut
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(errOut.Fd()))
	}
}

func enableVirtualTerminal() {
	enableUTF8Console()
	enableVirtualTerminalForHandle(windows.STD_OUTPUT_HANDLE)
	enableVirtualTerminalForHandle(windows.STD_ERROR_HANDLE)
}

func enableUTF8Console() {
	procSetConsoleOutputCP.Call(uintptr(utf8CodePage))
	procSetConsoleCP.Call(uintptr(utf8CodePage))
}

func enableVirtualTerminalForHandle(kind uint32) {
	handle, err := windows.GetStdHandle(kind)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return
	}

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}

	mode |= enableProcessedOutput | enableVirtualTerminalProcessing
	_ = windows.SetConsoleMode(handle, mode)
}

func PauseBeforeExit() {
	if !shouldPauseBeforeExit() {
		return
	}

	// Re-disable mouse tracking: Bubble Tea's own disable lands a moment later, and
	// queued MOUSE_EVENTs must drain before the keypress wait sees a real key —
	// otherwise it reads as "the window takes seconds to close".
	fmt.Fprint(os.Stdout, "\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[?1006l")
	fmt.Fprint(os.Stderr, "\nPress any key to exit . . .")
	waitForFreshConsoleKeypress()
	fmt.Fprintln(os.Stderr)
}

func LikelyExplorerLaunch() bool {
	return shouldPauseBeforeExit()
}

// Legacy conhost prints '?' for glyphs its font lacks, and neither the raster
// "Terminal" font nor Lucida Console carries rounded borders (U+256D-U+2570) or
// braille spinner frames (U+28xx) — a codepage switch cannot fix glyph coverage.
// Only hosts that advertise themselves are trusted: a false negative costs an
// ASCII fallback, a false positive litters '?' across the UI.
func SupportsUnicodeGlyphs() bool {
	if value, ok := os.LookupEnv("ConEmuANSI"); ok {
		return strings.EqualFold(strings.TrimSpace(value), "ON")
	}
	if term := strings.TrimSpace(os.Getenv("TERM")); term != "" {
		return !strings.EqualFold(term, "dumb")
	}
	for _, key := range []string{
		"WT_SESSION",
		"WT_PROFILE_ID",
		"TERM_PROGRAM",
		"ALACRITTY_WINDOW_ID",
		"WEZTERM_EXECUTABLE",
	} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return true
		}
	}
	return false
}

func SyncBufferToWindow() {
	if !hasInteractiveConsoleHandles() {
		return
	}
	syncBufferToWindowForHandle(windows.STD_OUTPUT_HANDLE)
	syncBufferToWindowForHandle(windows.STD_ERROR_HANDLE)
}

func CurrentSize() (int, int, bool) {
	if !hasInteractiveConsoleHandles() {
		return 0, 0, false
	}
	return consoleSizeForHandle(windows.STD_OUTPUT_HANDLE)
}

func shouldPauseBeforeExit() bool {
	if !hasConsoleWindow() || !hasInteractiveConsoleHandles() {
		return false
	}

	processes := make([]uint32, 8)
	r1, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&processes[0])),
		uintptr(len(processes)),
	)
	if r1 == 0 {
		return false
	}

	// If FIR is the only process attached to this console, it was likely launched
	// by Explorer / Right Click and should wait for user acknowledgement.
	return r1 == 1
}

func waitForFreshConsoleKeypress() {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return
	}

	procFlushConsoleInputBuffer.Call(uintptr(handle))

	records := make([]inputRecord, 1)
	for {
		var read uint32
		r1, _, _ := procReadConsoleInputW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&records[0])),
			1,
			uintptr(unsafe.Pointer(&read)),
		)
		if r1 == 0 || read == 0 {
			return
		}

		if records[0].EventType != keyEventType {
			continue
		}

		keyEvent := (*keyEventRecord)(unsafe.Pointer(&records[0].Event[0]))
		if keyEvent.BKeyDown != 0 {
			return
		}
	}
}

func syncBufferToWindowForHandle(kind uint32) {
	handle, err := windows.GetStdHandle(kind)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return
	}

	info, ok := getConsoleScreenBufferInfo(handle)
	if !ok {
		return
	}

	windowWidth := info.SrWindow.Right - info.SrWindow.Left + 1
	windowHeight := info.SrWindow.Bottom - info.SrWindow.Top + 1
	if windowWidth <= 0 || windowHeight <= 0 {
		return
	}

	if info.DwSize.X == windowWidth && info.DwSize.Y == windowHeight {
		return
	}

	// On Windows, SetConsoleScreenBufferSize cannot set the buffer smaller
	// than the current window extent. When the user shrinks the terminal,
	// we must first shrink the visible window rect so the buffer can follow.
	needShrinkX := info.DwSize.X > windowWidth
	needShrinkY := info.DwSize.Y > windowHeight
	if needShrinkX || needShrinkY {
		// Shrink the window rect to match the visible area before resizing
		// the buffer. This avoids the "buffer < window" constraint that
		// causes SetConsoleScreenBufferSize to silently fail.
		shrunkRect := smallRect{
			Left:   0,
			Top:    0,
			Right:  windowWidth - 1,
			Bottom: windowHeight - 1,
		}
		procSetConsoleWindowInfo.Call(
			uintptr(handle),
			1, // bAbsolute = TRUE
			uintptr(unsafe.Pointer(&shrunkRect)),
		)
	}

	procSetConsoleScreenBufferSize.Call(
		uintptr(handle),
		packCoord(windowWidth, windowHeight),
	)
}

func consoleSizeForHandle(kind uint32) (int, int, bool) {
	handle, err := windows.GetStdHandle(kind)
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return 0, 0, false
	}

	info, ok := getConsoleScreenBufferInfo(handle)
	if !ok {
		return 0, 0, false
	}

	windowWidth := int(info.SrWindow.Right - info.SrWindow.Left + 1)
	windowHeight := int(info.SrWindow.Bottom - info.SrWindow.Top + 1)
	if windowWidth <= 0 || windowHeight <= 0 {
		return 0, 0, false
	}
	return windowWidth, windowHeight, true
}

func getConsoleScreenBufferInfo(handle windows.Handle) (consoleScreenBufferInfo, bool) {
	var info consoleScreenBufferInfo
	r1, _, _ := procGetConsoleScreenBufferInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 == 0 {
		return consoleScreenBufferInfo{}, false
	}
	return info, true
}

func packCoord(x, y int16) uintptr {
	return uintptr(uint32(uint16(x)) | (uint32(uint16(y)) << 16))
}
