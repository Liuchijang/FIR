//go:build windows

package console

import (
	"os"

	"golang.org/x/sys/windows"
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAllocConsole     = modKernel32.NewProc("AllocConsole")
	procAttachConsole    = modKernel32.NewProc("AttachConsole")
	procGetConsoleWindow = modKernel32.NewProc("GetConsoleWindow")
)

const attachParentProcess = ^uint32(0)

// Ensure makes sure FIR has a usable console in both terminal and Explorer launches.
func Ensure() {
	if hasConsoleWindow() || hasUsableStdHandles() {
		return
	}

	if attachParentConsole() {
		rebindStandardStreams()
		return
	}

	if allocConsole() {
		rebindStandardStreams()
		return
	}
}

func hasConsoleWindow() bool {
	hwnd, _, _ := procGetConsoleWindow.Call()
	return hwnd != 0
}

func hasUsableStdHandles() bool {
	return isUsableStdHandle(windows.STD_OUTPUT_HANDLE) || isUsableStdHandle(windows.STD_ERROR_HANDLE)
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
