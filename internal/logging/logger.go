// Package logging provides a dual-output logger for Tyto.
// Console output shows only progress/status messages with color.
// File output captures full structured logs for forensic audit trail.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

type Logger struct {
	mu            sync.Mutex
	fileLog       *slog.Logger
	logFile       *os.File
	verbose       bool
	startTime     time.Time
	consoleOutput bool
}

var (
	globalMu sync.RWMutex
	global   *Logger
)

func Init(logDir string, verbose bool) error {
	l, err := newLogger(logDir, verbose)
	if err != nil {
		return err
	}
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		global.close()
	}
	global = l
	return nil
}

func newLogger(logDir string, verbose bool) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, "collector.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	fileHandler := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})
	return &Logger{
		fileLog:       slog.New(fileHandler),
		logFile:       f,
		verbose:       verbose,
		startTime:     time.Now(),
		consoleOutput: true,
	}, nil
}

func Close() {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		global.close()
	}
}

// close redirects the file logger to io.Discard before closing the handle, so a
// module goroutine still logging after shutdown writes nowhere instead of to a
// closed descriptor.
func (l *Logger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog = slog.New(slog.NewJSONHandler(io.Discard, nil))
	if l.logFile != nil {
		l.logFile.Close()
		l.logFile = nil
	}
}

func G() *Logger {
	globalMu.RLock()
	l := global
	globalMu.RUnlock()
	if l == nil {
		return &Logger{
			fileLog:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
			startTime:     time.Now(),
			consoleOutput: true,
		}
	}
	return l
}

func SetConsoleOutput(enabled bool) {
	l := G()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consoleOutput = enabled
}

func (l *Logger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Info(msg, args...)
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[+]%s %s\n", colorGreen, colorReset, msg)
}

func (l *Logger) Success(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Info(msg, args...)
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[OK]%s %s\n", colorGreen, colorReset, msg)
}

func (l *Logger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Warn(msg, args...)
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[!]%s %s\n", colorYellow, colorReset, msg)
}

func (l *Logger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Error(msg, args...)
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[-]%s %s\n", colorRed, colorReset, msg)
}

func (l *Logger) Debug(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Debug(msg, args...)
	if l.verbose && l.consoleOutput {
		fmt.Fprintf(os.Stderr, "%s[D]%s %s\n", colorGray, colorReset, msg)
	}
}

func (l *Logger) Progress(collector, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileLog.Info(msg, "collector", collector)
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[+]%s %sCollecting:%s %s\n", colorCyan, colorReset, colorBold, colorReset, collector)
}

func (l *Logger) Done(collector string, count int, label string, elapsed time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("Done: %s (%d %s) ... (%.1fs)", collector, count, label, elapsed.Seconds())
	l.fileLog.Info(msg, "collector", collector, "count", count, "elapsed_s", elapsed.Seconds())
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[OK]%s Done: %s%s%s (%d %s) %s... (%.1fs)%s\n", colorGreen, colorReset, colorBold, collector, colorReset, count, label, colorGray, elapsed.Seconds(), colorReset)
}

func (l *Logger) Failed(collector string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("Failed: %s: %v", collector, err)
	l.fileLog.Error(msg, "collector", collector, "error", err.Error())
	if !l.consoleOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[-]%s Failed: %s%s%s: %v\n", colorRed, colorReset, colorBold, collector, colorReset, err)
}
