package main

import (
	"os"

	"github.com/Liuchijang/FIR/cmd"
	"github.com/Liuchijang/FIR/internal/console"
)

func main() {
	console.Ensure()
	exitCode := 0
	if err := cmd.Execute(); err != nil {
		exitCode = 1
	}

	console.PauseBeforeExit()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
