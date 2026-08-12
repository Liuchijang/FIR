package main

import (
	"fmt"
	"os"

	"github.com/Liuchijang/Tyto/cmd"
	"github.com/Liuchijang/Tyto/internal/console"
)

func main() {
	console.Ensure()
	exitCode := 0
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Error: %v%s\n", "\033[31m", err, "\033[0m")
		exitCode = 1
	}

	console.PauseBeforeExit()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
