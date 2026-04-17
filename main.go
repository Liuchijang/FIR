package main

import (
	"os"

	"github.com/Liuchijang/FIR/cmd"
	"github.com/Liuchijang/FIR/internal/console"
)

func main() {
	console.Ensure()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
