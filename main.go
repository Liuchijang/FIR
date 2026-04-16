package main

import (
	"os"

	"github.com/fir/fir/cmd"
	"github.com/fir/fir/internal/console"
)

func main() {
	console.Ensure()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
