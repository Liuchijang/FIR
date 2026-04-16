package main

import (
	"os"

	"github.com/fir/fir/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
