// Package cmd implements the Cobra CLI commands for FIR.
package cmd

import (
	"fmt"
	"os"

	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/utils"
	"github.com/spf13/cobra"

	_ "github.com/Liuchijang/FIR/internal/analyzers"
	_ "github.com/Liuchijang/FIR/internal/analyzers/live_response"
	_ "github.com/Liuchijang/FIR/internal/collectors/browser"
	_ "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	_ "github.com/Liuchijang/FIR/internal/collectors/execution"
	_ "github.com/Liuchijang/FIR/internal/collectors/memory"
	_ "github.com/Liuchijang/FIR/internal/collectors/ntfs"
	_ "github.com/Liuchijang/FIR/internal/collectors/registry"
	_ "github.com/Liuchijang/FIR/internal/collectors/system"
)

var (
	outputDir string
	verbose   bool
)

var rootCmd = &cobra.Command{
	Use:   "fir",
	Short: "FIR - Freedom Incident Response",
	Long: `FIR is a production-grade Windows DFIR artifact collection tool.
It runs collection and analyzer modules for incident response.

Run without subcommands to enter interactive mode, or use 'fir collect' for flag-driven mode.`,
	Version: output.Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}
		return preflightChecks()
	},
	RunE:          func(cmd *cobra.Command, args []string) error { return runInteractive() },
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	cobra.MousetrapHelpText = ""
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", ".", "Base output directory for collected artifacts")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
}

func Execute() error { return rootCmd.Execute() }

func runInteractive() error {
	return runUnifiedInteractive()
}

func preflightChecks() error {
	if !utils.IsAdmin() {
		return fmt.Errorf("Administrator privileges required.\n    Right-click fir.exe and choose 'Run as Administrator', or launch from an elevated terminal.")
	}

	errs := utils.EnableForensicPrivileges()
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "%s[!] Privilege warning: %v%s\n", "\033[33m", err, "\033[0m")
	}
	return nil
}
