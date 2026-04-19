// Package cmd implements the Cobra CLI commands for FIR.
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Liuchijang/FIR/internal/cli"
	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/utils"
	"github.com/spf13/cobra"

	_ "github.com/Liuchijang/FIR/internal/browser"
	_ "github.com/Liuchijang/FIR/internal/eventlog"
	_ "github.com/Liuchijang/FIR/internal/execution"
	_ "github.com/Liuchijang/FIR/internal/live"
	_ "github.com/Liuchijang/FIR/internal/memory"
	_ "github.com/Liuchijang/FIR/internal/ntfs"
	_ "github.com/Liuchijang/FIR/internal/registry"
	_ "github.com/Liuchijang/FIR/internal/system"
)

var (
	outputDir string
	verbose   bool
)

var rootCmd = &cobra.Command{
	Use:   "fir",
	Short: "FIR - Freedom Incident Response",
	Long: `FIR is a production-grade Windows DFIR artifact collection tool.
It collects forensic artifacts with minimal system impact for incident response.

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
	console.EnsureInteractive()

	collectors, err := cli.RunInteractiveMenu()
	if err != nil {
		return fmt.Errorf("interactive menu: %w", err)
	}
	if len(collectors) == 0 {
		fmt.Fprintf(os.Stderr, "\n[+] No collectors selected. Exiting.\n")
		return nil
	}
	if concurrencyFlag == 0 {
		concurrencyFlag = 2
	}
	if timeoutFlag == 0 {
		timeoutFlag = 5 * time.Minute
	}
	return runInteractiveCollection(collectors)
}

func preflightChecks() error {
	if !utils.IsAdmin() {
		fmt.Fprintf(os.Stderr, "\n%s[!] WARNING: Not running as Administrator.%s\n", "\033[33m", "\033[0m")
		fmt.Fprintf(os.Stderr, "    Some collectors may fail without elevated privileges.\n")
		fmt.Fprintf(os.Stderr, "    Recommend: Right-click -> Run as Administrator\n\n")
	} else {
		errs := utils.EnableForensicPrivileges()
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "%s[!] Privilege warning: %v%s\n", "\033[33m", err, "\033[0m")
		}
	}
	return nil
}
