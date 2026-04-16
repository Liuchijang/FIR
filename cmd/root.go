// Package cmd implements the Cobra CLI commands for FIR.
package cmd

import (
	"fmt"
	"os"

	"github.com/fir/fir/internal/cli"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/output"
	"github.com/fir/fir/internal/utils"
	"github.com/spf13/cobra"

	// Import all collectors to trigger self-registration via init().
	_ "github.com/fir/fir/internal/eventlog"
	_ "github.com/fir/fir/internal/execution"
	_ "github.com/fir/fir/internal/memory"
	_ "github.com/fir/fir/internal/ntfs"
	_ "github.com/fir/fir/internal/registry"
	_ "github.com/fir/fir/internal/system"
)

var (
	// Global flags.
	outputDir string
	verbose   bool
)

var rootCmd = &cobra.Command{
	Use:   "fir",
	Short: "FIR — Freedom Incident Response",
	Long: `FIR is a production-grade Windows DFIR artifact collection tool.
It collects forensic artifacts with minimal system impact for incident response.

Run without subcommands to enter interactive mode, or use 'fir collect' for flag-driven mode.`,
	Version: output.Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip privilege checks for help/version.
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}
		return preflightChecks()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default: interactive mode.
		return runInteractive()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", ".", "Base output directory for collected artifacts")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// runInteractive launches the interactive menu-driven mode.
func runInteractive() error {
	// Print the banner first.
	log := logging.G()
	log.Banner(output.Version)

	// Show the interactive menu.
	collectors, err := cli.RunInteractiveMenu()
	if err != nil {
		return fmt.Errorf("interactive menu: %w", err)
	}

	if len(collectors) == 0 {
		fmt.Fprintf(os.Stderr, "\n[+] No collectors selected. Exiting.\n")
		return nil
	}

	// Set default concurrency and timeout if not overridden.
	if concurrencyFlag == 0 {
		concurrencyFlag = 2
	}
	if timeoutFlag == 0 {
		timeoutFlag = 5 * 60 * 1e9 // 5 minutes in nanoseconds.
	}

	return executeCollection(collectors)
}

// preflightChecks runs pre-collection validation.
func preflightChecks() error {
	// Check for admin privileges.
	if !utils.IsAdmin() {
		fmt.Fprintf(os.Stderr, "\n%s[!] WARNING: Not running as Administrator.%s\n", "\033[33m", "\033[0m")
		fmt.Fprintf(os.Stderr, "    Some collectors may fail without elevated privileges.\n")
		fmt.Fprintf(os.Stderr, "    Recommend: Right-click → Run as Administrator\n\n")
	} else {
		// Enable forensic privileges.
		errs := utils.EnableForensicPrivileges()
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "%s[!] Privilege warning: %v%s\n", "\033[33m", err, "\033[0m")
		}
	}

	return nil
}
