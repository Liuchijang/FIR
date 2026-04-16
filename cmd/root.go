// Package cmd implements the Cobra CLI commands for FIR.
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fir/fir/internal/cli"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/output"
	"github.com/fir/fir/internal/utils"
	"github.com/spf13/cobra"

	_ "github.com/fir/fir/internal/eventlog"
	_ "github.com/fir/fir/internal/execution"
	_ "github.com/fir/fir/internal/memory"
	_ "github.com/fir/fir/internal/ntfs"
	_ "github.com/fir/fir/internal/registry"
	_ "github.com/fir/fir/internal/system"
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
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", ".", "Base output directory for collected artifacts")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
}

func Execute() error { return rootCmd.Execute() }

func runInteractive() error {
	log := logging.G()
	log.Banner(output.Version)
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
	return executeCollection(collectors)
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
