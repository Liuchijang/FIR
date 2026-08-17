// Package cmd implements the Cobra CLI commands for Tyto.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/tui"
	"github.com/Liuchijang/Tyto/internal/utils"
	"github.com/spf13/cobra"

	_ "github.com/Liuchijang/Tyto/internal/analyzers"
	_ "github.com/Liuchijang/Tyto/internal/analyzers/live_response"
	_ "github.com/Liuchijang/Tyto/internal/collectors/browser"
	_ "github.com/Liuchijang/Tyto/internal/collectors/eventlog"
	_ "github.com/Liuchijang/Tyto/internal/collectors/execution"
	_ "github.com/Liuchijang/Tyto/internal/collectors/memory"
	_ "github.com/Liuchijang/Tyto/internal/collectors/ntfs"
	_ "github.com/Liuchijang/Tyto/internal/collectors/registry"
	_ "github.com/Liuchijang/Tyto/internal/collectors/system"
)

var (
	outputDir string
	verbose   bool
)

var rootCmd = &cobra.Command{
	Use:   "tyto",
	Short: "Tyto - Windows DFIR triage",
	Long: `Windows DFIR artifact collection and triage tool.

Run without a subcommand for the interactive workflow, 'tyto collect' to acquire
artifacts from this machine, or 'tyto analyze' to parse a run collected earlier.`,
	Version:       output.Version,
	RunE:          func(cmd *cobra.Command, args []string) error { return runInteractive() },
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	cobra.MousetrapHelpText = ""

	// Cobra offers a `completion` subcommand on every root command. Tyto does not
	// want it: the tool is copied onto a subject machine and run once from an
	// elevated prompt, so nobody is installing shell completion for it, and it was
	// a listed command that could not work anyway — printing a shell script went
	// through the privilege gate and failed with "Administrator privileges
	// required".
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Assigned here rather than in the literal above: touchesMachine compares
	// against rootCmd, and naming it inside rootCmd's own initializer is an
	// initialization cycle.
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Printing the module list reads nothing and writes nothing, so it may not
		// demand Administrator either.
		if !touchesMachine(cmd) || requestsModuleList(cmd) {
			return nil
		}
		// Printed here rather than by each command, so it lands ahead of anything
		// preflightChecks has to say. Interactive mode draws its own banner inside
		// the TUI and is skipped by commandBannerSubtitle.
		if subtitle := commandBannerSubtitle(cmd); subtitle != "" {
			fmt.Fprintln(os.Stderr, tui.RenderCommandBanner(subtitle))
		}
		return preflightChecks(cmd)
	}

	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", ".", "Base output directory for collected artifacts")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")

	// Every help screen opens with the banner, the same as a run does. Cobra
	// resolves a command's help func by walking up to its parent, so setting it
	// once on the root covers every subcommand.
	//
	// The default is captured first and called through: the point is to prepend to
	// cobra's help, not to reimplement its template. Reading it back inside the
	// closure instead would find this one and recurse.
	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// Help goes to stdout, so the banner does too — piping `--help` somewhere
		// should not leave half of it behind on the terminal.
		fmt.Fprintln(cmd.OutOrStdout(), tui.RenderCommandBanner(""))
		defaultHelp(cmd, args)
	})
}

func Execute() error { return rootCmd.Execute() }

// touchesMachine reports whether an invocation reads or writes anything, which
// is what decides whether the privilege gate applies to it at all.
//
// An allow-list rather than a deny-list, and matched by identity rather than by
// name. Cobra adds commands of its own — `help`, `completion`, and the hidden
// `__complete` a shell calls on every Tab — and all of them reach this hook. A
// deny-list gated whatever it had not been told about: `tyto completion
// powershell` failed with "Administrator privileges required" for printing a
// shell script, and tab completion would have failed the same way. Naming the
// three commands that do work means the next generated one cannot inherit it.
func touchesMachine(cmd *cobra.Command) bool {
	switch cmd {
	case rootCmd, collectCmd, analyzeCmd:
		return true
	default:
		return false
	}
}

// commandBannerSubtitle names what a flag-driven invocation is about to do, and
// returns "" for the commands that should not print a banner at all.
func commandBannerSubtitle(cmd *cobra.Command) string {
	switch cmd.Name() {
	case collectCmd.Name():
		return "collecting " + artifactFlag
	case analyzeCmd.Name():
		if analyzeInputFlag != "" {
			return "analyzing " + filepath.Base(analyzeInputFlag)
		}
		return "live analysis"
	default:
		return ""
	}
}

func runInteractive() error {
	return runUnifiedInteractive()
}

// elevationOptional marks a command that can do useful work without
// Administrator, as an annotation rather than a name check so the claim sits on
// the command that makes it.
//
// Only `analyze` carries it. Acquisition genuinely cannot proceed unelevated —
// raw volume reads, RegSaveKey and winpmem all fail outright — but analysis of a
// collected run only reads files the operator already has. That holds for every
// analyzer now, registry included: a collected hive is parsed from its file by
// internal/registryfile rather than mounted, so nothing in the offline path asks
// Windows for a privilege.
const (
	elevationOptional    = "tyto.elevation.optional"
	elevationOptionalYes = "yes"
)

// elevationRequired reports whether this invocation refuses to start unelevated.
//
// It is per-invocation, not per-command, because `analyze` is two things: with
// --input it reads a collected run and needs nothing, and without it the
// analyzers read the live machine — the same registry, volumes and event logs a
// collection reads, so the same privileges apply. Flags are parsed before
// PersistentPreRunE runs, so the value is available here.
func elevationRequired(cmd *cobra.Command) bool {
	if cmd.Annotations[elevationOptional] != elevationOptionalYes {
		return true
	}
	return analyzeInputFlag == ""
}

func preflightChecks(cmd *cobra.Command) error {
	if utils.IsAdmin() {
		errs := utils.EnableForensicPrivileges()
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "%s[!] Privilege warning: %v%s\n", "\033[33m", err, "\033[0m")
		}
		return nil
	}

	if elevationRequired(cmd) {
		return fmt.Errorf("Administrator privileges required.\n    Right-click tyto.exe and choose 'Run as Administrator', or launch from an elevated terminal.")
	}

	// Nothing to warn about on the unelevated analysis path: it reads files and
	// parses collected hives itself, so there is no step left that elevation would
	// change.
	return nil
}
