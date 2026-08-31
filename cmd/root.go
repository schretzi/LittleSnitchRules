// Package cmd implements the lsrules CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/schretzi/littlesnitchrules/internal/config"
	"github.com/schretzi/littlesnitchrules/internal/version"

	"github.com/spf13/cobra"
)

var configPath string

// appName is the binary name: it drives the launchd label, the log file names
// and the `version` output.
const appName = "lsrules"

// licenseNotice is printed by `lsrules version`.
const licenseNotice = `Copyright (C) 2026 Schretzi
License: MIT <https://opensource.org/licenses/MIT>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.`

var rootCmd = &cobra.Command{
	Use:   "lsrules",
	Short: "Serve Little Snitch rule groups over HTTPS from this machine",
	Long: `Serve Little Snitch rule groups (.lsrules) over HTTPS from this machine.

Little Snitch subscribes to a rule group by URL and refuses anything but
HTTPS - a local file is rejected with "For security reasons, only HTTPS URLs
are allowed". Publishing the files somewhere public is the other way to
satisfy that, but a rule group describes what runs on this machine, so this
serves them from it instead, on loopback, with a certificate from the
machine's own CA.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI and exits the process on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Root returns the root command, for tooling that needs the command tree
// without running it (e.g. the docs generator in tools/gendocs).
func Root() *cobra.Command { return rootCmd }

func loadConfig() (config.Config, error) { return config.Load(configPath) }

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", config.DefaultPath(), "path to config file")
	// Avoid a generation-timestamp footer that would otherwise churn every
	// time docs/ is regenerated with no real content change.
	rootCmd.DisableAutoGenTag = true

	// `--version` and `version` report the same thing, from the same place.
	rootCmd.Version = version.String(appName)
	rootCmd.AddCommand(version.NewCommand(appName, licenseNotice))
}
