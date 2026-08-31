package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/schretzi/littlesnitchrules/internal/config"
	"github.com/schretzi/littlesnitchrules/internal/server"
	"github.com/schretzi/littlesnitchrules/internal/service"

	"github.com/spf13/cobra"
)

// certExpiryWarning is when `status` starts complaining. local_ca issues this
// certificate for a year and nothing renews it; the failure is otherwise
// silent until a subscription refresh fails.
const certExpiryWarning = 30 * 24 * time.Hour

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show what is served, whether the port answers, and the launchd job",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()

		fmt.Fprintf(out, "config: %s\n", configPath)
		fmt.Fprintf(out, "base_url: %s\n", cfg.BaseURL())

		dir, err := config.ExpandPath(cfg.RulesDir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "rules_dir: %s\n", dir)
		files, err := server.RuleFiles(dir)
		if err != nil {
			fmt.Fprintf(out, "rule_groups: cannot read directory: %v\n", err)
		} else if len(files) == 0 {
			fmt.Fprintf(out, "rule_groups: none (no *.lsrules in %s)\n", dir)
		} else {
			fmt.Fprintf(out, "rule_groups: %d\n", len(files))
			for _, f := range files {
				fmt.Fprintf(out, "  %s%s\n", cfg.BaseURL(), f)
			}
		}

		// Probed, not assumed: launchd reporting the job as running says
		// nothing about whether the port answers, and a subscription that
		// silently stops refreshing is the failure this is meant to catch.
		fmt.Fprintf(out, "listening: %s\n", listenState(cmd.Context(), cfg))
		fmt.Fprintf(out, "certificate: %s\n", certState(cfg))

		fmt.Fprintln(out, "service:")
		st, err := service.New(appName).Status()
		if err != nil {
			return err
		}
		service.WriteStatus(out, st)
		return nil
	},
}

func listenState(ctx context.Context, cfg config.Config) string {
	dialCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", cfg.Address())
	if err != nil {
		return "no - nothing accepts connections on " + cfg.Address()
	}
	_ = conn.Close()

	// A TCP connect only proves something is there. Little Snitch needs TLS to
	// complete, so complete one - against the machine's own trust store, which
	// is the same question the subscription asks.
	tlsCtx, cancelTLS := context.WithTimeout(ctx, time.Second)
	defer cancelTLS()
	tlsDialer := &tls.Dialer{NetDialer: &net.Dialer{}}
	tlsConn, err := tlsDialer.DialContext(tlsCtx, "tcp", cfg.Address())
	if err != nil {
		return fmt.Sprintf("yes, but TLS fails: %v", err)
	}
	_ = tlsConn.Close()
	return "yes, TLS verified against the system trust store"
}

func certState(cfg config.Config) string {
	info, err := server.InspectCertificate(cfg)
	if err != nil {
		return fmt.Sprintf("cannot read: %v", err)
	}
	state := fmt.Sprintf("CN=%s, issued by %s, chain of %d, expires %s",
		info.Subject, info.Issuer, info.ChainLen, info.NotAfter.Format(time.DateOnly))
	switch {
	case info.ExpiresIn <= 0:
		return state + " - EXPIRED, subscriptions will fail"
	case info.ExpiresIn < certExpiryWarning:
		return state + fmt.Sprintf(" - in %d days, reissue with MacbookSetup's local_ca role",
			int(info.ExpiresIn.Hours()/24))
	}
	return state
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Create and validate configuration",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a starter configuration",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		expanded, err := config.ExpandPath(configPath)
		if err != nil {
			return err
		}
		if _, err := os.Stat(expanded); err == nil {
			return fmt.Errorf("config already exists at %s", expanded)
		}
		if err := config.Save(configPath, config.Default()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", expanded)
		fmt.Fprintln(cmd.OutOrStdout(), "review it, then: lsrules config validate")
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check the configuration without starting anything",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ok: %s serves %s\n", cfg.BaseURL(), cfg.RulesDir)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	configCmd.AddCommand(configInitCmd, configValidateCmd)
	rootCmd.AddCommand(configCmd)
}
