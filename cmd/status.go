package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

// statusJSON is the machine-readable shape of `status`.
//
// It exists because macswitcher's observe shows this daemon as a row and has
// to read the state from somewhere. Scraping the human output is what that
// tool already learned not to do - the wording is presentation and changes -
// so the contract is here instead, and the human text is free to move.
type statusJSON struct {
	BaseURL     string   `json:"baseUrl"`
	RulesDir    string   `json:"rulesDir"`
	RuleGroups  []string `json:"ruleGroups"`
	Listening   bool     `json:"listening"`
	TLSOK       bool     `json:"tlsOk"`
	TLSError    string   `json:"tlsError,omitempty"`
	Certificate struct {
		Subject   string `json:"subject"`
		Issuer    string `json:"issuer"`
		NotAfter  string `json:"notAfter"`
		ExpiresIn int    `json:"expiresInDays"`
	} `json:"certificate"`
	CertificateError string `json:"certificateError,omitempty"`
}

var statusJSONOut bool

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
		if statusJSONOut {
			return writeStatusJSON(cmd, cfg)
		}

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

// writeStatusJSON reports the same facts as the human output, probed the same
// way: the port is dialled and a TLS handshake completed, because launchd
// calling the job "running" says nothing about whether a subscription can
// still refresh.
func writeStatusJSON(cmd *cobra.Command, cfg config.Config) error {
	var st statusJSON
	st.BaseURL = cfg.BaseURL()

	dir, err := config.ExpandPath(cfg.RulesDir)
	if err != nil {
		return err
	}
	st.RulesDir = dir
	st.RuleGroups = []string{}
	if files, err := server.RuleFiles(dir); err == nil {
		st.RuleGroups = files
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	if conn, err := d.DialContext(ctx, "tcp", cfg.Address()); err == nil {
		_ = conn.Close()
		st.Listening = true
		tlsDialer := &tls.Dialer{NetDialer: &net.Dialer{}}
		if tlsConn, err := tlsDialer.DialContext(ctx, "tcp", cfg.Address()); err == nil {
			_ = tlsConn.Close()
			st.TLSOK = true
		} else {
			st.TLSError = err.Error()
		}
	}

	if info, err := server.InspectCertificate(cfg); err == nil {
		st.Certificate.Subject = info.Subject
		st.Certificate.Issuer = info.Issuer
		st.Certificate.NotAfter = info.NotAfter.Format(time.RFC3339)
		st.Certificate.ExpiresIn = int(info.ExpiresIn.Hours() / 24)
	} else {
		st.CertificateError = err.Error()
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSONOut, "json", false, "machine-readable output")
	rootCmd.AddCommand(statusCmd)
	configCmd.AddCommand(configInitCmd, configValidateCmd)
	rootCmd.AddCommand(configCmd)
}
