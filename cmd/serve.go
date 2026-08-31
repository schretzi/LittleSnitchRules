package cmd

import (
	"os/signal"
	"syscall"

	"github.com/schretzi/littlesnitchrules/internal/config"
	"github.com/schretzi/littlesnitchrules/internal/logfile"
	"github.com/schretzi/littlesnitchrules/internal/server"

	"github.com/spf13/cobra"
)

// serve is the foreground process the launchd job runs. It is a separate word
// from `service`, which manages that job - the two are never the same command.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the HTTPS server in the foreground",
	Long: `Run the HTTPS server in the foreground.

This is what the launchd job executes; run it by hand to see the server's
output on the terminal. It logs every request, so a subscription refresh is
visible as a conditional request answered with 304.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return runServe(cmd, cfg)
	},
}

func runServe(cmd *cobra.Command, cfg config.Config) error {
	logPath, err := config.ExpandPath(cfg.Log.Path)
	if err != nil {
		return err
	}
	// internal/logfile re-stats the path and reopens when the inode it holds
	// is no longer the one there: newsyslog rotates by renaming, and a
	// process that keeps writing into the renamed file logs into a compressed
	// archive for ever while the new file stays empty.
	lf, err := logfile.Open(logPath)
	if err != nil {
		return err
	}
	defer func() { _ = lf.Close() }()

	srv, err := server.New(cfg, lf)
	if err != nil {
		return err
	}

	// SIGTERM is what launchd sends to stop the job, including when newsyslog
	// restarts it after a rotation.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
