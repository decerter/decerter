// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/pkg/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// DECERTER_LOG_LEVEL, DECERTER_UID, …
	environmentPrefix string = "decerter"
)

var (
	logger  = logging.New(os.Stderr, slog.LevelInfo)
	rootCmd = &cobra.Command{
		Use:   "decerter",
		Short: "read and rewrite the live traffic of local processes with eBPF",
		Long: `decerter reads and rewrites the live TCP, UDP, TLS and DTLS traffic of selected local processes.
eBPF cgroup hooks pick the sockets of the selected processes and a uprobe on the TLS library reads their session secrets,
so there is no CA certificate to install, no proxy setting and no change to the app.

decerter runs as root on Linux 6.6 or newer with BTF, and on rooted Android 15 or newer (GKI android15-6.6 or newer).
Nothing is selected until --uid or --pid, or a proc.uid or proc.pid term of --filter, names a process.
Logs are JSON lines on stderr; stdout carries the output of the command.

Every flag can also be set with an environment variable DECERTER_<FLAG>, upper case with - as _, for example DECERTER_LOG_LEVEL=debug.
The command line wins over the environment, and sudo passes the variable on only with --preserve-env.`,
		Version:           api.Version(),
		PersistentPreRunE: applyEnvironment,
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.SetVersionTemplate("{{ .Name }} {{ .Version }}\n")
	rootCmd.PersistentFlags().Func("log-level", "log `level` (default is info, valid values: trace, debug, info, warn, error)", parseLogLevel)
}

func Execute() {
	err := rootCmd.Execute()

	if err != nil {
		os.Exit(1)
	}
}

// environment variables only, decerter reads no configuration file
func initConfig() {
	viper.SetEnvPrefix(environmentPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

// a flag that is not on the command line takes the value of its environment variable, with the same parsing and checks
// runs before cobra checks the required and mutually exclusive flags, so a flag from the environment counts for them
func applyEnvironment(cmd *cobra.Command, args []string) (err error) {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if (err != nil) || flag.Changed || (flag.Name == "help") || (flag.Name == "version") || !viper.IsSet(flag.Name) {
			return
		}

		setErr := cmd.Flags().Set(flag.Name, viper.GetString(flag.Name))

		if setErr != nil {
			err = fmt.Errorf("invalid environment variable %s: %w", strings.ToUpper(environmentPrefix+"_"+strings.ReplaceAll(flag.Name, "-", "_")), setErr)
		}
	})

	return
}

func parseLogLevel(value string) (err error) {
	level, parseErr := logging.ParseLevel(value)

	if err = parseErr; err != nil {
		return
	}

	logger.ChangeLogLevel(level)
	return
}

// the flags were valid, a failure from here on is logged where it happens and only sets the exit code
func quiet(cmd *cobra.Command) {
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
}
