// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	keylogCmd = &cobra.Command{
		Use:   "keylog",
		Short: "Print the TLS secrets of the selected processes in NSS key log format",
		Long: `Print the TLS secrets of the processes selected with --uid and --pid on stdout in NSS key log format, the format of
SSLKEYLOGFILE, until stopped. Only the secrets uprobe is attached: nothing is redirected or captured.
A TLS 1.3 session gets four lines (both handshake and both application traffic secrets), a TLS 1.2 or DTLS 1.2
session one CLIENT_RANDOM line. The logs go to stderr.`,
		Example: `  sudo decerter keylog --uid 1001 > keys.log
  sudo -u test curl -s https://example.com/ > /dev/null`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.Keylog(selection, packageNames, libssl, &logger)
			return
		},
	}
)

func init() {
	keylogCmd.Flags().SortFlags = false
	addProcessFlags(keylogCmd.Flags())
	addLibsslFlag(keylogCmd.Flags())
	rootCmd.AddCommand(keylogCmd)
}
