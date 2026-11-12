// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	androidCmd = &cobra.Command{
		Use:   "android",
		Short: "Android helpers",
		Args:  cobra.NoArgs,
	}
	androidRestoreCmd = &cobra.Command{
		Use:   "restore",
		Short: "Put netd's cgroup hooks back after decerter was killed",
		Long: `On Android netd holds most cgroup hooks exclusively. While decerter runs it attaches netd's programs again in shared mode,
next to its own, and on exit it puts them back, also on SIGHUP when the adb shell closes.
After a SIGKILL netd's programs stay shared, and a netd restart then fails until they are exclusive again.
restore puts them back from the state file the killed decerter left in /data/local/tmp/decerter.d, then exits.
A decerter that starts over such a state file restores first by itself.
restore is refused while another decerter runs, and outside of Android.`,
		Example: `  adb shell /data/local/tmp/decerter android restore`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.RestoreAndroid(&logger)
			return
		},
	}
)

func init() {
	androidCmd.AddCommand(androidRestoreCmd)
	rootCmd.AddCommand(androidCmd)
}
