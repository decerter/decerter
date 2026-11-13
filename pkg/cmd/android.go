// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"strconv"

	"github.com/decerter/decerter/internal/android"
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	setupOptions android.Options
	setupRemove  bool
	androidCmd   = &cobra.Command{
		Use:   "android",
		Short: "Set decerter up on an Android device or emulator, and put netd's hooks back",
		Long: `decerter runs on rooted Android 15 or newer with a GKI android15-6.6 or newer kernel, x86_64 emulators and arm64 devices.
setup runs on the Linux host as your user and leaves decerter on the device, the binary at /data/local/tmp/decerter (its data
directory is /data/local/tmp/decerter.d), with the control API's abstract socket @decerter-api forwarded to a host port.
Then decerter runs on the device as root with --package <app>, and decerter ui runs on the host.
restore runs on the device and puts netd's cgroup hooks back after decerter was killed.

Without setup, the same by hand:
  adb root
  adb push decerter /data/local/tmp/decerter                  # decerter-arm64 for an arm64 device
  adb shell /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.example.app
  adb forward tcp:8080 localabstract:decerter-api
  decerter ui --api-socket 127.0.0.1:8080`,
		Args: cobra.NoArgs,
	}
	androidSetupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Push decerter to an Android device or emulator, forward its API and print the commands to run",
		Long: `Run on the Linux host as your user, not as root: adb and the emulator belong to your user.

setup finds adb (ADB, then ANDROID_HOME, ANDROID_SDK_ROOT, PATH, ~/Android/Sdk) and picks the one device adb sees,
the one --serial names, or the emulator of --avd, which it boots without a window when it doesn't run. It reads the
device's ABI, Android release and kernel and refuses Android before 15 and kernels before android15-6.6 with the reason.
It makes adbd root with adb root; a Google Play image is a production build where adbd can't be root, a Google APIs
image works. A real device is accepted with a warning, it is experimental; a rooted production build (Magisk,
KernelSU) is used through su.

It pushes the static decerter binary for the device's ABI to /data/local/tmp/decerter: this binary for an x86_64 emulator,
decerter-arm64 next to it (make build-arm64) for an arm64 device, or the one --binary names. It checks that decerter has
Conscrypt offsets for the Android release, without them TLS is relayed but not decrypted. --package is looked up on
the device the way decerter run --package does it. Then it forwards a host port to the control API's abstract socket
@decerter-api (adb forward tcp:<port> localabstract:decerter-api), keeping the forward an earlier setup made, and prints two
commands: decerter run on the device with --package, and decerter ui on the host.

--remove undoes it: it is refused while decerter runs on the device, puts back netd's hooks a killed decerter left shared, and
removes the binary, the data directory /data/local/tmp/decerter.d and the forwards to @decerter-api.`,
		Example: `  # the running emulator, the app to look at
  decerter android setup --package com.example.app

  # boot the AVD decerter-a15 first, without a window
  decerter android setup --avd decerter-a15 --package com.example.app

  # an arm64 phone among several devices, with the binary of make build-arm64
  decerter android setup --serial 0A1B2C3D --binary ./decerter-arm64 --port 8080

  # undo the push and the forward
  decerter android setup --remove --serial emulator-5554`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.SetupAndroid(setupOptions, setupRemove, &logger)
			return
		},
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
	androidSetupCmd.Flags().SortFlags = false
	androidSetupCmd.Flags().StringVar(&setupOptions.Serial, "serial", "", "use the device with this `serial` of adb devices (default is the one device adb sees)")
	androidSetupCmd.Flags().StringVar(&setupOptions.AVD, "avd", "", "use the emulator of this `avd`, booted without a window when it doesn't run (default is none, use a running device)")
	androidSetupCmd.Flags().StringVar(&setupOptions.Package, "package", "", "check that the app with this package `name` is installed and put it into the printed command (default is none, the command has PACKAGE in its place)")
	androidSetupCmd.Flags().StringVar(&setupOptions.Binary, "binary", "", "push the static decerter binary at this `path` (default is this binary for x86_64, decerter-arm64 next to it for arm64)")
	androidSetupCmd.Flags().Func("port", "forward this host `port` to the control API on the device (default is the port of an existing forward, or one adb picks)", parseSetupPort)
	androidSetupCmd.Flags().BoolVar(&setupRemove, "remove", false, "remove the binary, its data directory and the forward from the device instead (default is false)")
	androidSetupCmd.MarkFlagsMutuallyExclusive("serial", "avd")

	for _, flag := range []string{"avd", "package", "binary", "port"} {
		androidSetupCmd.MarkFlagsMutuallyExclusive("remove", flag)
	}

	androidCmd.AddCommand(androidSetupCmd)
	androidCmd.AddCommand(androidRestoreCmd)
	rootCmd.AddCommand(androidCmd)
}

func parseSetupPort(value string) (err error) {
	port, parseErr := strconv.ParseUint(value, 10, 16)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid port %q: %w", value, err)
		return
	}

	if port == 0 {
		err = fmt.Errorf("invalid port %q: must be between 1 and 65535", value)
		return
	}

	setupOptions.Port = uint16(port)
	return
}
