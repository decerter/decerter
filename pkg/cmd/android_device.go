// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

// the android commands that run on the device, a decerter built for a Mac only has setup
var (
	androidTLSCmd = &cobra.Command{
		Use:   "tls --package <name>",
		Short: "Say whether decerter decrypts the TLS of an app, a Flutter or Chromium app needs known offsets",
		Long: `Runs on the device as root and prints one line per package and library (and per install directory during an update).
Java apps get TLS from Conscrypt, whose offsets come with the Android release. A Flutter app links its own BoringSSL
into libflutter.so (dart:io's HttpClient and SecureSocket use it): decerter reads the Dart version the engine prints,
picks the BoringSSL offsets of that version from its table and finds ssl_log_secret through its key log labels.
Chrome, WebView and Cronet link their own BoringSSL into libmonochrome(_64).so, libchrome.so, libwebviewchromium.so or
libcronet.<version>.so: decerter reads the Chromium version in the library and picks the offsets of its branch. Chrome
built on Trichrome has the library in the Trichrome library package with Chrome's versionCode, which is looked at
too. A library may be extracted (lib/<isa>/ of the install directory) or stored uncompressed in the apk. Cronet of
Play services lives in a module directory of com.google.android.gms; decerter run finds it in the processes' mappings.
A library with an unknown version, or one decerter can't read (a 32 bit one too), makes the command fail after printing;
decerter run relays such an app's TLS without decrypting it. make generate-flutter-offsets FLUTTER_VERSIONS=<release>
adds a Flutter release to the table, make generate-chrome-offsets the newest Chrome release branches, and
CHROME_BUILDS a Chromium build of no release branch. A Chromium app's last line says that it prefers QUIC.
decerter android setup --package runs this for its package.`,
		Example: `  adb shell /data/local/tmp/decerter android tls --package com.example.app`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(packageNames) == 0 {
				err = ErrNoPackage
				return
			}

			quiet(cmd)
			err = internal.AndroidTLS(packageNames, &logger)
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
	androidTLSCmd.Flags().Func("package", "check the app with this package `name`, repeatable or comma separated (required)", parsePackageNames)
	androidCmd.AddCommand(androidTLSCmd)
	androidCmd.AddCommand(androidRestoreCmd)
}
