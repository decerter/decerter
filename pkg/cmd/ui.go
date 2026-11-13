// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"

	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/ui"
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	uiTarget    ui.Target
	openBrowser bool
	uiCmd       = &cobra.Command{
		Use:   "ui",
		Short: "Serve the minimal web UI on 127.0.0.1, a client of the control API",
		Long: `Serve a small web page on 127.0.0.1 with a port the kernel picks, for a decerter run that serves the control API
(--api-socket): the live flow list with a filter, the messages of a flow as text or hex, intercept on and off, and the
held messages to edit, forward or drop. It only talks to the API, so it can do nothing curl on the socket can't.

decerter ui runs as your user, not as root: it only needs the API socket, which is for root and the members of the group
decerter (groupadd decerter, usermod -aG decerter $USER, then log in again and restart decerter run). It prints a URL with a random
token on stdout. The first load of it sets the token as a cookie and drops it from the address bar; every request
without the cookie, or with another Host than 127.0.0.1:<port>, gets 403.

--api-socket takes a socket path, @name for an abstract socket, or a loopback ip:port, such as the host side of
adb forward tcp:8080 localabstract:decerter-api for a decerter on an Android device.`,
		Example: `  sudo decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
  decerter ui                       # as your user in the group decerter, prints http://127.0.0.1:<port>/?token=…

  # a decerter on an Android device, the UI on the workstation
  adb forward tcp:8080 localabstract:decerter-api
  decerter ui --api-socket 127.0.0.1:8080 --open`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if uiTarget.Address == "" {
				err = parseUIAPISocket(platform.Detect("/").APISocket)

				if err != nil {
					return
				}
			}

			quiet(cmd)
			err = internal.UI(uiTarget, openBrowser, &logger)
			return
		},
	}
)

func init() {
	uiCmd.Flags().SortFlags = false
	uiCmd.Flags().Func("api-socket", "the control API at this `address`: a socket path, @name for an abstract socket or a loopback ip:port such as 127.0.0.1:8080 of adb forward (default is /run/decerter/api.sock on Linux, @decerter-api on Android)", parseUIAPISocket)
	uiCmd.Flags().BoolVar(&openBrowser, "open", false, "open the URL with xdg-open, the token is then in xdg-open's command line while it runs (default is false, only print it)")
	rootCmd.AddCommand(uiCmd)
}

func parseUIAPISocket(value string) (err error) {
	target, parseErr := ui.ParseTarget(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid api socket: %w", err)
		return
	}

	uiTarget = target
	return
}
