// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/decerter/decerter/internal/ui"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// serve the minimal UI on 127.0.0.1 until stopped, a client of the control API at target; the URL with the token goes to stdout, openBrowser hands xdg-open a URL with a one-time code
func UI(target ui.Target, openBrowser bool, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()

	if os.Geteuid() == 0 {
		logger.Warn("decerter ui runs as root, it only needs the api socket: run it as your user in the group decerter")
	}

	status, err := ui.Check(ctx, target)

	if err != nil {
		logger.Error("Could not reach the control api", "error", err, "api", target.String())
		return
	}

	credentials, err := ui.NewCredentials()

	if err != nil {
		logger.Error("Could not make the ui token", "error", err)
		return
	}

	listener, host, err := ui.Listen()

	if err != nil {
		logger.Error("Could not listen for the ui", "error", err)
		return
	}

	_, err = fmt.Fprintln(os.Stdout, ui.URL(host, credentials.Token))

	if err != nil {
		logger.Error("Could not print the ui address", "error", err)
		err = errors.Join(err, listener.Close())
		return
	}

	logger.Info("Minimal ui listening, open the printed URL", "address", "http://"+host+"/", "api", target.String(), "mode", status.Mode, "processing", status.Processing, "version", status.Version)

	// the browser's command line gets a code that works once, not the token
	if openBrowser {
		code, codeErr := credentials.NewCode()

		if err = codeErr; err != nil {
			logger.Error("Could not make the ui code", "error", err)
			err = errors.Join(err, listener.Close())
			return
		}

		ui.Open(ui.CodeURL(host, code), logger.Slog())
	}

	err = ui.Serve(ctx, listener, ui.Handler(target, credentials, host, logger.Slog()), logger.Slog())

	if ctx.Err() != nil {
		logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
	}

	return
}
