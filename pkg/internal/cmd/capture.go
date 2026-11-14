// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"time"

	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// write the packets of the selected flows, packageNames add the uids of these Android apps to the selection, to capturePath, - is stdout, empty is no file, until stopped; nothing is redirected
// apiSocket serves the control API with its captures and its live stream, empty serves none; one of the two is given
// the redirect object is loaded in record-only mode, its proxy port is a load-time constant that nothing uses then; blockQuic makes UDP to port 443 of the selected processes fail
func Capture(selection redirect.Filter, packageNames []string, scopeFilter *filter.Filter, capturePath string, apiSocket string, plaintext bool, snaplen uint32, flowTable bool, blockQuic bool, libssl string, proxyPort uint16, logger *logging.Logger) (err error) {
	currentPlatform := platform.Detect("/")
	selection, err = selectPackages(selection, packageNames, currentPlatform, platform.AndroidPackagesList, logger)

	if err != nil {
		return
	}

	ctx, cancel := shutdownContext()
	defer cancel()
	decerter := app.New(ctx, selection, scopeFilter, proxyPort, time.Duration(0), blockQuic, flowTable, false, false, nil, apiSocket, time.Duration(0), time.Duration(0), libssl, true, capturePath, plaintext, snaplen, currentPlatform, logger.Slog())
	err = serve(ctx, &decerter, logger)
	return
}
