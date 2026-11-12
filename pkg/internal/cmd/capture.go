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

// write the packets of the selected flows to capturePath, - is stdout, until stopped; nothing is redirected
// the redirect object is loaded in record-only mode, its proxy port is a load-time constant that nothing uses then
func Capture(selection redirect.Filter, scopeFilter *filter.Filter, capturePath string, plaintext bool, snaplen uint32, flowTable bool, libssl string, proxyPort uint16, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()
	decerter := app.New(ctx, selection, scopeFilter, proxyPort, time.Duration(0), flowTable, false, false, nil, libssl, capturePath, plaintext, snaplen, platform.Detect("/"), logger.Slog())
	err = serve(ctx, &decerter, logger)
	return
}
