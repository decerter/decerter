// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"time"

	"github.com/decerter/decerter/app"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// redirect the selected flows through the proxy until stopped; decrypt prints the plaintext of TLS and DTLS records, interceptFlows runs every message through the identity rule and prints it
// apiSocket serves the control API on this socket, empty serves none; holdTimeout is how long a message held over the API waits for a decision
func Run(selection redirect.Filter, scopeFilter *filter.Filter, proxyPort uint16, udpIdleTimeout time.Duration, flowTable bool, decrypt bool, interceptFlows bool, apiSocket string, holdTimeout time.Duration, libssl string, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()

	// the command line has the identity rule, which prints every message; the API adds its rules and hold queue after it
	var rules []intercept.Rule

	if interceptFlows {
		rules = []intercept.Rule{intercept.IdentityRule{}}
	}

	decerter := app.New(ctx, selection, scopeFilter, proxyPort, udpIdleTimeout, flowTable, false, decrypt, rules, apiSocket, holdTimeout, libssl, "", false, capturebpf.MaxSnaplen, platform.Detect("/"), logger.Slog())
	err = serve(ctx, &decerter, logger)
	return
}
