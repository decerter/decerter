// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/decerter/decerter/internal/mcp"
	"github.com/decerter/decerter/internal/ui"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// serve the MCP read tools, and the write tools with allowWrite, on stdio until the client closes stdin or a shutdown signal, a client of the control API at target; the export tools write into outputDir
// an api that can't be reached at start is only logged: the client starts decerter mcp on its own, and every tool call tells why it fails until decerter runs
func MCP(target ui.Target, outputDir string, allowWrite bool, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()

	if os.Geteuid() == 0 {
		logger.Warn("decerter mcp runs as root, it only needs the api socket: run it as your user in the group decerter")
	}

	output, err := mcp.OpenOutput(outputDir)

	if err != nil {
		logger.Error("Could not open the output directory", "error", err, "outputDir", outputDir)
		return
	}

	defer func() {
		err = errors.Join(err, output.Close())
	}()

	status, checkErr := ui.Check(ctx, target)

	if checkErr != nil {
		logger.Warn("Could not reach the control api, the tools answer with this error until it can be reached", "error", checkErr, "api", target.String())
	} else {
		logger.Info("Control api reached", "api", target.String(), "mode", status.Mode, "processing", status.Processing, "version", status.Version)
	}

	// the SDK logs every session step at info, and a signal as an error; decerter mcp logs its own failures, the SDK's logs are for --log-level debug
	sdkLogger := slog.New(slog.DiscardHandler)

	if logger.Slog().Enabled(ctx, slog.LevelDebug) {
		sdkLogger = logger.Slog()
	}

	server, err := mcp.NewServer(mcp.NewClient(target), output, allowWrite, sdkLogger)

	if err != nil {
		logger.Error("Could not make the MCP server", "error", err)
		return
	}

	logger.Info("MCP server on stdio", "outputDir", outputDir, "allowWrite", allowWrite)
	err = mcp.Serve(ctx, server)

	if err != nil {
		logger.Error("Could not serve MCP", "error", err)
		return
	}

	if ctx.Err() != nil {
		logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
		return
	}

	logger.Debug("MCP client went away")
	return
}
