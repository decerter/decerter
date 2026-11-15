// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/decerter/decerter/internal/capture"
)

// hands every block of the capture stream to the client at once: the hub writes one block per Write
type streamWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

// the live pcapng of the flows in scope from now on, for Wireshark, tshark and the extcap: a section and interface block, then the packets, with a DSB in front of each TLS session, sessions that are open already included
// it ends when the client goes away, when decerter stops, or when the client reads so slowly that packets would be lost; a write that takes captureWriteTimeout ends it too
func streamCapture(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.Captures == nil {
		writeError(writer, http.StatusConflict, ErrNoCaptures, logger)
		return
	}

	scope, err := queryFilter(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	// the stream decides each flow when it starts, like a capture
	if scope != nil {
		err = scope.CheckFlowScope()

		if err != nil {
			writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: filter: %w", ErrBadRequest, err), logger)
			return
		}
	}

	plaintext := false

	if text := request.URL.Query().Get("plaintext"); text != "" {
		plaintext, err = strconv.ParseBool(text)

		if err != nil {
			writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: plaintext %q, must be true or false", ErrBadRequest, text), logger)
			return
		}
	}

	writer.Header().Set("Content-Type", pcapngMediaType)
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)
	logger.Info("Capture stream started over the api", "filter", request.URL.Query().Get("filter"), "plaintext", plaintext)
	output := &streamWriter{writer: writer, controller: http.NewResponseController(writer)}
	err = backend.Captures.Stream(request.Context(), output, scope, plaintext, logger.With("stream", true))

	switch {
	case err == nil:
		logger.Info("Capture stream ended")
	case errors.Is(err, capture.ErrSlowReader):
		logger.Warn("Capture stream too slow, dropping it", "error", err)
	default:
		logger.Info("Capture stream ended", "error", err)
	}
}

func (output *streamWriter) Write(data []byte) (count int, err error) {
	err = output.controller.SetWriteDeadline(time.Now().Add(captureWriteTimeout))

	if err != nil {
		return
	}

	count, err = output.writer.Write(data)

	if err != nil {
		return
	}

	err = output.controller.Flush()
	return
}
