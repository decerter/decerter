// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
)

const (
	// pcapng has no registered media type: application/vnd.tcpdump.pcap is the classic pcap format, the IETF pcap draft asks for application/pcap; this is the one Wireshark and shared-mime-info use
	pcapngMediaType string = "application/x-pcapng"
)

func listCaptures(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	captures := []v1.Capture{}

	if backend.Captures != nil {
		captures = backend.Captures.List()
	}

	writeJSON(writer, http.StatusOK, v1.CaptureList{Captures: captures}, logger)
}

// the body is optional, without one every flow in scope is captured with its secrets
func startCapture(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.Captures == nil {
		writeError(writer, http.StatusConflict, ErrNoCaptures, logger)
		return
	}

	captureRequest := v1.CaptureRequest{}

	if request.ContentLength != 0 {
		err := readJSON(writer, request, &captureRequest)

		if err != nil {
			writeError(writer, http.StatusBadRequest, err, logger)
			return
		}
	}

	var scope *filter.Filter

	if captureRequest.Filter != "" {
		parsed, err := parseFilter(captureRequest.Filter)

		if err != nil {
			writeError(writer, http.StatusBadRequest, err, logger)
			return
		}

		// a capture decides each flow when it starts
		if scopeErr := parsed.CheckFlowScope(); scopeErr != nil {
			writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: filter: %w", ErrBadRequest, scopeErr), logger)
			return
		}

		scope = parsed
	}

	view, err := backend.Captures.Start(scope, captureRequest.Plaintext)

	switch {
	case err == nil:
	case errors.Is(err, capture.ErrTooManyCaptures), errors.Is(err, capture.ErrStopped):
		writeError(writer, http.StatusConflict, err, logger)
		return
	default:
		logger.Error("Could not start capture", "error", err)
		writeError(writer, http.StatusInternalServerError, err, logger)
		return
	}

	writer.Header().Set("Location", v1.BasePath+"/captures/"+strconv.FormatUint(view.ID, 10))
	writeJSON(writer, http.StatusCreated, view, logger)
}

func stopCapture(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, ok := captureID(backend, writer, request, logger)

	if !ok {
		return
	}

	view, err := backend.Captures.Stop(id)

	if err != nil {
		writeError(writer, http.StatusNotFound, err, logger)
		return
	}

	writeJSON(writer, http.StatusOK, view, logger)
}

// the file of a stopped capture, ranges work
func downloadCapture(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, ok := captureID(backend, writer, request, logger)

	if !ok {
		return
	}

	file, view, err := backend.Captures.Open(id)

	switch {
	case err == nil:
	case errors.Is(err, capture.ErrCaptureNotFound):
		writeError(writer, http.StatusNotFound, err, logger)
		return
	case errors.Is(err, capture.ErrCaptureRunning):
		writeError(writer, http.StatusConflict, err, logger)
		return
	default:
		logger.Error("Could not open capture file", "error", err, "captureID", id)
		writeError(writer, http.StatusInternalServerError, err, logger)
		return
	}

	defer func() {
		closeErr := file.Close()

		if closeErr != nil {
			logger.Debug("Could not close capture file", "error", closeErr, "captureID", id)
		}
	}()

	name := fmt.Sprintf("decerter-capture-%d.pcapng", view.ID)
	writer.Header().Set("Content-Type", pcapngMediaType)
	writer.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(writer, request, name, view.Stopped, file)
}

// the flows of the history as pcapng: plaintext on run mode synthesizes packets from the messages of its proxy, the app's side; capture mode, and dsb on run mode, write the packets the capture still keeps, on run mode the wire side of the proxy's upstream sockets
func exportPcap(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	scope, err := queryFilter(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	flowID, hasFlow, err := queryFlow(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	format := v1.CaptureFormat(request.URL.Query().Get("format"))

	switch format {
	case "":
		format = v1.PlaintextCaptureFormat

		// one flow for Wireshark: its packets with the TLS secrets when decerter keeps packets
		if hasFlow && (backend.Captures != nil) {
			format = v1.DSBCaptureFormat
		}
	case
		v1.PlaintextCaptureFormat,
		v1.DSBCaptureFormat:
	default:
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: format %q, valid values: plaintext, dsb", ErrBadRequest, format), logger)
		return
	}

	isHistory := (backend.Info.Mode == v1.RunMode) && (format == v1.PlaintextCaptureFormat)

	if (backend.Captures == nil) && !isHistory {
		writeError(writer, http.StatusConflict, ErrNoCaptures, logger)
		return
	}

	flows := backend.History.Export(scope)
	name := "decerter-flows.pcapng"

	if hasFlow {
		flows = slices.DeleteFunc(flows, func(flow history.ExportFlow) (isOther bool) { isOther = flow.Flow.ID != flowID; return })
		name = fmt.Sprintf("decerter-flow-%d.pcapng", flowID)

		if len(flows) == 0 {
			writeError(writer, http.StatusNotFound, fmt.Errorf("%w: flow %d", ErrNotFound, flowID), logger)
			return
		}
	}

	writer.Header().Set("Content-Type", pcapngMediaType)
	writer.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	writer.Header().Set(v1.FlowsHeader, strconv.Itoa(len(flows)))
	writer.WriteHeader(http.StatusOK)
	output := &exportWriter{writer: writer, writeErr: nil}

	if isHistory {
		err = capture.WriteHistory(output, flows)
	} else {
		cookies := map[uint64][32]byte{}

		// in run mode the packets of each flow's own upstream socket, the udp sessions of one app socket share its cookie
		for _, flow := range flows {
			cookies[flow.SocketCookie] = flow.ClientRandom
		}

		err = backend.Captures.Export(output, cookies, format == v1.PlaintextCaptureFormat, logger.With("export", true))
	}

	if err == nil {
		return
	}

	// a client that went away is no failure of decerter
	if (output.writeErr != nil) || (request.Context().Err() != nil) {
		logger.Debug("Could not write pcap export, the client went away", "error", err)
	} else {
		logger.Warn("Could not write pcap export", "error", err)
	}

	// the status is sent: the connection is cut without the end of the body, so the client sees a failed download and not a short file
	panic(http.ErrAbortHandler)
}

// the flow query parameter of the pcap export: one flow by its id
func queryFlow(request *http.Request) (id uint64, hasFlow bool, err error) {
	text := request.URL.Query().Get("flow")

	if text == "" {
		return
	}

	id, err = strconv.ParseUint(text, 10, 64)

	if err != nil {
		err = fmt.Errorf("%w: flow %q", ErrBadRequest, text)
		return
	}

	hasFlow = true
	return
}

func (output *exportWriter) Write(data []byte) (count int, err error) {
	count, err = output.writer.Write(data)

	if err != nil {
		output.writeErr = err
	}

	return
}

// the id of a capture request, ok is false when the answer is written already
func captureID(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) (id uint64, ok bool) {
	if backend.Captures == nil {
		writeError(writer, http.StatusConflict, ErrNoCaptures, logger)
		return
	}

	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	ok = true
	return
}
