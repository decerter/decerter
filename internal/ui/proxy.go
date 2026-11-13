// SPDX-License-Identifier: AGPL-3.0-only

package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"syscall"

	v1 "github.com/decerter/decerter/api"
)

// what --api-socket takes: @name is an abstract socket, ip:port a loopback TCP address (adb forward tcp:<port> localabstract:decerter-api), anything else a socket path
// a relative socket path that looks like host:port is written ./name
func ParseTarget(value string) (target Target, err error) {
	switch {
	case value == "", value == "@":
		err = fmt.Errorf("%w %q: empty", ErrAPIAddress, value)
		return
	case strings.HasPrefix(value, "@"), strings.Contains(value, "/"):
		target = Target{Network: UnixNetwork, Address: value}
		return
	default:
	}

	host, portText, splitErr := net.SplitHostPort(value)

	if splitErr != nil {
		target = Target{Network: UnixNetwork, Address: value}
		return
	}

	port, parseErr := strconv.ParseUint(portText, 10, 16)

	if err = parseErr; err != nil {
		err = fmt.Errorf("%w %q: port: %w", ErrAPIAddress, value, err)
		return
	}

	if port == 0 {
		err = fmt.Errorf("%w %q: port 0", ErrAPIAddress, value)
		return
	}

	address, parseErr := netip.ParseAddr(host)

	if (parseErr != nil) || !address.IsLoopback() || (address.Zone() != "") {
		err = fmt.Errorf("%w: %q", ErrNotLoopback, value)
		return
	}

	target = Target{Network: TCPNetwork, Address: net.JoinHostPort(address.Unmap().String(), portText)}
	return
}

// every connection goes to the api, whatever the URL names; decerter ui and decerter mcp both use it
func NewTransport(target Target) (transport *http.Transport) {
	transport = &http.Transport{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, string(target.Network), target.Address)
		},
		DisableCompression:    true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       idleTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return
}

// GET /api/v1/status once, so an api decerter ui can't use stops it at start with a reason
// on a connection of its own: a server that refuses the peer closes it, which reads as EOF here and not as an idle connection the transport retries
func Check(ctx context.Context, target Target) (status v1.Status, err error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, string(target.Network), target.Address)

	if err != nil {
		err = Explain(err, target)
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	deadline, _ := ctx.Deadline()
	err = connection.SetDeadline(deadline)

	if err != nil {
		return
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+v1.HostName+v1.BasePath+"/status", http.NoBody)

	if err != nil {
		return
	}

	request.Close = true
	err = request.Write(connection)

	if err != nil {
		err = Explain(err, target)
		return
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), request)

	if err != nil {
		err = Explain(err, target)
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxStatusBytes))

	if err != nil {
		err = Explain(err, target)
		return
	}

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("%w: status %d: %s", ErrAPI, response.StatusCode, strings.TrimSpace(string(body)))
		return
	}

	err = json.Unmarshal(body, &status)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrAPI, err)
	}

	return
}

// the reason a user can act on, the error of the dial after it; for any error of a request to target, other errors come back as they are
func Explain(err error, target Target) (explained error) {
	explained = err

	switch {
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		explained = fmt.Errorf("%w: %s: %w", ErrSocketPermission, target, err)
	case errors.Is(err, syscall.ENOENT):
		explained = fmt.Errorf("%w: %s: %w", ErrNoSocket, target, err)
	case errors.Is(err, syscall.ECONNREFUSED):
		explained = fmt.Errorf("%w: %s: %w", ErrNoServer, target, err)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		explained = fmt.Errorf("%w: %s: %w", ErrRefused, target, err)
	default:
	}

	return
}

// /api/v1/… to the api and nothing else; the cookie and the browser's Origin and Referer stay here, the event stream is flushed per event
// a client that goes away cancels its request, which closes the connection to the api
func newProxy(target Target, logger *slog.Logger) (handler http.Handler) {
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.Out.URL.Scheme = "http"
			proxyRequest.Out.URL.Host = v1.HostName
			proxyRequest.Out.Host = v1.HostName

			for _, name := range []string{"Cookie", "Origin", "Referer", "Authorization"} {
				proxyRequest.Out.Header.Del(name)
			}
		},
		Transport:     NewTransport(target),
		FlushInterval: -1,
		ErrorLog:      slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
		// the security headers of the guard stay the only ones, the api sets no cookie
		ModifyResponse: func(response *http.Response) (err error) {
			response.Header.Del("Set-Cookie")
			response.Header.Del("Cache-Control")
			return
		},
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			// the browser went away, nobody reads the answer
			if errors.Is(err, context.Canceled) {
				logger.Debug("Ui api request cancelled", "path", request.URL.Path)
				writer.WriteHeader(http.StatusBadGateway)
				return
			}

			err = Explain(err, target)
			logger.Warn("Could not reach the control api", "error", err, "path", request.URL.Path)
			writeError(writer, http.StatusBadGateway, err, logger)
		},
	}

	handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !isAPIPath(request) {
			writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %s", ErrPath, request.URL.Path), logger)
			return
		}

		reverseProxy.ServeHTTP(writer, request)
	})
	return
}

// a clean path under /api/v1/ with no escaped characters, so what is checked is what the api gets
func isAPIPath(request *http.Request) (isAPI bool) {
	requestPath := request.URL.Path
	isAPI = (request.URL.RawPath == "") && strings.HasPrefix(requestPath, v1.BasePath+"/") && (path.Clean(requestPath) == requestPath || path.Clean(requestPath)+"/" == requestPath) && !strings.Contains(requestPath, "\\")
	return
}

// an error the page shows, in the api's own error body
func writeError(writer http.ResponseWriter, status int, err error, logger *slog.Logger) {
	body, marshalErr := json.Marshal(v1.Error{Error: err.Error()})

	if marshalErr != nil {
		logger.Error("Could not encode ui error", "error", marshalErr)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, writeErr := writer.Write(append(body, '\n'))

	if writeErr != nil {
		logger.Debug("Could not write ui error", "error", writeErr)
	}
}
