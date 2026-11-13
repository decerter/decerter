// SPDX-License-Identifier: AGPL-3.0-only

package ui

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os/exec"

	v1 "github.com/decerter/decerter/api"
)

// the page: index.html, app.js and app.css, vanilla JS with no build step
//
//go:embed web
var webFiles embed.FS

// 127.0.0.1 with a port the kernel picks; host is 127.0.0.1:<port>, the only Host the guard lets in
// [::1] is not offered: a second address would be a second origin with its own cookie, and IPv4 loopback is always there
func Listen() (listener net.Listener, host string, err error) {
	listener, err = net.Listen("tcp4", listenAddress)

	if err != nil {
		return
	}

	host = listener.Addr().String()
	return
}

// the page and the /api/v1 proxy to target, every request behind the guard
func Handler(target Target, token string, host string, logger *slog.Logger) (handler http.Handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveFile(webDirectory+"/index.html"))
	mux.HandleFunc("GET /app.js", serveFile(webDirectory+"/app.js"))
	mux.HandleFunc("GET /app.css", serveFile(webDirectory+"/app.css"))
	// the browser asks for it on its own, there is none
	mux.HandleFunc("GET /favicon.ico", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	proxy := newProxy(target, logger)

	// the methods of api/openapi.yaml; a pattern per method, "GET /" and a bare "/api/v1/" would overlap
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete} {
		mux.Handle(method+" "+v1.BasePath+"/", proxy)
	}

	handler = guard(mux, token, host, logger)
	return
}

func serveFile(name string) (handle http.HandlerFunc) {
	handle = func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFileFS(writer, request, webFiles, name)
	}
	return
}

// serve until ctx is done; the event streams end with ctx, the other requests have a moment to finish
func Serve(ctx context.Context, listener net.Listener, handler http.Handler, logger *slog.Logger) (err error) {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}
	serveErrChannel := make(chan error, 1)

	// ui http server
	go func() {
		serveErrChannel <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		logger.Debug("Context cancelled")
	case err = <-serveErrChannel:
		logger.Error("Could not serve the ui", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)

	if shutdownErr != nil {
		logger.Debug("Could not shut the ui down in time, closing it", "error", shutdownErr)
		err = errors.Join(err, server.Close())
	}

	return
}

// xdg-open in the background, a browser that does not start is only logged; the URL with the token is in xdg-open's arguments while it runs
// not tied to a context: a browser xdg-open started stays when decerter ui stops
func Open(address string, logger *slog.Logger) {
	// browser opener
	go func() {
		err := exec.Command("xdg-open", address).Run()

		if err != nil {
			logger.Warn("Could not open the browser, open the printed URL yourself", "error", err)
		}
	}()
}
