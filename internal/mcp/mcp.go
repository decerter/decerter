// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	v1 "github.com/decerter/decerter/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// the export tools write into directory, which must exist; a relative path is taken from the working directory
func OpenOutput(directory string) (output Output, err error) {
	absolute, err := filepath.Abs(directory)

	if err != nil {
		err = fmt.Errorf("%w %q: %w", ErrOutputDirectory, directory, err)
		return
	}

	root, err := os.OpenRoot(absolute)

	if err != nil {
		err = fmt.Errorf("%w %q: %w", ErrOutputDirectory, directory, err)
		return
	}

	output = Output{root: root, directory: absolute}
	return
}

func (output Output) Close() (err error) {
	err = output.root.Close()
	return
}

// the MCP server with the read tools for the api of client; logger gets the SDK's own logs
func NewServer(client Client, output Output, logger *slog.Logger) (server *sdk.Server, err error) {
	server = sdk.NewServer(
		&sdk.Implementation{Name: serverName, Title: serverTitle, Version: v1.Version()},
		&sdk.ServerOptions{
			Instructions: serverInstructions(),
			Logger:       logger,
			// tools only, no logging capability; the tool list does not change while the server runs
			Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{ListChanged: false}},
		},
	)
	server.AddReceivingMiddleware(nullArguments)
	err = addReadTools(server, client, output)
	return
}

// "arguments": null is no arguments: the SDK would apply the defaults of the input schema to a nil map and panic
func nullArguments(next sdk.MethodHandler) (handle sdk.MethodHandler) {
	handle = func(ctx context.Context, method string, request sdk.Request) (result sdk.Result, err error) {
		if callRequest, isCall := request.(*sdk.CallToolRequest); isCall && (callRequest.Params != nil) && (string(bytes.TrimSpace(callRequest.Params.Arguments)) == "null") {
			callRequest.Params.Arguments = nil
		}

		result, err = next(ctx, method, request)
		return
	}
	return
}

// serve on stdin and stdout until the client closes stdin or ctx is done; stdout carries nothing else
func Serve(ctx context.Context, server *sdk.Server) (err error) {
	err = server.Run(ctx, &sdk.StdioTransport{})

	if ctx.Err() != nil {
		err = nil
	}

	return
}

func serverInstructions() (instructions string) {
	instructions = `decerter reads and rewrites the live TCP, UDP, TLS and DTLS traffic of selected local processes with eBPF. ` +
		`These tools read its state over its control API: status, the flow history (list_flows takes the decerter filter language, e.g. proc.comm == "curl", tls.sni contains "example", tcp.dstport == 443), ` +
		`the messages of a flow and their payloads (get_message, 4 KiB windows paged with offset and length), the live event stream (tail_events), held messages, rules and captures. ` +
		`export_keylog, export_pcap and download_pcap write files into the output directory and return only their path, size and SHA-256; key material and pcaps never come back in a result. ` +
		"\n\n" + untrustedNote
	return
}

// a new file decerter-<kind>-<time>.<extension> (decerter-<kind>-<time>-<n>.<extension> when that is taken) with reader's bytes, mode 0600; a file that could not be written whole is removed
// an error that names a path is the file's, any other came from reader
func (output Output) save(kind string, extension string, reader io.Reader) (result FileResult, err error) {
	stamp := time.Now().UTC().Format(fileTimeFormat)
	name := ""
	var file *os.File

	for try := range maxFileTries {
		name = "decerter-" + kind + "-" + stamp + "." + extension

		if try > 0 {
			name = "decerter-" + kind + "-" + stamp + "-" + strconv.Itoa(try+1) + "." + extension
		}

		file, err = output.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)

		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrOutputFile, err)
		return
	}

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), reader)
	closeErr := file.Close()

	if _, isFileErr := errors.AsType[*fs.PathError](copyErr); isFileErr {
		copyErr = fmt.Errorf("%w: %w", ErrOutputFile, copyErr)
	}

	if closeErr != nil {
		closeErr = fmt.Errorf("%w: %w", ErrOutputFile, closeErr)
	}

	if err = errors.Join(copyErr, closeErr); err != nil {
		err = errors.Join(err, output.root.Remove(name))
		return
	}

	result = FileResult{Path: filepath.Join(output.directory, name), Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}
	return
}
