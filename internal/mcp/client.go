// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/ui"
)

// a client of the control API at target, the transport of decerter ui: every connection goes to target whatever the URL names
func NewClient(target ui.Target) (client Client) {
	client = Client{
		target: target,
		client: &http.Client{Transport: ui.NewTransport(target)},
	}
	return
}

// GET path with query (nil is none) and decode the JSON answer into result
func (client Client) getJSON(ctx context.Context, path string, query url.Values, result any) (err error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	response, err := client.get(ctx, path, query, jsonMediaType)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBytes+1))

	if err != nil {
		err = ui.Explain(err, client.target)
		return
	}

	if int64(len(body)) > maxJSONBytes {
		err = fmt.Errorf("%w: GET %s: the answer is larger than %d bytes", ErrAPI, path, maxJSONBytes)
		return
	}

	err = json.Unmarshal(body, result)

	if err != nil {
		err = fmt.Errorf("%w: GET %s: %w", ErrAPI, path, err)
	}

	return
}

// GET path and write the answer, it must have mediaType, into a new file of output named after kind; the file is only made once the api answered 200
// runs as long as the copy, until ctx is done
func (client Client) download(ctx context.Context, path string, query url.Values, mediaType string, output Output, kind string, extension string) (result FileResult, err error) {
	response, err := client.get(ctx, path, query, mediaType)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	result, err = output.save(kind, extension, response.Body)

	// a file error names its path, anything else came from reading the answer
	if _, isFileErr := errors.AsType[*fs.PathError](err); (err != nil) && !isFileErr {
		err = ui.Explain(err, client.target)
	}

	return
}

// GET /events until handle returns false, ctx is done or the stream ends; isClosed is true when decerter ended the stream
// each data line is one JSON event, comment, id and event lines are skipped
func (client Client) events(ctx context.Context, handle func(event v1.Event) (isMore bool)) (isClosed bool, err error) {
	response, err := client.get(ctx, "/events", nil, eventMediaType)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxEventLineBytes)

	for scanner.Scan() {
		data, isData := bytes.CutPrefix(scanner.Bytes(), []byte("data:"))

		if !isData {
			continue
		}

		event := v1.Event{}
		err = json.Unmarshal(bytes.TrimSpace(data), &event)

		if err != nil {
			err = fmt.Errorf("%w: %w", ErrEventStream, err)
			return
		}

		if !handle(event) {
			return
		}
	}

	err = scanner.Err()

	// the tail's own time ran out
	if ctx.Err() != nil {
		err = nil
		return
	}

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrEventStream, ui.Explain(err, client.target))
		return
	}

	isClosed = true
	return
}

// one GET to the api; an answer other than 200 with mediaType is an error with the api's message, its body is closed then
func (client Client) get(ctx context.Context, path string, query url.Values, mediaType string) (response *http.Response, err error) {
	address := url.URL{Scheme: "http", Host: v1.HostName, Path: v1.BasePath + path, RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), http.NoBody)

	if err != nil {
		return
	}

	response, err = client.client.Do(request)

	if err != nil {
		err = ui.Explain(err, client.target)
		return
	}

	if response.StatusCode != http.StatusOK {
		err = errors.Join(apiError(response, path), response.Body.Close())
		response = nil
		return
	}

	actual, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))

	if (parseErr != nil) || (actual != mediaType) {
		err = errors.Join(fmt.Errorf("%w: GET %s: %q, expected %s", ErrContentType, path, response.Header.Get("Content-Type"), mediaType), response.Body.Close())
		response = nil
		return
	}

	return
}

// the error of an answer that is not 200: the message of the api's error body, or the start of the body
func apiError(response *http.Response, path string) (err error) {
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBytes))
	message := strings.TrimSpace(string(body))
	apiErr := v1.Error{}

	if (readErr == nil) && (json.Unmarshal(body, &apiErr) == nil) && (apiErr.Error != "") {
		message = apiErr.Error
	}

	err = fmt.Errorf("%w: GET %s: %s: %s", ErrAPI, path, response.Status, message)
	return
}
