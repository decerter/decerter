// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// drops every message that contains word
type dropRule struct {
	word []byte
}

func (rule dropRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = bytes.Contains(message.Plain, rule.word)
	return
}

func (rule dropRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	verdict = intercept.DropVerdict
	return
}

// one TLS session through interceptTCP: the client writes each request as a record of its own and closes, the server reads until then and answers the same way
// IsLate keeps the secrets back until the server read the requests, they went on raw then; ErrAfter, ReadyAfter and IsCorrupt go to the keyLogLookup; Garbage is what the server sends after its TLS session, outside of a record
type interceptCase struct {
	Name       string
	Version    uint16
	Protocols  []string
	Rules      []intercept.Rule
	HTTPSpecs  []intercept.MatchSpec
	HasSecrets bool
	IsLate     bool
	LookupErr  error
	ErrAfter   int64
	ReadyAfter int64
	IsCorrupt  bool
	Requests   []string
	Responses  []string
	Garbage    []byte
}

type interceptResult struct {
	server   []byte
	client   []byte
	written  [2]int64
	output   string
	logs     string
	passed   int
	recorder *history.History
	err      error
}

func interceptTLS(state *testing.T, testCase interceptCase) (result interceptResult) {
	keyLog := newLockedBuffer()
	serverConfig, clientConfig := tlsConfigs(state, testCase.Version, testCase.Protocols, keyLog)
	lookup := newKeyLogLookup(keyLog, testCase.Version, !testCase.IsLate)
	lookup.err = testCase.LookupErr
	lookup.errAfter = testCase.ErrAfter
	lookup.readyAfter = testCase.ReadyAfter
	lookup.isCorrupt = testCase.IsCorrupt
	useSecrets(state, lookup.lookup)
	passedChannel := make(chan struct{}, 1)
	pipeline := intercept.New(testCase.Rules, nil, func(message intercept.Message, processed intercept.Result, origin intercept.Origin) {
		if origin != intercept.PassedOrigin {
			return
		}

		select {
		case passedChannel <- struct{}{}:
		default:
		}
	})
	var flowHTTP *httpFlow

	if testCase.HTTPSpecs != nil {
		result.recorder, flowHTTP, _ = httpTestLayer(state, testCase.HTTPSpecs, 5*time.Second)
	}

	secretsMaps := map[bpf.BpfMapName]*ebpf.Map(nil)

	if testCase.HasSecrets {
		secretsMaps = testSecretsMaps
	}

	app, proxyClient, err := tcpPair()

	if err != nil {
		state.Fatalf("Test of proxy.interceptTCP failed, cannot connect, error: %s", err.Error())
	}

	proxyUpstream, server, err := tcpPair()

	if err != nil {
		state.Fatalf("Test of proxy.interceptTCP failed, cannot connect, error: %s", err.Error())
	}

	logger, logs := bufferLogger()
	flow := intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})
	doneChannel := make(chan [2]int64, 1)
	serverChannel := make(chan tcpEndResult, 1)
	result.output = captureStdout(state, func() {
		// the proxy in the middle, with the ClientHello read first as handleTCP does
		go func() {
			hello := readClientOpening(proxyClient)
			opening := []TLSChunk{{direction: tlsrecord.ClientDirection, data: hello.data}}
			upBytes, downBytes := interceptTCP(state.Context(), proxyClient, proxyUpstream, opening, flow, pipeline, secretsMaps, flowHTTP, logger)

			// as handleTCP does, an aborted flow ends for its peers here
			if closeErr := errors.Join(proxyClient.Close(), proxyUpstream.Close()); closeErr != nil {
				state.Errorf("Test of proxy.interceptTCP failed, cannot close the proxy sockets, error: %s", closeErr.Error())
			}

			doneChannel <- [2]int64{upBytes, downBytes}
		}()

		// test server
		go func() {
			tlsServer := tls.Server(server, serverConfig)
			received, serverErr := io.ReadAll(tlsServer)

			if testCase.IsLate {
				lookup.ready.Store(true)

				select {
				case <-passedChannel:
					result.passed++
				case <-time.After(5 * time.Second):
				}
			}

			for _, response := range testCase.Responses {
				_, writeErr := tlsServer.Write([]byte(response))
				serverErr = errors.Join(serverErr, writeErr)
			}

			serverErr = errors.Join(serverErr, tlsServer.CloseWrite())

			// close_notify left a write deadline in the past on the socket
			if testCase.Garbage != nil {
				deadlineErr := server.SetWriteDeadline(time.Time{})
				_, writeErr := server.Write(testCase.Garbage)
				serverErr = errors.Join(serverErr, deadlineErr, writeErr)
			}

			serverChannel <- tcpEndResult{received: received, err: errors.Join(serverErr, server.CloseWrite())}
		}()

		tlsClient := tls.Client(app, clientConfig)

		for _, request := range testCase.Requests {
			_, writeErr := tlsClient.Write([]byte(request))
			err = errors.Join(err, writeErr)
		}

		err = errors.Join(err, tlsClient.CloseWrite())
		received, readErr := io.ReadAll(tlsClient)
		result.client = received
		err = errors.Join(err, readErr, app.CloseWrite())
		serverResult := <-serverChannel
		result.server = serverResult.received
		result.err = errors.Join(err, serverResult.err)
		result.written = <-doneChannel
	})
	result.err = errors.Join(result.err, app.Close(), server.Close())
	result.logs = logs.String()
	return
}

// Test if proxy.interceptTCP returns with the expected output for TLS sessions with their secrets: records are decrypted, changed, dropped or split by the rules and sealed again,
// the HTTP layer reads and edits the exchange, records that went on raw before late secrets are shown, a failed lookup relays the rest raw.
func TestInterceptTLSPositive(state *testing.T) {
	growth := strings.Repeat("x", 20000)
	positiveCases := []struct {
		Case     interceptCase
		Server   string
		Client   string
		Line     string
		IsPassed bool
	}{
		{
			Case:   interceptCase{Name: "tls 1.3 replace", Version: tls.VersionTLS13, Protocols: nil, Rules: []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("hello, world")}}, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"hi", "hello back"}, Garbage: nil},
			Server: "hello, world", Client: "hihello, world back", Line: "changed:1", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.2 drop", Version: tls.VersionTLS12, Protocols: nil, Rules: []intercept.Rule{dropRule{word: []byte("drop")}}, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"keep1", "drop me", "keep2"}, Responses: []string{"drop", "fine"}, Garbage: nil},
			Server: "keep1keep2", Client: "fine", Line: "dropped:1", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 split", Version: tls.VersionTLS13, Protocols: nil, Rules: []intercept.Rule{replaceRule{old: []byte("grow"), new: []byte(growth)}}, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"grow"}, Responses: []string{"ok"}, Garbage: nil},
			Server: growth, Client: "ok", Line: "split:1", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.2 http", Version: tls.VersionTLS12, Protocols: []string{"http/1.1"}, Rules: nil, HTTPSpecs: []intercept.MatchSpec{{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: "world", Replace: "planet"}}, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n"}, Responses: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "world"}, Garbage: nil},
			Server: "GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n", Client: "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nplanet", Line: "alpn=\"http/1.1\"", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 http until the end of the stream", Version: tls.VersionTLS13, Protocols: []string{"http/1.1"}, Rules: nil, HTTPSpecs: []intercept.MatchSpec{{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: "world", Replace: "planet"}}, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n"}, Responses: []string{"HTTP/1.0 200 OK\r\n\r\n", "world"}, Garbage: nil},
			Server: "GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n", Client: "HTTP/1.0 200 OK\r\n\r\nplanet", Line: "alpn=\"http/1.1\"", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 late secrets", Version: tls.VersionTLS13, Protocols: nil, Rules: []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}, HTTPSpecs: nil, HasSecrets: true, IsLate: true, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"hello"}, Garbage: nil},
			Server: "hello", Client: "HELLO", Line: "passed:1", IsPassed: true,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 lookup error", Version: tls.VersionTLS13, Protocols: nil, Rules: []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: errTestLookup, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"hello"}, Garbage: nil},
			Server: "hello", Client: "hello", Line: "sealed:0", IsPassed: false,
		},
	}

	hello := []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}
	lateHTTP := []intercept.MatchSpec{{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: "world", Replace: "planet"}}
	positiveCases = append(positiveCases, []struct {
		Case     interceptCase
		Server   string
		Client   string
		Line     string
		IsPassed bool
	}{
		{
			Case:   interceptCase{Name: "tls 1.3 secrets right after the first lookup", Version: tls.VersionTLS13, Protocols: nil, Rules: hello, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 1, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"hello"}, Garbage: nil},
			Server: "HELLO", Client: "HELLO", Line: "changed:1", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 lookup error after the first lookup", Version: tls.VersionTLS13, Protocols: nil, Rules: hello, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: errTestLookup, ErrAfter: 1, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"hello"}, Garbage: nil},
			Server: "hello", Client: "hello", Line: "sealed:0", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.2 wrong secrets", Version: tls.VersionTLS12, Protocols: nil, Rules: hello, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: true, Requests: []string{"hello"}, Responses: []string{"hello"}, Garbage: nil},
			Server: "hello", Client: "hello", Line: "sealed:0", IsPassed: false,
		},
		{
			Case:   interceptCase{Name: "tls 1.3 late secrets with http", Version: tls.VersionTLS13, Protocols: []string{"http/1.1"}, Rules: nil, HTTPSpecs: lateHTTP, HasSecrets: true, IsLate: true, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n"}, Responses: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"}, Garbage: nil},
			Server: "GET / HTTP/1.1\r\nHost: decerter.test\r\n\r\n", Client: "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nplanet", Line: "passed:1", IsPassed: true,
		},
	}...)

	for _, positive := range positiveCases {
		result := interceptTLS(state, positive.Case)

		if (result.err != nil) || (string(result.server) != positive.Server) || (string(result.client) != positive.Client) {
			state.Errorf("Test of proxy.interceptTCP function failed, case %q, the server should get %q and the client %q, they got %q and %q, error: %v, logs: %s", positive.Case.Name, shorten(positive.Server), positive.Client, shorten(string(result.server)), result.client, result.err, result.logs)
			return
		}

		if !strings.Contains(result.output, positive.Line) || !strings.Contains(result.output, "tls pid=") || (positive.IsPassed != (result.passed == 1)) {
			state.Errorf("Test of proxy.interceptTCP function failed, case %q, the records line should have %q, passed: %d, output: %q", positive.Case.Name, positive.Line, result.passed, result.output)
			return
		}

		if ((positive.Case.LookupErr != nil) || positive.Case.IsCorrupt) && !strings.Contains(result.logs, "Could not intercept tls flow, relaying raw") {
			state.Errorf("Test of proxy.interceptTCP function failed, case %q, the failed lookup should be logged, logs: %s", positive.Case.Name, result.logs)
			return
		}

		if result.recorder == nil {
			continue
		}

		exchanges, _, _ := result.recorder.Exchanges(1, 0, 10)

		if (len(exchanges) != 1) || (exchanges[0].Response == nil) || !exchanges[0].Response.Edited || (exchanges[0].Response.State != api.CompleteHTTPState) {
			state.Errorf("Test of proxy.interceptTCP function failed, case %q, the history should have the edited exchange, exchanges: %+v", positive.Case.Name, exchanges)
			return
		}
	}
}

// Test if proxy.interceptTCP returns with the expected errors: raw bytes after a direction changed its record count abort the flow.
func TestInterceptTLSNegative(state *testing.T) {
	result := interceptTLS(state, interceptCase{Name: "garbage after a drop", Version: tls.VersionTLS13, Protocols: nil, Rules: []intercept.Rule{dropRule{word: []byte("drop")}}, HTTPSpecs: nil, HasSecrets: true, IsLate: false, LookupErr: nil, ErrAfter: 0, ReadyAfter: 0, IsCorrupt: false, Requests: []string{"hello"}, Responses: []string{"drop", "fine"}, Garbage: []byte("not a record")})

	if !strings.Contains(result.logs, ErrChangedStream.Error()) || !strings.Contains(result.logs, "Could not intercept tls flow, relaying raw") {
		state.Errorf("Test of proxy.interceptTCP function failed, raw bytes after a dropped record should abort the flow, client: %q, error: %v, logs: %s", result.client, result.err, result.logs)
		return
	}
}

// an interception of flow 1 as interceptTCP makes it, without its sockets
func newTestInterception(secretsMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, flowHTTP *httpFlow, logger *slog.Logger) (flowInterception *interception) {
	flowInterception = newInterception(intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{}), pipeline, secretsMaps, flowHTTP, logger)
	return
}

// the kinds of the items in the queue of a direction
func (interception *interception) kinds(direction tlsrecord.Direction) (kinds []sendKind) {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()

	for _, item := range interception.queues[direction] {
		kinds = append(kinds, item.kind)
	}

	return
}

// Test if proxy.interception returns with the expected output for the steps of its state: a server that speaks first and a client that leaves undecided are plain tcp,
// a full queue waits for its sender, the HTTP layer asks for one flush at a time, a dropped chunk sends nothing and secrets that never come relay TLS raw.
func TestInterceptionPositive(state *testing.T) {
	logger := discardLogger()
	pipeline := intercept.New([]intercept.Rule{dropRule{word: []byte("drop")}}, nil, nil)

	// the server speaks first
	serverFirst := newTestInterception(nil, pipeline, nil, logger)

	if !serverFirst.take(tlsrecord.ServerDirection, []byte("220 smtp\r\n")) || (serverFirst.mode != tcpInterceptMode) || !slices.Equal(serverFirst.kinds(tlsrecord.ServerDirection), []sendKind{chunkSendKind}) {
		state.Errorf("Test of proxy.interception.take function failed, a server that speaks first should make a plain tcp flow, mode: %s", serverFirst.mode)
		return
	}

	// the start of a ClientHello and the end of the stream, an end without any bytes
	undecided := newTestInterception(testSecretsMaps, pipeline, nil, logger)
	undecided.take(tlsrecord.ClientDirection, []byte{0x16})
	isUndecided := (undecided.mode == undecidedInterceptMode) && (len(undecided.kinds(tlsrecord.ClientDirection)) == 0)
	undecided.end(tlsrecord.ClientDirection)
	empty := newTestInterception(nil, pipeline, nil, logger)
	empty.end(tlsrecord.ClientDirection)

	if !isUndecided || (undecided.mode != tcpInterceptMode) || !slices.Equal(undecided.kinds(tlsrecord.ClientDirection), []sendKind{chunkSendKind}) || (empty.mode != tcpInterceptMode) || (len(empty.kinds(tlsrecord.ClientDirection)) != 0) {
		state.Errorf("Test of proxy.interception.end function failed, an undecided flow should end as plain tcp with its prefix, modes: %s %s", undecided.mode, empty.mode)
		return
	}

	// a full queue takes the next bytes once its sender made room
	full := newTestInterception(nil, pipeline, nil, logger)
	full.take(tlsrecord.ClientDirection, []byte("GET"))
	full.mutex.Lock()
	full.queuedBytes[tlsrecord.ClientDirection] = maxSendQueueBytes
	full.mutex.Unlock()
	takenChannel := make(chan bool, 1)

	// reader of the full direction
	go func() {
		takenChannel <- full.take(tlsrecord.ClientDirection, []byte(" /"))
	}()

	full.sent(tlsrecord.ClientDirection, maxSendQueueBytes)

	if !<-takenChannel || (len(full.kinds(tlsrecord.ClientDirection)) != 2) {
		state.Errorf("Test of proxy.interception.take function failed, the bytes should be taken once there is room")
		return
	}

	// a dropped chunk sends nothing, a flush without HTTP layer or without bytes neither
	encrypter := tlsrecord.NewEncrypter()
	carrier := (*tlsrecord.Record)(nil)
	dropped, droppedErr := full.prepare(state.Context(), tlsrecord.ClientDirection, sendItem{kind: chunkSendKind, data: []byte("drop")}, &encrypter, &carrier, logger)
	flushed, flushedErr := full.prepare(state.Context(), tlsrecord.ClientDirection, sendItem{kind: flushSendKind}, &encrypter, &carrier, logger)
	full.http = newHTTPFlow(1, nil, HTTPLayer{Pipeline: nil, Timeout: time.Second})
	httpFlushed, httpErr := full.prepare(state.Context(), tlsrecord.ClientDirection, sendItem{kind: flushSendKind}, &encrypter, &carrier, logger)

	if (dropped != nil) || (flushed != nil) || (httpFlushed != nil) || (errors.Join(droppedErr, flushedErr, httpErr) != nil) || full.http.isKeeping(tlsrecord.ClientDirection) {
		state.Errorf("Test of proxy.interception.prepare function failed, nothing should be sent, dropped: %q, flushed: %q %q", dropped, flushed, httpFlushed)
		return
	}

	// the HTTP layer asks for frames, a second ask while the first waits adds nothing, an aborted flow takes no more
	full.wakeHTTP(tlsrecord.ServerDirection)
	full.wakeHTTP(tlsrecord.ServerDirection)
	isOneFlush := slices.Equal(full.kinds(tlsrecord.ServerDirection), []sendKind{flushSendKind})
	full.mutex.Lock()
	full.aborted = true
	full.mutex.Unlock()
	full.wakeHTTP(tlsrecord.ClientDirection)

	if !isOneFlush || (len(full.kinds(tlsrecord.ClientDirection)) != 2) || full.take(tlsrecord.ClientDirection, []byte("late")) {
		state.Errorf("Test of proxy.interception.wakeHTTP function failed, one flush should wait and an aborted flow take nothing, kinds: %v", full.kinds(tlsrecord.ServerDirection))
		return
	}

	// a finished flow does not look its secrets up any more
	full.mutex.Lock()
	full.finished = true
	full.mutex.Unlock()
	full.poll()
	full.finish()
}

// Test if proxy.interception returns with the expected errors: secrets that are not there when the hold time is over relay the TLS flow raw.
func TestInterceptionNegative(state *testing.T) {
	chunks, keyLog, _ := recordTLS(state, tls.VersionTLS13, nil, []byte("request"), []byte("response"))
	lookup := newKeyLogLookup(keyLog, tls.VersionTLS13, false)
	useSecrets(state, lookup.lookup)
	logger, logs := bufferLogger()
	interception := newTestInterception(testSecretsMaps, intercept.New(nil, nil, nil), nil, logger)

	for _, chunk := range chunks {
		interception.take(chunk.direction, chunk.data)
	}

	interception.mutex.Lock()
	interception.holdDeadline = time.Now().Add(-time.Second)
	interception.mutex.Unlock()
	interception.poll()
	interception.spinGroup.Wait()
	interception.finish()

	if (interception.mode != rawInterceptMode) || !strings.Contains(logs.String(), ErrNoSecrets.Error()) {
		state.Errorf("Test of proxy.interception.poll function failed, the flow should go raw without secrets, mode: %s, logs: %s", interception.mode, logs.String())
		return
	}

	// a reader of an aborted flow stops at its next bytes
	app, proxyClient, err := tcpPair()

	if err != nil {
		state.Fatalf("Test of proxy.interception.read failed, cannot connect, error: %s", err.Error())
	}

	doneChannel := make(chan struct{})

	// reader
	go func() {
		interception.read(proxyClient, tlsrecord.ClientDirection, func() {}, logger)
		close(doneChannel)
	}()

	interception.mutex.Lock()
	interception.aborted = true
	interception.mutex.Unlock()
	_, err = app.Write([]byte("more"))
	<-doneChannel

	if err = errors.Join(err, app.Close(), proxyClient.Close()); err != nil {
		state.Errorf("Test of proxy.interception.read function failed, error: %s", err.Error())
		return
	}
}

// Test if proxy.interceptTCP returns with the expected errors: a server that is gone aborts the flow when its bytes can't be written.
func TestInterceptTCPNegative(state *testing.T) {
	app, proxyClient, err := tcpPair()

	if err != nil {
		state.Fatalf("Test of proxy.interceptTCP failed, cannot connect, error: %s", err.Error())
	}

	proxyUpstream, server, err := tcpPair()

	if err != nil {
		state.Fatalf("Test of proxy.interceptTCP failed, cannot connect, error: %s", err.Error())
	}

	// the server resets the connection before the flow starts
	err = errors.Join(server.SetLinger(0), server.Close())
	_, readErr := proxyUpstream.Read(make([]byte, 1))

	if (err != nil) || !errors.Is(readErr, syscall.ECONNRESET) {
		state.Fatalf("Test of proxy.interceptTCP failed, cannot reset the server, error: %v", errors.Join(err, readErr))
	}

	logger, logs := bufferLogger()
	doneChannel := make(chan [2]int64, 1)

	// the proxy in the middle
	go func() {
		upBytes, downBytes := interceptTCP(state.Context(), proxyClient, proxyUpstream, nil, intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{}), intercept.New(nil, nil, nil), nil, nil, logger)
		doneChannel <- [2]int64{upBytes, downBytes}
	}()

	_, err = app.Write([]byte("hello"))
	written := <-doneChannel
	err = errors.Join(err, app.Close(), proxyClient.Close(), proxyUpstream.Close())

	if (err != nil) || (written != [2]int64{0, 0}) || !strings.Contains(logs.String(), "Could not write tcp stream") {
		state.Errorf("Test of proxy.interceptTCP function failed, the flow should abort, written: %v, error: %v, logs: %s", written, err, logs.String())
		return
	}
}
