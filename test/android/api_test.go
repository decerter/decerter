// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	// the abstract socket of decerter on Android, adb forwards a host port to it
	apiSocket string = "@decerter-api"
	// how often the held messages are looked at
	holdPoll time.Duration = 100 * time.Millisecond
	// what decerter logs for every client of the api socket, with its uid
	apiClientLog string = `"msg":"Api client connected"`
	// the port of decerter's proxy, the app's sockets talk to it over loopback
	proxyPort string = "15001"
)

// the control API of the decerter on the device through adb forward tcp:<port> localabstract:decerter-api
type apiClient struct {
	client *http.Client
	port   string
}

// what the dex printed, or why it failed
type dexResult struct {
	err error
}

// Test if a rule added over the API through adb forward rewrites GET / to GET /test of a Conscrypt call over TLS 1.3 and TLS 1.2, and a deleted rule changes nothing.
func TestRewritePositive(state *testing.T) {
	requireDex(state)
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "rewrite", apiArguments(appPackage), redirectReady)
	client := forwardAPI(state)
	rule := v1.Rule{}
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, &rule)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the rewrite failed, cannot add the rule over adb forward, status: %d, error: %v", status, err)
	}

	for _, server := range servers {
		err = testDex(state.Context(), appUID, server, "/", "/test")

		if err != nil {
			state.Errorf("Test of the rewrite failed, error: %s", err.Error())
		}
	}

	// the Conscrypt requests of --package as exchanges of the HTTP layer, after the record rule
	flows := v1.FlowList{}
	_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(`http.request.method == "GET" && http.request.uri == "/test" && http.response.code == 200`), nil, &flows)
	exchanges := v1.ExchangeList{}

	if (err == nil) && (len(flows.Flows) > 0) {
		_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", flows.Flows[0].ID), nil, &exchanges)
	}

	if (err != nil) || (len(flows.Flows) != len(servers)) || (len(exchanges.Exchanges) != 1) || (exchanges.Exchanges[0].Request == nil) || !strings.HasPrefix(exchanges.Exchanges[0].Request.URL, "https://") {
		state.Errorf("Test of the rewrite failed, the dex's requests should be exchanges, flows: %d, exchanges: %+v, error: %v", len(flows.Flows), exchanges, err)
	}

	status, err = client.call(state.Context(), http.MethodDelete, fmt.Sprintf("/rules/%d", rule.ID), nil, nil)

	if (err != nil) || (status != http.StatusNoContent) {
		state.Fatalf("Test of the rewrite failed, cannot delete the rule, status: %d, error: %v", status, err)
	}

	err = testDex(state.Context(), appUID, servers[0], "/", "/")

	if err != nil {
		state.Errorf("Test of the rewrite failed, a deleted rule should change nothing, error: %s", err.Error())
	}

	checkAPIClient(state, decerter)
	stopDeviceDecerter(state, decerter, true)
}

// Test if the rule leaves the HTTPS calls of a uid decerter does not select alone.
func TestRewriteNegative(state *testing.T) {
	requireDex(state)
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "rewrite-negative", apiArguments(appPackage), redirectReady)
	client := forwardAPI(state)
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Direction: v1.UpDirection, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the rewrite failed, cannot add the rule over adb forward, status: %d, error: %v", status, err)
	}

	for _, server := range servers {
		err = testDex(state.Context(), shellUID, server, "/", "/")

		if err != nil {
			state.Errorf("Test of the rewrite failed, error: %s", err.Error())
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if a Conscrypt request held over the API through adb forward can be edited from GET / to GET /test and forwarded, and the server receives /test.
func TestHoldPositive(state *testing.T) {
	requireDex(state)
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "hold", apiArguments(appPackage), redirectReady)
	client := forwardAPI(state)
	status, err := client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: "tls", Direction: v1.UpDirection}, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of the hold failed, cannot turn intercept on over adb forward, status: %d, error: %v", status, err)
	}

	for _, server := range servers {
		resultChannel := make(chan dexResult, 1)

		// the app's call, it waits while its request is held
		go func() {
			resultChannel <- dexResult{err: testDex(state.Context(), appUID, server, "/", "/test")}
		}()

		held, holdErr := client.waitHeld(state.Context())

		if holdErr != nil {
			state.Fatalf("Test of the hold failed, port %s, error: %s", server.Port, holdErr.Error())
		}

		payload, decodeErr := hex.DecodeString(held.Payload.Hex)

		if (decodeErr != nil) || !bytes.HasPrefix(payload, []byte("GET / HTTP/1.1\r\n")) {
			state.Fatalf("Test of the hold failed, port %s, the held request should start with GET /, payload: %q, error: %v", server.Port, payload, decodeErr)
		}

		status, err = client.call(state.Context(), http.MethodPut, fmt.Sprintf("/holds/%d", held.ID), v1.EditRequest{Payload: v1.Value{Type: v1.TextValueType, Value: strings.Replace(string(payload), "GET / ", "GET /test ", 1)}}, nil)

		if (err == nil) && (status == http.StatusOK) {
			status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, nil)
		}

		result := <-resultChannel

		if (err != nil) || (status != http.StatusNoContent) || (result.err != nil) {
			state.Errorf("Test of the hold failed, port %s, the edited request should reach the server, status: %d, error: %v", server.Port, status, errors.Join(err, result.err))
		}
	}

	checkAPIClient(state, decerter)
	stopDeviceDecerter(state, decerter, true)
}

// decerter run with --intercept, --package and the API on its abstract socket, debug logs name the uid of every api client
func apiArguments(packageName string) (arguments string) {
	arguments = "--log-level debug run --intercept --api-socket " + apiSocket + " --package " + packageName + " --dst-cidr " + hostCIDR
	return
}

// adb forward of a free host port to the api socket, removed when the test ends
func forwardAPI(state *testing.T) (client apiClient) {
	output, err := device.run(state.Context(), adbTimeout, "forward", "tcp:0", "localabstract:"+strings.TrimPrefix(apiSocket, "@"))

	if err != nil {
		state.Fatalf("Could not forward the api socket, error: %s", err.Error())
	}

	port := strings.TrimSpace(output)

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), adbTimeout)
		defer cancel()

		if _, removeErr := device.run(ctx, adbTimeout, "forward", "--remove", "tcp:"+port); removeErr != nil {
			state.Errorf("Could not remove the adb forward, error: %s", removeErr.Error())
		}
	})

	client = apiClient{client: &http.Client{Timeout: adbTimeout}, port: port}
	return
}

// adbd connects to the abstract socket as root after adb root, as shell otherwise, and decerter let it in
func checkAPIClient(state *testing.T, decerter deviceDecerter) {
	log, err := decerter.log(state.Context())

	if err != nil {
		state.Fatalf("Could not read the log of %s, error: %s", decerter.Binary, err.Error())
	}

	isRoot := strings.Contains(log, apiClientLog+`,"uid":0,`)
	isShell := strings.Contains(log, apiClientLog+`,"uid":2000,`)

	if (!isRoot && !isShell) || strings.Contains(log, `"msg":"Refused api client"`) {
		state.Errorf("adb forward should connect as root or shell and be let in, log:\n%s", log)
	}
}

// one request with a JSON body, nil sends none; result nil reads no answer
func (client apiClient) call(ctx context.Context, method string, path string, body any, result any) (status int, err error) {
	var reader io.Reader = http.NoBody

	if body != nil {
		encoded, encodeErr := json.Marshal(body)

		if err = encodeErr; err != nil {
			return
		}

		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort("127.0.0.1", client.port)+v1.BasePath+path, reader)

	if err != nil {
		return
	}

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	status = response.StatusCode
	answer, err := io.ReadAll(response.Body)

	if (err != nil) || (result == nil) || (status >= 300) {
		return
	}

	err = json.Unmarshal(answer, result)
	return
}

// the first held message, it comes once the dex sent its request
func (client apiClient) waitHeld(ctx context.Context) (held v1.Hold, err error) {
	holdCtx, cancel := context.WithTimeout(ctx, outputTimeout)
	defer cancel()

	for {
		holds := v1.HoldList{}
		_, err = client.call(holdCtx, http.MethodGet, "/holds", nil, &holds)

		if err != nil {
			return
		}

		if len(holds.Holds) > 0 {
			held = holds.Holds[0]
			return
		}

		select {
		case <-holdCtx.Done():
			err = fmt.Errorf("no message was held: %w", holdCtx.Err())
			return
		case <-time.After(holdPoll):
		}
	}
}

// Test if decerter capture --api-socket works through adb forward: a capture started, stopped and downloaded over the API holds the decrypted requests of the app's TLS 1.3 and TLS 1.2 calls for tshark on the host, and so does the live stream read through the forward.
func TestCaptureAPIPositive(state *testing.T) {
	requireDex(state)

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "capture-api", "--log-level debug capture --api-socket "+apiSocket+" --uid "+strconv.FormatUint(uint64(appUID), 10)+" --dst-cidr "+hostCIDR, captureReady)
	client := forwardAPI(state)
	started := v1.Capture{}
	status, err := client.call(state.Context(), http.MethodPost, "/captures", v1.CaptureRequest{Filter: "tls", Plaintext: false}, &started)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the capture api failed, cannot start a capture over adb forward, status: %d, error: %v", status, err)
	}

	stream := client.startStream(state, servers)

	for _, server := range servers {
		err = testDex(state.Context(), appUID, server, "/capture-api", "/capture-api")

		if err != nil {
			state.Errorf("Test of the capture api failed, error: %s", err.Error())
		}
	}

	hasRequests := func(output string) (isFound bool) {
		isFound = true

		for _, server := range servers {
			isFound = isFound && slices.Contains(strings.Split(output, "\n"), server.Port+"\tGET\t/capture-api")
		}

		return
	}
	output, err := stream.wait(state.Context(), hasRequests)

	if err != nil {
		state.Errorf("Test of the capture api failed, tshark should find GET /capture-api to ports %s and %s in the stream, output:\n%s\nerrors:\n%s", servers[0].Port, servers[1].Port, output, stream.errors.String())
	}

	status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/captures/%d/stop", started.ID), nil, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of the capture api failed, cannot stop the capture, status: %d, error: %v", status, err)
	}

	capturePath := filepath.Join(state.TempDir(), "capture.pcapng")
	err = client.download(state.Context(), fmt.Sprintf("/captures/%d/pcap", started.ID), capturePath)

	if err != nil {
		state.Fatalf("Test of the capture api failed, cannot download the capture, error: %s", err.Error())
	}

	arguments := []string{"-n", "-r", capturePath}

	for _, server := range servers {
		arguments = append(arguments, "-d", "tcp.port=="+server.Port+",tls")
	}

	arguments = append(arguments, "-Y", "http.request", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.method", "-e", "http.request.uri")
	fileOutput, err := exec.CommandContext(state.Context(), tsharkPath, arguments...).Output()

	if (err != nil) || !hasRequests(string(fileOutput)) {
		state.Errorf("Test of the capture api failed, tshark should find GET /capture-api to ports %s and %s in the downloaded file, output:\n%s\nerror: %v", servers[0].Port, servers[1].Port, fileOutput, err)
	}

	stream.stop()
	checkAPIClient(state, decerter)
	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter run --intercept --api-socket captures the wire side through adb forward: with a rule rewriting GET / to GET /test, a capture started over the API and the live stream show the edited request to the server's real address 10.0.2.2, decrypted by tshark on the host, for the app's TLS 1.3 and TLS 1.2 calls.
func TestRunCaptureAPIPositive(state *testing.T) {
	requireDex(state)

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "run-capture", apiArguments(appPackage), redirectReady)
	client := forwardAPI(state)
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the run mode capture failed, cannot add the rule over adb forward, status: %d, error: %v", status, err)
	}

	started := v1.Capture{}
	status, err = client.call(state.Context(), http.MethodPost, "/captures", v1.CaptureRequest{Filter: "tls", Plaintext: false}, &started)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the run mode capture failed, cannot start a capture over adb forward, status: %d, error: %v", status, err)
	}

	stream := client.startStream(state, servers)

	for _, server := range servers {
		err = testDex(state.Context(), appUID, server, "/", "/test")

		if err != nil {
			state.Errorf("Test of the run mode capture failed, error: %s", err.Error())
		}
	}

	hasRequests := func(output string) (isFound bool) {
		isFound = true

		for _, server := range servers {
			isFound = isFound && slices.Contains(strings.Split(output, "\n"), server.Port+"\tGET\t/test")
		}

		return
	}
	output, err := stream.wait(state.Context(), hasRequests)

	if err != nil {
		state.Errorf("Test of the run mode capture failed, tshark should find GET /test to ports %s and %s in the stream, output:\n%s\nerrors:\n%s", servers[0].Port, servers[1].Port, output, stream.errors.String())
	}

	capturePath := client.stopAndDownload(state, started)
	fileOutput, err := runTshark(state.Context(), capturePath, servers, "http.request", "tcp.dstport", "http.request.method", "http.request.uri")

	if (err != nil) || !hasRequests(fileOutput) {
		state.Errorf("Test of the run mode capture failed, tshark should find GET /test to ports %s and %s in the downloaded file, output:\n%s\nerror: %v", servers[0].Port, servers[1].Port, fileOutput, err)
	}

	// the wire side: the connections go to the server's address, nothing of the app's loopback connection to the proxy
	syns, err := runTshark(state.Context(), capturePath, servers, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst", "tcp.dstport")
	proxied, proxiedErr := runTshark(state.Context(), capturePath, servers, "tcp.port == "+proxyPort, "tcp.stream")

	for _, server := range servers {
		if (errors.Join(err, proxiedErr) != nil) || !slices.Contains(strings.Split(syns, "\n"), hostAddress+"\t"+server.Port) || (proxied != "") {
			state.Errorf("Test of the run mode capture failed, the file should have the SYN to %s port %s and no packet of the proxy port %s, syns:\n%s\nproxy packets:\n%s\nerror: %v", hostAddress, server.Port, proxyPort, syns, proxied, errors.Join(err, proxiedErr))
		}
	}

	stream.stop()
	checkAPIClient(state, decerter)
	stopDeviceDecerter(state, decerter, true)
}

// Test if the capture of decerter run leaves out what it must not have: the HTTPS call of a uid decerter does not select, and with a filter that takes no flow even the app's call.
func TestRunCaptureAPINegative(state *testing.T) {
	requireDex(state)

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "run-capture-negative", apiArguments(appPackage), redirectReady)
	client := forwardAPI(state)
	captures := map[string]v1.CaptureRequest{"all": {Filter: "", Plaintext: false}, "none": {Filter: "proc.comm == \"nothing\"", Plaintext: false}}
	started := map[string]v1.Capture{}

	for name, request := range captures {
		capture := v1.Capture{}
		status, err := client.call(state.Context(), http.MethodPost, "/captures", request, &capture)

		if (err != nil) || (status != http.StatusCreated) {
			state.Fatalf("Test of the run mode capture failed, cannot start the %s capture, status: %d, error: %v", name, status, err)
		}

		started[name] = capture
	}

	// the app calls the first server through the proxy, the shell uid the second one directly
	err := errors.Join(testDex(state.Context(), appUID, servers[0], "/negative", "/negative"), testDex(state.Context(), shellUID, servers[1], "/negative", "/negative"))

	if err != nil {
		state.Errorf("Test of the run mode capture failed, error: %s", err.Error())
	}

	for name, capture := range started {
		capturePath := client.stopAndDownload(state, capture)
		syns, tsharkErr := runTshark(state.Context(), capturePath, servers, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "tcp.dstport")
		expected := servers[0].Port + "\n"

		if name == "none" {
			expected = ""
		}

		if (tsharkErr != nil) || (syns != expected) {
			state.Errorf("Test of the run mode capture failed, the %s capture should have the SYNs %q, syns: %q, error: %v", name, expected, syns, tsharkErr)
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// stop a capture of the API and download its file
func (client apiClient) stopAndDownload(state *testing.T, capture v1.Capture) (capturePath string) {
	status, err := client.call(state.Context(), http.MethodPost, fmt.Sprintf("/captures/%d/stop", capture.ID), nil, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Could not stop capture %d, status: %d, error: %v", capture.ID, status, err)
	}

	capturePath = filepath.Join(state.TempDir(), fmt.Sprintf("capture-%d.pcapng", capture.ID))
	err = client.download(state.Context(), fmt.Sprintf("/captures/%d/pcap", capture.ID), capturePath)

	if err != nil {
		state.Fatalf("Could not download capture %d, error: %s", capture.ID, err.Error())
	}

	return
}

// the fields of the packets of a capture file the display filter takes, tab separated, the servers' ports decoded as TLS
func runTshark(ctx context.Context, capturePath string, servers []httpsServer, displayFilter string, fields ...string) (output string, err error) {
	arguments := []string{"-n", "-r", capturePath}

	for _, server := range servers {
		arguments = append(arguments, "-d", "tcp.port=="+server.Port+",tls")
	}

	arguments = append(arguments, "-Y", displayFilter, "-T", "fields", "-E", "separator=/t")

	for _, field := range fields {
		arguments = append(arguments, "-e", field)
	}

	outputBytes, err := exec.CommandContext(ctx, tsharkPath, arguments...).Output()
	output = string(outputBytes)
	return
}

// tshark on the host reading GET /api/v1/captures/stream through adb forward
type apiStream struct {
	cancel context.CancelFunc
	tshark *exec.Cmd
	output lockedBuffer
	errors lockedBuffer
}

func (client apiClient) startStream(state *testing.T, servers []httpsServer) (stream *apiStream) {
	ctx, cancel := context.WithCancel(state.Context())
	stream = &apiStream{cancel: cancel, tshark: nil, output: newLockedBuffer(), errors: newLockedBuffer()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", client.port)+v1.BasePath+"/captures/stream", http.NoBody)

	if err != nil {
		cancel()
		state.Fatalf("Could not make the stream request, error: %s", err.Error())
	}

	// no timeout, the stream ends with the context
	response, err := (&http.Client{}).Do(request)

	if err != nil {
		cancel()
		state.Fatalf("Could not open the capture stream, error: %s", err.Error())
	}

	// tshark reads the body until the request is cancelled
	state.Cleanup(func() {
		if closeErr := response.Body.Close(); (closeErr != nil) && !errors.Is(closeErr, context.Canceled) {
			state.Errorf("Could not close the capture stream, error: %s", closeErr.Error())
		}
	})

	if (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != "application/x-pcapng") {
		cancel()
		state.Fatalf("Could not open the capture stream, status: %d, type: %s", response.StatusCode, response.Header.Get("Content-Type"))
	}

	arguments := []string{"-l", "-n", "-i", "-"}

	for _, server := range servers {
		arguments = append(arguments, "-d", "tcp.port=="+server.Port+",tls")
	}

	arguments = append(arguments, "-Y", "http.request", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.method", "-e", "http.request.uri")
	stream.tshark = exec.CommandContext(state.Context(), tsharkPath, arguments...)
	stream.tshark.Stdin = response.Body
	stream.tshark.Stdout = stream.output
	stream.tshark.Stderr = stream.errors
	stream.tshark.WaitDelay = time.Second
	err = stream.tshark.Start()

	if err != nil {
		cancel()
		state.Fatalf("Could not start tshark, error: %s", err.Error())
	}

	state.Cleanup(stream.stop)
	return
}

// the cancelled request ends tshark's input, tshark ends with it; a second call does nothing
func (stream *apiStream) stop() {
	stream.cancel()

	if stream.tshark.ProcessState == nil {
		_ = stream.tshark.Wait()
	}
}

// wait until tshark's output passes check
func (stream *apiStream) wait(ctx context.Context, check func(output string) (isFound bool)) (output string, err error) {
	outputCtx, cancel := context.WithTimeout(ctx, outputTimeout)
	defer cancel()
	err = poll(outputCtx, func() (isDone bool, pollErr error) {
		output = stream.output.String()
		isDone = check(output)
		return
	})
	return
}

// save the body of a GET to filePath, an error unless it is a 200 pcapng
func (client apiClient) download(ctx context.Context, path string, filePath string) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", client.port)+v1.BasePath+path, http.NoBody)

	if err != nil {
		return
	}

	response, err := client.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return
	}

	if (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != "application/x-pcapng") {
		err = fmt.Errorf("GET %s answered %d: %s", path, response.StatusCode, body)
		return
	}

	err = os.WriteFile(filePath, body, 0o600)
	return
}
