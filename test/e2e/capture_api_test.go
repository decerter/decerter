// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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
	"sync"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the body of the bulk server, more than a stream that is not read may fall behind
	bulkBytes int = 64 << 20
	// curl reads the bulk body at this rate, so packet_map keeps up
	bulkRate string = "40M"
	// how long a stream that is not read may take to be cut off and closed, its last write waits for the write timeout of the api
	slowStreamEnd time.Duration = 30 * time.Second
	// how long tshark may take to print a request of the live stream
	streamArrival time.Duration = 15 * time.Second
)

// Test if a capture started and stopped over the API of decerter capture downloads as a file tshark decrypts, with only the flows of its filter, while the -w file of the same decerter has every flow and a stream that is never read is cut off without stalling either.
func TestCaptureAPIPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	directory := state.TempDir()
	filePath := filepath.Join(directory, "all.pcapng")
	client, stop := startCaptureAPIDecerter(state, filePath)
	captured := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13})
	other := startServer(state, serverConfig{Certificate: &ecdsaCertificate, Version: tls.VersionTLS12})
	bulk := startBulkServer(state)
	capturedPort := serverPort(state, captured)
	otherPort := serverPort(state, other)
	started := v1.Capture{}
	status, err := client.call(state.Context(), http.MethodPost, "/captures", v1.CaptureRequest{Filter: "tcp.dstport == " + capturedPort, Plaintext: false}, &started)

	if (err != nil) || (status != http.StatusCreated) || (started.State != v1.RunningCaptureState) || (started.Format != v1.DSBCaptureFormat) {
		state.Fatalf("Test of the capture api failed, cannot start a capture, status: %d, capture: %+v, error: %v", status, started, err)
	}

	// a running capture is not downloaded
	status, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/captures/%d/pcap", started.ID), nil, nil)

	if (err != nil) || (status != http.StatusConflict) {
		state.Errorf("Test of the capture api failed, a running capture should answer 409, status: %d, error: %v", status, err)
		return
	}

	slowStream := openSlowStream(state, client.socket)

	for index, server := range []testServer{captured, other} {
		testCase := curlCase{Name: server.URL, Server: serverConfig{Certificate: []*certificate{&rsaCertificate, &ecdsaCertificate}[index]}, Suite: "", Expected: receivedRequest{}}
		output, curlErr := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL))

		if (curlErr != nil) || (output != "/") {
			state.Fatalf("Test of the capture api failed, capture mode should change nothing, output: %q, error: %v", output, curlErr)
		}
	}

	// the bulk body runs past the queue of the stream nobody reads, the capture and the -w file go on
	start := time.Now()
	_, err = runCurl(state.Context(), testUser, []string{"--limit-rate", bulkRate, "--output", "/dev/null", bulk})

	if err != nil {
		state.Fatalf("Test of the capture api failed, the bulk download should finish, error: %s", err.Error())
	}

	state.Logf("bulk download of %d MiB took %s", bulkBytes>>20, time.Since(start))
	stopped := v1.Capture{}
	status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/captures/%d/stop", started.ID), nil, &stopped)

	if (err != nil) || (status != http.StatusOK) || (stopped.State != v1.StoppedCaptureState) || (stopped.Size == 0) || (stopped.DroppedPackets != 0) {
		state.Fatalf("Test of the capture api failed, the capture should stop with its file and no lost packet, status: %d, capture: %+v, error: %v", status, stopped, err)
	}

	downloadPath := filepath.Join(directory, "download.pcapng")
	err = client.download(state.Context(), fmt.Sprintf("/captures/%d/pcap", started.ID), downloadPath)

	if err != nil {
		state.Fatalf("Test of the capture api failed, cannot download the capture, error: %s", err.Error())
	}

	// the capture has the decrypted request of its port and nothing of the other servers
	err = testTshark(state.Context(), tsharkPath, downloadPath, []capturedCall{{Name: "captured", Port: capturedPort, IsTLS: true, IsHTTP2: false}}, false)

	if err != nil {
		state.Errorf("Test of the capture api failed, error: %s", err.Error())
		return
	}

	ports, err := capturedPorts(state.Context(), tsharkPath, downloadPath)

	if (err != nil) || ports[otherPort] || ports[serverPortOf(testServer{URL: bulk})] {
		state.Errorf("Test of the capture api failed, the capture should only have port %s, ports: %v, error: %v", capturedPort, ports, err)
		return
	}

	err = slowStream.waitEnd()

	if err != nil {
		state.Errorf("Test of the capture api failed, the stream that is not read should be cut off, error: %s", err.Error())
		return
	}

	list := v1.CaptureList{}
	status, err = client.call(state.Context(), http.MethodGet, "/captures", nil, &list)

	if (err != nil) || (status != http.StatusOK) || (len(list.Captures) != 1) || (list.Captures[0].Size != stopped.Size) {
		state.Errorf("Test of the capture api failed, the list should have the stopped capture, list: %+v, error: %v", list, err)
		return
	}

	// the -w file of the same decerter has both TLS calls
	err = stop()

	if err != nil {
		state.Fatalf("Could not stop decerter, error: %s", err.Error())
	}

	// the file has the bulk body too: its port is decoded as data, or tshark reassembles all of it as one HTTP response, which takes a slow host longer than its timeout
	start = time.Now()
	err = testTshark(state.Context(), tsharkPath, filePath, []capturedCall{{Name: "captured", Port: capturedPort, IsTLS: true, IsHTTP2: false}, {Name: "other", Port: otherPort, IsTLS: true, IsHTTP2: false}}, false, serverPortOf(testServer{URL: bulk}))
	state.Logf("tshark read the -w file in %s", time.Since(start))

	if err != nil {
		state.Errorf("Test of the capture api failed, the -w file should have both calls, error: %s", err.Error())
		return
	}

	// the files of the captures go with decerter
	if entries, readErr := os.ReadDir("/run/decerter/captures"); !errors.Is(readErr, os.ErrNotExist) {
		state.Errorf("Test of the capture api failed, the captures should be removed when decerter stops, entries: %v, error: %v", entries, readErr)
		return
	}
}

// Test if curl -N on the capture stream piped into tshark shows curl's requests live, decrypted: one of a TLS session that was open before the stream started and one that starts after it; and if the plaintext stream comes through decerter ui.
func TestCaptureAPIStreamPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	client, _ := startCaptureAPIDecerter(state, "")
	server := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13})
	port := serverPort(state, server)
	early := startTLSClient(state, port)
	live := startStreamReader(state, tsharkPath, client.socket, port)
	_, err := io.WriteString(early.stdin, "GET /early HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

	if err != nil {
		state.Fatalf("Test of the capture stream failed, cannot send the request of the open session, error: %s", err.Error())
	}

	testCase := curlCase{Name: server.URL, Server: serverConfig{Certificate: &rsaCertificate}, Suite: "", Expected: receivedRequest{}}
	output, err := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL+"late"))

	if (err != nil) || (output != "/late") {
		state.Fatalf("Test of the capture stream failed, curl should get /late, output: %q, error: %v", output, err)
	}

	found := live.waitFor(func(text string) bool {
		return strings.Contains(text, port+"\t/early") && strings.Contains(text, port+"\t/late")
	})

	if !found {
		state.Errorf("Test of the capture stream failed, tshark should show /early and /late to port %s, output:\n%s\nerrors:\n%s", port, live.output.String(), live.errors.String())
		return
	}

	// the plaintext stream through decerter ui: the reverse proxy hands it on unbuffered
	browser := startUI(state, client.socket)
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	request, err := browser.request(ctx, http.MethodGet, "/api/v1/captures/stream?plaintext=true", nil)

	if err != nil {
		state.Fatalf("Test of the capture stream failed, cannot make the ui request, error: %s", err.Error())
	}

	response, err := browser.client.Do(request)

	if err != nil {
		state.Fatalf("Test of the capture stream failed, cannot open the stream through the ui, error: %s", err.Error())
	}

	defer func() {
		if closeErr := response.Body.Close(); (closeErr != nil) && !errors.Is(closeErr, context.Canceled) {
			state.Errorf("Test of the capture stream failed, cannot close the ui stream, error: %s", closeErr.Error())
		}
	}()

	viaUI := make(chan bool, 1)

	// the reader of the ui stream: the synthesized packets carry the request as text
	go func() {
		viaUI <- readUntil(response.Body, []byte("GET /viaui HTTP/1.1"))
	}()

	// the stream is subscribed once its first blocks are through
	time.Sleep(500 * time.Millisecond)
	output, err = runCurl(state.Context(), testUser, curlArguments(testCase, server.URL+"viaui"))

	if (err != nil) || (output != "/viaui") || (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != "application/x-pcapng") {
		state.Fatalf("Test of the capture stream failed, curl should get /viaui through the ui stream, status: %d, output: %q, error: %v", response.StatusCode, output, err)
	}

	select {
	case isFound := <-viaUI:
		if !isFound {
			state.Errorf("Test of the capture stream failed, the plaintext stream through the ui should carry GET /viaui")
			return
		}
	case <-time.After(streamArrival):
		state.Errorf("Test of the capture stream failed, the plaintext stream through the ui did not carry GET /viaui in %s", streamArrival)
		return
	}
}

// Test if GET /flows/pcap?format=plaintext of decerter run shows the request as a rule edited it, GET /test, from the history: the app's side, with a comment on the change.
func TestAPIExportPcapPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	client := startRewriteDecerter(state)
	server := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13})
	port := serverPort(state, server)
	testCase := curlCase{Name: server.URL, Server: serverConfig{Certificate: &rsaCertificate}, Suite: "", Expected: receivedRequest{}}
	output, err := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL))

	if (err != nil) || (output != "/test") {
		state.Fatalf("Test of the pcap export failed, the rule should edit the request, output: %q, error: %v", output, err)
	}

	exportPath := filepath.Join(state.TempDir(), "flows.pcapng")
	err = client.download(state.Context(), "/flows/pcap?format=plaintext&filter="+url.QueryEscape("tcp.dstport == "+port), exportPath)

	if err != nil {
		state.Fatalf("Test of the pcap export failed, cannot export, error: %s", err.Error())
	}

	tsharkOutput, err := runCommand(state.Context(), tsharkPath, "-n", "-r", exportPath, "-d", "tcp.port=="+port+",http", "-Y", "http.request", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.uri", "-e", "frame.comment")

	if (err != nil) || !strings.Contains(tsharkOutput, port+"\t/test") || !strings.Contains(tsharkOutput, "was changed") {
		state.Errorf("Test of the pcap export failed, tshark should find GET /test to port %s with a comment on the change, output:\n%s\nerror: %v", port, tsharkOutput, err)
		return
	}
}

// Test if decerter run --intercept with the API captures the wire side: a capture started over the API, the live stream and GET /flows/pcap?format=dsb show the edited GET /test to the real server address, decrypted by tshark, for TLS 1.3 and TLS 1.2, and a capture with a process filter has only the flow it takes.
func TestRunCaptureAPIPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	client := startRewriteDecerter(state)
	tls13 := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13})
	tls12 := startServer(state, serverConfig{Certificate: &ecdsaCertificate, Version: tls.VersionTLS12})
	port13 := serverPort(state, tls13)
	port12 := serverPort(state, tls12)
	started := v1.Capture{}
	status, err := client.call(state.Context(), http.MethodPost, "/captures", nil, &started)

	if (err != nil) || (status != http.StatusCreated) || (started.Format != v1.DSBCaptureFormat) {
		state.Fatalf("Test of the run mode capture failed, cannot start a capture, status: %d, capture: %+v, error: %v", status, started, err)
	}

	// the process fields come from the app's flow, the upstream socket is decerter's own
	filtered := v1.Capture{}
	status, err = client.call(state.Context(), http.MethodPost, "/captures", v1.CaptureRequest{Filter: fmt.Sprintf("proc.uid == %d && proc.comm == \"curl\" && tcp.dstport == %s", testUser.UID, port13), Plaintext: false}, &filtered)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the run mode capture failed, cannot start the filtered capture, status: %d, error: %v", status, err)
	}

	live := startStreamReader(state, tsharkPath, client.socket, port13, port12)

	for index, server := range []testServer{tls13, tls12} {
		testCase := curlCase{Name: server.URL, Server: serverConfig{Certificate: []*certificate{&rsaCertificate, &ecdsaCertificate}[index]}, Suite: "", Expected: receivedRequest{}}
		output, curlErr := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL))

		if (curlErr != nil) || (output != "/test") {
			state.Fatalf("Test of the run mode capture failed, the rule should edit the request to %s, output: %q, error: %v", server.URL, output, curlErr)
		}
	}

	found := live.waitFor(func(text string) bool {
		return strings.Contains(text, port13+"\t/test") && strings.Contains(text, port12+"\t/test")
	})

	if !found {
		state.Errorf("Test of the run mode capture failed, the live stream should show GET /test to ports %s and %s, output:\n%s\nerrors:\n%s", port13, port12, live.output.String(), live.errors.String())
		return
	}

	directory := state.TempDir()
	paths := map[string]string{}

	for name, capture := range map[string]v1.Capture{"all": started, "filtered": filtered} {
		status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/captures/%d/stop", capture.ID), nil, nil)

		if (err != nil) || (status != http.StatusOK) {
			state.Fatalf("Test of the run mode capture failed, cannot stop the %s capture, status: %d, error: %v", name, status, err)
		}

		paths[name] = filepath.Join(directory, name+".pcapng")
		err = client.download(state.Context(), fmt.Sprintf("/captures/%d/pcap", capture.ID), paths[name])

		if err != nil {
			state.Fatalf("Test of the run mode capture failed, cannot download the %s capture, error: %s", name, err.Error())
		}
	}

	paths["export"] = filepath.Join(directory, "export.pcapng")
	err = client.download(state.Context(), "/flows/pcap?format=dsb", paths["export"])

	if err != nil {
		state.Fatalf("Test of the run mode capture failed, cannot export the flows with format=dsb, error: %s", err.Error())
	}

	// the capture, the dsb export and the filtered capture have the edited requests on the wire, decrypted with their DSB
	expected := map[string][]string{"all": {port13, port12}, "export": {port13, port12}, "filtered": {port13}}

	for name, ports := range expected {
		requests, tsharkErr := wireRequests(state.Context(), tsharkPath, paths[name], port13, port12)

		if tsharkErr != nil {
			state.Fatalf("Test of the run mode capture failed, cannot read the %s file, error: %s", name, tsharkErr.Error())
		}

		for _, port := range []string{port13, port12} {
			if requests[port+"\t/test"] != slices.Contains(ports, port) {
				state.Errorf("Test of the run mode capture failed, the %s file should have GET /test to port %s: %v, requests: %v", name, port, slices.Contains(ports, port), requests)
				return
			}
		}
	}
}

// Test if the capture of decerter run returns with the expected output for what it must not have: the app's loopback packets to the proxy, a flow of a user decerter does not select, and with a process filter that takes no flow nothing.
func TestRunCaptureAPINegative(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	client := startRewriteDecerter(state)
	server := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13})
	port := serverPort(state, server)
	captures := map[string]v1.CaptureRequest{"all": {Filter: "", Plaintext: false}, "none": {Filter: "proc.comm == \"wget\"", Plaintext: false}}
	started := map[string]v1.Capture{}

	for name, request := range captures {
		capture := v1.Capture{}
		status, err := client.call(state.Context(), http.MethodPost, "/captures", request, &capture)

		if (err != nil) || (status != http.StatusCreated) {
			state.Fatalf("Test of the run mode capture failed, cannot start the %s capture, status: %d, error: %v", name, status, err)
		}

		started[name] = capture
	}

	testCase := curlCase{Name: server.URL, Server: serverConfig{Certificate: &rsaCertificate}, Suite: "", Expected: receivedRequest{}}

	for runAs, expected := range map[account]string{testUser: "/test", otherUser: "/"} {
		output, err := runCurl(state.Context(), runAs, curlArguments(testCase, server.URL))

		if (err != nil) || (output != expected) {
			state.Fatalf("Test of the run mode capture failed, curl as %s should get %s, output: %q, error: %v", runAs.Name, expected, output, err)
		}
	}

	directory := state.TempDir()

	for name, capture := range started {
		status, err := client.call(state.Context(), http.MethodPost, fmt.Sprintf("/captures/%d/stop", capture.ID), nil, nil)

		if (err != nil) || (status != http.StatusOK) {
			state.Fatalf("Test of the run mode capture failed, cannot stop the %s capture, status: %d, error: %v", name, status, err)
		}

		path := filepath.Join(directory, name+".pcapng")
		err = client.download(state.Context(), fmt.Sprintf("/captures/%d/pcap", capture.ID), path)

		if err != nil {
			state.Fatalf("Test of the run mode capture failed, cannot download the %s capture, error: %s", name, err.Error())
		}

		// one SYN to the server: the proxy's upstream connection of the test user, nobody's direct connection is not proxied and not captured
		syns, tsharkErr := runCommand(state.Context(), tsharkPath, "-n", "-r", path, "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "-T", "fields", "-e", "tcp.dstport")

		if tsharkErr != nil {
			state.Fatalf("Test of the run mode capture failed, cannot read the %s capture, error: %s", name, tsharkErr.Error())
		}

		ports, tsharkErr := capturedPorts(state.Context(), tsharkPath, path)

		if tsharkErr != nil {
			state.Fatalf("Test of the run mode capture failed, cannot read the %s capture, error: %s", name, tsharkErr.Error())
		}

		expectedSyns := port + "\n"

		if name == "none" {
			expectedSyns = ""
		}

		if (syns != expectedSyns) || ports[strconv.Itoa(int(proxyPort))] || ((name == "none") && (len(ports) != 0)) {
			state.Errorf("Test of the run mode capture failed, the %s capture should have %q as SYNs and no packet of the proxy port %d, syns: %q, ports: %v", name, expectedSyns, proxyPort, syns, ports)
			return
		}
	}

	// a capture that does not exist
	status, err := client.call(state.Context(), http.MethodPost, "/captures/99/stop", nil, nil)

	if (err != nil) || (status != http.StatusNotFound) {
		state.Errorf("Test of the run mode capture failed, stopping a capture that does not exist should answer 404, status: %d, error: %v", status, err)
		return
	}
}

// decerter run --intercept with the API and a rule of the API that rewrites GET / to GET /test in TLS records
func startRewriteDecerter(state *testing.T) (client apiClient) {
	client = startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Could not add the rewrite rule, status: %d, error: %v", status, err)
	}

	return
}

// the HTTP requests tshark decrypts in a capture of the TLS servers on ports, as "port\turi"
func wireRequests(ctx context.Context, tsharkPath string, capturePath string, ports ...string) (requests map[string]bool, err error) {
	arguments := []string{"-n", "-r", capturePath}

	for _, port := range ports {
		arguments = append(arguments, "-d", "tcp.port=="+port+",tls")
	}

	arguments = append(arguments, "-Y", "http.request", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.uri")
	output, runErr := runCommand(ctx, tsharkPath, arguments...)

	if err = runErr; err != nil {
		return
	}

	requests = map[string]bool{}

	for line := range strings.Lines(output) {
		requests[strings.TrimRight(line, "\n")] = true
	}

	return
}

// decerter capture with the API on a socket of the test and capturePath as its -w file, empty is none
func startCaptureAPIDecerter(state *testing.T, capturePath string) (client apiClient, stop func() error) {
	socket := filepath.Join(state.TempDir(), "api.sock")
	decerter := newAPIDecerter(state, CaptureDecerterMode, capturePath, nil, testFlags(), "", socket)
	stop = startApp(state, &decerter, CaptureDecerterMode)
	client = apiClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
		socket: socket,
	}
	return
}

// save the body of a GET to path, an error unless it is 200
func (client apiClient) download(ctx context.Context, path string, filePath string) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+v1.HostName+v1.BasePath+path, http.NoBody)

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
		err = fmt.Errorf("GET %s answered %d %s: %s", path, response.StatusCode, response.Header.Get("Content-Type"), body)
		return
	}

	err = os.WriteFile(filePath, body, 0o600)
	return
}

// a plain HTTP server on loopback that answers every request with bulkBytes of zeros, url is its address
func startBulkServer(state *testing.T) (address string) {
	listener, err := net.Listen("tcp", net.JoinHostPort(destinationPrefix.Addr().String(), "0"))

	if err != nil {
		state.Fatalf("Could not listen for the bulk server, error: %s", err.Error())
	}

	body := make([]byte, bulkBytes)
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write(body)
		}),
		ReadHeaderTimeout: commandTimeout,
	}
	serveErrChannel := make(chan error, 1)

	// bulk server
	go func() {
		serveErrChannel <- httpServer.Serve(listener)
	}()

	state.Cleanup(func() {
		closeErr := httpServer.Close()

		if serveErr := <-serveErrChannel; !errors.Is(serveErr, http.ErrServerClosed) {
			closeErr = errors.Join(closeErr, serveErr)
		}

		if closeErr != nil {
			state.Errorf("Could not close the bulk server, error: %s", closeErr.Error())
		}
	})

	address = "http://" + listener.Addr().String() + "/"
	return
}

// a client of the capture stream that sends its request and reads nothing until waitEnd
type slowStream struct {
	connection net.Conn
}

func openSlowStream(state *testing.T, socket string) (stream slowStream) {
	connection, err := net.Dial("unix", socket)

	if err != nil {
		state.Fatalf("Could not connect the slow stream, error: %s", err.Error())
	}

	state.Cleanup(func() {
		_ = connection.Close()
	})

	_, err = io.WriteString(connection, "GET "+v1.BasePath+"/captures/stream HTTP/1.1\r\nHost: "+v1.HostName+"\r\n\r\n")

	if err != nil {
		state.Fatalf("Could not request the slow stream, error: %s", err.Error())
	}

	stream = slowStream{connection: connection}
	return
}

// read what the server still sends, the stream must end: the server cut it off, the response ends after the last whole block
func (stream slowStream) waitEnd() (err error) {
	err = stream.connection.SetReadDeadline(time.Now().Add(slowStreamEnd))

	if err != nil {
		return
	}

	response, err := http.ReadResponse(bufio.NewReader(stream.connection), nil)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	_, err = io.Copy(io.Discard, response.Body)

	if err != nil {
		err = fmt.Errorf("the stream did not end in %s: %w", slowStreamEnd, err)
		return
	}

	if (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != "application/x-pcapng") {
		err = fmt.Errorf("the stream answered %d %s", response.StatusCode, response.Header.Get("Content-Type"))
	}

	return
}

// openssl s_client as the test user with a TLS session to port that waits for its request on stdin
type tlsClient struct {
	stdin io.WriteCloser
}

func startTLSClient(state *testing.T, port string) (client tlsClient) {
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, "openssl", "s_client", "-connect", net.JoinHostPort(destinationPrefix.Addr().String(), port), "-tls1_3", "-quiet")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUser.UID, Gid: testUser.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	output := &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	command.Stdout = output
	command.Stderr = output
	stdin, err := command.StdinPipe()

	if err != nil {
		cancel()
		state.Fatalf("Could not make the stdin of s_client, error: %s", err.Error())
	}

	err = command.Start()

	if err != nil {
		cancel()
		state.Fatalf("Could not start s_client, error: %s", err.Error())
	}

	state.Cleanup(func() {
		cancel()
		_ = command.Wait()
	})

	// the session is open once the handshake is through, s_client -quiet prints the verify result then
	deadline := time.Now().Add(commandTimeout)

	for !strings.Contains(output.String(), "verify") {
		if time.Now().After(deadline) {
			state.Fatalf("s_client did not finish its handshake, output:\n%s", output.String())
		}

		time.Sleep(20 * time.Millisecond)
	}

	client = tlsClient{stdin: stdin}
	return
}

// curl -N on the capture stream piped into tshark, which prints the port and path of every HTTP request it decrypts
type streamReader struct {
	output *lockedBuffer
	errors *lockedBuffer
}

func startStreamReader(state *testing.T, tsharkPath string, socket string, ports ...string) (reader streamReader) {
	ctx, cancel := context.WithCancel(context.Background())
	var decodeAs strings.Builder

	for _, port := range ports {
		decodeAs.WriteString(" -d tcp.port==" + port + ",tls")
	}

	pipeline := fmt.Sprintf("curl -sN --unix-socket %s http://%s%s/captures/stream | %s -l -n -i -%s -Y http.request -T fields -e tcp.dstport -e http.request.uri", socket, v1.HostName, v1.BasePath, tsharkPath, decodeAs.String())
	command := exec.CommandContext(ctx, "sh", "-c", pipeline)
	// the pipeline is its own process group, so its tshark and curl go when the test ends
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		return syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	}
	command.WaitDelay = 2 * time.Second
	reader = streamReader{output: &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}, errors: &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}}
	command.Stdout = reader.output
	command.Stderr = reader.errors
	err := command.Start()

	if err != nil {
		cancel()
		state.Fatalf("Could not start the stream reader, error: %s", err.Error())
	}

	state.Cleanup(func() {
		cancel()
		_ = command.Wait()
	})

	// tshark reads the stream once it printed this
	isReady := reader.waitFor(func(text string) bool {
		return strings.Contains(reader.errors.String(), "Capturing on")
	})

	if !isReady {
		state.Fatalf("tshark did not start reading the stream, errors:\n%s", reader.errors.String())
	}

	return
}

// look at what tshark printed until check is true or streamArrival passed
func (reader streamReader) waitFor(check func(text string) bool) (isFound bool) {
	deadline := time.Now().Add(streamArrival)

	for time.Now().Before(deadline) {
		if check(reader.output.String()) {
			isFound = true
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	return
}

// read the stream until it carries expected, false when it ends first
func readUntil(stream io.Reader, expected []byte) (isFound bool) {
	reader := bufio.NewReaderSize(stream, 1<<16)
	window := []byte{}
	buffer := make([]byte, 1<<16)

	for {
		count, err := reader.Read(buffer)
		window = append(window, buffer[:count]...)

		if bytes.Contains(window, expected) {
			isFound = true
			return
		}

		// what is kept can still hold the start of expected
		if len(window) > len(expected) {
			window = window[len(window)-len(expected):]
		}

		if err != nil {
			return
		}
	}
}
