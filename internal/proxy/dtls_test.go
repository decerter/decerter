// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// a DTLS 1.2 session between openssl s_client and s_server recorded for the tlsrecord tests: the key log line, the datagrams in the order they were sent and one application data line each way
type dtlsFixture struct {
	keyLog       *lockedBuffer
	clientRandom [32]byte
	secrets      tlsrecord.Secrets
	datagrams    []TLSChunk
	lines        [2]string
}

// the datagrams a dtlsInterception wrote, in the order of the writes
type dtlsWrites struct {
	mutex  *sync.Mutex
	chunks []TLSChunk
	err    error
}

func (writes *dtlsWrites) writers() (writers [2]func(datagram []byte) error) {
	for index := range writers {
		writers[index] = func(datagram []byte) (err error) {
			writes.mutex.Lock()
			defer writes.mutex.Unlock()

			if err = writes.err; err != nil {
				return
			}

			writes.chunks = append(writes.chunks, TLSChunk{direction: tlsrecord.Direction(index), data: bytes.Clone(datagram)})
			return
		}
	}

	return
}

func (writes *dtlsWrites) taken() (chunks []TLSChunk) {
	writes.mutex.Lock()
	defer writes.mutex.Unlock()
	chunks = writes.chunks
	return
}

// the fixture of the AES-128-GCM session of internal/tlsrecord/testdata
func readDTLSFixture(state *testing.T) (fixture dtlsFixture) {
	content, err := os.ReadFile(filepath.Join("..", "tlsrecord", "testdata", "dtls_ecdhe_rsa_aes128_gcm_sha256.txt"))

	if err != nil {
		state.Fatalf("Test of the dtls proxy failed, cannot read fixture, error: %s", err.Error())
	}

	fixture.keyLog = newLockedBuffer()

	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)

		switch {
		case (len(fields) == 3) && (fields[0] == "CLIENT_RANDOM"):
			random, randomErr := hex.DecodeString(fields[1])
			masterKey, keyErr := hex.DecodeString(fields[2])
			_, writeErr := fixture.keyLog.Write([]byte(line))

			if err = errors.Join(randomErr, keyErr, writeErr); err != nil {
				state.Fatalf("Test of the dtls proxy failed, cannot read key log line, error: %s", err.Error())
			}

			copy(fixture.clientRandom[:], random)
			fixture.secrets = tlsrecord.Secrets{Version: tlsrecord.VersionDTLS12, MasterKey: masterKey}
		case (len(fields) == 2) && ((fields[0] == "c") || (fields[0] == "s")):
			data, dataErr := hex.DecodeString(fields[1])

			if dataErr != nil {
				state.Fatalf("Test of the dtls proxy failed, cannot read datagram, error: %s", dataErr.Error())
			}

			direction := tlsrecord.ClientDirection

			if fields[0] == "s" {
				direction = tlsrecord.ServerDirection
			}

			fixture.datagrams = append(fixture.datagrams, TLSChunk{direction: direction, data: data})
		default:
			state.Fatalf("Test of the dtls proxy failed, unexpected fixture line %q", line)
		}
	}

	fixture.lines = [2]string{"hello dtls ECDHE-RSA-AES128-GCM-SHA256\n", "hello from server ECDHE-RSA-AES128-GCM-SHA256\n"}
	return
}

// the application data of both directions of datagrams, read with the secrets of the fixture in the order given
func dtlsPlain(fixture dtlsFixture, datagrams []TLSChunk) (plain [2][]byte, err error) {
	conn := tlsrecord.NewDTLS(maxHoldBytes, false)
	records, err := conn.SetSecrets(fixture.secrets)

	for _, datagram := range datagrams {
		if err != nil {
			return
		}

		fed, feedErr := conn.Feed(datagram.direction, datagram.data)
		records = append(records, fed...)
		err = feedErr
	}

	for _, record := range records {
		if record.Decrypted && (record.ContentType == tlsrecord.ApplicationDataContentType) {
			plain[record.Direction] = append(plain[record.Direction], record.Payload...)
		}
	}

	return
}

// the bytes of each direction of datagrams
func dtlsBytes(datagrams []TLSChunk) (data [2][]byte) {
	for _, datagram := range datagrams {
		data[datagram.direction] = append(data[datagram.direction], datagram.data...)
	}

	return
}

// a dtlsInterception of a new udp session of flow 1 of recorder
func newTestDTLS(pipeline *intercept.Pipeline, recorder *history.History, logger *slog.Logger) (dtls *dtlsInterception) {
	session := &UDPSession{key: UDPSessionKey{client: testClient, cookie: 1, destination: testFlow.OriginalDestination}, flow: testFlow, interceptFlow: intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})}
	dtls = newDTLSInterception(session, pipeline, testSecretsMaps, recorder, logger)
	return
}

// the senders wrote everything they were given
func (dtls *dtlsInterception) isDrained() (isDrained bool) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()
	isDrained = (dtls.queuedBytes[0] == 0) && (dtls.queuedBytes[1] == 0) && (len(dtls.queues[0]) == 0) && (len(dtls.queues[1]) == 0)
	return
}

func (dtls *dtlsInterception) isHeld() (isHeld bool) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()
	isHeld = dtls.conn.Holding()
	return
}

// a pipeline with rules whose recorder counts the messages that went on before the rules saw them
func countingPipeline(rules []intercept.Rule) (pipeline *intercept.Pipeline, passed *atomic.Int64) {
	passed = &atomic.Int64{}
	pipeline = intercept.New(rules, nil, func(message intercept.Message, result intercept.Result, origin intercept.Origin) {
		if origin == intercept.PassedOrigin {
			passed.Add(1)
		}
	})
	return
}

// Test if proxy.dtlsInterception returns with the expected output when it intercepts: the application data goes through the rules and is sealed again,
// a record that grows is split, a dropped record is left out, a failed lookup or missing secrets relay the session raw, records that went on before late secrets are shown.
func TestDTLSInterceptPositive(state *testing.T) {
	fixture := readDTLSFixture(state)
	growth := strings.Repeat("x", 3000)
	positiveCases := []struct {
		Name      string
		Rules     []intercept.Rule
		IsReady   bool
		LookupErr error
		IsExpired bool
		IsLate    bool
		IsCorrupt bool
		Plain     [2]string
		IsRaw     bool
		Line      string
	}{
		{Name: "replace", Rules: []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}, IsReady: true, LookupErr: nil, IsExpired: false, IsLate: false, IsCorrupt: false, Plain: [2]string{"HELLO dtls ECDHE-RSA-AES128-GCM-SHA256\n", "HELLO from server ECDHE-RSA-AES128-GCM-SHA256\n"}, IsRaw: false, Line: "changed:1"},
		{Name: "split", Rules: []intercept.Rule{replaceRule{old: []byte("hello dtls"), new: []byte(growth)}}, IsReady: true, LookupErr: nil, IsExpired: false, IsLate: false, IsCorrupt: false, Plain: [2]string{growth + " ECDHE-RSA-AES128-GCM-SHA256\n", fixture.lines[1]}, IsRaw: false, Line: "split:1"},
		{Name: "drop", Rules: []intercept.Rule{dropRule{word: []byte("from server")}}, IsReady: true, LookupErr: nil, IsExpired: false, IsLate: false, IsCorrupt: false, Plain: [2]string{fixture.lines[0], ""}, IsRaw: false, Line: "dropped:1"},
		{Name: "lookup error", Rules: []intercept.Rule{intercept.IdentityRule{}}, IsReady: true, LookupErr: errTestLookup, IsExpired: false, IsLate: false, IsCorrupt: false, Plain: [2]string{fixture.lines[0], fixture.lines[1]}, IsRaw: true, Line: "sealed:0"},
		{Name: "no secrets", Rules: []intercept.Rule{intercept.IdentityRule{}}, IsReady: false, LookupErr: nil, IsExpired: true, IsLate: false, IsCorrupt: false, Plain: [2]string{fixture.lines[0], fixture.lines[1]}, IsRaw: true, Line: "sealed:0"},
		{Name: "identity", Rules: []intercept.Rule{intercept.IdentityRule{}}, IsReady: true, LookupErr: nil, IsExpired: false, IsLate: false, IsCorrupt: false, Plain: [2]string{fixture.lines[0], fixture.lines[1]}, IsRaw: false, Line: "identical:"},
		{Name: "wrong secrets", Rules: []intercept.Rule{intercept.IdentityRule{}}, IsReady: true, LookupErr: nil, IsExpired: false, IsLate: false, IsCorrupt: true, Plain: [2]string{fixture.lines[0], fixture.lines[1]}, IsRaw: true, Line: "sealed:0"},
		{Name: "late secrets", Rules: []intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}, IsReady: false, LookupErr: nil, IsExpired: false, IsLate: true, IsCorrupt: false, Plain: [2]string{fixture.lines[0], fixture.lines[1]}, IsRaw: true, Line: "passed:1"},
	}

	for _, positive := range positiveCases {
		lookup := newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, positive.IsReady)
		lookup.err = positive.LookupErr
		lookup.isCorrupt = positive.IsCorrupt
		useSecrets(state, lookup.lookup)
		pipeline, passed := countingPipeline(positive.Rules)
		logger, logs := bufferLogger()
		writes := &dtlsWrites{mutex: &sync.Mutex{}, chunks: nil, err: nil}
		var err error
		output := captureStdout(state, func() {
			dtls := newTestDTLS(pipeline, nil, logger)

			// the wait for the secrets is over before it starts
			if positive.IsExpired {
				dtls.holdDeadline = time.Now().Add(-time.Second)
			}

			dtls.start(state.Context(), writes.writers())

			// one datagram after the other, as the peers wait for each other
			for _, datagram := range fixture.datagrams {
				if !dtls.take(datagram.direction, datagram.data) {
					err = errors.Join(err, errors.New("a datagram was not taken"))
				}

				if !waitFor(dtls.isDrained) {
					err = errors.Join(err, errors.New("the senders did not write the datagram"))
				}
			}

			// the held records go on raw after the grace time, the secrets come later and show them
			if positive.IsLate {
				isReleased := waitFor(func() bool {
					return !dtls.isHeld() && dtls.isDrained() && (len(dtlsBytes(writes.taken())[tlsrecord.ServerDirection]) == len(dtlsBytes(fixture.datagrams)[tlsrecord.ServerDirection]))
				})
				lookup.ready.Store(true)
				isShown := waitFor(func() bool {
					return passed.Load() >= 2
				})

				if !isReleased || !isShown {
					err = errors.Join(err, fmt.Errorf("the late records should be released and shown, released: %v, passed: %d", isReleased, passed.Load()))
				}
			}

			dtls.close()
		})
		taken := writes.taken()
		plain, plainErr := dtlsPlain(fixture, taken)
		err = errors.Join(err, plainErr)

		if (err != nil) || (string(plain[0]) != positive.Plain[0]) || (string(plain[1]) != positive.Plain[1]) {
			state.Errorf("Test of proxy.dtlsInterception function failed, case %q, the application data should be %q, it is %q, error: %v, logs: %s", positive.Name, positive.Plain, plain, err, logs.String())
			return
		}

		written := dtlsBytes(taken)
		original := dtlsBytes(fixture.datagrams)

		if positive.IsRaw && (!bytes.Equal(written[0], original[0]) || !bytes.Equal(written[1], original[1])) {
			state.Errorf("Test of proxy.dtlsInterception function failed, case %q, the session should go on raw, logs: %s", positive.Name, logs.String())
			return
		}

		if !strings.Contains(output, "dtls pid=") || !strings.Contains(output, positive.Line) {
			state.Errorf("Test of proxy.dtlsInterception function failed, case %q, the records line should have %q, output: %q", positive.Name, positive.Line, output)
			return
		}
	}
}

// Test if proxy.dtlsInterception returns with the expected errors: a closed session and a full queue take no datagram, a datagram that can't be written is lost with a log line.
func TestDTLSInterceptNegative(state *testing.T) {
	fixture := readDTLSFixture(state)
	useSecrets(state, newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, true).lookup)
	logger, logs := bufferLogger()
	pipeline := intercept.New([]intercept.Rule{intercept.IdentityRule{}}, nil, nil)
	writes := &dtlsWrites{mutex: &sync.Mutex{}, chunks: nil, err: errors.New("test write failed")}
	output := captureStdout(state, func() {
		dtls := newTestDTLS(pipeline, nil, logger)
		dtls.start(state.Context(), writes.writers())
		isTaken := dtls.take(fixture.datagrams[0].direction, fixture.datagrams[0].data)
		isDrained := waitFor(dtls.isDrained)
		dtls.close()
		dtls.poll()

		if !isTaken || !isDrained || dtls.take(tlsrecord.ClientDirection, fixture.datagrams[0].data) {
			state.Errorf("Test of proxy.dtlsInterception.take function failed, a datagram should be taken before the close and not after it")
		}

		// a raw session without senders fills its queue
		full := newTestDTLS(pipeline, nil, logger)
		full.isRaw = true
		datagram := make([]byte, maxDatagramSize)
		count := 0

		for full.take(tlsrecord.ServerDirection, datagram) {
			count++
		}

		if count != (maxSendQueueBytes+maxDatagramSize-1)/maxDatagramSize {
			state.Errorf("Test of proxy.dtlsInterception.take function failed, the queue should take %d datagrams, it took %d", (maxSendQueueBytes+maxDatagramSize-1)/maxDatagramSize, count)
		}

		full.close()
	})

	if !strings.Contains(logs.String(), "Could not send dtls datagram") || !strings.Contains(output, "records up=") {
		state.Errorf("Test of proxy.dtlsInterception function failed, the lost datagram should be logged, logs: %s, output: %q", logs.String(), output)
		return
	}
}

// Test if proxy.dtlsInterception returns with the expected output when the record layer gives up in the middle of a datagram: the record that ended
// it and the records behind it in the same datagram go on raw too, the relay forwards the whole datagram.
func TestDTLSInterceptTailPositive(state *testing.T) {
	fixture := readDTLSFixture(state)
	useSecrets(state, newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, true).lookup)
	logger, logs := bufferLogger()
	pipeline := intercept.New([]intercept.Rule{intercept.IdentityRule{}}, nil, nil)
	writes := &dtlsWrites{mutex: &sync.Mutex{}, chunks: nil, err: nil}
	// application data in epoch 0 ends the record layer, the ClientHello behind it can't be read any more
	datagram := slices.Concat([]byte{byte(tlsrecord.ApplicationDataContentType), 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 9, 0, 5}, []byte("GET /"), fixture.datagrams[0].data)
	var isDrained bool
	_ = captureStdout(state, func() {
		dtls := newTestDTLS(pipeline, nil, logger)
		dtls.start(state.Context(), writes.writers())
		dtls.take(tlsrecord.ClientDirection, datagram)
		isDrained = waitFor(dtls.isDrained)
		dtls.close()
	})
	written := dtlsBytes(writes.taken())

	if !isDrained || !bytes.Equal(written[tlsrecord.ClientDirection], datagram) || !strings.Contains(logs.String(), "relaying raw") {
		state.Errorf("Test of proxy.dtlsInterception.take function failed, the whole datagram should go on, written: %x, datagram: %x, logs: %s", written[tlsrecord.ClientDirection], datagram, logs.String())
		return
	}
}

// Test if proxy.dtlsInterception returns with the expected output when it only observes: the application data is printed and goes into the history, also with late secrets.
func TestDTLSObservePositive(state *testing.T) {
	fixture := readDTLSFixture(state)

	for _, isLate := range []bool{false, true} {
		lookup := newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, !isLate)
		useSecrets(state, lookup.lookup)
		recorder := history.New(history.DefaultLimits(), nil)
		recorder.OpenFlow(1, filter.Values{}, fixture.clientRandom)
		logger, logs := bufferLogger()
		output := captureStdout(state, func() {
			dtls := newTestDTLS(nil, recorder, logger)

			for _, datagram := range fixture.datagrams {
				dtls.observe(datagram.direction, datagram.data)
			}

			if isLate {
				lookup.ready.Store(true)
			}

			waitFor(func() bool {
				payloads, _ := historyPayloads(recorder, 1)
				return len(payloads[tlsrecord.ServerDirection]) != 0
			})
			dtls.close()
			dtls.observe(tlsrecord.ClientDirection, fixture.datagrams[0].data)
		})
		payloads, _ := historyPayloads(recorder, 1)

		if (string(payloads[0]) != fixture.lines[0]) || (string(payloads[1]) != fixture.lines[1]) || (strings.Count(output, "sni=") != 1) || !strings.Contains(output, "dtls pid=") {
			state.Errorf("Test of proxy.dtlsInterception.observe function failed, late %v, the lines should be in the history and the output, payloads: %q, output: %q, logs: %s", isLate, payloads, output, logs.String())
			return
		}
	}
}

// Test if proxy.dtlsInterception returns with the expected errors when it only observes: a failed lookup and missing secrets end the decryption with a warning.
func TestDTLSObserveNegative(state *testing.T) {
	fixture := readDTLSFixture(state)

	for _, isExpired := range []bool{false, true} {
		lookup := newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, false)
		warning := ErrNoSecrets.Error()

		if !isExpired {
			lookup.err = errTestLookup
			warning = errTestLookup.Error()
		}

		useSecrets(state, lookup.lookup)
		logger, logs := bufferLogger()
		output := captureStdout(state, func() {
			dtls := newTestDTLS(nil, nil, logger)
			dtls.holdDeadline = time.Now().Add(-time.Second)

			for _, datagram := range fixture.datagrams {
				dtls.observe(datagram.direction, datagram.data)
			}

			waitFor(func() bool {
				return strings.Contains(logs.String(), warning)
			})
			dtls.close()
		})

		if (output != "") || !strings.Contains(logs.String(), "Could not decrypt dtls session") || !strings.Contains(logs.String(), warning) {
			state.Errorf("Test of proxy.dtlsInterception.observe function failed, the warning should be %q, output: %q, logs: %s", warning, output, logs.String())
			return
		}
	}
}

// Test if proxy.datagramLimits returns with the expected output: the records of one datagram share its bytes, a raw datagram stands alone.
func TestDatagramLimitsPositive(state *testing.T) {
	items := []dtlsItem{
		{datagram: nil, record: tlsrecord.Record{Datagram: 1, Raw: make([]byte, 900)}, session: tlsrecord.Session{}},
		{datagram: nil, record: tlsrecord.Record{Datagram: 1, Raw: make([]byte, 900)}, session: tlsrecord.Session{}},
		{datagram: []byte("raw"), record: tlsrecord.Record{}, session: tlsrecord.Session{}},
		{datagram: nil, record: tlsrecord.Record{Datagram: 2, Raw: make([]byte, 10)}, session: tlsrecord.Session{}},
	}
	limits := datagramLimits(items)
	expected := []int{1800, 1800, tlsrecord.MinDatagramLength, tlsrecord.MinDatagramLength}

	for index := range expected {
		if limits[index] != expected[index] {
			state.Errorf("Test of proxy.datagramLimits function failed, limits should be %v, limits: %v", expected, limits)
			return
		}
	}
}
