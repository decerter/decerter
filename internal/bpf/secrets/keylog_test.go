// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit && (amd64 || arm64)

package secrets

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// a writer that always fails
type failingWriter struct{}

func (writer failingWriter) Write(data []byte) (length int, err error) {
	err = errors.New("write failed")
	return
}

// the records and errors a ringbuf read returns one after the other, ErrClosed after the last one
func reads(state *testing.T, results ...any) (read func() (ringbuf.Record, error), calls *int) {
	calls = new(int)
	read = func() (record ringbuf.Record, err error) {
		*calls++

		if *calls > len(results) {
			err = ringbuf.ErrClosed
			return
		}

		switch result := results[*calls-1].(type) {
		case error:
			err = result
		case bpfTlsSecrets:
			buffer := bytes.Buffer{}
			writeErr := binary.Write(&buffer, binary.NativeEndian, result)

			if writeErr != nil {
				state.Errorf("Could not encode secrets event, error: %s", writeErr.Error())
			}

			record.RawSample = buffer.Bytes()
		default:
			state.Errorf("Unknown read result %T", result)
		}

		return
	}
	return
}

// run readKeyLog with a deadline, a loop that never returns fails the test instead of hanging it
func runReadKeyLog(state *testing.T, ctx context.Context, read func() (ringbuf.Record, error), writer io.Writer) (err error) {
	logs := bytes.Buffer{}
	doneChannel := make(chan error, 1)

	// key log reader
	go func() {
		doneChannel <- readKeyLog(ctx, read, time.Millisecond, writer, slog.New(slog.NewTextHandler(&logs, nil)))
	}()

	select {
	case err = <-doneChannel:
	case <-time.After(5 * time.Second):
		state.Fatalf("Test of secrets.readKeyLog failed, the loop should end, logs:\n%s", logs.String())
	}

	return
}

// Test if secrets.readKeyLog returns with the expected output: failed reads between good ones are retried and the count starts again after a good
// one, every session is printed and a closed ring ends the loop without an error.
func TestReadKeyLogPositive(state *testing.T) {
	failure := errors.New("epoll wait failed")
	results := []any{entry(tls12Version, 0x0300c02f, 0)}

	for range readFailures - 1 {
		results = append(results, failure)
	}

	results = append(results, entry(dtls12Version, 0x0300c02b, 0))

	for range readFailures - 1 {
		results = append(results, failure)
	}

	read, calls := reads(state, results...)
	output := bytes.Buffer{}
	err := runReadKeyLog(state, context.Background(), read, &output)

	if (err != nil) || (*calls != len(results)+1) || (strings.Count(output.String(), "CLIENT_RANDOM ") != 2) {
		state.Errorf("Test of secrets.readKeyLog failed, both sessions should be printed and the closed ring end the loop, calls: %d, output: %q, error: %v", *calls, output.String(), err)
		return
	}
}

// Test if secrets.readKeyLog returns with the expected errors: a ring that keeps failing ends the loop after readFailures reads with ErrRingbufRead
// instead of spinning, a cancelled context ends the backoff, and a failed write ends the loop with its error.
func TestReadKeyLogNegative(state *testing.T) {
	failure := errors.New("epoll wait failed")
	failures := []any{}

	for range 100 {
		failures = append(failures, failure)
	}

	read, calls := reads(state, failures...)
	err := runReadKeyLog(state, context.Background(), read, io.Discard)

	if !errors.Is(err, ErrRingbufRead) || !errors.Is(err, failure) || (*calls != readFailures) {
		state.Errorf("Test of secrets.readKeyLog failed, a ring that keeps failing should end the loop, calls: %d, error: %v", *calls, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	read, calls = reads(state, failures...)
	err = runReadKeyLog(state, ctx, read, io.Discard)

	if (err != nil) || (*calls != 1) {
		state.Errorf("Test of secrets.readKeyLog failed, a cancelled context should end the backoff, calls: %d, error: %v", *calls, err)
		return
	}

	read, _ = reads(state, entry(tls12Version, 0x0300c02f, 0), entry(tls12Version, 0x0300c02f, 0))
	err = runReadKeyLog(state, context.Background(), read, failingWriter{})

	if (err == nil) || (err.Error() != "write failed") {
		state.Errorf("Test of secrets.readKeyLog failed, a failed write should end the loop, error: %v", err)
		return
	}
}
