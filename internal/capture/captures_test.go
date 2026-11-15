// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
)

// the captures of a hub of the tests in a new data directory that does not exist yet
func testCaptures(state *testing.T) (captures *Captures, hub *Hub, dataDirectory string) {
	hub = testHub(state, false)
	dataDirectory = filepath.Join(state.TempDir(), "data")
	captures, err := NewCaptures(hub, dataDirectory, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.NewCaptures failed, error: %s", err.Error())
	}

	return
}

// the views of the captures by their id
func viewsOf(captures *Captures) (views map[uint64]api.Capture) {
	views = map[uint64]api.Capture{}

	for _, view := range captures.List() {
		views[view.ID] = view
	}

	return
}

// Test if capture.Captures starts, lists, stops and opens the captures of the API: each one writes the packets of the hub into its own file, which is removed when decerter stops, a capture that still runs then is stopped by the shutdown.
func TestCapturesPositive(state *testing.T) {
	captures, hub, dataDirectory := testCaptures(state)
	scope, err := filter.Parse("tcp")

	if err != nil {
		state.Fatalf("Test of capture.Captures failed, cannot parse filter, error: %s", err.Error())
	}

	first, err := captures.Start(nil, false)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Start failed, error: %s", err.Error())
	}

	second, err := captures.Start(&scope, true)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Start failed, error: %s", err.Error())
	}

	if (first.ID != 1) || (first.Format != api.DSBCaptureFormat) || (first.Filter != "") || (second.ID != 2) || (second.Format != api.PlaintextCaptureFormat) || (second.Filter != scope.String()) || (first.State != api.RunningCaptureState) {
		state.Fatalf("Test of capture.Captures.Start failed, the captures should be 1 with DSBs and 2 plaintext with its filter, views: %+v, %+v", first, second)
	}

	status := captures.Status()

	if !status.Available || (status.Running != 2) || (status.Stored != 2) || (status.Size <= 0) || (status.Limits.Captures != MaxCaptures) || (len(captures.List()) != 2) {
		state.Fatalf("Test of capture.Captures.Status failed, two captures should run, status: %+v", status)
	}

	_, _, err = captures.Open(first.ID)

	if !errors.Is(err, ErrCaptureRunning) {
		state.Fatalf("Test of capture.Captures.Open failed, error should be %v, error: %v", ErrCaptureRunning, err)
	}

	packets := testFlow(1, hubClient, hubServer, "GET /capture HTTP/1.1\r\n\r\n")

	for _, packet := range packets {
		hub.offerAll(packet)
	}

	stopped, err := captures.Stop(first.ID)

	if (err != nil) || (stopped.State != api.StoppedCaptureState) || (stopped.Reason != "") || (stopped.Stopped.IsZero()) {
		state.Fatalf("Test of capture.Captures.Stop failed, the capture should be stopped without a reason, view: %+v, error: %v", stopped, err)
	}

	// a stopped capture is left as it is
	again, err := captures.Stop(first.ID)

	if (err != nil) || (again != stopped) {
		state.Fatalf("Test of capture.Captures.Stop failed, a second stop should give the same view, view: %+v, error: %v", again, err)
	}

	file, view, err := captures.Open(first.ID)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Open failed, error: %s", err.Error())
	}

	content, readErr := io.ReadAll(file)
	err = errors.Join(readErr, file.Close())
	blocks, blocksErr := readBlocks(content)
	written, _, _ := capturedOf(blocks)

	if (errors.Join(err, blocksErr) != nil) || (view.Size != int64(len(content))) || !slices.EqualFunc(written, dataOf(packets), bytes.Equal) {
		state.Fatalf("Test of capture.Captures.Open failed, the file of %d bytes should have the %d packets, file: %d bytes, packets: %d, error: %v", view.Size, len(packets), len(content), len(written), errors.Join(err, blocksErr))
	}

	// the pass-through to the hub: the hub keeps no packets, the stream ends with its context
	ctx, cancel := context.WithCancel(state.Context())
	cancel()
	exportErr := captures.Export(io.Discard, map[uint64][32]byte{}, false, slog.New(slog.DiscardHandler))
	streamErr := captures.Stream(ctx, io.Discard, nil, false, slog.New(slog.DiscardHandler))

	if !errors.Is(exportErr, ErrNoPacketHistory) || (streamErr != nil) {
		state.Fatalf("Test of capture.Captures failed, the export should fail with %v and the stream end, errors: %v, %v", ErrNoPacketHistory, exportErr, streamErr)
	}

	// decerter stops: the hub is done, the running capture finishes, the files and the data directory the captures made are removed
	close(hub.doneChannel)
	err = captures.Close()
	views := viewsOf(captures)

	if (err != nil) || (views[second.ID].State != api.StoppedCaptureState) || (views[second.ID].Reason != shutdownReason) {
		state.Fatalf("Test of capture.Captures.Close failed, the running capture should be stopped by the shutdown, view: %+v, error: %v", views[second.ID], err)
	}

	if _, statErr := os.Stat(dataDirectory); !errors.Is(statErr, fs.ErrNotExist) {
		state.Errorf("Test of capture.Captures.Close failed, the data directory should be gone, error: %v", statErr)
		return
	}
}

// Test if capture.Captures keeps at most MaxCaptures: a new capture removes the oldest stopped one with its file.
func TestCapturesCountPositive(state *testing.T) {
	captures, _, _ := testCaptures(state)

	for range MaxCaptures + 1 {
		view, err := captures.Start(nil, false)

		if err == nil {
			_, err = captures.Stop(view.ID)
		}

		if err != nil {
			state.Fatalf("Test of capture.Captures failed, error: %s", err.Error())
		}
	}

	views := viewsOf(captures)
	_, statErr := os.Stat(filepath.Join(captures.directory, "1"+captureFileSuffix))

	if _, isThere := views[1]; (len(views) != MaxCaptures) || isThere || (views[uint64(MaxCaptures)+1].ID != uint64(MaxCaptures)+1) || !errors.Is(statErr, fs.ErrNotExist) {
		state.Errorf("Test of capture.Captures failed, the %d latest captures should be kept and the file of the first one gone, captures: %d, stat: %v", MaxCaptures, len(views), statErr)
		return
	}

	err := captures.Close()

	if err != nil {
		state.Errorf("Test of capture.Captures.Close failed, error: %s", err.Error())
		return
	}
}

// Test if capture.NewCaptures removes the captures a decerter before left behind and capture.Captures.Close leaves a data directory with other files in it.
func TestNewCapturesPositive(state *testing.T) {
	dataDirectory := state.TempDir()
	leftOver := filepath.Join(dataDirectory, CaptureDirectoryName, "1"+captureFileSuffix)
	err := os.MkdirAll(filepath.Dir(leftOver), captureDirectoryMode)

	if err == nil {
		err = os.WriteFile(leftOver, []byte("old"), fileMode)
	}

	if err != nil {
		state.Fatalf("Test of capture.NewCaptures failed, cannot write the old capture, error: %s", err.Error())
	}

	_, err = NewCaptures(testHub(state, false), dataDirectory, slog.New(slog.DiscardHandler))

	if _, statErr := os.Stat(leftOver); (err != nil) || !errors.Is(statErr, fs.ErrNotExist) {
		state.Fatalf("Test of capture.NewCaptures failed, the old capture should be gone, stat: %v, error: %v", statErr, err)
	}

	// the data directory the captures made gets the lock of decerter, it stays
	captures, _, dataDirectory := testCaptures(state)
	_, err = captures.Start(nil, false)

	if err == nil {
		_, err = captures.Stop(1)
	}

	if err == nil {
		err = os.WriteFile(filepath.Join(dataDirectory, "lock"), nil, fileMode)
	}

	if err == nil {
		err = captures.Close()
	}

	if _, statErr := os.Stat(filepath.Join(dataDirectory, "lock")); (err != nil) || (statErr != nil) || !captures.isParentCreated {
		state.Errorf("Test of capture.Captures.Close failed, the data directory with the lock should stay, stat: %v, error: %v", statErr, err)
		return
	}
}

// Test if capture.Captures returns with the expected errors: too many running captures, captures that hold all the bytes, a file that is there, a directory that can't be made and a hub that is done.
func TestCapturesNegative(state *testing.T) {
	captures, hub, dataDirectory := testCaptures(state)

	for range MaxRunningCaptures {
		_, err := captures.Start(nil, false)

		if err != nil {
			state.Fatalf("Test of capture.Captures.Start failed, error: %s", err.Error())
		}
	}

	_, err := captures.Start(nil, false)

	if !errors.Is(err, ErrTooManyCaptures) || (len(captures.List()) != MaxRunningCaptures) {
		state.Fatalf("Test of capture.Captures.Start failed, error should be %v, captures: %d, error: %v", ErrTooManyCaptures, len(captures.List()), err)
	}

	for id := range uint64(MaxRunningCaptures) {
		_, err = captures.Stop(id + 1)

		if err != nil {
			state.Fatalf("Test of capture.Captures.Stop failed, error: %s", err.Error())
		}
	}

	// the stopped captures hold all the bytes: the oldest one goes for the new capture
	captures.mutex.Lock()
	captures.totalBytes = MaxCaptureBytes
	captures.captures[0].view.Size = MaxCaptureBytes
	captures.mutex.Unlock()
	view, err := captures.Start(nil, false)
	views := viewsOf(captures)

	if _, isThere := views[1]; (err != nil) || (len(views) != MaxRunningCaptures) || isThere || (views[view.ID].State != api.RunningCaptureState) {
		state.Fatalf("Test of capture.Captures.Start failed, the oldest capture should make room for the new one, captures: %v, error: %v", views, err)
	}

	_, err = captures.Stop(view.ID)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Stop failed, error: %s", err.Error())
	}

	// the running captures hold all the bytes, nothing can go
	captures.mutex.Lock()
	kept := captures.captures
	captures.captures = nil
	captures.totalBytes = MaxCaptureBytes
	captures.mutex.Unlock()
	_, err = captures.Start(nil, false)

	if !errors.Is(err, ErrTooManyCaptures) {
		state.Fatalf("Test of capture.Captures.Start failed, error should be %v, error: %v", ErrTooManyCaptures, err)
	}

	captures.mutex.Lock()
	captures.captures = kept
	captures.totalBytes = 0
	captures.mutex.Unlock()

	// the file of the next capture is there already
	next := filepath.Join(dataDirectory, CaptureDirectoryName, "6"+captureFileSuffix)
	err = os.WriteFile(next, nil, fileMode)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Start failed, cannot write file, error: %s", err.Error())
	}

	count := len(captures.List())
	_, err = captures.Start(nil, false)

	if !errors.Is(err, ErrOpenFile) || (len(captures.List()) != count) {
		state.Fatalf("Test of capture.Captures.Start failed, error should be %v and no capture kept, captures: %d, error: %v", ErrOpenFile, len(captures.List()), err)
	}

	// the hub is done: the file of the capture is removed again
	close(hub.doneChannel)
	_, err = captures.Start(nil, false)

	if _, statErr := os.Stat(filepath.Join(dataDirectory, CaptureDirectoryName, "7"+captureFileSuffix)); !errors.Is(err, ErrStopped) || !errors.Is(statErr, fs.ErrNotExist) || (len(captures.List()) != count) {
		state.Fatalf("Test of capture.Captures.Start failed, error should be %v without a file, stat: %v, error: %v", ErrStopped, statErr, err)
	}

	_, err = captures.Stop(99)
	_, _, openErr := captures.Open(99)

	if !errors.Is(err, ErrCaptureNotFound) || !errors.Is(openErr, ErrCaptureNotFound) {
		state.Fatalf("Test of capture.Captures failed, errors should be %v, errors: %v, %v", ErrCaptureNotFound, err, openErr)
	}

	err = captures.Close()

	if err != nil {
		state.Fatalf("Test of capture.Captures.Close failed, error: %s", err.Error())
	}

	// the data directory became a file
	captures, _, dataDirectory = testCaptures(state)
	err = os.WriteFile(dataDirectory, nil, fileMode)

	if err == nil {
		_, err = captures.Start(nil, false)
	}

	if !errors.Is(err, ErrCaptureDirectory) || (len(captures.List()) != 0) {
		state.Errorf("Test of capture.Captures.Start failed, error should be %v, error: %v", ErrCaptureDirectory, err)
		return
	}
}

// Test if capture.Captures stops a capture with the reason when its writer fails or the captures reach their size limit, and removes the oldest stopped capture for the bytes of a running one.
func TestCapturesLimitNegative(state *testing.T) {
	captures, hub, _ := testCaptures(state)
	first, err := captures.Start(nil, false)

	if err == nil {
		_, err = captures.Stop(first.ID)
	}

	if err != nil {
		state.Fatalf("Test of capture.Captures failed, error: %s", err.Error())
	}

	// the header of the new file takes the bytes over the limit, the stopped capture goes
	captures.mutex.Lock()
	captures.totalBytes = MaxCaptureBytes - 1
	captures.mutex.Unlock()
	second, err := captures.Start(nil, false)
	views := viewsOf(captures)

	if (err != nil) || (len(views) != 1) || (views[second.ID].State != api.RunningCaptureState) {
		state.Fatalf("Test of capture.Captures failed, the stopped capture should make room, captures: %d, error: %v", len(views), err)
	}

	_, err = captures.Stop(second.ID)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Stop failed, error: %s", err.Error())
	}

	// nothing can go: the capture that writes is stopped with its reason
	captures.mutex.Lock()
	captures.captures = nil
	captures.totalBytes = MaxCaptureBytes - 1
	captures.mutex.Unlock()
	third, err := captures.Start(nil, false)

	// the capture stops on its own, a stop could come first
	if err == nil {
		captures.mutex.Lock()
		stored := captures.find(third.ID)
		captures.mutex.Unlock()
		<-stored.doneChannel
		third, err = captures.Stop(third.ID)
	}

	if (err != nil) || (third.Reason != sizeLimitReason) {
		state.Fatalf("Test of capture.Captures failed, the capture should stop at the size limit, view: %+v, error: %v", third, err)
	}

	// the writer fails: a packet longer than the snaplen of the file
	captures.mutex.Lock()
	captures.totalBytes = 0
	captures.mutex.Unlock()
	hub.snaplen = 64
	fourth, err := captures.Start(nil, false)

	if err != nil {
		state.Fatalf("Test of capture.Captures.Start failed, error: %s", err.Error())
	}

	hub.offerAll(testFlow(1, hubClient, hubServer, "")[0])
	long := testFlow(1, hubClient, hubServer, string(bytes.Repeat([]byte("x"), 100)))[3]
	hub.offerAll(long)
	fourth, err = captures.Stop(fourth.ID)

	if (err != nil) || (fourth.Reason == "") || (fourth.Reason == shutdownReason) {
		state.Errorf("Test of capture.Captures failed, the capture should stop with the error of its writer, view: %+v, error: %v", fourth, err)
		return
	}

	err = captures.Close()

	if err != nil {
		state.Errorf("Test of capture.Captures.Close failed, error: %s", err.Error())
		return
	}
}

// Test if capture.NewCaptures and capture.Captures.Close return with the expected errors for a capture directory that can't be removed, and a capture file that can't be removed is forgotten.
func TestCapturesDirectoryNegative(state *testing.T) {
	if os.Geteuid() == 0 {
		state.Skip("root removes every directory")
	}

	dataDirectory := state.TempDir()
	directory := filepath.Join(dataDirectory, CaptureDirectoryName)
	err := os.MkdirAll(filepath.Join(directory, "sub"), captureDirectoryMode)

	if err == nil {
		err = os.Chmod(directory, 0o500)
	}

	if err != nil {
		state.Fatalf("Test of capture.NewCaptures failed, cannot prepare directory, error: %s", err.Error())
	}

	// the temporary directory of the test is removed at its end
	state.Cleanup(func() {
		chmodErr := os.Chmod(directory, captureDirectoryMode)

		if chmodErr != nil {
			state.Errorf("Test of capture.NewCaptures failed, cannot restore directory, error: %s", chmodErr.Error())
		}
	})
	_, err = NewCaptures(testHub(state, false), dataDirectory, slog.New(slog.DiscardHandler))

	if !errors.Is(err, ErrCaptureDirectory) {
		state.Fatalf("Test of capture.NewCaptures failed, error should be %v, error: %v", ErrCaptureDirectory, err)
	}

	captures := &Captures{mutex: &sync.Mutex{}, hub: nil, directory: directory, isParentCreated: false, captures: nil, nextID: 0, totalBytes: 0, waitGroup: &sync.WaitGroup{}, logger: slog.New(slog.DiscardHandler)}
	err = captures.Close()

	if !errors.Is(err, ErrCaptureDirectory) {
		state.Errorf("Test of capture.Captures.Close failed, error should be %v, error: %v", ErrCaptureDirectory, err)
		return
	}

	// the file of the oldest stopped capture can't be removed, it is forgotten all the same
	captures, _, _ = testCaptures(state)
	first, err := captures.Start(nil, false)

	if err == nil {
		_, err = captures.Stop(first.ID)
	}

	if err == nil {
		err = os.Chmod(captures.directory, 0o500)
	}

	if err != nil {
		state.Fatalf("Test of capture.Captures failed, error: %s", err.Error())
	}

	captures.mutex.Lock()
	captures.totalBytes = MaxCaptureBytes
	captures.mutex.Unlock()
	second, err := captures.Start(nil, false)

	if err == nil {
		_, err = captures.Stop(second.ID)
	}

	views := viewsOf(captures)

	if _, statErr := os.Stat(filepath.Join(captures.directory, "1"+captureFileSuffix)); (err != nil) || (statErr != nil) || (len(views) != 1) || (views[second.ID].ID != second.ID) {
		state.Errorf("Test of capture.Captures.Start failed, the old capture should be forgotten and its file stay, captures: %v, stat: %v, error: %v", views, statErr, err)
		return
	}

	err = captures.Close()

	if err != nil {
		state.Errorf("Test of capture.Captures.Close failed, error: %s", err.Error())
		return
	}
}
