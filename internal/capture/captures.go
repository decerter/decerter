// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
)

const (
	// the captures of the API: how many files are kept, how many captures may run at once, and the bytes of all files together
	MaxCaptures        int   = 16
	MaxRunningCaptures int   = 4
	MaxCaptureBytes    int64 = 1 << 30
	// in the platform's data directory, only for root
	CaptureDirectoryName string      = "captures"
	captureDirectoryMode os.FileMode = 0o700
	captureFileSuffix    string      = ".pcapng"
	// why a capture stopped when nobody stopped it
	sizeLimitReason string = "the captures reached their size limit"
	shutdownReason  string = "decerter stopped"
)

// the captures started over the API, oldest first; their files are in directory with mode 0600 for root and are removed when decerter stops
// a new capture over the count, or a file that takes the bytes over the limit, removes the oldest stopped capture first; isParentCreated: the data directory was made for the captures and goes with them
type Captures struct {
	mutex           *sync.Mutex
	hub             *Hub
	directory       string
	isParentCreated bool
	captures        []*storedCapture
	nextID          uint64
	totalBytes      int64
	waitGroup       *sync.WaitGroup
	isClosed        bool
	logger          *slog.Logger
}

// one capture of the API: view is what the API shows, size and state included; consumer is its writer behind the hub
// stopChannel is closed by a stop, limitChannel when the captures are full, doneChannel when the file is finished
type storedCapture struct {
	view         api.Capture
	path         string
	consumer     *Consumer
	stopChannel  chan struct{}
	isStopping   bool
	limitChannel chan struct{}
	isLimited    bool
	doneChannel  chan struct{}
}

// counts what is written to the file of a capture against the size limit
type captureWriter struct {
	file     *os.File
	captures *Captures
	stored   *storedCapture
}

// the captures of the hub, in dataDirectory/captures; files a killed decerter left there are removed first, they can't be downloaded any more
func NewCaptures(hub *Hub, dataDirectory string, logger *slog.Logger) (captures *Captures, err error) {
	captures = &Captures{
		mutex:           &sync.Mutex{},
		hub:             hub,
		directory:       filepath.Join(dataDirectory, CaptureDirectoryName),
		isParentCreated: false,
		captures:        nil,
		nextID:          0,
		totalBytes:      0,
		waitGroup:       &sync.WaitGroup{},
		isClosed:        false,
		logger:          logger,
	}
	entries, readErr := os.ReadDir(captures.directory)

	if errors.Is(readErr, fs.ErrNotExist) {
		return
	}

	if readErr == nil {
		logger.Warn("Removing the captures a decerter before left behind", "directory", captures.directory, "files", len(entries))
	}

	err = os.RemoveAll(captures.directory)

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrCaptureDirectory, captures.directory, err)
	}

	return
}

// start a capture of the flows in scope that scope takes, nil takes all; plaintext writes synthesized decrypted packets instead of the packets and the DSBs
func (captures *Captures) Start(scope *filter.Filter, plaintext bool) (view api.Capture, err error) {
	stored, addErr := captures.add(scope, plaintext)

	if err = addErr; err != nil {
		return
	}

	file, openErr := os.OpenFile(stored.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrOpenFile, err)
		captures.discard(stored)
		return
	}

	logger := captures.logger.With("captureID", stored.view.ID)
	current, addErr := captures.hub.Add(&captureWriter{file: file, captures: captures, stored: stored}, ConsumerOptions{Stream: false, IsCut: false, Scope: scope, Plaintext: plaintext, Limit: stored.limitChannel}, logger)

	if err = addErr; err != nil {
		err = errors.Join(err, file.Close(), os.Remove(stored.path))
		captures.discard(stored)
		return
	}

	captures.mutex.Lock()
	stored.consumer = current
	view = captures.viewOf(stored)
	captures.mutex.Unlock()
	logger.Info("Capture started over the api", "filter", view.Filter, "format", view.Format, "fileName", stored.path)

	// api capture writer, finishes its file when it is stopped or decerter stops
	captures.waitGroup.Go(func() {
		consumeErr := captures.hub.Consume(context.Background(), current, stored.stopChannel)
		captures.finished(stored, errors.Join(consumeErr, file.Close()), logger)
	})

	return
}

// keep a new capture in the list before its file is made, so it counts against the limits at once
func (captures *Captures) add(scope *filter.Filter, plaintext bool) (stored *storedCapture, err error) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	running := 0

	for _, current := range captures.captures {
		if current.view.State == api.RunningCaptureState {
			running++
		}
	}

	if running >= MaxRunningCaptures {
		err = fmt.Errorf("%w: %d are running, stop one first", ErrTooManyCaptures, running)
		return
	}

	if (len(captures.captures) >= MaxCaptures) && !captures.removeOldestStopped(nil) {
		err = fmt.Errorf("%w: %d are kept", ErrTooManyCaptures, len(captures.captures))
		return
	}

	for captures.totalBytes >= MaxCaptureBytes {
		if !captures.removeOldestStopped(nil) {
			err = fmt.Errorf("%w: the running captures hold %d bytes", ErrTooManyCaptures, captures.totalBytes)
			return
		}
	}

	err = captures.prepareDirectory()

	if err != nil {
		return
	}

	captures.nextID++
	stored = &storedCapture{
		view: api.Capture{
			ID:             captures.nextID,
			Filter:         "",
			Format:         api.DSBCaptureFormat,
			State:          api.RunningCaptureState,
			Started:        time.Now(),
			Stopped:        time.Time{},
			Size:           0,
			DroppedPackets: 0,
			Reason:         "",
		},
		path:         filepath.Join(captures.directory, strconv.FormatUint(captures.nextID, 10)+captureFileSuffix),
		consumer:     nil,
		stopChannel:  make(chan struct{}),
		isStopping:   false,
		limitChannel: make(chan struct{}),
		isLimited:    false,
		doneChannel:  make(chan struct{}),
	}

	if scope != nil {
		stored.view.Filter = scope.String()
	}

	if plaintext {
		stored.view.Format = api.PlaintextCaptureFormat
	}

	captures.captures = append(captures.captures, stored)
	return
}

// the directory is made with the first capture, for root only; the mutex is held
func (captures *Captures) prepareDirectory() (err error) {
	parent := filepath.Dir(captures.directory)

	if _, statErr := os.Stat(parent); errors.Is(statErr, fs.ErrNotExist) {
		captures.isParentCreated = true
	}

	err = os.MkdirAll(captures.directory, captureDirectoryMode)

	if err == nil {
		err = os.Chmod(captures.directory, captureDirectoryMode)
	}

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrCaptureDirectory, captures.directory, err)
	}

	return
}

// a capture that could not start is forgotten, a Stop that waits for it finds it gone
func (captures *Captures) discard(stored *storedCapture) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	captures.captures = slices.DeleteFunc(captures.captures, func(current *storedCapture) bool {
		return current == stored
	})
	close(stored.doneChannel)
}

// the writer of the capture is done, why it stopped is kept when nobody asked for it
func (captures *Captures) finished(stored *storedCapture, err error, logger *slog.Logger) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	stored.view.State = api.StoppedCaptureState
	stored.view.Stopped = time.Now()
	stored.view.DroppedPackets = stored.consumer.Dropped()

	switch {
	case errors.Is(err, ErrSizeLimit):
		stored.view.Reason = sizeLimitReason
	case err != nil:
		stored.view.Reason = err.Error()
	case !stored.isStopping || captures.isClosed:
		stored.view.Reason = shutdownReason
	default:
	}

	if err != nil {
		logger.Warn("Capture stopped", "error", err, "size", stored.view.Size, "droppedPackets", stored.view.DroppedPackets)
	} else {
		logger.Info("Capture stopped", "size", stored.view.Size, "droppedPackets", stored.view.DroppedPackets)
	}

	close(stored.doneChannel)
}

// stop a running capture and wait until its file is finished; a stopped capture is left as it is
func (captures *Captures) Stop(id uint64) (view api.Capture, err error) {
	captures.mutex.Lock()
	stored := captures.find(id)

	if stored == nil {
		captures.mutex.Unlock()
		err = fmt.Errorf("%w: %d", ErrCaptureNotFound, id)
		return
	}

	if !stored.isStopping && (stored.view.State == api.RunningCaptureState) {
		stored.isStopping = true
		close(stored.stopChannel)
	}

	captures.mutex.Unlock()
	<-stored.doneChannel
	captures.mutex.Lock()
	defer captures.mutex.Unlock()

	// the capture could not start
	if captures.find(id) == nil {
		err = fmt.Errorf("%w: %d", ErrCaptureNotFound, id)
		return
	}

	view = captures.viewOf(stored)
	return
}

// every capture that is kept, oldest first
func (captures *Captures) List() (views []api.Capture) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	views = []api.Capture{}

	for _, stored := range captures.captures {
		views = append(views, captures.viewOf(stored))
	}

	return
}

// the file of a stopped capture, the caller closes it; the file stays readable when the capture is removed meanwhile
func (captures *Captures) Open(id uint64) (file *os.File, view api.Capture, err error) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	stored := captures.find(id)

	if stored == nil {
		err = fmt.Errorf("%w: %d", ErrCaptureNotFound, id)
		return
	}

	view = captures.viewOf(stored)

	if view.State == api.RunningCaptureState {
		err = fmt.Errorf("%w: %d", ErrCaptureRunning, id)
		return
	}

	file, err = os.Open(stored.path)
	return
}

// what the status shows of the captures
func (captures *Captures) Status() (status api.CaptureStatus) {
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	status = api.CaptureStatus{
		Available: true,
		Running:   0,
		Stored:    len(captures.captures),
		Size:      captures.totalBytes,
		Limits:    api.CaptureLimits{Captures: MaxCaptures, Running: MaxRunningCaptures, Size: MaxCaptureBytes},
	}

	for _, stored := range captures.captures {
		if stored.view.State == api.RunningCaptureState {
			status.Running++
		}
	}

	return
}

// the live stream of the API, see Hub.Stream
func (captures *Captures) Stream(ctx context.Context, output io.Writer, scope *filter.Filter, plaintext bool, logger *slog.Logger) (err error) {
	err = captures.hub.Stream(ctx, output, scope, plaintext, logger)
	return
}

// capture mode's pcap export, see Hub.Export
func (captures *Captures) Export(output io.Writer, flows map[uint64][32]byte, plaintext bool, logger *slog.Logger) (err error) {
	err = captures.hub.Export(output, flows, plaintext, logger)
	return
}

// stop the running captures and wait for their writers, then remove the files: they hold secrets and nobody can download them after decerter
func (captures *Captures) Close() (err error) {
	captures.mutex.Lock()
	captures.isClosed = true

	// a writer also ends when the hub is done, but the hub never ran when decerter failed to start
	for _, stored := range captures.captures {
		if !stored.isStopping && (stored.view.State == api.RunningCaptureState) {
			stored.isStopping = true
			close(stored.stopChannel)
		}
	}

	captures.mutex.Unlock()
	captures.waitGroup.Wait()
	err = os.RemoveAll(captures.directory)

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrCaptureDirectory, captures.directory, err)
		return
	}

	// the data directory has other files when the api socket or the lock is there, it stays then
	if captures.isParentCreated {
		removeErr := os.Remove(filepath.Dir(captures.directory))

		if (removeErr != nil) && !errors.Is(removeErr, fs.ErrNotExist) {
			captures.logger.Debug("Could not remove data directory", "error", removeErr, "directory", filepath.Dir(captures.directory))
		}
	}

	return
}

// the mutex is held
func (captures *Captures) find(id uint64) (stored *storedCapture) {
	for _, current := range captures.captures {
		if current.view.ID == id {
			stored = current
			return
		}
	}

	return
}

// the mutex is held
func (captures *Captures) viewOf(stored *storedCapture) (view api.Capture) {
	view = stored.view

	if stored.consumer != nil {
		view.DroppedPackets = stored.consumer.Dropped()
	}

	return
}

// remove the oldest stopped capture other than except and its file, isRemoved is false when there is none; the mutex is held
func (captures *Captures) removeOldestStopped(except *storedCapture) (isRemoved bool) {
	index := slices.IndexFunc(captures.captures, func(current *storedCapture) bool {
		return (current != except) && (current.view.State == api.StoppedCaptureState)
	})

	if index < 0 {
		return
	}

	stored := captures.captures[index]
	removeErr := os.Remove(stored.path)

	if (removeErr != nil) && !errors.Is(removeErr, fs.ErrNotExist) {
		captures.logger.Warn("Could not remove capture file", "error", removeErr, "fileName", stored.path)
	}

	captures.totalBytes -= stored.view.Size
	captures.captures = slices.Delete(captures.captures, index, index+1)
	captures.logger.Info("Removed the oldest stopped capture to make room", "captureID", stored.view.ID, "size", stored.view.Size)
	isRemoved = true
	return
}

// the bytes of every capture count against MaxCaptureBytes; over it the oldest stopped captures go, and when none is left the writing capture is told to stop
// the write itself always goes through, so the file ends with whole blocks
func (writer *captureWriter) Write(data []byte) (count int, err error) {
	count, err = writer.file.Write(data)
	captures := writer.captures
	captures.mutex.Lock()
	defer captures.mutex.Unlock()
	writer.stored.view.Size += int64(count)
	captures.totalBytes += int64(count)

	for captures.totalBytes > MaxCaptureBytes {
		if !captures.removeOldestStopped(writer.stored) {
			break
		}
	}

	if (captures.totalBytes > MaxCaptureBytes) && !writer.stored.isLimited {
		writer.stored.isLimited = true
		close(writer.stored.limitChannel)
	}

	return
}
