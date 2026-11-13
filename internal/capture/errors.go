// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"errors"
)

var (
	ErrOpenFile   = errors.New("could not open capture file")
	ErrRead       = errors.New("could not read packet_map")
	ErrTerminal   = errors.New("stdout is a terminal, the capture stream is binary and holds secrets: pipe it into a reader or redirect it to a file")
	ErrPollStream = errors.New("could not poll capture stream")
	ErrNoFlowMap  = errors.New("no flow_map to look the flow up in")
	// the hub and its writers
	ErrStopped         = errors.New("the capture stopped, decerter is shutting down")
	ErrSlowReader      = errors.New("the reader of the capture stream is too slow, packets would be lost")
	ErrSizeLimit       = errors.New("the captures reached their size limit")
	ErrNoPacketHistory = errors.New("the capture keeps no packets without the api")
	// the captures of the api
	ErrCaptureNotFound  = errors.New("no such capture")
	ErrCaptureRunning   = errors.New("the capture is still running, stop it first")
	ErrTooManyCaptures  = errors.New("too many captures")
	ErrCaptureDirectory = errors.New("could not prepare the capture directory")
)
