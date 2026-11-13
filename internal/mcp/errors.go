// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"errors"
)

var (
	// the api
	ErrAPI         = errors.New("the decerter api answered with an error")
	ErrContentType = errors.New("the decerter api answered with an unexpected content type")
	ErrEventStream = errors.New("could not read the decerter event stream")
	ErrHex         = errors.New("the decerter api sent a payload that is not hex")
	ErrNoHold      = errors.New("no such held message")
	// the output directory
	ErrOutputDirectory = errors.New("invalid output directory")
	ErrOutputFile      = errors.New("could not write the output file")
)
