// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"errors"
)

var (
	ErrProtocol = errors.New("no decoder for this protocol")
	// a name of a DNS message
	errNameShort    = errors.New("the name runs past the end of the message")
	errNameLong     = errors.New("the name is longer than 255 bytes")
	errNameLoop     = errors.New("too many compression pointers, a pointer loop")
	errLabelType    = errors.New("reserved label type")
	errFieldShort   = errors.New("the field runs past the end of its data")
	errRecordShort  = errors.New("the record runs past the end of the message")
	errRdataTrailer = errors.New("bytes after the end of the rdata fields")
)
