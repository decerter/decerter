// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrSyntax       = errors.New("syntax error")
	ErrUnknownField = errors.New("unknown field")
	ErrType         = errors.New("type mismatch")
	ErrOperator     = errors.New("operator does not fit the field")
	ErrEscape       = errors.New("invalid escape sequence")
	ErrRegex        = errors.New("invalid regular expression")
	ErrCommLength   = errors.New("proc.comm is at most 15 bytes, the kernel cuts longer process names, use proc.exe or proc.cmdline")
	ErrRange        = errors.New("number out of range for the field")
	ErrProcess      = errors.New("could not read process info")
	// a filter that decides a flow before its first byte can't ask for what the HTTP layer reads later
	ErrFlowScope = errors.New("the http fields are known only after a flow started, they filter the history, rules and holds but not a scope or a capture")
)

// a filter that could not be parsed, Column counts characters from 1 and Length the characters that are wrong
type PositionError struct {
	Filter string
	Column int
	Length int
	Err    error
}

func (positionError *PositionError) Error() (message string) {
	message = fmt.Sprintf("column %d: %s", positionError.Column, positionError.Err.Error())
	return
}

func (positionError *PositionError) Unwrap() (err error) {
	err = positionError.Err
	return
}

// the filter and a line under it that points at the wrong part, the way tshark shows it
func (positionError *PositionError) Marker() (marker string) {
	length := max(positionError.Length, 1)
	marker = positionError.Filter + "\n" + strings.Repeat(" ", positionError.Column-1) + "^" + strings.Repeat("~", length-1)
	return
}

// offset and length are bytes of text, the error counts characters
func newPositionError(text string, offset int, length int, err error) (positionError *PositionError) {
	offset = min(max(offset, 0), len(text))
	end := min(offset+max(length, 0), len(text))
	positionError = &PositionError{
		Filter: text,
		Column: utf8.RuneCountInString(text[:offset]) + 1,
		Length: utf8.RuneCountInString(text[offset:end]),
		Err:    err,
	}
	return
}
