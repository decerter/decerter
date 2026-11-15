// SPDX-License-Identifier: AGPL-3.0-only

package output

import (
	"os"
	"sync"
)

// a file whose reader can go away, see Stdout
type Writer struct {
	file   *os.File
	mutex  *sync.Mutex
	onGone func()
	isGone bool
}

func (writer *Writer) Write(data []byte) (length int, err error) {
	length, err = writer.file.Write(data)

	if (err != nil) && IsGone(err) {
		writer.gone()
	}

	return
}

func (writer *Writer) WriteString(text string) (length int, err error) {
	length, err = writer.file.WriteString(text)

	if (err != nil) && IsGone(err) {
		writer.gone()
	}

	return
}

// onGone runs once, at the first write that finds the reader gone; when that write came before, OnGone calls it at once; nil runs nothing
func (writer *Writer) OnGone(onGone func()) {
	writer.mutex.Lock()
	writer.onGone = onGone
	isGone := writer.isGone
	writer.mutex.Unlock()

	if isGone && (onGone != nil) {
		onGone()
	}
}

func (writer *Writer) gone() {
	writer.mutex.Lock()
	onGone := writer.onGone
	isFirst := !writer.isGone
	writer.isGone = true
	writer.mutex.Unlock()

	if isFirst && (onGone != nil) {
		onGone()
	}
}
