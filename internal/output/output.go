// SPDX-License-Identifier: AGPL-3.0-only

// the output of the tool on stdout and the escaping of the fields in its lines; a leaf package, so the bpf loaders, the proxy and the rules can all use it
package output

import (
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
)

const hexDigits string = "0123456789abcdef"

// the flow lines, records, messages, key log and flow table of run and keylog mode
// SIGPIPE is ignored, a write after the reader went away (decerter run | head after head exited) fails with EPIPE: the first such write calls the function
// given to OnGone, so decerter stops like other Unix tools do instead of running on with no one reading
var Stdout = NewWriter(os.Stdout)

func NewWriter(file *os.File) (writer *Writer) {
	writer = &Writer{
		file:   file,
		mutex:  &sync.Mutex{},
		onGone: nil,
		isGone: false,
	}
	return
}

// the reader of a pipe went away, or behind adb exec-out the pty of stdout is gone, which fails with EIO
func IsGone(err error) (isGone bool) {
	isGone = errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.EIO)
	return
}

// one field of a line that a process or a peer chose, such as comm (prctl PR_SET_NAME takes any byte but NUL): printable ASCII stays, a backslash is
// \\, every other byte \xNN, so no control sequence reaches the terminal and the field can't end its line
func EscapeField(field string) (text string) {
	builder := strings.Builder{}
	builder.Grow(len(field))

	for index := range len(field) {
		value := field[index]

		switch {
		case value == '\\':
			builder.WriteString(`\\`)
		case (value >= ' ') && (value <= '~'):
			builder.WriteByte(value)
		default:
			builder.WriteString(`\x`)
			builder.WriteByte(hexDigits[value>>4])
			builder.WriteByte(hexDigits[value&0x0f])
		}
	}

	text = builder.String()
	return
}
