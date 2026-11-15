// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"fmt"
)

// the comment the next synthesized packet carries: notes joined by "; ", the notes past maxNoteBytes are only counted, a flow with many dropped or cut
// messages would need more than the 65535 bytes of a pcapng comment; more is what the count of the left out notes says, "more notes" when empty
type packetNote struct {
	text    string
	omitted int
	more    string
}

func (note *packetNote) add(text string) {
	if (note.text != "") && (len(note.text)+len(text) > maxNoteBytes) {
		note.omitted++
		return
	}

	if note.text != "" {
		note.text += "; "
	}

	note.text += text
}

func (note *packetNote) isEmpty() (isEmpty bool) {
	isEmpty = (note.text == "") && (note.omitted == 0)
	return
}

// the comment with notePrefix, empty without a note; the note is empty after
func (note *packetNote) take() (comment string) {
	if note.isEmpty() {
		return
	}

	text := note.text

	// a note is only counted while one waits, the count goes behind it
	if note.omitted > 0 {
		more := note.more

		if more == "" {
			more = "more notes"
		}

		text += fmt.Sprintf("; %d %s", note.omitted, more)
	}

	comment = notePrefix + text
	note.text, note.omitted = "", 0
	return
}
