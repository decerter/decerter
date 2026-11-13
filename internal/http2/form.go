// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// the edit form of an HTTP/2 message for the rules of layer http: one "name: value" line per field, the pseudo-header fields first in their order, then the others in theirs,
// a blank line and the body (the DATA payloads joined, without padding); lines end in CR LF
func Form(fields []Field, body []byte) (form []byte) {
	for _, isPseudo := range []bool{true, false} {
		for _, field := range fields {
			if strings.HasPrefix(field.Name, ":") == isPseudo {
				form = fmt.Appendf(form, "%s: %s\r\n", field.Name, field.Value)
			}
		}
	}

	form = append(form, "\r\n"...)
	form = append(form, body...)
	return
}

// the fields and body of an edit form; lines may end in LF alone, names are made lower case (HTTP/2 has no others), white space around a value is dropped
// err when the head has no blank line after it, a line is no field, a name or value can't be sent, or a pseudo-header field comes after another field
func ParseForm(form []byte) (fields []Field, body []byte, err error) {
	head, rest, found := cutHead(form)

	if !found {
		err = fmt.Errorf("%w: no blank line after the header fields", ErrForm)
		return
	}

	body = rest
	isRegular := false

	for line := range strings.SplitSeq(string(head), "\n") {
		line = strings.TrimSuffix(line, "\r")
		start := 0

		if strings.HasPrefix(line, ":") {
			start = 1
		}

		colon := strings.IndexByte(line[start:], ':')

		if colon < 0 {
			err = fmt.Errorf("%w: no colon in %q", ErrForm, line)
			return
		}

		name := strings.ToLower(line[:start+colon])
		value := strings.Trim(line[start+colon+1:], " \t")

		if !httpguts.ValidHeaderFieldName(name[start:]) || !httpguts.ValidHeaderFieldValue(value) {
			err = fmt.Errorf("%w: field %q can't be sent", ErrForm, line)
			return
		}

		if (start == 1) && isRegular {
			err = fmt.Errorf("%w: pseudo-header field %s after another field", ErrForm, name)
			return
		}

		isRegular = isRegular || (start == 0)
		fields = append(fields, Field{Name: name, Value: value})
	}

	return
}

// the head of a form up to its first blank line, CR LF or LF
func cutHead(form []byte) (head []byte, body []byte, found bool) {
	end, size := bytes.Index(form, []byte("\r\n\r\n")), 4

	if lf := bytes.Index(form, []byte("\n\n")); (lf >= 0) && ((end < 0) || (lf < end)) {
		end, size = lf, 2
	}

	if end <= 0 {
		return
	}

	head, body, found = form[:end], form[end+size:], true
	return
}
