// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type tokenKind string

const (
	endTokenKind tokenKind = "end"
	// a field name, a keyword (and, or, not, in, contains, matches, eq, …), a number, an address or a CIDR prefix, told apart by the parser
	wordTokenKind tokenKind = "word"
	// a double quoted string with its escapes resolved, or a raw string r"…"
	stringTokenKind      tokenKind = "string"
	punctuationTokenKind tokenKind = "punctuation"
)

// text is the word or the punctuation as written, the value of a string
// offset and length are the bytes the token takes in the filter
type token struct {
	kind   tokenKind
	text   string
	offset int
	length int
}

var (
	// longest first, so == is not read as two =
	punctuations = []string{"===", "!==", "==", "!=", "<=", ">=", "&&", "||", "<", ">", "!", "(", ")", "{", "}", ",", "~"}
)

// split the filter into tokens, the last one is always an end token at the end of the text
func lex(text string) (tokens []token, err error) {
	offset := 0

	for offset < len(text) {
		character := text[offset]

		switch {
		case (character == ' ') || (character == '\t') || (character == '\n') || (character == '\r'):
			offset++
		case character == '"':
			value, end, stringErr := lexString(text, offset, false)

			if err = stringErr; err != nil {
				return
			}

			tokens = append(tokens, token{kind: stringTokenKind, text: value, offset: offset, length: end - offset})
			offset = end
		case ((character == 'r') || (character == 'R')) && strings.HasPrefix(text[offset+1:], `"`):
			value, end, stringErr := lexString(text, offset+1, true)

			if err = stringErr; err != nil {
				return
			}

			tokens = append(tokens, token{kind: stringTokenKind, text: value, offset: offset, length: end - offset})
			offset = end
		case isWordByte(character):
			end := offset

			for (end < len(text)) && isWordByte(text[end]) {
				end++
			}

			tokens = append(tokens, token{kind: wordTokenKind, text: text[offset:end], offset: offset, length: end - offset})
			offset = end
		default:
			punctuation := ""

			for _, candidate := range punctuations {
				if strings.HasPrefix(text[offset:], candidate) {
					punctuation = candidate
					break
				}
			}

			if punctuation == "" {
				_, size := utf8.DecodeRuneInString(text[offset:])
				err = newPositionError(text, offset, size, unexpectedCharacter(text[offset:offset+size]))
				return
			}

			tokens = append(tokens, token{kind: punctuationTokenKind, text: punctuation, offset: offset, length: len(punctuation)})
			offset += len(punctuation)
		}
	}

	tokens = append(tokens, token{kind: endTokenKind, text: "", offset: len(text), length: 0})
	return
}

// a field name, a number, an IPv4 or IPv6 address and a CIDR prefix are made of these, a range a..b too
func isWordByte(character byte) (isWord bool) {
	isWord = ((character >= 'a') && (character <= 'z')) || ((character >= 'A') && (character <= 'Z')) || ((character >= '0') && (character <= '9')) || (character == '_') || (character == '.') || (character == ':') || (character == '/')
	return
}

// a single = or & is a common slip, the error says what is meant
func unexpectedCharacter(character string) (err error) {
	switch character {
	case "=":
		err = fmt.Errorf("%w: unexpected \"=\", equality is ==", ErrSyntax)
	case "&":
		err = fmt.Errorf("%w: unexpected \"&\", logical and is && or and", ErrSyntax)
	case "|":
		err = fmt.Errorf("%w: unexpected \"|\", logical or is || or or", ErrSyntax)
	case "'":
		err = fmt.Errorf("%w: strings are in double quotes", ErrSyntax)
	default:
		err = fmt.Errorf("%w: unexpected %q", ErrSyntax, character)
	}

	return
}

// read the string whose opening quote is at start, end is the offset behind its closing quote
// Wireshark's escapes: \\ \" \' \a \b \f \n \r \t \v, \ooo octal, \xhh, \uhhhh and \Uhhhhhhhh, any other is an error
// a raw string keeps every backslash, a \" in it does not end the string and stays as it is
func lexString(text string, start int, isRaw bool) (value string, end int, err error) {
	var builder strings.Builder
	offset := start + 1

	for offset < len(text) {
		character := text[offset]

		if character == '"' {
			value = builder.String()
			end = offset + 1
			return
		}

		if character != '\\' {
			builder.WriteByte(character)
			offset++
			continue
		}

		if offset+1 >= len(text) {
			break
		}

		if isRaw {
			builder.WriteString(text[offset : offset+2])
			offset += 2
			continue
		}

		length, escapeErr := writeEscape(&builder, text[offset:])

		if escapeErr != nil {
			err = newPositionError(text, offset, max(length, 2), escapeErr)
			return
		}

		offset += length
	}

	err = newPositionError(text, start, len(text)-start, fmt.Errorf("%w: string without closing quote", ErrSyntax))
	return
}

// escape starts with the backslash, length is the bytes the escape takes
func writeEscape(builder *strings.Builder, escape string) (length int, err error) {
	simple := map[byte]byte{'\\': '\\', '"': '"', '\'': '\'', 'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}

	if replacement, ok := simple[escape[1]]; ok {
		builder.WriteByte(replacement)
		length = 2
		return
	}

	switch {
	case (escape[1] >= '0') && (escape[1] <= '7'):
		digits := countDigits(escape[1:], 3, 8)
		code, parseErr := strconv.ParseUint(escape[1:1+digits], 8, 16)
		length = 1 + digits

		if (parseErr != nil) || (code > 0xFF) {
			err = fmt.Errorf("%w: %s is more than a byte", ErrEscape, escape[:length])
			return
		}

		builder.WriteByte(byte(code))
	case escape[1] == 'x':
		digits := countDigits(escape[2:], 2, 16)
		length = 2 + digits

		if digits == 0 {
			err = fmt.Errorf("%w: \\x needs hex digits", ErrEscape)
			return
		}

		code, _ := strconv.ParseUint(escape[2:length], 16, 8)
		builder.WriteByte(byte(code))
	case (escape[1] == 'u') || (escape[1] == 'U'):
		width := 4

		if escape[1] == 'U' {
			width = 8
		}

		digits := countDigits(escape[2:], width, 16)
		length = 2 + digits
		code, parseErr := strconv.ParseUint(escape[2:length], 16, 32)

		if (digits != width) || (parseErr != nil) || !utf8.ValidRune(rune(code)) {
			err = fmt.Errorf("%w: \\%c needs %d hex digits of a valid code point", ErrEscape, escape[1], width)
			return
		}

		builder.WriteRune(rune(code))
	default:
		_, size := utf8.DecodeRuneInString(escape[1:])
		length = 1 + size
		err = fmt.Errorf("%w: %s, a backslash in a regular expression is written \\\\ or in a raw string r\"…\"", ErrEscape, escape[:length])
	}

	return
}

// how many of the first limit bytes of text are digits of base
func countDigits(text string, limit int, base int) (count int) {
	for (count < len(text)) && (count < limit) {
		character := text[count]
		isDigit := false

		switch base {
		case 8:
			isDigit = (character >= '0') && (character <= '7')
		default:
			isDigit = ((character >= '0') && (character <= '9')) || ((character >= 'a') && (character <= 'f')) || ((character >= 'A') && (character <= 'F'))
		}

		if !isDigit {
			break
		}

		count++
	}

	return
}
