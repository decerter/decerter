// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// the PostgreSQL frontend/backend protocol 3.0 and 3.2 from the PostgreSQL documentation (chapter "Frontend/Backend Protocol"): the untyped first
// messages (StartupMessage, SSLRequest, GSSENCRequest, CancelRequest), the one-byte answer to SSLRequest and GSSENCRequest, and the typed messages
// of both sides; after an SSLRequest the server took, the rest of the stream is TLS
const (
	postgresProtocol string = "pgsql"
	postgresTitle    string = "PostgreSQL"
	// the codes of the untyped messages in the place of the protocol version
	postgresSSLCode    uint32 = 80877103
	postgresGSSCode    uint32 = 80877104
	postgresCancelCode uint32 = 80877102
	// a message longer than this is no PostgreSQL message in practice (the server's limit is 1 GiB)
	postgresMaxLength int = 1 << 30
	// streamState.mode after an accepted GSSENCRequest: the rest is GSSAPI wrapped
	gssMode string = "gss"
	// the bytes of a query the summary shows
	postgresSummaryQuery int = 80
)

var (
	postgresFrontend = map[byte]string{
		'Q': "Query", 'P': "Parse", 'B': "Bind", 'E': "Execute", 'D': "Describe", 'S': "Sync", 'H': "Flush", 'C': "Close", 'X': "Terminate",
		'p': "Password message", 'F': "Function call", 'd': "Copy data", 'c': "Copy done", 'f': "Copy fail",
	}
	postgresBackend = map[byte]string{
		'R': "Authentication request", 'K': "Backend key data", 'S': "Parameter status", 'Z': "Ready for query", 'T': "Row description", 'D': "Data row",
		'C': "Command completion", 'E': "Error", 'N': "Notice", '1': "Parse completion", '2': "Bind completion", '3': "Close completion", 'n': "No data",
		's': "Portal suspended", 't': "Parameter description", 'I': "Empty query", 'A': "Notification", 'G': "Copy in response", 'H': "Copy out response",
		'W': "Copy both response", 'd': "Copy data", 'c': "Copy done", 'V': "Function call response", 'v': "Negotiate protocol version",
	}
	// the types only a client sends: a message without a direction is the client's when it has one of them
	postgresFrontendOnly   = "QPBEXpFf"
	postgresAuthentication = nameTable{names: map[uint16]string{
		0: "Success", 2: "Kerberos V5", 3: "Cleartext password", 5: "MD5 password", 7: "GSSAPI", 8: "GSSAPI continue", 9: "SSPI", 10: "SASL",
		11: "SASL continue", 12: "SASL final",
	}, unknown: "Type %d"}
	// the fields of ErrorResponse and NoticeResponse
	postgresFields = map[byte]string{
		'S': "Severity", 'V': "Severity (not localized)", 'C': "Code", 'M': "Message", 'D': "Detail", 'H': "Hint", 'P': "Position", 'p': "Internal position",
		'q': "Internal query", 'W': "Where", 's': "Schema", 't': "Table", 'c': "Column", 'd': "Data type", 'n': "Constraint", 'F': "File", 'L': "Line",
		'R': "Routine",
	}
	postgresStatus = map[byte]string{'I': "idle", 'T': "in transaction", 'E': "in failed transaction"}
)

func init() {
	register(decoder{
		Protocol:   postgresProtocol,
		Title:      postgresTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 5432}, {Layer: v1.TLSLayer, Number: 5432}},
		hint:       postgresHint,
		sniff:      postgresSniff,
		decode:     framedDecode(postgresProtocol),
		fromTarget: nil,
		frame:      postgresFrame,
		pdu:        postgresPDU,
		unit:       "message",
	})
}

// a direct TLS connection of PostgreSQL 17 names itself with the ALPN postgresql
func postgresHint(context Context) (reason string) {
	if (context.Layer == v1.TLSLayer) && (context.ALPN == "postgresql") {
		reason = "TLS ALPN postgresql is PostgreSQL"
	}

	return
}

// an untyped first message with a known code or protocol version is certain; typed messages that frame up to the end of the bytes possible
func postgresSniff(data []byte, context Context) (score int) {
	if (context.Transport != StreamTransport) || (len(data) < 1) {
		return
	}

	if (len(data) == 1) && (context.Direction == v1.DownDirection) && (strings.IndexByte("SGN", data[0]) >= 0) {
		score = 60
		return
	}

	if len(data) < 5 {
		return
	}

	if (data[0] == 0) && (len(data) >= 8) {
		length := int(binary.BigEndian.Uint32(data))

		switch code := binary.BigEndian.Uint32(data[4:]); {
		case (length == 8) && ((code == postgresSSLCode) || (code == postgresGSSCode)):
			score = 100
		case (length == 16) && (code == postgresCancelCode):
			score = 90
		case (code>>16 == 3) && (length >= 9) && (length < 10000):
			score = 100
		}

		return
	}

	// the server's answer to an SSLRequest, alone or before its TLS records
	if (context.Direction == v1.DownDirection) && ((data[0] == 'S') || (data[0] == 'G')) && isTLSStart(data[1:]) {
		score = 80
		return
	}

	// typed messages: the types and lengths have to hold for all of them
	state := &streamState{context: context, index: 0, isTLS: false, mode: "", waiting: 0, columns: 0, sequence: 0, command: 0}
	offset, count := 0, 0

	for (offset < len(data)) && (count < 64) {
		if _, name := postgresType(data[offset], context.Direction); name == "" {
			return
		}

		length := postgresFrame(data[offset:], state)

		if length <= 0 {
			break
		}

		offset += length
		count++
	}

	switch {
	case (count >= 2) && (offset == len(data)):
		score = 50
	case count >= 1:
		score = 20
	}

	return
}

// the side and name of a message type; a message without a direction is the client's for the types only a client sends
func postgresType(kind byte, direction v1.Direction) (isFrontend bool, name string) {
	isFrontend = direction == v1.UpDirection

	if (direction != v1.UpDirection) && (direction != v1.DownDirection) {
		isFrontend = strings.IndexByte(postgresFrontendOnly, kind) >= 0
	}

	name = postgresBackend[kind]

	if isFrontend {
		name = postgresFrontend[kind]
	}

	return
}

// the one-byte answer to an SSLRequest or a GSSENCRequest, at the start of the server's stream: S, G or N, not followed by a typed message's length
func isPostgresAnswer(data []byte, state *streamState) (isAnswer bool) {
	isAnswer = (state.index == 0) && (state.context.Direction == v1.DownDirection) && (strings.IndexByte("SGN", data[0]) >= 0) && ((len(data) == 1) || (data[1] != 0))
	return
}

func postgresFrame(data []byte, state *streamState) (length int) {
	switch {
	case state.mode == gssMode:
		length = len(data)
		return
	case isPostgresAnswer(data, state):
		length = 1
		return
	case data[0] == 0:
		// an untyped message: its length comes first
		if len(data) < 4 {
			return
		}

		length = int(binary.BigEndian.Uint32(data))
	default:
		if len(data) < 5 {
			return
		}

		length = 1 + int(binary.BigEndian.Uint32(data[1:]))

		if length < 5 {
			length = -1
			return
		}
	}

	if (length < 4) || (length > postgresMaxLength) {
		length = -1
	}

	return
}

func postgresPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	kind := data[start]

	switch {
	case state.mode == gssMode:
		root = tree.add(nil, postgresProtocol, postgresTitle+" (GSSAPI encrypted)", strconv.Itoa(len(data)-start)+" bytes", start, len(data)-start)
		tree.addSummary("PostgreSQL GSSAPI encrypted data")
		return
	case isPostgresAnswer(data[start:], state):
		answer := map[byte]string{'S': "SSL accepted", 'G': "GSSAPI encryption accepted", 'N': "refused"}[kind]
		root = tree.add(nil, postgresProtocol, postgresTitle+" (encryption answer)", answer, start, 1)
		tree.add(root, "pgsql.ssl_response", "Answer", fmt.Sprintf("%c, %s", kind, answer), start, 1)

		switch kind {
		case 'S':
			state.mode = starttlsMode
		case 'G':
			state.mode = gssMode
		}

		tree.addSummary("PostgreSQL encryption " + answer)
		return
	case kind == 0:
		root = tree.add(nil, postgresProtocol, postgresTitle, "", start, len(data)-start)
		postgresUntyped(tree, root, data, start, state)
		return
	}

	isFrontend, name := postgresType(kind, state.context.Direction)

	if name == "" {
		name = fmt.Sprintf("Unknown message type 0x%02x", kind)
	}

	root = tree.add(nil, postgresProtocol, postgresTitle+" ("+name+")", "", start, len(data)-start)
	reader := fieldsOf(tree, root, data, start, len(data))
	reader.number("pgsql.type", "Type", 1, func(value uint32) (text string) {
		text = fmt.Sprintf("%s (%s)", name, textValue([]byte{byte(value)}))
		return
	})
	reader.number("pgsql.length", "Length", 4, nil)
	summary := "PostgreSQL " + name

	if isFrontend {
		summary += postgresFrontendFields(tree, root, reader, kind)
	} else {
		summary += postgresBackendFields(tree, root, reader, kind, state)
	}

	if reader.left() > 0 {
		reader.restField("pgsql.data", "Data")
	}

	reader.finish()
	root.value = strings.TrimPrefix(summary, "PostgreSQL "+name+" ")
	tree.addSummary(summary)
	return
}

// StartupMessage, SSLRequest, GSSENCRequest and CancelRequest
func postgresUntyped(tree *Tree, root *node, data []byte, start int, state *streamState) {
	reader := fieldsOf(tree, root, data, start, len(data))
	reader.number("pgsql.length", "Length", 4, nil)
	code, _ := reader.number("pgsql.version", "Protocol version", 4, func(value uint32) (text string) {
		switch value {
		case postgresSSLCode:
			text = "SSLRequest (80877103)"
		case postgresGSSCode:
			text = "GSSENCRequest (80877104)"
		case postgresCancelCode:
			text = "CancelRequest (80877102)"
		default:
			text = fmt.Sprintf("%d.%d", value>>16, value&0xffff)
		}

		return
	})

	switch code {
	case postgresSSLCode:
		root.label = postgresTitle + " (SSLRequest)"
		tree.addSummary("PostgreSQL SSLRequest")
		state.mode = starttlsMode
	case postgresGSSCode:
		root.label = postgresTitle + " (GSSENCRequest)"
		tree.addSummary("PostgreSQL GSSENCRequest")
	case postgresCancelCode:
		root.label = postgresTitle + " (CancelRequest)"
		pid, _ := reader.number("pgsql.pid", "Process ID", 4, nil)
		reader.bytesField("pgsql.key", "Secret key", reader.left())
		tree.addSummary(fmt.Sprintf("PostgreSQL CancelRequest pid %d", pid))
	default:
		root.label = postgresTitle + " (StartupMessage)"
		parameters := []string{}

		for (reader.left() > 1) && !reader.isShort && !reader.tree.isFull {
			parameterStart := reader.offset
			parameter := tree.add(root, "pgsql.parameter", "Parameter", "", parameterStart, 0)
			values := fieldsOf(tree, parameter, data, parameterStart, reader.end)
			key, _ := values.cString("pgsql.parameter_name", "Parameter name")
			value, _ := values.cString("pgsql.parameter_value", "Parameter value")
			parameter.length = values.offset - parameterStart
			parameter.value = textValue(key) + "=" + textValue(value)
			reader.offset = values.offset
			reader.isShort = values.isShort

			if (string(key) == "user") || (string(key) == "database") {
				parameters = append(parameters, string(key)+"="+textValue(value))
			}
		}

		if (reader.left() == 1) && (data[reader.offset] == 0) {
			reader.offset++
		}

		summary := fmt.Sprintf("PostgreSQL StartupMessage %d.%d", code>>16, code&0xffff)

		if len(parameters) > 0 {
			summary += " " + strings.Join(parameters, " ")
		}

		tree.addSummary(summary)
	}

	reader.finish()
}

// the fields of a client's message and the summary's tail
func postgresFrontendFields(tree *Tree, root *node, reader *cursor, kind byte) (summary string) {
	switch kind {
	case 'Q':
		query, _ := reader.cString("pgsql.query", "Query")
		summary = " " + shortText(query, postgresSummaryQuery)
	case 'P':
		statement, _ := reader.cString("pgsql.statement", "Statement")
		query, _ := reader.cString("pgsql.query", "Query")
		postgresOIDs(reader)
		summary = " " + textValue(statement) + " " + shortText(query, postgresSummaryQuery)
	case 'B':
		portal, _ := reader.cString("pgsql.portal", "Portal")
		statement, _ := reader.cString("pgsql.statement", "Statement")
		postgresFormats(reader, "pgsql.format", "Parameter formats")
		count, _ := reader.number("pgsql.parameter_count", "Parameters", 2, nil)
		postgresValues(tree, root, reader, int(count), "pgsql.parameter_value", "Parameter")
		postgresFormats(reader, "pgsql.result_format", "Result formats")
		summary = " " + textValue(portal) + " " + textValue(statement)
	case 'E':
		portal, _ := reader.cString("pgsql.portal", "Portal")
		reader.number("pgsql.rows", "Returns rows", 4, func(value uint32) (text string) {
			text = map[bool]string{true: "all", false: strconv.Itoa(int(value))}[value == 0]
			return
		})
		summary = " " + textValue(portal)
	case 'D', 'C':
		what, _ := reader.number("pgsql.what", "Statement or portal", 1, func(value uint32) (text string) {
			text = map[uint32]string{'S': "statement", 'P': "portal"}[value]
			return
		})
		name, _ := reader.cString("pgsql.name", "Name")
		summary = " " + map[uint32]string{'S': "statement", 'P': "portal"}[what] + " " + textValue(name)
	case 'p':
		// a password, or the SASL mechanism and its first data, or SASL data: shown as it is, the traffic is the user's own
		if reader.left() > 0 {
			reader.restField("pgsql.password", "Password or SASL data")
		}
	case 'f':
		message, _ := reader.cString("pgsql.error", "Error message")
		summary = " " + textValue(message)
	case 'F':
		reader.number("pgsql.oid", "Function OID", 4, nil)
	}

	return
}

// the fields of a server's message and the summary's tail
func postgresBackendFields(tree *Tree, root *node, reader *cursor, kind byte, state *streamState) (summary string) {
	switch kind {
	case 'R':
		code, _ := reader.number("pgsql.authtype", "Authentication type", 4, named(postgresAuthentication))
		summary = " " + shortName(postgresAuthentication, uint16(code))

		switch code {
		case 5:
			reader.bytesField("pgsql.salt", "Salt", 4)
		case 10:
			mechanisms := []string{}

			for (reader.left() > 1) && !reader.isShort {
				mechanism, _ := reader.cString("pgsql.auth.sasl.mech", "SASL mechanism")
				mechanisms = append(mechanisms, textValue(mechanism))
			}

			if (reader.left() == 1) && (reader.data[reader.offset] == 0) {
				reader.offset++
			}

			summary += " " + strings.Join(mechanisms, " ")
		}
	case 'K':
		pid, _ := reader.number("pgsql.pid", "Process ID", 4, nil)
		reader.bytesField("pgsql.key", "Secret key", reader.left())
		summary = fmt.Sprintf(" pid %d", pid)
	case 'S':
		name, _ := reader.cString("pgsql.parameter_name", "Parameter name")
		value, _ := reader.cString("pgsql.parameter_value", "Parameter value")
		summary = " " + textValue(name) + "=" + textValue(value)
	case 'Z':
		status, _ := reader.number("pgsql.status", "Status", 1, func(value uint32) (text string) { text = postgresStatus[byte(value)]; return })
		summary = " " + postgresStatus[byte(status)]
	case 'T':
		count, _ := reader.number("pgsql.field.count", "Fields", 2, nil)
		state.columns = int(count)
		names := []string{}

		for index := 0; (index < int(count)) && !reader.isShort && !tree.isFull; index++ {
			fieldStart := reader.offset
			field := tree.add(root, "pgsql.field", "Field", "", fieldStart, 0)
			values := fieldsOf(tree, field, reader.data, fieldStart, reader.end)
			name, _ := values.cString("pgsql.col.name", "Column name")
			values.number("pgsql.oid.table", "Table OID", 4, nil)
			values.number("pgsql.col.index", "Column index", 2, nil)
			values.number("pgsql.oid.type", "Type OID", 4, nil)
			values.number("pgsql.val.length", "Type size", 2, func(value uint32) (text string) { text = strconv.Itoa(int(int16(value))); return })
			values.number("pgsql.col.typemod", "Type modifier", 4, func(value uint32) (text string) { text = strconv.Itoa(int(int32(value))); return })
			values.number("pgsql.format", "Format", 2, postgresFormatText)
			field.value, field.length = textValue(name), values.offset-fieldStart
			reader.offset, reader.isShort = values.offset, values.isShort
			names = append(names, textValue(name))
		}

		summary = fmt.Sprintf(" %d columns %s", count, strings.Join(names[:min(len(names), 8)], " "))
	case 'D':
		count, _ := reader.number("pgsql.field.count", "Columns", 2, nil)
		postgresValues(tree, root, reader, int(count), "pgsql.val.data", "Column")
		summary = fmt.Sprintf(" %d columns", count)
	case 'C':
		tag, _ := reader.cString("pgsql.tag", "Tag")
		summary = " " + textValue(tag)
	case 'E', 'N':
		fields := map[byte]string{}

		for (reader.left() > 1) && !reader.isShort && !tree.isFull {
			code := reader.data[reader.offset]
			label, isKnown := postgresFields[code]

			if !isKnown {
				label = fmt.Sprintf("Field %s", textValue([]byte{code}))
			}

			fieldStart := reader.offset
			end := bytes.IndexByte(reader.data[fieldStart+1:reader.end], 0)

			if end < 0 {
				_, _, _ = reader.take(label+" (no zero byte ends it)", reader.left()+1)
				break
			}

			value, _, ok := reader.take(label, 2+end)

			if !ok {
				break
			}

			fields[code] = textValue(value[1 : 1+end])
			reader.add("pgsql.error_field", label, fields[code], fieldStart, 2+end)
		}

		if (reader.left() == 1) && (reader.data[reader.offset] == 0) {
			reader.offset++
		}

		summary = " " + strings.Trim(fields['S'], `"`) + " " + strings.Trim(fields['C'], `"`) + " " + fields['M']
	case 't':
		postgresOIDs(reader)
	case 'A':
		pid, _ := reader.number("pgsql.pid", "Process ID", 4, nil)
		channel, _ := reader.cString("pgsql.channel", "Channel")
		reader.cString("pgsql.payload", "Payload")
		summary = fmt.Sprintf(" pid %d %s", pid, textValue(channel))
	case 'G', 'H', 'W':
		reader.number("pgsql.copydata.format", "Format", 1, postgresFormatText)
		postgresFormats(reader, "pgsql.format", "Column formats")
	case 'v':
		minor, _ := reader.number("pgsql.minor", "Newest minor version", 4, nil)
		count, _ := reader.number("pgsql.option.count", "Options not known", 4, nil)

		for index := 0; (index < int(count)) && !reader.isShort; index++ {
			reader.cString("pgsql.option", "Option")
		}

		summary = fmt.Sprintf(" 3.%d", minor)
	}

	return
}

func postgresFormatText(value uint32) (text string) {
	text = map[uint32]string{0: "text (0)", 1: "binary (1)"}[value]

	if text == "" {
		text = strconv.Itoa(int(value))
	}

	return
}

// a list of 2-byte format codes with a 2-byte count
func postgresFormats(reader *cursor, name string, label string) {
	count, start, ok := reader.lengthOf(label, 2)

	if !ok {
		return
	}

	list := reader.add(name+"s", label, strconv.Itoa(count), start, min(2+2*count, reader.end-start))
	inner := newCursor(reader.tree, list, reader.data, reader.offset, reader.end, reader.place)

	for index := 0; (index < count) && !inner.isShort; index++ {
		inner.number(name, "Format", 2, postgresFormatText)
	}

	reader.offset, reader.isShort = inner.offset, inner.isShort
}

// count values with a 4-byte length each, -1 for NULL
func postgresValues(tree *Tree, root *node, reader *cursor, count int, name string, label string) {
	for index := 0; (index < count) && !reader.isShort && !tree.isFull; index++ {
		header, valueStart, ok := reader.take(label+" length", 4)

		if !ok {
			return
		}

		size := int(int32(binary.BigEndian.Uint32(header)))
		valueLabel := fmt.Sprintf("%s %d", label, index+1)

		if size < 0 {
			reader.add(name, valueLabel, "NULL", valueStart, 4)
			continue
		}

		value, _, ok := reader.take(valueLabel, size)

		if !ok {
			return
		}

		text := textValue(value)

		if !isText(value) {
			text = hexValue(value)
		}

		reader.add(name, valueLabel, text, valueStart, 4+size)
	}
}

// at most size bytes of text, quoted and escaped, with ... when there were more
func shortText(data []byte, size int) (text string) {
	text = textValue(data[:min(len(data), size)])

	if len(data) > size {
		text += "..."
	}

	return
}

// a list of 4-byte type OIDs with a 2-byte count
func postgresOIDs(reader *cursor) {
	count, start, ok := reader.lengthOf("Parameter types", 2)

	if !ok {
		return
	}

	list := reader.add("pgsql.parameter_types", "Parameter types", strconv.Itoa(count), start, min(2+4*count, reader.end-start))
	inner := newCursor(reader.tree, list, reader.data, reader.offset, reader.end, reader.place)

	for index := 0; (index < count) && !inner.isShort; index++ {
		inner.number("pgsql.oid.type", "Type OID", 4, nil)
	}

	reader.offset, reader.isShort = inner.offset, inner.isShort
}
