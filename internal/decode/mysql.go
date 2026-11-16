// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// the MySQL client/server protocol from the MySQL source documentation ("Client/Server Protocol"): the packet header, the initial handshake v10,
// the handshake response 41 and the SSL request, the command packets, OK, ERR and EOF, and text result sets (column count, column definitions 41,
// rows); MariaDB speaks the same; a stream follows the result set in streamState.mode, and after an SSL request the rest is TLS
const (
	mysqlProtocol string = "mysql"
	mysqlTitle    string = "MySQL Protocol"
	// a packet header: 3 bytes of length, little-endian, and the sequence id
	mysqlHeaderBytes int = 4
	// the payload of an SSL request: the first 32 bytes of a handshake response
	mysqlSSLRequestBytes int = 32
	// streamState.mode inside a result set: the column definitions to come (streamState.waiting of them), then the rows
	mysqlColumnsMode string = "columns"
	mysqlRowsMode    string = "rows"
	// capability flags
	mysqlConnectWithDB uint64 = 0x00000008
	mysqlSSL           uint64 = 0x00000800
	mysqlSecure        uint64 = 0x00008000
	mysqlPluginAuth    uint64 = 0x00080000
	mysqlConnectAttrs  uint64 = 0x00100000
	mysqlLengthAuth    uint64 = 0x00200000
	// the bytes of a query the summary shows
	mysqlSummaryQuery int = 80
	// streamState.command after a column definition: an EOF then is the one before the rows
	mysqlAfterColumn byte = 1
)

var (
	mysqlCommands = nameTable{names: map[uint16]string{
		0x00: "Sleep", 0x01: "Quit", 0x02: "Use Database", 0x03: "Query", 0x04: "Show Fields", 0x05: "Create Database", 0x06: "Drop Database",
		0x07: "Refresh", 0x08: "Shutdown", 0x09: "Statistics", 0x0a: "Process List", 0x0b: "Connect", 0x0c: "Kill Server Thread", 0x0d: "Dump Debuginfo",
		0x0e: "Ping", 0x0f: "Time", 0x10: "Insert Delayed", 0x11: "Change User", 0x12: "Send Binlog", 0x13: "Send Table", 0x14: "Slave Connect",
		0x15: "Register Slave", 0x16: "Prepare Statement", 0x17: "Execute Statement", 0x18: "Send BLOB", 0x19: "Close Statement", 0x1a: "Reset Statement",
		0x1b: "Set Option", 0x1c: "Fetch Data", 0x1d: "Daemon", 0x1e: "Binlog Dump GTID", 0x1f: "Reset Connection",
	}, unknown: "Command 0x%02x"}
	mysqlTypes = nameTable{names: map[uint16]string{
		0: "DECIMAL", 1: "TINY", 2: "SHORT", 3: "LONG", 4: "FLOAT", 5: "DOUBLE", 6: "NULL", 7: "TIMESTAMP", 8: "LONGLONG", 9: "INT24", 10: "DATE",
		11: "TIME", 12: "DATETIME", 13: "YEAR", 15: "VARCHAR", 16: "BIT", 245: "JSON", 246: "NEWDECIMAL", 247: "ENUM", 248: "SET", 249: "TINY_BLOB",
		250: "MEDIUM_BLOB", 251: "LONG_BLOB", 252: "BLOB", 253: "VAR_STRING", 254: "STRING", 255: "GEOMETRY",
	}, unknown: "Type %d"}
	mysqlCapabilities = []struct {
		mask uint64
		name string
	}{
		{0x1, "LONG_PASSWORD"}, {0x2, "FOUND_ROWS"}, {0x4, "LONG_FLAG"}, {0x8, "CONNECT_WITH_DB"}, {0x10, "NO_SCHEMA"}, {0x20, "COMPRESS"}, {0x40, "ODBC"},
		{0x80, "LOCAL_FILES"}, {0x100, "IGNORE_SPACE"}, {0x200, "PROTOCOL_41"}, {0x400, "INTERACTIVE"}, {0x800, "SSL"}, {0x1000, "IGNORE_SIGPIPE"},
		{0x2000, "TRANSACTIONS"}, {0x8000, "SECURE_CONNECTION"}, {0x10000, "MULTI_STATEMENTS"}, {0x20000, "MULTI_RESULTS"}, {0x40000, "PS_MULTI_RESULTS"},
		{0x80000, "PLUGIN_AUTH"}, {0x100000, "CONNECT_ATTRS"}, {0x200000, "PLUGIN_AUTH_LENENC_CLIENT_DATA"}, {0x400000, "CAN_HANDLE_EXPIRED_PASSWORDS"},
		{0x800000, "SESSION_TRACK"}, {0x1000000, "DEPRECATE_EOF"}, {0x2000000, "OPTIONAL_RESULTSET_METADATA"}, {0x4000000, "ZSTD_COMPRESSION"},
		{0x8000000, "QUERY_ATTRIBUTES"},
	}
)

func init() {
	register(decoder{
		Protocol:   mysqlProtocol,
		Title:      mysqlTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 3306}, {Layer: v1.TLSLayer, Number: 3306}},
		hint:       noHint,
		sniff:      mysqlSniff,
		decode:     framedDecode(mysqlProtocol),
		fromTarget: nil,
		frame:      mysqlFrame,
		pdu:        mysqlPDU,
		unit:       "packet",
	})
}

// a server greeting (protocol 10 and a version text) is certain; a client's query packet likely; packets that frame to the end possible
func mysqlSniff(data []byte, context Context) (score int) {
	if (context.Transport != StreamTransport) || (len(data) < mysqlHeaderBytes+1) {
		return
	}

	length := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	payload := data[mysqlHeaderBytes:min(len(data), mysqlHeaderBytes+length)]

	if (length == 0) || (len(payload) == 0) {
		return
	}

	switch {
	case (data[3] == 0) && (payload[0] == 10) && (length > 40):
		end := bytes.IndexByte(payload[1:], 0)

		if (end > 0) && isText(payload[1:1+end]) && (payload[1] >= '0') && (payload[1] <= '9') {
			score = 100
		}
	case (data[3] == 0) && (payload[0] == 0x03) && (len(payload) > 1) && isText(payload[1:]):
		score = 60
	case (data[3] == 1) && (len(payload) >= mysqlSSLRequestBytes) && bytes.Equal(payload[9:mysqlSSLRequestBytes], make([]byte, 23)):
		score = 90
	default:
		// packets with sequence ids that frame up to the end of the bytes
		offset, count := 0, 0

		for (offset+mysqlHeaderBytes <= len(data)) && (count < 64) {
			offset += mysqlHeaderBytes + (int(data[offset]) | int(data[offset+1])<<8 | int(data[offset+2])<<16)
			count++
		}

		if offset == len(data) {
			score = 15
		}
	}

	return
}

func mysqlFrame(data []byte, state *streamState) (length int) {
	if len(data) < mysqlHeaderBytes {
		return
	}

	length = mysqlHeaderBytes + (int(data[0]) | int(data[1])<<8 | int(data[2])<<16)
	return
}

// a length-encoded integer at the cursor, null for 0xfb
func (reader *cursor) lengthEncoded(name string, label string) (value uint64, isNull bool, ok bool) {
	if reader.left() == 0 {
		_, _, _ = reader.take(label, 1)
		return
	}

	first := reader.data[reader.offset]
	size := map[byte]int{0xfc: 2, 0xfd: 3, 0xfe: 8}[first]

	switch {
	case first == 0xfb:
		reader.offset++
		reader.add(name, label, "NULL", reader.offset-1, 1)
		isNull, ok = true, true
		return
	case first == 0xff:
		_, _, _ = reader.take(label+" (0xff is no length)", reader.left()+1)
		return
	case size == 0:
		value, ok = reader.little(name, label, 1, nil)
		return
	}

	header, start, ok := reader.take(label, 1+size)

	if !ok {
		return
	}

	for index := size; index >= 1; index-- {
		value = value<<8 | uint64(header[index])
	}

	reader.add(name, label, strconv.FormatUint(value, 10), start, 1+size)
	return
}

// a length-encoded string, text quoted and escaped, else hex
func (reader *cursor) lengthEncodedText(name string, label string) (text string, ok bool) {
	start := reader.offset
	length, isNull, ok := reader.peekLength()

	if !ok {
		_, _, _ = reader.take(label, reader.left()+1)
		return
	}

	if isNull {
		reader.offset++
		text = "NULL"
		reader.add(name, label, text, start, 1)
		return
	}

	header := reader.offset - start
	value, _, ok := reader.take(label, int(length))

	if !ok {
		return
	}

	text = textValue(value)

	if !isText(value) {
		text = hexValue(value)
	}

	reader.add(name, label, text, start, header+len(value))
	return
}

// a length-encoded integer without a node: the cursor moves past it; ok is false when it is cut short or 0xff
func (reader *cursor) peekLength() (length uint64, isNull bool, ok bool) {
	if reader.left() == 0 {
		return
	}

	first := reader.data[reader.offset]
	size := map[byte]int{0xfc: 2, 0xfd: 3, 0xfe: 8}[first]

	switch {
	case first == 0xfb:
		isNull, ok = true, true
		return
	case first == 0xff:
		return
	case size == 0:
		length = uint64(first)
		reader.offset++
		ok = length <= uint64(reader.left())
		return
	case reader.left() < 1+size:
		return
	}

	for index := size; index >= 1; index-- {
		length = length<<8 | uint64(reader.data[reader.offset+index])
	}

	reader.offset += 1 + size
	ok = length <= uint64(reader.left())
	return
}

func mysqlCapabilityText(value uint64) (text string) {
	names := []string{}

	for _, capability := range mysqlCapabilities {
		if value&capability.mask != 0 {
			names = append(names, capability.name)
		}
	}

	text = fmt.Sprintf("0x%08x %s", value, strings.Join(names, " "))
	return
}

func mysqlPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	root = tree.add(nil, mysqlProtocol, mysqlTitle, "", start, len(data)-start)
	reader := fieldsOf(tree, root, data, start, len(data))
	length, _ := reader.little("mysql.packet_length", "Packet Length", 3, nil)
	sequence, _ := reader.little("mysql.packet_number", "Packet Number", 1, nil)
	state.sequence = int(sequence)
	payload := data[reader.offset:]
	kind, summary := "", ""

	switch {
	case len(payload) == 0:
		kind, summary = "empty packet", "MySQL empty packet"
	case state.context.Direction == v1.UpDirection:
		kind, summary = mysqlClient(tree, root, reader, payload, state)
	default:
		kind, summary = mysqlServer(tree, root, reader, payload, state)
	}

	if kind != "column definition" {
		state.command = 0
	}

	if (int(length) == 0xffffff) && (kind != "") {
		kind += ", continued in the next packet"
	}

	tree.setLabel(root, mysqlTitle+" ("+kind+")")

	if reader.left() > 0 {
		reader.restField("mysql.payload", "Payload")
	}

	reader.finish()
	tree.addSummary(summary)
	return
}

// a client's packet: a command with sequence 0, else the handshake response, the SSL request, or more auth data
func mysqlClient(tree *Tree, root *node, reader *cursor, payload []byte, state *streamState) (kind string, summary string) {
	if state.sequence > 0 {
		if (len(payload) >= mysqlSSLRequestBytes) && bytes.Equal(payload[9:mysqlSSLRequestBytes], make([]byte, 23)) {
			kind, summary = mysqlHandshakeResponse(tree, root, reader, payload, state)
			return
		}

		kind, summary = "auth data", "MySQL auth data"
		reader.bytesField("mysql.auth_data", "Auth data", reader.left())
		return
	}

	state.mode, state.waiting = "", 0
	command, _ := reader.number("mysql.command", "Command", 1, hexNumber(mysqlCommands, 2))
	kind = shortName(mysqlCommands, uint16(command))
	summary = "MySQL " + kind

	switch command {
	case 0x03, 0x16:
		// a query with query attributes starts with their count, a plain one is its text
		query := reader.data[reader.offset:reader.end]
		reader.textField("mysql.query", "Statement", reader.left())
		summary += " " + shortText(query, mysqlSummaryQuery)
	case 0x02, 0x04, 0x05, 0x06:
		name := reader.data[reader.offset:reader.end]
		reader.textField("mysql.schema", "Schema", reader.left())
		summary += " " + textValue(name)
	case 0x17:
		statement, _ := reader.little("mysql.stmt_id", "Statement ID", 4, nil)
		reader.number("mysql.exec_flags", "Flags", 1, func(value uint32) (text string) { text = fmt.Sprintf("0x%02x", value); return })
		reader.little("mysql.exec_iter", "Iterations", 4, nil)
		summary += fmt.Sprintf(" id %d", statement)
	case 0x19, 0x1a, 0x1c:
		statement, _ := reader.little("mysql.stmt_id", "Statement ID", 4, nil)
		summary += fmt.Sprintf(" id %d", statement)
	case 0x0c:
		thread, _ := reader.little("mysql.thread_id", "Thread ID", 4, nil)
		summary += fmt.Sprintf(" %d", thread)
	case 0x11:
		user, _ := reader.cString("mysql.user", "Username")
		summary += " " + textValue(user)
	case 0x1b:
		reader.little("mysql.option", "Option", 2, nil)
	}

	return
}

// the handshake response 41, or the SSL request (its first 32 bytes alone) after which the rest is TLS
func mysqlHandshakeResponse(tree *Tree, root *node, reader *cursor, payload []byte, state *streamState) (kind string, summary string) {
	capabilities, _ := reader.little("mysql.caps.client", "Client Capabilities", 4, mysqlCapabilityText)
	reader.little("mysql.max_packet", "MAX Packet", 4, nil)
	reader.little("mysql.collation", "Collation", 1, nil)
	reader.bytesField("mysql.unused", "Unused", 23)

	if len(payload) == mysqlSSLRequestBytes {
		kind, summary = "SSL request", "MySQL SSL request"
		state.mode = starttlsMode
		return
	}

	kind = "login request"
	user, _ := reader.cString("mysql.user", "Username")
	summary = "MySQL login request user " + textValue(user)

	switch {
	case capabilities&mysqlLengthAuth != 0:
		reader.lengthEncodedText("mysql.passwd", "Auth response")
	case capabilities&mysqlSecure != 0:
		reader.opaque("mysql.passwd", "Auth response", 1)
	default:
		reader.cString("mysql.passwd", "Auth response")
	}

	if (capabilities&mysqlConnectWithDB != 0) && (reader.left() > 0) {
		schema, _ := reader.cString("mysql.schema", "Schema")
		summary += " schema " + textValue(schema)
	}

	if (capabilities&mysqlPluginAuth != 0) && (reader.left() > 0) {
		plugin, _ := reader.cString("mysql.client_auth_plugin", "Client Auth Plugin")
		summary += " " + textValue(plugin)
	}

	if (capabilities&mysqlConnectAttrs != 0) && (reader.left() > 0) {
		length, _, ok := reader.peekLength()

		if ok {
			attributes := reader.add("mysql.connattrs", "Connection Attributes", fmt.Sprintf("%d bytes", length), reader.offset, int(length))
			inner := newCursor(tree, attributes, reader.data, reader.offset, reader.offset+int(length), reader.place)

			for (inner.left() > 0) && !inner.isShort && !tree.isFull {
				inner.lengthEncodedText("mysql.connattrs.name", "Name")
				inner.lengthEncodedText("mysql.connattrs.value", "Value")
			}

			reader.offset = inner.end
		}
	}

	return
}

// a server's packet: the greeting with sequence 0, OK, ERR, EOF, the parts of a result set, or auth packets
func mysqlServer(tree *Tree, root *node, reader *cursor, payload []byte, state *streamState) (kind string, summary string) {
	first := payload[0]

	switch {
	case (state.sequence == 0) && (first == 10) && (state.index == 0):
		kind, summary = mysqlGreeting(reader)
		return
	case first == 0xff:
		kind = "error"
		state.mode = ""
		reader.number("mysql.response_code", "Response Code", 1, func(value uint32) (text string) { text = "0xff (ERR)"; return })
		code, _ := reader.little("mysql.error_code", "Error Code", 2, nil)

		if (reader.left() > 0) && (reader.data[reader.offset] == '#') {
			reader.offset++
			reader.textField("mysql.sqlstate", "SQL state", min(5, reader.left()))
		}

		message := reader.data[reader.offset:reader.end]
		reader.textField("mysql.error.message", "Error message", reader.left())
		summary = fmt.Sprintf("MySQL error %d %s", code, shortText(message, mysqlSummaryQuery))
		return
	case (first == 0xfe) && (len(payload) < 9):
		kind = "EOF"
		reader.number("mysql.response_code", "Response Code", 1, func(value uint32) (text string) { text = "0xfe (EOF)"; return })

		if reader.left() >= 4 {
			reader.little("mysql.warnings", "Warnings", 2, nil)
			reader.little("mysql.server_status", "Server Status", 2, func(value uint64) (text string) { text = fmt.Sprintf("0x%04x", value); return })
		}

		// the EOF right after the column definitions starts the rows, the one after the rows ends the result set
		switch {
		case state.mode == mysqlColumnsMode:
			state.mode = mysqlRowsMode
		case (state.mode == mysqlRowsMode) && (state.command != mysqlAfterColumn):
			state.mode = ""
			kind = "EOF, the end of the result set"
		}

		summary = "MySQL " + kind
		return
	case bytes.HasPrefix(payload, []byte("\x03def")):
		kind, summary = mysqlColumn(reader, state)
		return
	case state.mode == mysqlRowsMode:
		kind = "row"
		values := []string{}

		for index := 0; (index < state.columns) && (reader.left() > 0) && !reader.isShort && !tree.isFull; index++ {
			value, _ := reader.lengthEncodedText("mysql.field", fmt.Sprintf("Field %d", index+1))
			values = append(values, value)
		}

		// the values are quoted and escaped already
		text := strings.Join(values, " ")

		if len(text) > mysqlSummaryQuery {
			text = text[:mysqlSummaryQuery] + "..."
		}

		summary = "MySQL row " + text
		return
	case first == 0x00:
		kind = "OK"
		state.mode = ""
		reader.number("mysql.response_code", "Response Code", 1, func(value uint32) (text string) { text = "0x00 (OK)"; return })
		rows, _, _ := reader.lengthEncoded("mysql.affected_rows", "Affected Rows")
		reader.lengthEncoded("mysql.insert_id", "Last Insert ID")

		if reader.left() >= 4 {
			reader.little("mysql.server_status", "Server Status", 2, func(value uint64) (text string) { text = fmt.Sprintf("0x%04x", value); return })
			reader.little("mysql.warnings", "Warnings", 2, nil)
		}

		summary = fmt.Sprintf("MySQL OK, %d rows", rows)
		return
	case first == 0xfe:
		kind = "auth switch request"
		reader.number("mysql.response_code", "Response Code", 1, nil)
		plugin, _ := reader.cString("mysql.auth_plugin", "Auth Plugin")
		reader.bytesField("mysql.auth_data", "Auth data", reader.left())
		summary = "MySQL auth switch request " + textValue(plugin)
		return
	case first == 0xfb:
		kind = "LOCAL INFILE request"
		reader.number("mysql.response_code", "Response Code", 1, nil)
		name := reader.data[reader.offset:reader.end]
		reader.textField("mysql.infile", "File name", reader.left())
		summary = "MySQL LOCAL INFILE " + textValue(name)
		return
	case (first == 0x01) && (state.mode == ""):
		kind = "auth more data"
		reader.number("mysql.response_code", "Response Code", 1, nil)
		reader.bytesField("mysql.auth_data", "Auth data", reader.left())
		summary = "MySQL auth more data"
		return
	}

	// a result set starts with its column count, the whole payload
	count, _, ok := reader.lengthEncoded("mysql.num_fields", "Number of fields")

	if ok && (reader.left() == 0) {
		kind = "result set"
		state.mode, state.waiting, state.columns = mysqlColumnsMode, int(count), int(count)
		summary = fmt.Sprintf("MySQL result set, %d columns", count)
		return
	}

	kind, summary = "response", "MySQL response"
	return
}

// the initial handshake packet v10
func mysqlGreeting(reader *cursor) (kind string, summary string) {
	kind = "server greeting"
	reader.little("mysql.protocol", "Protocol", 1, nil)
	version, _ := reader.cString("mysql.version", "Version")
	thread, _ := reader.little("mysql.thread_id", "Thread ID", 4, nil)
	reader.bytesField("mysql.salt", "Salt", 8)
	reader.bytesField("mysql.filler", "Filler", 1)
	lower, _ := reader.little("mysql.caps.server", "Server Capabilities", 2, mysqlCapabilityText)
	reader.little("mysql.server_language", "Server Language", 1, nil)
	reader.little("mysql.server_status", "Server Status", 2, func(value uint64) (text string) { text = fmt.Sprintf("0x%04x", value); return })
	upper, _ := reader.little("mysql.extcaps.server", "Extended Server Capabilities", 2, func(value uint64) (text string) { text = mysqlCapabilityText(value << 16); return })
	authLength, _ := reader.little("mysql.auth_plugin.length", "Authentication Plugin Length", 1, nil)
	reader.bytesField("mysql.unused", "Unused", 10)
	capabilities := upper<<16 | lower

	if capabilities&mysqlSecure != 0 {
		reader.bytesField("mysql.salt2", "Salt", min(reader.left(), max(13, int(authLength)-8)))
	}

	plugin := []byte(nil)

	if (capabilities&mysqlPluginAuth != 0) && (reader.left() > 0) {
		plugin, _ = reader.cString("mysql.auth_plugin", "Authentication Plugin")
	}

	summary = fmt.Sprintf("MySQL server greeting %s thread %d", textValue(version), thread)

	if len(plugin) > 0 {
		summary += " " + textValue(plugin)
	}

	return
}

// a column definition 41
func mysqlColumn(reader *cursor, state *streamState) (kind string, summary string) {
	kind = "column definition"
	reader.lengthEncodedText("mysql.field.catalog", "Catalog")
	schema, _ := reader.lengthEncodedText("mysql.field.db", "Database")
	table, _ := reader.lengthEncodedText("mysql.field.table", "Table")
	reader.lengthEncodedText("mysql.field.org_table", "Original table")
	name, _ := reader.lengthEncodedText("mysql.field.name", "Name")
	reader.lengthEncodedText("mysql.field.org_name", "Original name")
	reader.lengthEncoded("mysql.field.fields_length", "Length of the fixed fields")
	reader.little("mysql.field.charsetnr", "Charset number", 2, nil)
	reader.little("mysql.field.length", "Length", 4, nil)
	fieldType, _ := reader.little("mysql.field.type", "Type", 1, func(value uint64) (text string) { text = nameOf(mysqlTypes, uint16(value)); return })
	reader.little("mysql.field.flags", "Flags", 2, func(value uint64) (text string) { text = fmt.Sprintf("0x%04x", value); return })
	reader.little("mysql.field.decimals", "Decimals", 1, nil)

	if reader.left() >= 2 {
		reader.bytesField("mysql.field.filler", "Filler", 2)
	}

	state.command = mysqlAfterColumn

	if state.mode == mysqlColumnsMode {
		state.waiting--

		// without EOF packets (CLIENT_DEPRECATE_EOF) the rows come right after the last column
		if state.waiting <= 0 {
			state.mode = mysqlRowsMode
		}
	}

	summary = fmt.Sprintf("MySQL column %s.%s.%s %s", strings.Trim(schema, `"`), strings.Trim(table, `"`), strings.Trim(name, `"`), shortName(mysqlTypes, uint16(fieldType)))
	return
}
