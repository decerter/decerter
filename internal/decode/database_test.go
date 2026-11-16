// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
	"github.com/jackc/pgx/v5/pgproto3"
)

// the wire bytes of PostgreSQL messages as pgproto3 (pgx, MIT) encodes them: the oracle of the tests
func pgMessages(state *testing.T, messages ...pgproto3.Message) (data []byte) {
	for _, message := range messages {
		encoded, err := message.Encode(data)

		if err != nil {
			state.Fatalf("Could not encode %T: %v", message, err)
		}

		data = encoded
	}

	return
}

// Test if decode.Decode returns with the expected output for PostgreSQL, with the messages pgproto3 encodes: an SSLRequest and the server's S that
// switches both sides to TLS, a startup and a simple query with its answer, an extended query with a NULL parameter, a DataRow of 100 KiB in a joined
// stream, and an ErrorResponse.
func TestPostgresPositive(state *testing.T) {
	hello := tlsRecord(22, 0x0301, handshakeMessage(1, make([]byte, 40)))
	result := mustDecode(state, join(pgMessages(state, &pgproto3.SSLRequest{}), hello), streamContext(9999, v1.UpDirection, true), "")

	if (result.Protocol != postgresProtocol) || (len(result.Tree) != 2) || (result.Tree[1].Name != "pgsql.tls") || (result.Summary != "PostgreSQL SSLRequest; TLS") {
		state.Errorf("Test of PostgreSQL failed, the SSLRequest should be followed by TLS, result: %+v", result)
	}

	result = mustDecode(state, join([]byte("S"), hello), streamContext(5432, v1.DownDirection, true), "")

	if (len(result.Tree) != 2) || (result.Summary != "PostgreSQL encryption SSL accepted; TLS") {
		state.Errorf("Test of PostgreSQL failed, the server's S should be followed by TLS, result: %+v", result)
	}

	client := pgMessages(state,
		&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "alice"}},
		&pgproto3.PasswordMessage{Password: "secret"},
		&pgproto3.Query{String: "SELECT id, name FROM items"},
		&pgproto3.Parse{Name: "s1", Query: "SELECT $1::int", ParameterOIDs: []uint32{23}},
		&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "s1", ParameterFormatCodes: []int16{0}, Parameters: [][]byte{nil}, ResultFormatCodes: []int16{1}},
		&pgproto3.Describe{ObjectType: 'P', Name: ""},
		&pgproto3.Execute{Portal: "", MaxRows: 0},
		&pgproto3.Sync{},
		&pgproto3.Terminate{},
	)
	result = mustDecode(state, client, streamContext(9999, v1.UpDirection, true), "")
	expected := `PostgreSQL StartupMessage 3.0 user="alice"; PostgreSQL Password message; PostgreSQL Query "SELECT id, name FROM items"; ` +
		`PostgreSQL Parse "s1" "SELECT $1::int"; PostgreSQL Bind "" "s1"; PostgreSQL Describe portal ""; PostgreSQL Execute ""; PostgreSQL Sync; PostgreSQL Terminate`

	if (result.Protocol != postgresProtocol) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of PostgreSQL failed, the client's messages should decode, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the PostgreSQL client", result, map[string]string{"pgsql.parameter_value": `"alice"`, "pgsql.parameter_value#1": "NULL", "pgsql.oid.type": "23", "pgsql.result_format": "binary (1)"})
	large := strings.Repeat("x", 100<<10)
	server := pgMessages(state,
		&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}},
		&pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "17.2"},
		&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{1, 2, 3, 4}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id"), TableOID: 1, TableAttributeNumber: 1, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, Format: 0}, {Name: []byte("name"), TableOID: 1, TableAttributeNumber: 2, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte(large)}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2"), nil}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "42P01", Message: `relation "nope" does not exist`, Position: 15},
		&pgproto3.ReadyForQuery{TxStatus: 'E'},
	)
	result = mustDecode(state, server, streamContext(5432, v1.DownDirection, true), "")
	expected = `PostgreSQL Authentication request SASL "SCRAM-SHA-256"; PostgreSQL Authentication request Success; PostgreSQL Parameter status "server_version"="17.2"; ` +
		`PostgreSQL Backend key data pid 4242; PostgreSQL Ready for query idle; PostgreSQL Row description 2 columns "id" "name"; PostgreSQL Data row 2 columns; ` +
		`PostgreSQL Data row 2 columns; PostgreSQL Command completion "SELECT 2"; PostgreSQL Error ERROR 42P01 "relation "nope" does not exist"; PostgreSQL Ready for query in failed transaction`

	if (len(result.Tree) != 11) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of PostgreSQL failed, the server's messages should decode, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the PostgreSQL server", result, map[string]string{"pgsql.val.data#2": `"2"`, "pgsql.val.data#3": "NULL", "pgsql.col.typemod": "-1", "pgsql.error_field#2": `"42P01"`, "pgsql.error_field#4": `"15"`})

	if rows := findAll(result.Tree, "pgsql.val.data"); (len(rows) != 4) || (rows[1].Length != 4+len(large)) {
		state.Errorf("Test of PostgreSQL failed, the 100 KiB column should be one value, rows: %d", len(rows))
	}
}

// Test if decode.Decode returns with the expected errors for PostgreSQL: a typed message with a length under 4, a string without its zero byte, a DataRow
// whose value runs past the message, and a message cut in one read.
func TestPostgresNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data      []byte
		direction v1.Direction
		isJoined  bool
		expected  string
	}{
		"length":  {data: []byte{'Q', 0, 0, 0, 2}, direction: v1.UpDirection, isJoined: true, expected: "the bytes are no PostgreSQL message"},
		"string":  {data: []byte{'Q', 0, 0, 0, 7, 'a', 'b', 'c'}, direction: v1.UpDirection, isJoined: true, expected: "Query (no zero byte ends it): the field runs past the end"},
		"value":   {data: join([]byte{'D', 0, 0, 0, 12}, be16(1), be32(50), []byte("ab")), direction: v1.DownDirection, isJoined: true, expected: "Column 1: the field runs past the end"},
		"cut":     {data: join([]byte{'Q', 0, 0, 0, 40}, []byte("SELECT")), direction: v1.UpDirection, isJoined: false, expected: "the message continues in the next read: 11 of its 41 bytes are here"},
		"startup": {data: join(be32(20), be32(196608), []byte("user\x00x")), direction: v1.UpDirection, isJoined: true, expected: "the stream ends inside the message: 14 of its 20 bytes are kept"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(5432, negative.direction, negative.isJoined), postgresProtocol)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of PostgreSQL failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// a MySQL packet: the 3-byte length, the sequence id and the payload
func mysqlPacket(sequence byte, payload []byte) (data []byte) {
	data = join([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), sequence}, payload)
	return
}

// a length-encoded string of MySQL
func mysqlText(text string) (data []byte) {
	data = join([]byte{byte(len(text))}, []byte(text))
	return
}

func little16(value uint16) (data []byte) {
	data = []byte{byte(value), byte(value >> 8)}
	return
}

func little32(value uint32) (data []byte) {
	data = []byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}
	return
}

// a column definition 41 of a VAR_STRING column
func mysqlColumnPacket(sequence byte, name string) (data []byte) {
	data = mysqlPacket(sequence, join(mysqlText("def"), mysqlText("shop"), mysqlText("items"), mysqlText("items"), mysqlText(name), mysqlText(name), []byte{0x0c}, little16(33), little32(255), []byte{253}, little16(0), []byte{0}, []byte{0, 0}))
	return
}

// Test if decode.Decode returns with the expected output for MySQL: a server greeting v10 by sniffing, the login request, a query and its text result set
// with EOF packets, a row of 100 KiB in a joined stream, OK and ERR, and the SSL request that switches to TLS.
func TestMySQLPositive(state *testing.T) {
	salt := []byte("abcdefgh")
	capabilities := uint32(0x000fa68d | 0x00080000 | 0x00008000)
	greeting := mysqlPacket(0, join([]byte{10}, []byte("8.4.3\x00"), little32(77), salt, []byte{0}, little16(uint16(capabilities)), []byte{255}, little16(2), little16(uint16(capabilities>>16)), []byte{21}, make([]byte, 10), []byte("ijklmnopqrst\x00"), []byte("caching_sha2_password\x00")))
	large := strings.Repeat("y", 100<<10)
	row := join(mysqlText("1"), []byte{0xfd, byte(len(large)), byte(len(large) >> 8), byte(len(large) >> 16)}, []byte(large))
	server := join(greeting, mysqlPacket(2, []byte{0, 0, 0, 2, 0, 0, 0}), mysqlPacket(1, []byte{2}), mysqlColumnPacket(2, "id"), mysqlColumnPacket(3, "name"),
		mysqlPacket(4, []byte{0xfe, 0, 0, 0x22, 0}), mysqlPacket(5, row), mysqlPacket(6, join(mysqlText("2"), []byte{0xfb})), mysqlPacket(7, []byte{0xfe, 0, 0, 0x22, 0}),
		mysqlPacket(1, join([]byte{0xff}, little16(1146), []byte("#42S02Table 'shop.nope' doesn't exist"))))
	result := mustDecode(state, server, streamContext(13306, v1.DownDirection, true), "")
	expected := `MySQL server greeting "8.4.3" thread 77 "caching_sha2_password"; MySQL OK, 0 rows; MySQL result set, 2 columns; MySQL column shop.items.id VAR_STRING; ` +
		`MySQL column shop.items.name VAR_STRING; MySQL EOF; MySQL row "1" "` + strings.Repeat("y", 75) + `...; MySQL row "2" NULL; ` +
		`MySQL EOF, the end of the result set; MySQL error 1146 "Table 'shop.nope' doesn't exist"`

	if (result.Protocol != mysqlProtocol) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of MySQL failed, the server's packets should decode, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the MySQL server", result, map[string]string{"mysql.version": `"8.4.3"`, "mysql.salt2": hexValue([]byte("ijklmnopqrst\x00")), "mysql.sqlstate": `"42S02"`, "mysql.field#3": "NULL", "mysql.field.type": "VAR_STRING (253)"})
	login := mysqlPacket(1, join(little32(capabilities|0x08), little32(1<<24), []byte{255}, make([]byte, 23), []byte("bob\x00"), []byte{3, 1, 2, 3}, []byte("shop\x00"), []byte("caching_sha2_password\x00")))
	client := join(login, mysqlPacket(0, join([]byte{3}, []byte("SELECT id, name FROM items"))), mysqlPacket(0, []byte{0x0e}), mysqlPacket(0, []byte{1}))
	result = mustDecode(state, client, streamContext(3306, v1.UpDirection, true), "")
	expected = `MySQL login request user "bob" schema "shop" "caching_sha2_password"; MySQL Query "SELECT id, name FROM items"; MySQL Ping; MySQL Quit`

	if (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of MySQL failed, the client's packets should decode, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	hello := tlsRecord(22, 0x0301, handshakeMessage(1, make([]byte, 40)))
	result = mustDecode(state, join(mysqlPacket(1, join(little32(capabilities|0x800), little32(1<<24), []byte{255}, make([]byte, 23))), hello), streamContext(3306, v1.UpDirection, true), "")

	if (len(result.Tree) != 2) || (result.Summary != "MySQL SSL request; TLS") {
		state.Errorf("Test of MySQL failed, the SSL request should be followed by TLS, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors for MySQL: a packet cut in one read, a length-encoded string past its packet, a string without
// its zero byte.
func TestMySQLNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data      []byte
		direction v1.Direction
		isJoined  bool
		expected  string
	}{
		"cut":     {data: mysqlPacket(0, []byte("\x03SELECT 1"))[:8], direction: v1.UpDirection, isJoined: false, expected: "the packet continues in the next read: 8 of its 13 bytes are here"},
		"column":  {data: mysqlPacket(2, join(mysqlText("def"), []byte{40}, []byte("ab"))), direction: v1.DownDirection, isJoined: true, expected: "Database: the field runs past the end"},
		"version": {data: mysqlPacket(0, join([]byte{10}, []byte("8.4.3"))), direction: v1.DownDirection, isJoined: true, expected: "Version (no zero byte ends it)"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(3306, negative.direction, negative.isJoined), mysqlProtocol)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of MySQL failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// Fuzz if decode.Decode never fails on any bytes as PostgreSQL and MySQL, over a read and a joined stream each way.
func FuzzDatabase(fuzz *testing.F) {
	fuzz.Add(join(be32(8), be32(postgresSSLCode), []byte("S"), []byte{'Q', 0, 0, 0, 9, 'a', 'b', 'c', 0}))
	fuzz.Add(join([]byte{'D', 0, 0, 0, 16}, be16(2), be32(2), []byte("ab"), be32(0xffffffff), []byte{'E', 0, 0, 0, 9, 'S', 'x', 0, 0}))
	fuzz.Add(join(mysqlPacket(0, join([]byte{10}, []byte("8.0\x00"), make([]byte, 40))), mysqlPacket(1, []byte{1}), mysqlColumnPacket(2, "a"), mysqlPacket(3, []byte{0xfe, 0, 0, 0, 0}), mysqlPacket(4, []byte{1, 'x'})))
	fuzz.Add(mysqlPacket(1, join(little32(0x3fffff), little32(0), []byte{0}, make([]byte, 23), []byte("u\x00"), []byte{0}, []byte("d\x00p\x00"), []byte{4, 1, 'a', 1, 'b'})))
	contexts := []Context{}

	for _, direction := range []v1.Direction{v1.UpDirection, v1.DownDirection} {
		for _, isJoined := range []bool{false, true} {
			contexts = append(contexts, streamContext(5432, direction, isJoined), streamContext(3306, direction, isJoined))
		}
	}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, contexts, []string{"", postgresProtocol, mysqlProtocol})
	})
}
