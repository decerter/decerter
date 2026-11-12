// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"github.com/decerter/decerter/internal/tlsrecord"
)

// the record layer of a flow: tlsrecord.Conn reads a TLS session from the bytes of a TCP stream, tlsrecord.DTLSConn a DTLS session datagram by datagram
type recordLayer interface {
	Feed(direction tlsrecord.Direction, data []byte) (records []tlsrecord.Record, err error)
	SetSecrets(secrets tlsrecord.Secrets) (records []tlsrecord.Record, err error)
	Session() (session tlsrecord.Session)
}
