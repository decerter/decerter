// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// what the relay reads at once while a flow is observed, the buffer size of io.Copy
	copyBufferLength int = 32 * 1024
	// copies the observer has not taken yet, in chunks and in bytes; a flow over either is relayed without decryption from then on
	observerQueueLength int   = 1024
	maxObserverBytes    int64 = 16 << 20
	// hold queue: the bytes and the time records may wait for the secrets of their session
	maxHoldBytes int           = 1 << 20
	holdTimeout  time.Duration = 10 * time.Second
	// the secrets are looked up with a growing pause while records wait for them
	holdPollStart time.Duration = time.Millisecond
	holdPollMax   time.Duration = 100 * time.Millisecond
)

// decrypt the copies of one flow until the flow ends or decryption stops, records that need the secrets wait for them in the hold queue of the conn
// the secrets are polled from secrets_map: its ringbuf can have only one reader and a session can be in the map before its flow asks, so the map has to be read anyway
func watchTLS(ctx context.Context, observer *TLSObserver, logger *slog.Logger) {
	conn := tlsrecord.New(maxHoldBytes, false)
	isDetected := false
	isSessionPrinted := false
	var prefix []byte
	var holdDeadline time.Time
	pollPause := holdPollStart
	pollTimer := time.NewTimer(holdPollStart)
	pollTimer.Stop()
	defer pollTimer.Stop()

	for {
		var records []tlsrecord.Record
		var err error

		select {
		case <-ctx.Done():
			return
		case chunk, isOpen := <-observer.chunks:
			if !isOpen {
				// the flow is over, a client that sent its first record inside the handshake call and left has its secrets by now
				if conn.Waiting() {
					records, err = lookupSecrets(&conn, observer, true)
					stopOrPrint(&conn, observer, records, err, &isSessionPrinted, logger)
				}

				return
			}

			observer.queuedBytes.Add(-int64(len(chunk.data)))

			if !isDetected {
				// the client speaks first in TLS, with a ClientHello
				if chunk.direction != tlsrecord.ClientDirection {
					observer.Stop(nil, logger)
					return
				}

				prefix = append(prefix, chunk.data...)
				isClientHello, isDecided := tlsrecord.IsClientHello(prefix)

				if !isDecided {
					continue
				}

				if !isClientHello {
					observer.Stop(nil, logger)
					return
				}

				isDetected = true
				chunk.data = prefix
				prefix = nil
			}

			wasWaiting := conn.Waiting()
			records, err = conn.Feed(chunk.direction, chunk.data)

			// the first record that needs the secrets: they are there already if the handshake call of the client has returned
			if (err == nil) && conn.Waiting() && !wasWaiting {
				holdDeadline = time.Now().Add(holdTimeout)
				pollPause = holdPollStart
				released, lookupErr := lookupSecrets(&conn, observer, false)
				records = append(records, released...)
				err = lookupErr

				if conn.Waiting() {
					pollTimer.Reset(pollPause)
				}
			}
		case <-pollTimer.C:
			records, err = lookupSecrets(&conn, observer, time.Now().After(holdDeadline))

			if conn.Waiting() {
				pollPause = min(2*pollPause, holdPollMax)
				pollTimer.Reset(pollPause)
			}
		}

		if !stopOrPrint(&conn, observer, records, err, &isSessionPrinted, logger) {
			return
		}
	}
}

// ask secrets_map for the session of the conn and let the hold queue go if they are there, isLast makes missing secrets an error
func lookupSecrets(conn *tlsrecord.Conn, observer *TLSObserver, isLast bool) (records []tlsrecord.Record, err error) {
	sessionSecrets, found, lookupErr := secrets.Lookup(conn.Session().ClientRandom, observer.secretsBpfMaps)

	if err = lookupErr; err != nil {
		return
	}

	if !found {
		if isLast {
			err = ErrNoSecrets
		}

		return
	}

	records, err = conn.SetSecrets(sessionSecrets)
	return
}

// an error ends the observer with one log line, otherwise the decrypted application data is printed; goOn is false when the observer is done
func stopOrPrint(conn *tlsrecord.Conn, observer *TLSObserver, records []tlsrecord.Record, err error, isSessionPrinted *bool, logger *slog.Logger) (goOn bool) {
	session := conn.Session()

	for _, record := range records {
		if !record.Decrypted || (record.ContentType != tlsrecord.ApplicationDataContentType) {
			continue
		}

		if !*isSessionPrinted {
			*isSessionPrinted = true
			printSession(observer.flow, observer.client, session)
		}

		printRecord(observer.flow, observer.client, session, record)
	}

	if err != nil {
		observer.Stop(err, logger.With("serverName", session.ServerName, "version", tlsrecord.VersionName(session.Version), "cipherSuite", tlsrecord.CipherSuiteName(session.CipherSuite)))
		return
	}

	// the relay stopped the observer
	goOn = observer.Active()
	return
}

// the start of every TLS line, the same fields as the flow line of printFlow
func tlsLinePrefix(flow redirect.Flow, client netip.AddrPort, session tlsrecord.Session) (prefix string) {
	prefix = fmt.Sprintf("tls pid=%d uid=%d comm=%s %s client=%s version=%s suite=%s", flow.Tgid, flow.UID, flow.Comm, flow.OriginalDestination, client, tlsrecord.VersionName(session.Version), tlsrecord.CipherSuiteName(session.CipherSuite))
	return
}

// one line per decrypted session in front of its first record, sni and alpn come from the peers and are quoted
func printSession(flow redirect.Flow, client netip.AddrPort, session tlsrecord.Session) {
	fmt.Printf("%s sni=%q alpn=%q\n", tlsLinePrefix(flow, client, session), session.ServerName, session.Protocol)
}

// one header line per decrypted application data record and its plaintext below, in one write so the records of other flows don't get in between
func printRecord(flow redirect.Flow, client netip.AddrPort, session tlsrecord.Session, record tlsrecord.Record) {
	shown := min(len(record.Payload), intercept.MaxPrintBytes)
	text := fmt.Sprintf("%s direction=%s sequence=%d length=%d shown=%d\n", tlsLinePrefix(flow, client, session), intercept.DirectionName(record.Direction), record.Sequence, len(record.Payload), shown) + intercept.Escape(record.Payload[:shown])
	// stdout is the output of the tool as in printFlow, a failed write has nowhere to go
	_, _ = os.Stdout.WriteString(text)
}
