// SPDX-License-Identifier: AGPL-3.0-only

// the secrets object is generated for amd64 only (PT_REGS_*), other architectures get stub.go
//go:build amd64

package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// NSS key log line labels, tshark decrypts no TLS 1.3 stream without the two handshake traffic secret lines
const (
	clientRandomLabel    string = "CLIENT_RANDOM"
	clientHandshakeLabel string = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	serverHandshakeLabel string = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	clientTrafficLabel   string = "CLIENT_TRAFFIC_SECRET_0"
	serverTrafficLabel   string = "SERVER_TRAFFIC_SECRET_0"
)

// SSL_CONNECTION.version values and the labels of the handshake traffic secrets (RFC 8446 7.1)
const (
	tls12Version          uint32 = 0x0303
	tls13Version          uint32 = 0x0304
	handshakeLabelPrefix  string = "tls13 "
	clientHandshakeDerive string = "c hs traffic"
	serverHandshakeDerive string = "s hs traffic"
)

// TLS 1.3 cipher suites of OpenSSL: the low 16 bits of SSL_CIPHER.id are the suite on the wire, its hash gives the length of every secret
const (
	cipherSuiteMask           uint32 = 0xffff
	tlsAES128GCMSHA256        uint32 = 0x1301
	tlsAES256GCMSHA384        uint32 = 0x1302
	tlsChaCha20Poly1305SHA256 uint32 = 0x1303
	tlsAES128CCMSHA256        uint32 = 0x1304
	tlsAES128CCM8SHA256       uint32 = 0x1305
	tlsSHA256SHA256           uint32 = 0xc0b4
	tlsSHA384SHA384           uint32 = 0xc0b5
	sha256Length              int    = 32
	sha384Length              int    = 48
)

// read the secrets ringbuf and print one NSS key log block per new session on writer, logs failures on logger, returns when the context is cancelled
func ReadKeyLog(ctx context.Context, eventMap *ebpf.Map, writer io.Writer, logger *slog.Logger) {
	reader, readerErr := ringbuf.NewReader(eventMap)

	if readerErr != nil {
		logger.Error("Could not open secrets ringbuf reader", "error", readerErr)
		return
	}

	closeReader := func() {
		closeErr := reader.Close()

		if closeErr != nil {
			logger.Error("Could not close secrets ringbuf reader", "error", closeErr)
		}
	}
	// the cancelled context closes the reader, which unblocks Read
	stop := context.AfterFunc(ctx, closeReader)

	defer func() {
		// the loop ended before the context was cancelled
		if stop() {
			closeReader()
		}
	}()

	for {
		record, readErr := reader.Read()

		if readErr != nil {
			if errors.Is(readErr, ringbuf.ErrClosed) {
				logger.Debug("Secrets ringbuf reader closed")
				return
			}

			logger.Error("Could not read secrets ringbuf", "error", readErr)
			continue
		}

		var secrets bpfTlsSecrets
		decodeErr := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &secrets)

		if decodeErr != nil {
			logger.Error("Could not decode secrets event", "error", decodeErr)
			continue
		}

		lines, linesErr := keyLogLines(secrets)

		if linesErr != nil {
			logger.Warn("Could not format key log lines", "error", linesErr, "tlsVersion", secrets.TlsVersion, "cipherId", secrets.CipherId)
			continue
		}

		// one write per session, so its lines stay together
		_, writeErr := io.WriteString(writer, strings.Join(lines, "\n")+"\n")

		if writeErr != nil {
			logger.Error("Could not write key log lines", "error", writeErr)
			return
		}
	}
}

// build the NSS key log lines of a session: CLIENT_RANDOM for TLS 1.2, the handshake and application traffic secrets for TLS 1.3
func keyLogLines(secrets bpfTlsSecrets) (lines []string, err error) {
	clientRandom := hex.EncodeToString(secrets.ClientRandom[:])

	switch secrets.TlsVersion {
	case tls12Version:
		lines = []string{keyLogLine(clientRandomLabel, clientRandom, secrets.MasterKey[:])}
		return
	case tls13Version:
		hashLength, ok := hashLength(secrets.CipherId)

		if !ok {
			err = fmt.Errorf("%w: cipher id 0x%x", ErrUnknownCipher, secrets.CipherId)
			return
		}

		newHash := sha256.New

		if hashLength == sha384Length {
			newHash = sha512.New384
		}

		clientHandshake := expandLabel(secrets.HandshakeSecret[:hashLength], clientHandshakeDerive, secrets.HandshakeTrafficHash[:hashLength], hashLength, newHash)
		serverHandshake := expandLabel(secrets.HandshakeSecret[:hashLength], serverHandshakeDerive, secrets.HandshakeTrafficHash[:hashLength], hashLength, newHash)
		lines = []string{
			keyLogLine(clientHandshakeLabel, clientRandom, clientHandshake),
			keyLogLine(serverHandshakeLabel, clientRandom, serverHandshake),
			keyLogLine(clientTrafficLabel, clientRandom, secrets.ClientAppTrafficSecret[:hashLength]),
			keyLogLine(serverTrafficLabel, clientRandom, secrets.ServerAppTrafficSecret[:hashLength]),
		}
		return
	default:
		err = fmt.Errorf("%w: 0x%x", ErrUnknownTLSVersion, secrets.TlsVersion)
		return
	}
}

// one NSS key log line: "<label> <client_random hex> <secret hex>"
func keyLogLine(label string, clientRandom string, secret []byte) (text string) {
	text = label + " " + clientRandom + " " + hex.EncodeToString(secret)
	return
}

// the length is never guessed: a suite that is not listed gives no key log lines, a secret may end in zero bytes so the 64 byte fields can't be trimmed by content
func hashLength(cipherID uint32) (length int, ok bool) {
	ok = true

	switch cipherID & cipherSuiteMask {
	case
		tlsAES128GCMSHA256,
		tlsChaCha20Poly1305SHA256,
		tlsAES128CCMSHA256,
		tlsAES128CCM8SHA256,
		tlsSHA256SHA256:
		length = sha256Length
	case
		tlsAES256GCMSHA384,
		tlsSHA384SHA384:
		length = sha384Length
	default:
		ok = false
	}

	return
}

// HKDF-Expand-Label (RFC 8446 7.1), derives the handshake traffic secrets that TLS 1.3 does not store in the connection
func expandLabel(secret []byte, label string, transcript []byte, length int, newHash func() hash.Hash) (out []byte) {
	fullLabel := handshakeLabelPrefix + label
	info := bytes.Buffer{}
	info.WriteByte(byte(length >> 8))
	info.WriteByte(byte(length))
	info.WriteByte(byte(len(fullLabel)))
	info.WriteString(fullLabel)
	info.WriteByte(byte(len(transcript)))
	info.Write(transcript)

	// HKDF-Expand
	out = make([]byte, 0, length)
	block := []byte{}

	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(newHash, secret)
		mac.Write(block)
		mac.Write(info.Bytes())
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}

	out = out[:length]
	return
}
