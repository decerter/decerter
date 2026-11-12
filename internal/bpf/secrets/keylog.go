// SPDX-License-Identifier: AGPL-3.0-only

// the secrets object is generated for amd64 and arm64 (PT_REGS_*), other architectures get stub.go
//go:build amd64 || arm64

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

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tlsrecord"
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
	dtls12Version         uint32 = 0xfefd
	handshakeLabelPrefix  string = "tls13 "
	clientHandshakeDerive string = "c hs traffic"
	serverHandshakeDerive string = "s hs traffic"
)

// tls_secrets.secret_mask bits of the BoringSSL ssl_log_secret labels, as in secrets.h
const (
	clientRandomBit    uint32 = 1
	clientHandshakeBit uint32 = 2
	serverHandshakeBit uint32 = 4
	clientTrafficBit   uint32 = 8
	serverTrafficBit   uint32 = 16
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

// the secrets of a session by its client_random for the record layer, found is false until the uprobe has seen the complete secrets
// run mode has no reader on the secrets ringbuf, the proxy asks here when a record needs its keys
func Lookup(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (sessionSecrets tlsrecord.Secrets, found bool, err error) {
	secrets, found, lookupErr := lookup(clientRandom, bpfMaps)

	if err = lookupErr; (err != nil) || !found {
		return
	}

	sessionSecrets, err = recordSecrets(secrets)
	found = err == nil
	return
}

// the NSS key log lines of a session by its client_random for the capture writer, each line ends with a newline, found is false until the uprobe has seen the complete secrets
func LookupKeyLog(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (keyLog string, found bool, err error) {
	secrets, found, lookupErr := lookup(clientRandom, bpfMaps)

	if err = lookupErr; (err != nil) || !found {
		return
	}

	lines, linesErr := keyLogLines(secrets)

	if err = linesErr; err != nil {
		found = false
		return
	}

	keyLog = strings.Join(lines, "\n") + "\n"
	return
}

func lookup(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (secrets bpfTlsSecrets, found bool, err error) {
	key := bpfClientRandom{
		Value: clientRandom,
	}
	lookupErr := bpfMaps[SecretsMap].Lookup(&key, &secrets)

	if errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		return
	}

	if err = lookupErr; err != nil {
		err = fmt.Errorf("lookup %s: %w", bpfMapSecretsMap, err)
		return
	}

	found = true
	return
}

// the secrets the way the key log and the record layer take them: the TLS 1.3 secrets cut to the hash length of the suite and the handshake traffic secrets derived
func recordSecrets(secrets bpfTlsSecrets) (sessionSecrets tlsrecord.Secrets, err error) {
	sessionSecrets.Version = uint16(secrets.TlsVersion)

	switch secrets.TlsVersion {
	case
		tls12Version,
		dtls12Version:
		sessionSecrets.MasterKey = secrets.MasterKey[:]
		return
	case tls13Version:
		// BoringSSL passed the secrets with their length, the handshake traffic secrets included
		if secrets.SecretLength != 0 {
			length := int(secrets.SecretLength)

			if (length != sha256Length) && (length != sha384Length) {
				err = fmt.Errorf("%w: %d", ErrSecretLength, length)
				return
			}

			sessionSecrets.ClientHandshakeTrafficSecret = secrets.ClientHandshakeTrafficSecret[:length]
			sessionSecrets.ServerHandshakeTrafficSecret = secrets.ServerHandshakeTrafficSecret[:length]
			sessionSecrets.ClientTrafficSecret = secrets.ClientAppTrafficSecret[:length]
			sessionSecrets.ServerTrafficSecret = secrets.ServerAppTrafficSecret[:length]
			return
		}

		// OpenSSL: the length comes from the suite, the handshake traffic secrets are derived
		hashLength, ok := hashLength(secrets.CipherId)

		if !ok {
			err = fmt.Errorf("%w: cipher id 0x%x", ErrUnknownCipher, secrets.CipherId)
			return
		}

		newHash := sha256.New

		if hashLength == sha384Length {
			newHash = sha512.New384
		}

		sessionSecrets.ClientHandshakeTrafficSecret = expandLabel(secrets.HandshakeSecret[:hashLength], clientHandshakeDerive, secrets.HandshakeTrafficHash[:hashLength], hashLength, newHash)
		sessionSecrets.ServerHandshakeTrafficSecret = expandLabel(secrets.HandshakeSecret[:hashLength], serverHandshakeDerive, secrets.HandshakeTrafficHash[:hashLength], hashLength, newHash)
		sessionSecrets.ClientTrafficSecret = secrets.ClientAppTrafficSecret[:hashLength]
		sessionSecrets.ServerTrafficSecret = secrets.ServerAppTrafficSecret[:hashLength]
		return
	default:
		err = fmt.Errorf("%w: 0x%x", ErrUnknownTLSVersion, secrets.TlsVersion)
		return
	}
}

// build the NSS key log lines of a session: CLIENT_RANDOM for TLS 1.2 and DTLS 1.2, the handshake and application traffic secrets for TLS 1.3
func keyLogLines(secrets bpfTlsSecrets) (lines []string, err error) {
	sessionSecrets, secretsErr := recordSecrets(secrets)

	if err = secretsErr; err != nil {
		return
	}

	clientRandom := hex.EncodeToString(secrets.ClientRandom[:])

	if sessionSecrets.Version != tlsrecord.VersionTLS13 {
		lines = []string{keyLogLine(clientRandomLabel, clientRandom, sessionSecrets.MasterKey)}
		return
	}

	lines = []string{
		keyLogLine(clientHandshakeLabel, clientRandom, sessionSecrets.ClientHandshakeTrafficSecret),
		keyLogLine(serverHandshakeLabel, clientRandom, sessionSecrets.ServerHandshakeTrafficSecret),
		keyLogLine(clientTrafficLabel, clientRandom, sessionSecrets.ClientTrafficSecret),
		keyLogLine(serverTrafficLabel, clientRandom, sessionSecrets.ServerTrafficSecret),
	}
	return
}

// one NSS key log line: "<label> <client_random hex> <secret hex>"
func keyLogLine(label string, clientRandom string, secret []byte) (text string) {
	text = label + " " + clientRandom + " " + hex.EncodeToString(secret)
	return
}

// the NSS label of a secret_mask bit, for the layout error
func secretLabel(bit uint32) (label string) {
	switch bit {
	case clientRandomBit:
		label = clientRandomLabel
	case clientHandshakeBit:
		label = clientHandshakeLabel
	case serverHandshakeBit:
		label = serverHandshakeLabel
	case clientTrafficBit:
		label = clientTrafficLabel
	case serverTrafficBit:
		label = serverTrafficLabel
	default:
		label = fmt.Sprintf("label bit %d", bit)
	}

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
