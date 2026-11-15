// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit && (amd64 || arm64)

package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/tlsrecord"
)

// the handshake secret, the transcript hash of ClientHello..ServerHello and the handshake traffic secrets of RFC 8448 section 3
const (
	rfc8448HandshakeSecret       string = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
	rfc8448HandshakeHash         string = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
	rfc8448ClientHandshakeSecret string = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
	rfc8448ServerHandshakeSecret string = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
)

// Test if secrets.keyLogLines returns with the expected output for the secrets map entries of OpenSSL and BoringSSL.
func TestKeyLogLinesPositive(state *testing.T) {
	clientRandom := hex.EncodeToString(sequence(32, 0x10))
	rfc8448Secrets, err := rfc8448Entry(0x03001301)

	if err != nil {
		state.Fatalf("Test of secrets.keyLogLines failed, cannot decode the RFC 8448 secrets, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name     string
		Secrets  bpfTlsSecrets
		Expected []string
	}{
		{
			Name:     "tls 1.2",
			Secrets:  entry(tls12Version, 0x0300c02f, 0),
			Expected: []string{"CLIENT_RANDOM " + clientRandom + " " + hex.EncodeToString(sequence(48, 0x40))},
		},
		{
			Name:     "dtls 1.2",
			Secrets:  entry(dtls12Version, 0x0300c02b, 0),
			Expected: []string{"CLIENT_RANDOM " + clientRandom + " " + hex.EncodeToString(sequence(48, 0x40))},
		},
		// OpenSSL keeps no handshake traffic secrets, they are derived from the handshake secret and the transcript hash; the id carries 0x0300 in front of the suite
		{
			Name:    "tls 1.3 openssl sha256",
			Secrets: rfc8448Secrets,
			Expected: []string{
				"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + clientRandom + " " + rfc8448ClientHandshakeSecret,
				"SERVER_HANDSHAKE_TRAFFIC_SECRET " + clientRandom + " " + rfc8448ServerHandshakeSecret,
				"CLIENT_TRAFFIC_SECRET_0 " + clientRandom + " " + hex.EncodeToString(sequence(32, 0x80)),
				"SERVER_TRAFFIC_SECRET_0 " + clientRandom + " " + hex.EncodeToString(sequence(32, 0xc0)),
			},
		},
		// BoringSSL hands every secret over with its length
		{
			Name:    "tls 1.3 boringssl sha384",
			Secrets: entry(tls13Version, 0, 48),
			Expected: []string{
				"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + clientRandom + " " + hex.EncodeToString(sequence(48, 0x20)),
				"SERVER_HANDSHAKE_TRAFFIC_SECRET " + clientRandom + " " + hex.EncodeToString(sequence(48, 0x60)),
				"CLIENT_TRAFFIC_SECRET_0 " + clientRandom + " " + hex.EncodeToString(sequence(48, 0x80)),
				"SERVER_TRAFFIC_SECRET_0 " + clientRandom + " " + hex.EncodeToString(sequence(48, 0xc0)),
			},
		},
	}

	for _, positive := range positiveCases {
		lines, err := keyLogLines(positive.Secrets)

		if (err != nil) || !slices.Equal(lines, positive.Expected) {
			state.Errorf("Test of secrets.keyLogLines function failed, case %q, lines should be %q, lines: %q, error: %v", positive.Name, positive.Expected, lines, err)
			return
		}
	}

	// the record layer gets the same secrets, a SHA-384 suite of OpenSSL with 48 byte secrets
	sessionSecrets, err := recordSecrets(entry(tls13Version, 0x03001302, 0))

	if (err != nil) || (sessionSecrets.Version != tlsrecord.VersionTLS13) || (len(sessionSecrets.ClientHandshakeTrafficSecret) != 48) || !bytes.Equal(sessionSecrets.ServerTrafficSecret, sequence(48, 0xc0)) {
		state.Errorf("Test of secrets.recordSecrets function failed, secrets should be 48 bytes long, secrets: %+v, error: %v", sessionSecrets, err)
		return
	}
}

// Test if secrets.keyLogLines returns with the expected errors.
func TestKeyLogLinesNegative(state *testing.T) {
	negativeCases := []struct {
		Name    string
		Secrets bpfTlsSecrets
		Err     error
	}{
		{Name: "tls 1.1", Secrets: entry(0x0302, 0x0300c013, 0), Err: ErrUnknownTLSVersion},
		{Name: "dtls 1.0", Secrets: entry(0xfeff, 0x0300c013, 0), Err: ErrUnknownTLSVersion},
		// the length of a suite that is not listed is never guessed
		{Name: "unknown tls 1.3 suite", Secrets: entry(tls13Version, 0x03001306, 0), Err: ErrUnknownCipher},
		{Name: "boringssl length", Secrets: entry(tls13Version, 0, 40), Err: ErrSecretLength},
	}

	for _, negative := range negativeCases {
		lines, err := keyLogLines(negative.Secrets)

		if !errors.Is(err, negative.Err) || (lines != nil) {
			state.Errorf("Test of secrets.keyLogLines function failed, case %q, error should be %v, error: %v, lines: %q", negative.Name, negative.Err, err, lines)
			return
		}
	}
}

// Test if secrets.hashLength returns with the expected output.
func TestHashLengthPositive(state *testing.T) {
	positiveCases := []struct {
		CipherID uint32
		Length   int
		IsKnown  bool
	}{
		{CipherID: 0x03001301, Length: 32, IsKnown: true},
		{CipherID: 0x03001302, Length: 48, IsKnown: true},
		{CipherID: 0x03001303, Length: 32, IsKnown: true},
		{CipherID: 0x03001304, Length: 32, IsKnown: true},
		{CipherID: 0x03001305, Length: 32, IsKnown: true},
		{CipherID: 0x0300c0b4, Length: 32, IsKnown: true},
		{CipherID: 0x0300c0b5, Length: 48, IsKnown: true},
		{CipherID: 0x0300c02f, Length: 0, IsKnown: false},
		{CipherID: 0, Length: 0, IsKnown: false},
	}

	for _, positive := range positiveCases {
		length, isKnown := hashLength(positive.CipherID)

		if (length != positive.Length) || (isKnown != positive.IsKnown) {
			state.Errorf("Test of secrets.hashLength function failed, cipher id 0x%08x, length should be %d %v, length: %d %v", positive.CipherID, positive.Length, positive.IsKnown, length, isKnown)
			return
		}
	}
}

// Test if secrets.layoutMismatch returns with the expected output: no error while nothing was rejected.
func TestLayoutMismatchPositive(state *testing.T) {
	count, err := layoutMismatch(bpfLayoutError{Count: 0, TlsVersion: 0, SecretBit: 0, SecretLength: 0})

	if (count != 0) || (err != nil) {
		state.Errorf("Test of secrets.layoutMismatch function failed, count should be 0 without an error, count: %d, error: %v", count, err)
		return
	}
}

// Test if secrets.layoutMismatch returns with the expected errors: the sanity check against a Conscrypt APEX with another layout names the last rejected call.
func TestLayoutMismatchNegative(state *testing.T) {
	negativeCases := []struct {
		LayoutError bpfLayoutError
		Text        string
	}{
		{LayoutError: bpfLayoutError{Count: 3, TlsVersion: 0x0303, SecretBit: clientTrafficBit, SecretLength: 32}, Text: "3 secrets rejected, the last one CLIENT_TRAFFIC_SECRET_0 with version 0x0303 and a 32 byte secret"},
		{LayoutError: bpfLayoutError{Count: 1, TlsVersion: 0x0304, SecretBit: clientRandomBit, SecretLength: 48}, Text: "1 secrets rejected, the last one CLIENT_RANDOM with version 0x0304 and a 48 byte secret"},
		{LayoutError: bpfLayoutError{Count: 7, TlsVersion: 0, SecretBit: 64, SecretLength: 0}, Text: "7 secrets rejected, the last one label bit 64 with version 0x0000 and a 0 byte secret"},
	}

	for _, negative := range negativeCases {
		count, err := layoutMismatch(negative.LayoutError)

		if (count != negative.LayoutError.Count) || !errors.Is(err, ErrLayoutMismatch) || !strings.HasSuffix(err.Error(), negative.Text) {
			state.Errorf("Test of secrets.layoutMismatch function failed, error should be %v ending in %q, error: %v", ErrLayoutMismatch, negative.Text, err)
			return
		}
	}
}

// Test if secrets.secretLabel returns with the expected output.
func TestSecretLabelPositive(state *testing.T) {
	positiveCases := map[uint32]string{
		clientRandomBit:    "CLIENT_RANDOM",
		clientHandshakeBit: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		serverHandshakeBit: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
		clientTrafficBit:   "CLIENT_TRAFFIC_SECRET_0",
		serverTrafficBit:   "SERVER_TRAFFIC_SECRET_0",
		3:                  "label bit 3",
	}

	for bit, expected := range positiveCases {
		if label := secretLabel(bit); label != expected {
			state.Errorf("Test of secrets.secretLabel function failed, bit %d, label should be %s, label: %s", bit, expected, label)
			return
		}
	}

	if hooks := SymbolHooks(); !slices.Contains(hooks, "SSL_do_handshake") || !slices.Contains(hooks, "SSL_write_ex") || (len(hooks) != 5) {
		state.Errorf("Test of secrets.SymbolHooks function failed, hooks: %q", hooks)
		return
	}
}

// a secrets map entry whose fields are counting bytes from different starts, so a field read from the wrong place shows
// the client handshake traffic secret starts at 0x20, the server one at 0x60, the client application secret at 0x80, the server one at 0xc0
func entry(version uint32, cipherID uint32, secretLength uint32) (secrets bpfTlsSecrets) {
	secrets = bpfTlsSecrets{TlsVersion: version, CipherId: cipherID, MasterKeyLength: 48, SecretLength: secretLength, SecretMask: 0x1f}
	copy(secrets.ClientRandom[:], sequence(32, 0x10))
	copy(secrets.MasterKey[:], sequence(48, 0x40))
	copy(secrets.ClientHandshakeTrafficSecret[:], sequence(64, 0x20))
	copy(secrets.ServerHandshakeTrafficSecret[:], sequence(64, 0x60))
	copy(secrets.ClientAppTrafficSecret[:], sequence(64, 0x80))
	copy(secrets.ServerAppTrafficSecret[:], sequence(64, 0xc0))
	copy(secrets.HandshakeSecret[:], sequence(64, 0xa0))
	copy(secrets.HandshakeTrafficHash[:], sequence(64, 0xe0))
	return
}

// an OpenSSL entry with the handshake secret and transcript hash of RFC 8448, the rest of the 64 byte fields is not zero
func rfc8448Entry(cipherID uint32) (secrets bpfTlsSecrets, err error) {
	secrets = entry(tls13Version, cipherID, 0)
	handshakeSecret, decodeErr := hex.DecodeString(rfc8448HandshakeSecret)

	if err = decodeErr; err != nil {
		return
	}

	handshakeHash, decodeErr := hex.DecodeString(rfc8448HandshakeHash)

	if err = decodeErr; err != nil {
		return
	}

	copy(secrets.HandshakeSecret[:], handshakeSecret)
	copy(secrets.HandshakeTrafficHash[:], handshakeHash)
	return
}

func sequence(length int, start byte) (data []byte) {
	for index := range length {
		data = append(data, start+byte(index))
	}

	return
}

// Test if secrets.CheckSupported returns with the expected output: amd64 and arm64 have the secrets object.
func TestCheckSupportedPositive(state *testing.T) {
	err := CheckSupported()

	if err != nil {
		state.Errorf("Test of secrets.CheckSupported function failed, error: %s", err.Error())
		return
	}
}
