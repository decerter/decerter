// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// the header of an application data record of TLS 1.2, the MAC and the additional data only take its type and version
var cipherTestHeader = []byte{byte(ApplicationDataContentType), 3, 3, 0, 0}

// Test if tlsrecord.newProtection returns with the expected output.
func TestNewProtectionPositive(state *testing.T) {
	positiveCases := []struct {
		SuiteID        uint16
		EncryptThenMAC bool
		IsAEAD         bool
		ExplicitNonce  bool
		Expected       bool
	}{
		{SuiteID: tlsECDHERSAWithAES128GCMSHA256, EncryptThenMAC: false, IsAEAD: true, ExplicitNonce: true, Expected: false},
		// encrypt-then-MAC means nothing for an AEAD
		{SuiteID: tlsRSAWithAES256GCMSHA384, EncryptThenMAC: true, IsAEAD: true, ExplicitNonce: true, Expected: false},
		{SuiteID: tlsECDHEECDSAWithChaCha20Poly1305SHA256, EncryptThenMAC: false, IsAEAD: true, ExplicitNonce: false, Expected: false},
		{SuiteID: tlsECDHERSAWithAES128CBCSHA256, EncryptThenMAC: false, IsAEAD: false, ExplicitNonce: false, Expected: false},
		{SuiteID: tlsRSAWith3DESEDECBCSHA, EncryptThenMAC: true, IsAEAD: false, ExplicitNonce: false, Expected: true},
	}

	for _, positive := range positiveCases {
		suite, err := cipherSuiteByID(positive.SuiteID)

		if err != nil {
			state.Fatalf("Test of tlsrecord.newProtection failed, cannot find suite, error: %s", err.Error())
		}

		iv := bytes.Repeat([]byte{9}, suite.ivLength)
		recordProtection, err := newProtection(suite, make([]byte, suite.macLength), make([]byte, suite.keyLength), iv, positive.EncryptThenMAC)

		if err != nil {
			state.Errorf("Test of tlsrecord.newProtection function failed, suite: %s, error: %s", suite.name, err.Error())
			return
		}

		if ((recordProtection.aead != nil) != positive.IsAEAD) || ((recordProtection.block == nil) != positive.IsAEAD) || ((recordProtection.mac == nil) != positive.IsAEAD) {
			state.Errorf("Test of tlsrecord.newProtection function failed, suite: %s, AEAD should be %v, protection: %+v", suite.name, positive.IsAEAD, recordProtection)
			return
		}

		if (recordProtection.explicitNonce != positive.ExplicitNonce) || (recordProtection.encryptThenMAC != positive.Expected) {
			state.Errorf("Test of tlsrecord.newProtection function failed, suite: %s, explicit nonce and encrypt-then-MAC should be %v %v, result: %v %v", suite.name, positive.ExplicitNonce, positive.Expected, recordProtection.explicitNonce, recordProtection.encryptThenMAC)
			return
		}

		// the iv of the key block starts the nonce of an AEAD, a CBC record carries its own
		if positive.IsAEAD != bytes.HasPrefix(recordProtection.nonce[:], iv) {
			state.Errorf("Test of tlsrecord.newProtection function failed, suite: %s, nonce should start with the iv %v, nonce: %x", suite.name, positive.IsAEAD, recordProtection.nonce)
			return
		}
	}
}

// Test if tlsrecord.newProtection returns with the expected errors.
func TestNewProtectionNegative(state *testing.T) {
	negativeCases := []struct {
		SuiteID   uint16
		KeyLength int
	}{
		{SuiteID: tlsECDHERSAWithAES128GCMSHA256, KeyLength: 5},
		{SuiteID: tlsECDHERSAWithChaCha20Poly1305SHA256, KeyLength: 16},
		{SuiteID: tlsECDHERSAWithAES128CBCSHA, KeyLength: 5},
		{SuiteID: tlsRSAWith3DESEDECBCSHA, KeyLength: 16},
	}

	for _, negative := range negativeCases {
		suite, err := cipherSuiteByID(negative.SuiteID)

		if err != nil {
			state.Fatalf("Test of tlsrecord.newProtection failed, cannot find suite, error: %s", err.Error())
		}

		_, err = newProtection(suite, make([]byte, suite.macLength), make([]byte, negative.KeyLength), make([]byte, suite.ivLength), false)

		if !errors.Is(err, ErrSecrets) {
			state.Errorf("Test of tlsrecord.newProtection function failed, suite: %s, key of %d bytes, error should be %v, error: %v", suite.name, negative.KeyLength, ErrSecrets, err)
			return
		}
	}
}

// Test if tlsrecord.newProtectionTLS13 returns with the expected errors.
func TestNewProtectionTLS13Negative(state *testing.T) {
	// HKDF can't give a key longer than 255 hashes, and AES takes no key of 5 bytes: suites the table never holds
	negativeCases := []*cipherSuiteTLS13{
		{id: 0, name: "key longer than HKDF expands", keyLength: 255*sha256.Size + 1, newHash: sha256.New, newAEAD: newAESGCM},
		{id: 0, name: "key no AES takes", keyLength: 5, newHash: sha256.New, newAEAD: newAESGCM},
	}

	for _, negative := range negativeCases {
		recordProtection, err := newProtectionTLS13(negative, make([]byte, sha256.Size))

		if !errors.Is(err, ErrSecrets) || (recordProtection != nil) {
			state.Errorf("Test of tlsrecord.newProtectionTLS13 function failed, suite: %s, error should be %v without a protection, error: %v, protection: %v", negative.name, ErrSecrets, err, recordProtection)
			return
		}
	}
}

// Test if tlsrecord.expandLabel returns with the expected output and errors.
func TestExpandLabelPositive(state *testing.T) {
	secret := bytes.Repeat([]byte{7}, sha256.Size)
	key, err := expandLabel(sha256.New, secret, keyLabel, nil, aes128KeyLength)

	if err != nil {
		state.Fatalf("Test of tlsrecord.expandLabel failed, error: %s", err.Error())
	}

	iv, err := expandLabel(sha256.New, secret, ivLabel, nil, aeadNonceLength)

	if err != nil {
		state.Fatalf("Test of tlsrecord.expandLabel failed, error: %s", err.Error())
	}

	// another label gives other bytes, the same label the same ones
	again, err := expandLabel(sha256.New, secret, keyLabel, nil, aes128KeyLength)

	if (err != nil) || (len(key) != aes128KeyLength) || (len(iv) != aeadNonceLength) || !bytes.Equal(key, again) || bytes.Equal(key[:aeadNonceLength], iv) {
		state.Errorf("Test of tlsrecord.expandLabel function failed, key: %x, key again: %x, iv: %x, error: %v", key, again, iv, err)
		return
	}

	_, err = expandLabel(sha256.New, secret, keyLabel, nil, 255*sha256.Size+1)

	if !errors.Is(err, ErrSecrets) {
		state.Errorf("Test of tlsrecord.expandLabel function failed, error should be %v, error: %v", ErrSecrets, err)
		return
	}
}

// Test if tlsrecord.sealAEAD and tlsrecord.openAEAD return with the expected output.
func TestSealAEADPositive(state *testing.T) {
	for _, suiteID := range []uint16{tlsECDHERSAWithAES128GCMSHA256, tlsECDHERSAWithAES256GCMSHA384, tlsECDHERSAWithChaCha20Poly1305SHA256} {
		sealer, opener, err := newAEADPair(suiteID)

		if err != nil {
			state.Fatalf("Test of tlsrecord.sealAEAD failed, cannot create protection, error: %s", err.Error())
		}

		for _, length := range []int{0, 1, 1000, maxPlaintext} {
			plaintext := bytes.Repeat([]byte{byte(length)}, length)
			sequence := uint64(length) + 1<<40
			record := sealAEAD(sealer, sequence, ApplicationDataContentType, [2]byte{3, 3}, plaintext)
			explicitLength := 0

			// AES-GCM carries the sequence number in front of the ciphertext
			if sealer.explicitNonce {
				explicitLength = explicitNonceLength

				if binary.BigEndian.Uint64(record[recordHeaderLength:]) != sequence {
					state.Errorf("Test of tlsrecord.sealAEAD function failed, suite: 0x%04x, explicit nonce should be %d, nonce: %x", suiteID, sequence, record[recordHeaderLength:recordHeaderLength+explicitNonceLength])
					return
				}
			}

			expectedLength := explicitLength + length + sealer.aead.Overhead()

			if (len(record) != recordHeaderLength+expectedLength) || (int(binary.BigEndian.Uint16(record[recordHeaderLength-2:])) != expectedLength) || !bytes.Equal(record[:recordHeaderLength-2], cipherTestHeader[:recordHeaderLength-2]) {
				state.Errorf("Test of tlsrecord.sealAEAD function failed, suite: 0x%04x, record should have %d bytes behind its header, header: %x, length: %d", suiteID, expectedLength, record[:recordHeaderLength], len(record))
				return
			}

			opened, openErr := openAEAD(opener, sequence, record[:recordHeaderLength], bytes.Clone(record[recordHeaderLength:]))

			if (openErr != nil) || !bytes.Equal(opened, plaintext) {
				state.Errorf("Test of tlsrecord.openAEAD function failed, suite: 0x%04x, %d bytes should come back, bytes: %d, error: %v", suiteID, length, len(opened), openErr)
				return
			}
		}
	}
}

// Test if tlsrecord.openAEAD returns with the expected errors.
func TestOpenAEADNegative(state *testing.T) {
	negativeCases := []struct {
		Name    string
		SuiteID uint16
		Change  func(record []byte) (changed []byte)
		Offset  uint64
	}{
		{Name: "no payload", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte { return record[:recordHeaderLength] }, Offset: 0},
		{Name: "part of the explicit nonce", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte { return record[:recordHeaderLength+explicitNonceLength-1] }, Offset: 0},
		{Name: "explicit nonce and part of the tag", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte { return record[:recordHeaderLength+explicitNonceLength+15] }, Offset: 0},
		{Name: "part of the tag", SuiteID: tlsECDHERSAWithChaCha20Poly1305SHA256, Change: func(record []byte) []byte { return record[:recordHeaderLength+15] }, Offset: 0},
		{Name: "record without its last byte", SuiteID: tlsECDHERSAWithChaCha20Poly1305SHA256, Change: func(record []byte) []byte { return record[:len(record)-1] }, Offset: 0},
		{Name: "changed explicit nonce", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte {
			record[recordHeaderLength] ^= 1
			return record
		}, Offset: 0},
		{Name: "changed content type", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte {
			record[0] = byte(AlertContentType)
			return record
		}, Offset: 0},
		{Name: "other sequence number", SuiteID: tlsECDHERSAWithChaCha20Poly1305SHA256, Change: func(record []byte) []byte { return record }, Offset: 1},
		// the explicit nonce of AES-GCM is the whole nonce, the sequence number is still in the additional data
		{Name: "other sequence number with an explicit nonce", SuiteID: tlsECDHERSAWithAES128GCMSHA256, Change: func(record []byte) []byte { return record }, Offset: 1},
	}

	for _, negative := range negativeCases {
		sealer, opener, err := newAEADPair(negative.SuiteID)

		if err != nil {
			state.Fatalf("Test of tlsrecord.openAEAD failed, cannot create protection, error: %s", err.Error())
		}

		record := negative.Change(sealAEAD(sealer, 7, ApplicationDataContentType, [2]byte{3, 3}, []byte("GET / HTTP/1.1\r\n\r\n")))
		plaintext, err := openAEAD(opener, 7+negative.Offset, record[:recordHeaderLength], record[recordHeaderLength:])

		if !errors.Is(err, ErrBadRecordMAC) {
			state.Errorf("Test of tlsrecord.openAEAD function failed, case: %s, error should be %v, error: %v, plaintext: %q", negative.Name, ErrBadRecordMAC, err, plaintext)
			return
		}
	}
}

// Test if tlsrecord.openCBC returns with the expected errors for records that are too short, not whole blocks or have a bad padding.
func TestOpenCBCNegative(state *testing.T) {
	for _, suiteID := range []uint16{tlsECDHERSAWithAES128CBCSHA256, tlsECDHERSAWith3DESEDECBCSHA} {
		suite, err := cipherSuiteByID(suiteID)

		if err != nil {
			state.Fatalf("Test of tlsrecord.openCBC failed, cannot find suite, error: %s", err.Error())
		}

		for _, encryptThenMAC := range []bool{false, true} {
			sealer, opener, protectionErr := newCBCPair(suite, encryptThenMAC)

			if protectionErr != nil {
				state.Fatalf("Test of tlsrecord.openCBC failed, cannot create protection, error: %s", protectionErr.Error())
			}

			blockSize := sealer.block.BlockSize()
			macSize := sealer.mac.Size()
			// a block whose last byte asks for a padding of three bytes that hold something else
			badPadding := bytes.Repeat([]byte{'a'}, blockSize)
			badPadding[blockSize-1] = 3
			negativeCases := []struct {
				Name        string
				Payload     []byte
				IsMACInside bool
			}{
				{Name: "no payload", Payload: nil, IsMACInside: false},
				{Name: "less than a MAC", Payload: make([]byte, macSize-1), IsMACInside: false},
				{Name: "only an iv", Payload: authenticate(sealer, 7, make([]byte, blockSize)), IsMACInside: false},
				{Name: "an iv and half a block", Payload: authenticate(sealer, 7, make([]byte, blockSize+blockSize/2)), IsMACInside: false},
				// only when the MAC is inside the encryption, with encrypt-then-MAC this is a whole record of an empty padding
				{Name: "an iv and one block without room for the MAC", Payload: encryptBlocks(sealer, bytes.Repeat([]byte{0}, blockSize)), IsMACInside: true},
				{Name: "bad padding", Payload: authenticate(sealer, 7, encryptBlocks(sealer, append(bytes.Repeat([]byte{'b'}, 4*blockSize), badPadding...))), IsMACInside: false},
				{Name: "padding longer than the record", Payload: authenticate(sealer, 7, encryptBlocks(sealer, bytes.Repeat([]byte{200}, 4*blockSize))), IsMACInside: false},
			}

			for _, negative := range negativeCases {
				if negative.IsMACInside && encryptThenMAC {
					continue
				}

				plaintext, openErr := openCBC(opener, 7, cipherTestHeader, bytes.Clone(negative.Payload))

				if !errors.Is(openErr, ErrBadRecordMAC) {
					state.Errorf("Test of tlsrecord.openCBC function failed, suite: %s, encrypt-then-MAC: %v, case: %s, error should be %v, error: %v, plaintext: %x", suite.name, encryptThenMAC, negative.Name, ErrBadRecordMAC, openErr, plaintext)
					return
				}
			}
		}
	}
}

// Test if tlsrecord.extractPadding returns with the expected output.
func TestExtractPaddingPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Payload  []byte
		ToRemove int
		Good     byte
	}{
		{Name: "no payload", Payload: nil, ToRemove: 0, Good: 0},
		{Name: "only the length byte", Payload: []byte{'a', 'b', 0}, ToRemove: 1, Good: 255},
		{Name: "three bytes and the length byte", Payload: []byte{'a', 3, 3, 3, 3}, ToRemove: 4, Good: 255},
		{Name: "the whole payload", Payload: []byte{2, 2, 2}, ToRemove: 3, Good: 255},
		{Name: "the longest padding", Payload: bytes.Repeat([]byte{255}, 300), ToRemove: 256, Good: 255},
		// a bad padding only takes its length byte off
		{Name: "a byte that is not the length", Payload: []byte{'a', 3, 9, 3, 3}, ToRemove: 1, Good: 0},
		{Name: "longer than the payload", Payload: []byte{3, 3, 3}, ToRemove: 1, Good: 0},
		{Name: "longer than the payload by far", Payload: []byte{255}, ToRemove: 1, Good: 0},
	}

	for _, positive := range positiveCases {
		toRemove, good := extractPadding(positive.Payload)

		if (toRemove != positive.ToRemove) || (good != positive.Good) {
			state.Errorf("Test of tlsrecord.extractPadding function failed, case: %s, result should be %d %d, result: %d %d", positive.Name, positive.ToRemove, positive.Good, toRemove, good)
			return
		}
	}
}

// a write and a read protection of the same random keys of a TLS 1.2 AEAD suite
func newAEADPair(suiteID uint16) (sealer *protection, opener *protection, err error) {
	suite, err := cipherSuiteByID(suiteID)

	if err != nil {
		return
	}

	key := make([]byte, suite.keyLength)
	iv := make([]byte, suite.ivLength)
	_, err = rand.Read(key)

	if err != nil {
		return
	}

	_, err = rand.Read(iv)

	if err != nil {
		return
	}

	sealer, err = newProtection(suite, nil, key, iv, false)

	if err != nil {
		return
	}

	opener, err = newProtection(suite, nil, key, iv, false)
	return
}

// the payload of a CBC record from its iv and blocks: with encrypt-then-MAC the MAC of the record follows them, so only what the MAC covers is wrong with the record
func authenticate(sealer *protection, sequence uint64, body []byte) (payload []byte) {
	payload = bytes.Clone(body)

	if sealer.encryptThenMAC {
		payload = append(payload, recordMAC(sealer.mac, sequence, cipherTestHeader, body)...)
	}

	return
}

// a zero iv and the blocks encrypted under it
func encryptBlocks(sealer *protection, blocks []byte) (body []byte) {
	blockSize := sealer.block.BlockSize()
	body = append(make([]byte, blockSize), blocks...)
	cipher.NewCBCEncrypter(sealer.block, body[:blockSize]).CryptBlocks(body[blockSize:], body[blockSize:])
	return
}
