// SPDX-License-Identifier: AGPL-3.0-only AND BSD-3-Clause

// The cipher suite tables, the AEAD nonce rules, the TLS 1.2 MAC, the padding check and the record decryption
// are derived from crypto/tls of the Go standard library (cipher_suites.go and conn.go), which carry this notice:
//
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// That license is LICENSE-Go.txt in this directory.

package tlsrecord

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// cipher suites on the wire (IANA TLS Cipher Suites registry)
const (
	tlsRSAWith3DESEDECBCSHA                 uint16 = 0x000a
	tlsRSAWithAES128CBCSHA                  uint16 = 0x002f
	tlsRSAWithAES256CBCSHA                  uint16 = 0x0035
	tlsRSAWithAES128CBCSHA256               uint16 = 0x003c
	tlsRSAWithAES128GCMSHA256               uint16 = 0x009c
	tlsRSAWithAES256GCMSHA384               uint16 = 0x009d
	tlsECDHEECDSAWithAES128CBCSHA           uint16 = 0xc009
	tlsECDHEECDSAWithAES256CBCSHA           uint16 = 0xc00a
	tlsECDHERSAWith3DESEDECBCSHA            uint16 = 0xc012
	tlsECDHERSAWithAES128CBCSHA             uint16 = 0xc013
	tlsECDHERSAWithAES256CBCSHA             uint16 = 0xc014
	tlsECDHEECDSAWithAES128CBCSHA256        uint16 = 0xc023
	tlsECDHERSAWithAES128CBCSHA256          uint16 = 0xc027
	tlsECDHEECDSAWithAES128GCMSHA256        uint16 = 0xc02b
	tlsECDHEECDSAWithAES256GCMSHA384        uint16 = 0xc02c
	tlsECDHERSAWithAES128GCMSHA256          uint16 = 0xc02f
	tlsECDHERSAWithAES256GCMSHA384          uint16 = 0xc030
	tlsECDHERSAWithChaCha20Poly1305SHA256   uint16 = 0xcca8
	tlsECDHEECDSAWithChaCha20Poly1305SHA256 uint16 = 0xcca9
	tlsAES128GCMSHA256                      uint16 = 0x1301
	tlsAES256GCMSHA384                      uint16 = 0x1302
	tlsChaCha20Poly1305SHA256               uint16 = 0x1303
)

const (
	aeadNonceLength   int = 12
	noncePrefixLength int = 4
	// the part of the nonce a TLS 1.2 AES-GCM record carries in front of its ciphertext
	explicitNonceLength int = aeadNonceLength - noncePrefixLength
	sequenceLength      int = 8
	// sequence number, content type, version and length: the additional data of a TLS 1.2 AEAD and the head of the MAC input
	additionalDataLength int = sequenceLength + recordHeaderLength
	sha1Length           int = 20
	sha256Length         int = 32
	aes128KeyLength      int = 16
	aes256KeyLength      int = 32
	tripleDESKeyLength   int = 24
)

// a TLS 1.2 cipher suite: the lengths of its part of the key block, the hash of its PRF and either an AEAD or a CBC block cipher with a MAC
// the key exchange is not here, the master key comes from the client
type cipherSuite struct {
	id         uint16
	name       string
	keyLength  int
	macLength  int
	ivLength   int
	newHash    func() hash.Hash
	newAEAD    func(key []byte) (cipher.AEAD, error)
	newBlock   func(key []byte) (cipher.Block, error)
	newMACHash func() hash.Hash
}

// a TLS 1.3 cipher suite: the AEAD and the hash of HKDF (RFC 8446 appendix B.4)
type cipherSuiteTLS13 struct {
	id        uint16
	name      string
	keyLength int
	newHash   func() hash.Hash
	newAEAD   func(key []byte) (cipher.AEAD, error)
}

// the record protection of one direction under one set of keys
// nonce holds the iv the sequence number is xored into, for TLS 1.2 AES-GCM only the salt in its first bytes, the rest comes with every record
type protection struct {
	aead           cipher.AEAD
	nonce          [aeadNonceLength]byte
	explicitNonce  bool
	block          cipher.Block
	mac            hash.Hash
	encryptThenMAC bool
}

var (
	cipherSuites = []*cipherSuite{
		{id: tlsECDHERSAWithChaCha20Poly1305SHA256, name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", keyLength: chacha20poly1305.KeySize, macLength: 0, ivLength: aeadNonceLength, newHash: sha256.New, newAEAD: chacha20poly1305.New, newBlock: nil, newMACHash: nil},
		{id: tlsECDHEECDSAWithChaCha20Poly1305SHA256, name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", keyLength: chacha20poly1305.KeySize, macLength: 0, ivLength: aeadNonceLength, newHash: sha256.New, newAEAD: chacha20poly1305.New, newBlock: nil, newMACHash: nil},
		{id: tlsECDHERSAWithAES128GCMSHA256, name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", keyLength: aes128KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha256.New, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsECDHEECDSAWithAES128GCMSHA256, name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", keyLength: aes128KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha256.New, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsECDHERSAWithAES256GCMSHA384, name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", keyLength: aes256KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha512.New384, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsECDHEECDSAWithAES256GCMSHA384, name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", keyLength: aes256KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha512.New384, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsECDHERSAWithAES128CBCSHA256, name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", keyLength: aes128KeyLength, macLength: sha256Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha256.New},
		{id: tlsECDHERSAWithAES128CBCSHA, name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", keyLength: aes128KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsECDHEECDSAWithAES128CBCSHA256, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", keyLength: aes128KeyLength, macLength: sha256Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha256.New},
		{id: tlsECDHEECDSAWithAES128CBCSHA, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", keyLength: aes128KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsECDHERSAWithAES256CBCSHA, name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", keyLength: aes256KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsECDHEECDSAWithAES256CBCSHA, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", keyLength: aes256KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsRSAWithAES128GCMSHA256, name: "TLS_RSA_WITH_AES_128_GCM_SHA256", keyLength: aes128KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha256.New, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsRSAWithAES256GCMSHA384, name: "TLS_RSA_WITH_AES_256_GCM_SHA384", keyLength: aes256KeyLength, macLength: 0, ivLength: noncePrefixLength, newHash: sha512.New384, newAEAD: newAESGCM, newBlock: nil, newMACHash: nil},
		{id: tlsRSAWithAES128CBCSHA256, name: "TLS_RSA_WITH_AES_128_CBC_SHA256", keyLength: aes128KeyLength, macLength: sha256Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha256.New},
		{id: tlsRSAWithAES128CBCSHA, name: "TLS_RSA_WITH_AES_128_CBC_SHA", keyLength: aes128KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsRSAWithAES256CBCSHA, name: "TLS_RSA_WITH_AES_256_CBC_SHA", keyLength: aes256KeyLength, macLength: sha1Length, ivLength: aes.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: aes.NewCipher, newMACHash: sha1.New},
		{id: tlsECDHERSAWith3DESEDECBCSHA, name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", keyLength: tripleDESKeyLength, macLength: sha1Length, ivLength: des.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: des.NewTripleDESCipher, newMACHash: sha1.New},
		{id: tlsRSAWith3DESEDECBCSHA, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", keyLength: tripleDESKeyLength, macLength: sha1Length, ivLength: des.BlockSize, newHash: sha256.New, newAEAD: nil, newBlock: des.NewTripleDESCipher, newMACHash: sha1.New},
	}
	cipherSuitesTLS13 = []*cipherSuiteTLS13{
		{id: tlsAES128GCMSHA256, name: "TLS_AES_128_GCM_SHA256", keyLength: aes128KeyLength, newHash: sha256.New, newAEAD: newAESGCM},
		{id: tlsAES256GCMSHA384, name: "TLS_AES_256_GCM_SHA384", keyLength: aes256KeyLength, newHash: sha512.New384, newAEAD: newAESGCM},
		{id: tlsChaCha20Poly1305SHA256, name: "TLS_CHACHA20_POLY1305_SHA256", keyLength: chacha20poly1305.KeySize, newHash: sha256.New, newAEAD: chacha20poly1305.New},
	}
)

func cipherSuiteByID(id uint16) (suite *cipherSuite, err error) {
	for _, candidate := range cipherSuites {
		if candidate.id == id {
			suite = candidate
			return
		}
	}

	err = fmt.Errorf("%w: 0x%04x", ErrUnsupportedCipherSuite, id)
	return
}

func cipherSuiteTLS13ByID(id uint16) (suite *cipherSuiteTLS13, err error) {
	for _, candidate := range cipherSuitesTLS13 {
		if candidate.id == id {
			suite = candidate
			return
		}
	}

	err = fmt.Errorf("%w: 0x%04x", ErrUnsupportedCipherSuite, id)
	return
}

// the IANA name of a cipher suite this package can decrypt, the number of any other
func CipherSuiteName(id uint16) (name string) {
	for _, suite := range cipherSuites {
		if suite.id == id {
			name = suite.name
			return
		}
	}

	for _, suite := range cipherSuitesTLS13 {
		if suite.id == id {
			name = suite.name
			return
		}
	}

	name = fmt.Sprintf("0x%04x", id)
	return
}

func newAESGCM(key []byte) (aead cipher.AEAD, err error) {
	block, blockErr := aes.NewCipher(key)

	if err = blockErr; err != nil {
		return
	}

	aead, err = cipher.NewGCM(block)
	return
}

// protection of a TLS 1.2 direction from its part of the key block
func newProtection(suite *cipherSuite, macKey []byte, key []byte, iv []byte, encryptThenMAC bool) (recordProtection *protection, err error) {
	recordProtection = &protection{
		aead:           nil,
		nonce:          [aeadNonceLength]byte{},
		explicitNonce:  false,
		block:          nil,
		mac:            nil,
		encryptThenMAC: false,
	}

	if suite.newAEAD != nil {
		recordProtection.aead, err = suite.newAEAD(key)

		if err != nil {
			err = fmt.Errorf("%w: %w", ErrSecrets, err)
			return
		}

		// AES-GCM takes a salt of the key block and the rest of the nonce from the record, ChaCha20-Poly1305 a whole iv (RFC 5288 section 3, RFC 7905 section 2)
		recordProtection.explicitNonce = len(iv) == noncePrefixLength
		copy(recordProtection.nonce[:], iv)
		return
	}

	// the iv of the key block is not used, every TLS 1.2 CBC record carries its own
	recordProtection.block, err = suite.newBlock(key)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrSecrets, err)
		return
	}

	recordProtection.mac = hmac.New(suite.newMACHash, macKey)
	recordProtection.encryptThenMAC = encryptThenMAC
	return
}

// protection of a TLS 1.3 direction from its traffic secret (RFC 8446 section 7.3)
func newProtectionTLS13(suite *cipherSuiteTLS13, trafficSecret []byte) (recordProtection *protection, err error) {
	key, iv, keyErr := trafficKey(suite, trafficSecret)

	if err = keyErr; err != nil {
		return
	}

	aead, aeadErr := suite.newAEAD(key)

	if err = aeadErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrSecrets, err)
		return
	}

	recordProtection = &protection{
		aead:           aead,
		nonce:          [aeadNonceLength]byte{},
		explicitNonce:  false,
		block:          nil,
		mac:            nil,
		encryptThenMAC: false,
	}
	copy(recordProtection.nonce[:], iv)
	return
}

// the nonce of a record without an explicit part: the sequence number xored into the last bytes of the iv (RFC 8446 section 5.3, RFC 7905 section 2)
func sequenceNonce(recordProtection *protection, sequence uint64) (nonce [aeadNonceLength]byte) {
	nonce = recordProtection.nonce
	sequenceBytes := [sequenceLength]byte{}
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)

	for index, value := range sequenceBytes {
		nonce[noncePrefixLength+index] ^= value
	}

	return
}

// sequence number, content type and version of the record and the length of what is authenticated: the additional data of a TLS 1.2 AEAD and the head of the MAC input (RFC 5246 section 6.2.3)
func additionalData(sequence uint64, header []byte, length int) (data []byte) {
	data = make([]byte, additionalDataLength)
	binary.BigEndian.PutUint64(data, sequence)
	copy(data[sequenceLength:], header[:recordHeaderLength-2])
	binary.BigEndian.PutUint16(data[additionalDataLength-2:], uint16(length))
	return
}

// decrypt a TLS 1.3 record in place: the record header is the additional data, the content type is the last byte of the plaintext that is not padding (RFC 8446 section 5.2)
func openTLS13(recordProtection *protection, sequence uint64, header []byte, payload []byte) (plaintext []byte, contentType ContentType, err error) {
	if len(payload) > maxCiphertextTLS13 {
		err = fmt.Errorf("%w: %d bytes", ErrRecordOverflow, len(payload))
		return
	}

	nonce := sequenceNonce(recordProtection, sequence)
	plaintext, openErr := recordProtection.aead.Open(payload[:0], nonce[:], payload, header)

	if openErr != nil {
		err = ErrBadRecordMAC
		return
	}

	if len(plaintext) > maxPlaintext+1 {
		err = fmt.Errorf("%w: %d bytes of plaintext", ErrRecordOverflow, len(plaintext))
		return
	}

	// zero padding follows the content type
	for index := len(plaintext) - 1; index >= 0; index-- {
		if plaintext[index] != 0 {
			contentType = ContentType(plaintext[index])
			plaintext = plaintext[:index]
			return
		}
	}

	err = fmt.Errorf("%w: no content type in the plaintext", ErrUnexpectedRecord)
	return
}

// decrypt a TLS 1.2 AEAD record in place
func openAEAD(recordProtection *protection, sequence uint64, header []byte, payload []byte) (plaintext []byte, err error) {
	nonce := sequenceNonce(recordProtection, sequence)

	if recordProtection.explicitNonce {
		if len(payload) < explicitNonceLength {
			err = ErrBadRecordMAC
			return
		}

		nonce = recordProtection.nonce
		copy(nonce[noncePrefixLength:], payload[:explicitNonceLength])
		payload = payload[explicitNonceLength:]
	}

	if len(payload) < recordProtection.aead.Overhead() {
		err = ErrBadRecordMAC
		return
	}

	plaintext, openErr := recordProtection.aead.Open(payload[:0], nonce[:], payload, additionalData(sequence, header, len(payload)-recordProtection.aead.Overhead()))

	if openErr != nil {
		err = ErrBadRecordMAC
	}

	return
}

// decrypt a TLS 1.2 CBC record in place: an explicit iv, then the blocks, MAC-then-encrypt (RFC 5246 section 6.2.3.2) or encrypt-then-MAC when negotiated (RFC 7366)
func openCBC(recordProtection *protection, sequence uint64, header []byte, payload []byte) (plaintext []byte, err error) {
	blockSize := recordProtection.block.BlockSize()
	macSize := recordProtection.mac.Size()

	// encrypt-then-MAC: the MAC is behind the blocks and covers the iv and the ciphertext
	if recordProtection.encryptThenMAC {
		if len(payload) < macSize {
			err = ErrBadRecordMAC
			return
		}

		remoteMAC := payload[len(payload)-macSize:]
		payload = payload[:len(payload)-macSize]
		localMAC := recordMAC(recordProtection.mac, sequence, header, payload)

		if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 {
			err = ErrBadRecordMAC
			return
		}
	}

	// the iv and at least one block
	if (len(payload)%blockSize != 0) || (len(payload) < 2*blockSize) {
		err = ErrBadRecordMAC
		return
	}

	cipher.NewCBCDecrypter(recordProtection.block, payload[:blockSize]).CryptBlocks(payload[blockSize:], payload[blockSize:])
	payload = payload[blockSize:]
	paddingLength, paddingGood := extractPadding(payload)

	if recordProtection.encryptThenMAC {
		if paddingGood != 255 {
			err = ErrBadRecordMAC
			return
		}

		plaintext = payload[:len(payload)-paddingLength]
		return
	}

	// MAC-then-encrypt: the MAC is the end of the plaintext in front of the padding and covers the plaintext
	length := len(payload) - macSize - paddingLength

	if length < 0 {
		err = ErrBadRecordMAC
		return
	}

	remoteMAC := payload[length : length+macSize]
	localMAC := recordMAC(recordProtection.mac, sequence, header, payload[:length])

	if (subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1) || (paddingGood != 255) {
		err = ErrBadRecordMAC
		return
	}

	plaintext = payload[:length]
	return
}

// the HMAC of a TLS 1.2 record over the sequence number, the record header with the length of data, and data (RFC 5246 section 6.2.3.1)
func recordMAC(mac hash.Hash, sequence uint64, header []byte, data []byte) (sum []byte) {
	mac.Reset()
	mac.Write(additionalData(sequence, header, len(data)))
	mac.Write(data)
	sum = mac.Sum(nil)
	return
}

// the length of the CBC padding to remove from the end of payload with its length byte, good is 255 if every padding byte holds the padding length and 0 otherwise (RFC 5246 section 6.2.3.2)
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return
	}

	paddingLength := payload[len(payload)-1]
	remaining := uint(len(payload)-1) - uint(paddingLength)
	// if the payload is at least as long as the padding the most significant bit of remaining is zero
	good = byte(int32(^remaining) >> 31)
	// the longest possible padding and its length byte
	toCheck := min(256, len(payload))

	for index := range toCheck {
		distance := uint(paddingLength) - uint(index)
		// if index is inside the padding the most significant bit of distance is zero
		mask := byte(int32(^distance) >> 31)
		value := payload[len(payload)-1-index]
		good &^= mask&paddingLength ^ mask&value
	}

	// and the bits of good together and spread the result over all of them
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)
	// a bad padding removes only its length byte
	paddingLength &= good
	toRemove = int(paddingLength) + 1
	return
}
