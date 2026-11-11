// SPDX-License-Identifier: AGPL-3.0-only AND BSD-3-Clause

// The TLS 1.2 PRF and key block and the TLS 1.3 traffic key derivation are derived from
// crypto/tls of the Go standard library (prf.go and key_schedule.go), which carry these notices:
//
// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// That license is LICENSE-Go.txt in this directory.

package tlsrecord

import (
	"crypto/hkdf"
	"crypto/hmac"
	"fmt"
	"hash"
)

const (
	masterKeyLength int = 48
	randomLength    int = 32
	// labels of the TLS 1.2 key block (RFC 5246 section 6.3) and of HKDF-Expand-Label (RFC 8446 sections 7.1 to 7.3)
	keyExpansionLabel  string = "key expansion"
	labelPrefix        string = "tls13 "
	keyLabel           string = "key"
	ivLabel            string = "iv"
	trafficUpdateLabel string = "traffic upd"
)

// the TLS 1.2 key block cut into its parts
type keyBlock struct {
	clientMAC []byte
	serverMAC []byte
	clientKey []byte
	serverKey []byte
	clientIV  []byte
	serverIV  []byte
}

// P_hash of RFC 5246 section 5, fills result
func pHash(result []byte, secret []byte, seed []byte, newHash func() hash.Hash) {
	mac := hmac.New(newHash, secret)
	mac.Write(seed)
	chain := mac.Sum(nil)

	for offset := 0; offset < len(result); {
		mac.Reset()
		mac.Write(chain)
		mac.Write(seed)
		offset += copy(result[offset:], mac.Sum(nil))
		mac.Reset()
		mac.Write(chain)
		chain = mac.Sum(nil)
	}
}

// the TLS 1.2 key block from the master secret (RFC 5246 section 6.3), the PRF is P_hash with the hash of the suite over the label and the two randoms
func keysFromMasterSecret(suite *cipherSuite, masterSecret []byte, clientRandom []byte, serverRandom []byte) (keys keyBlock) {
	seed := make([]byte, 0, len(keyExpansionLabel)+len(serverRandom)+len(clientRandom))
	seed = append(seed, keyExpansionLabel...)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	keyMaterial := make([]byte, 2*suite.macLength+2*suite.keyLength+2*suite.ivLength)
	pHash(keyMaterial, masterSecret, seed, suite.newHash)
	parts := []struct {
		target *[]byte
		length int
	}{
		{target: &keys.clientMAC, length: suite.macLength},
		{target: &keys.serverMAC, length: suite.macLength},
		{target: &keys.clientKey, length: suite.keyLength},
		{target: &keys.serverKey, length: suite.keyLength},
		{target: &keys.clientIV, length: suite.ivLength},
		{target: &keys.serverIV, length: suite.ivLength},
	}

	for _, part := range parts {
		*part.target = keyMaterial[:part.length]
		keyMaterial = keyMaterial[part.length:]
	}

	return
}

// HKDF-Expand-Label of RFC 8446 section 7.1
func expandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) (out []byte, err error) {
	fullLabel := labelPrefix + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, expandErr := hkdf.Expand(newHash, secret, string(info), length)

	if expandErr != nil {
		err = fmt.Errorf("%w: %w", ErrSecrets, expandErr)
	}

	return
}

// key and iv of a traffic secret (RFC 8446 section 7.3)
func trafficKey(suite *cipherSuiteTLS13, trafficSecret []byte) (key []byte, iv []byte, err error) {
	key, err = expandLabel(suite.newHash, trafficSecret, keyLabel, nil, suite.keyLength)

	if err != nil {
		return
	}

	iv, err = expandLabel(suite.newHash, trafficSecret, ivLabel, nil, aeadNonceLength)
	return
}

// the traffic secret after a KeyUpdate (RFC 8446 section 7.2)
func nextTrafficSecret(suite *cipherSuiteTLS13, trafficSecret []byte) (next []byte, err error) {
	next, err = expandLabel(suite.newHash, trafficSecret, trafficUpdateLabel, nil, suite.newHash().Size())
	return
}
