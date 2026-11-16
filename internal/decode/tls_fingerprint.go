// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// the fingerprints of the hellos: JA3 and JA3S (github.com/salesforce/ja3: decimal fields joined, MD5 of them) and JA4 of a ClientHello
// (github.com/FoxIO-LLC/ja4, JA4 is BSD-3-Clause: protocol, version, SNI, counts and ALPN, then the truncated SHA-256 of the sorted cipher suites and of
// the sorted extensions with the signature algorithms); GREASE values are left out of all of them; JA4S and the other JA4+ fingerprints are not computed

// JA3 and JA4 of a ClientHello as nodes over the whole message
func tlsClientFingerprints(tree *Tree, messageNode *node, place placement, length int, hello helloInfo, isDTLS bool) {
	ja3 := strings.Join([]string{
		strconv.Itoa(int(hello.version)),
		decimals(hello.ciphers),
		decimals(hello.extensions),
		decimals(hello.groups),
		decimals(hello.pointFormats),
	}, ",")
	ja3Hash := md5.Sum([]byte(ja3))
	tree.addAt(messageNode, place, "tls.handshake.ja3_full", "JA3 fingerprint", ja3, 0, length)
	tree.addAt(messageNode, place, "tls.handshake.ja3", "JA3 hash", hex.EncodeToString(ja3Hash[:]), 0, length)
	tree.addAt(messageNode, place, "tls.handshake.ja4", "JA4 fingerprint", ja4(hello, isDTLS), 0, length)
}

// JA3S of a ServerHello
func tlsServerFingerprints(tree *Tree, messageNode *node, place placement, length int, hello helloInfo) {
	ja3s := strings.Join([]string{strconv.Itoa(int(hello.version)), decimals(hello.ciphers), decimals(hello.extensions)}, ",")
	ja3sHash := md5.Sum([]byte(ja3s))
	tree.addAt(messageNode, place, "tls.handshake.ja3s_full", "JA3S fingerprint", ja3s, 0, length)
	tree.addAt(messageNode, place, "tls.handshake.ja3s", "JA3S hash", hex.EncodeToString(ja3sHash[:]), 0, length)
}

// values without GREASE in decimal, joined by dashes
func decimals(values []uint16) (text string) {
	parts := []string{}

	for _, value := range values {
		if !isGREASE(value) {
			parts = append(parts, strconv.Itoa(int(value)))
		}
	}

	text = strings.Join(parts, "-")
	return
}

// values without GREASE as 4 hex digits each, sorted when isSorted
func hexList(values []uint16, isSorted bool, except ...uint16) (parts []string) {
	for _, value := range values {
		if !isGREASE(value) && !slices.Contains(except, value) {
			parts = append(parts, fmt.Sprintf("%04x", value))
		}
	}

	if isSorted {
		slices.Sort(parts)
	}

	return
}

// JA4 a_b_c of a ClientHello
func ja4(hello helloInfo, isDTLS bool) (fingerprint string) {
	protocol := "t"

	if isDTLS {
		protocol = "d"
	}

	version := hello.version

	for _, offered := range hello.versions {
		if !isGREASE(offered) && (ja4Rank(offered) > ja4Rank(version)) {
			version = offered
		}
	}

	versionText, isKnown := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}[version]

	if !isKnown {
		versionText = "00"
	}

	sni := "i"

	if hello.hasServerName {
		sni = "d"
	}

	ciphers := hexList(hello.ciphers, true)
	extensions := hexList(hello.extensions, false)
	partA := fmt.Sprintf("%s%s%s%02d%02d%s", protocol, versionText, sni, min(len(ciphers), 99), min(len(extensions), 99), ja4ALPN(hello.firstALPN))
	partB := truncatedHash(strings.Join(ciphers, ","), len(ciphers) == 0)
	sorted := hexList(hello.extensions, true, serverNameExtension, alpnExtension)
	signatures := hexList(hello.signatures, false)
	text := strings.Join(sorted, ",")

	if len(signatures) > 0 {
		text += "_" + strings.Join(signatures, ",")
	}

	partC := truncatedHash(text, len(sorted) == 0)
	fingerprint = partA + "_" + partB + "_" + partC
	return
}

// the order of versions for the highest one: DTLS counts down from 0xfeff
func ja4Rank(version uint16) (rank int) {
	rank = int(version)

	if version >= 0xfe00 {
		rank = 0x10000 - int(version)
	}

	return
}

// the first and last character of the first ALPN protocol, their hex digits when one is not alphanumeric, 00 without one
func ja4ALPN(protocol []byte) (text string) {
	if len(protocol) == 0 {
		text = "00"
		return
	}

	first, last := protocol[0], protocol[len(protocol)-1]

	if !isAlphanumeric(first) || !isAlphanumeric(last) {
		text = hex.EncodeToString([]byte{first})[:1] + hex.EncodeToString([]byte{last})[1:]
		return
	}

	text = string([]byte{first, last})
	return
}

func isAlphanumeric(value byte) (isAlphanumeric bool) {
	isAlphanumeric = ((value >= '0') && (value <= '9')) || ((value >= 'A') && (value <= 'Z')) || ((value >= 'a') && (value <= 'z'))
	return
}

// the first 12 hex digits of SHA-256, twelve zeros for an empty list
func truncatedHash(text string, isEmpty bool) (hash string) {
	if isEmpty {
		hash = "000000000000"
		return
	}

	sum := sha256.Sum256([]byte(text))
	hash = hex.EncodeToString(sum[:])[:12]
	return
}
