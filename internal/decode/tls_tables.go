// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
)

// the values of the IANA TLS parameters registries: versions, content types, handshake types, cipher suites, extensions, supported groups,
// signature schemes, alerts, EC point formats, PSK modes and certificate compression algorithms
var (
	tlsVersions = nameTable{names: map[uint16]string{
		0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0xfeff: "DTLS 1.0", 0xfefd: "DTLS 1.2",
		0xfefc: "DTLS 1.3",
	}, unknown: "0x%04x"}
	tlsContentTypes = nameTable{names: map[uint16]string{
		20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat", 25: "tls12_cid", 26: "ACK",
	}, unknown: "Content type %d"}
	tlsHandshakeTypes = nameTable{names: map[uint16]string{
		0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 3: "Hello Verify Request", 4: "New Session Ticket", 5: "End of Early Data",
		6: "Hello Retry Request", 8: "Encrypted Extensions", 9: "Request Connection ID", 10: "New Connection ID", 11: "Certificate", 12: "Server Key Exchange",
		13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify", 16: "Client Key Exchange", 17: "Client Certificate Request",
		20: "Finished", 21: "Certificate URL", 22: "Certificate Status", 23: "Supplemental Data", 24: "Key Update", 25: "Compressed Certificate",
		26: "EKT Key", 254: "Message Hash",
	}, unknown: "Handshake type %d"}
	tlsCipherSuites = nameTable{names: map[uint16]string{
		0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
		0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x003b: "TLS_RSA_WITH_NULL_SHA256",
		0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256", 0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		0x006a: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x008c: "TLS_PSK_WITH_AES_128_CBC_SHA", 0x008d: "TLS_PSK_WITH_AES_256_CBC_SHA",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x00a2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00a3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		0x00a8: "TLS_PSK_WITH_AES_128_GCM_SHA256", 0x00a9: "TLS_PSK_WITH_AES_256_GCM_SHA384", 0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256", 0x5600: "TLS_FALLBACK_SCSV", 0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xc035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xc036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", 0xc072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		0xc073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", 0xc076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0xc077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", 0xc09c: "TLS_RSA_WITH_AES_128_CCM", 0xc09d: "TLS_RSA_WITH_AES_256_CCM",
		0xc09e: "TLS_DHE_RSA_WITH_AES_128_CCM", 0xc09f: "TLS_DHE_RSA_WITH_AES_256_CCM", 0xc0a0: "TLS_RSA_WITH_AES_128_CCM_8",
		0xc0a1: "TLS_RSA_WITH_AES_256_CCM_8", 0xc0ac: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 0xc0ad: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		0xc0ae: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 0xc0af: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", 0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xccab: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xccac: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
		0xccad: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xd001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xd002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	}, unknown: "0x%04x"}
	tlsExtensionTypes = nameTable{names: map[uint16]string{
		0: "server_name", 1: "max_fragment_length", 2: "client_certificate_url", 3: "trusted_ca_keys", 4: "truncated_hmac", 5: "status_request",
		6: "user_mapping", 7: "client_authz", 8: "server_authz", 9: "cert_type", 10: "supported_groups", 11: "ec_point_formats", 12: "srp",
		13: "signature_algorithms", 14: "use_srtp", 15: "heartbeat", 16: "application_layer_protocol_negotiation", 17: "status_request_v2",
		18: "signed_certificate_timestamp", 19: "client_certificate_type", 20: "server_certificate_type", 21: "padding", 22: "encrypt_then_mac",
		23: "extended_master_secret", 24: "token_binding", 25: "cached_info", 27: "compress_certificate", 28: "record_size_limit", 34: "delegated_credential",
		35: "session_ticket", 41: "pre_shared_key", 42: "early_data", 43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes",
		47: "certificate_authorities", 48: "oid_filters", 49: "post_handshake_auth", 50: "signature_algorithms_cert", 51: "key_share", 54: "connection_id",
		57: "quic_transport_parameters", 17513: "application_settings (old)", 17613: "application_settings", 65037: "encrypted_client_hello",
		65281: "renegotiation_info",
	}, unknown: "0x%04x"}
	tlsGroups = nameTable{names: map[uint16]string{
		19: "secp192r1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 26: "brainpoolP256r1", 27: "brainpoolP384r1",
		28: "brainpoolP512r1", 29: "x25519", 30: "x448", 31: "brainpoolP256r1tls13", 32: "brainpoolP384r1tls13", 33: "brainpoolP512r1tls13",
		256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192", 512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024",
		4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024", 25497: "X25519Kyber768Draft00",
	}, unknown: "0x%04x"}
	tlsSignatureSchemes = nameTable{names: map[uint16]string{
		0x0201: "rsa_pkcs1_sha1", 0x0202: "dsa_sha1", 0x0203: "ecdsa_sha1", 0x0301: "rsa_pkcs1_sha224", 0x0303: "ecdsa_sha224", 0x0401: "rsa_pkcs1_sha256",
		0x0402: "dsa_sha256", 0x0403: "ecdsa_secp256r1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0503: "ecdsa_secp384r1_sha384", 0x0601: "rsa_pkcs1_sha512",
		0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519",
		0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
		0x081a: "ecdsa_brainpoolP256r1tls13_sha256", 0x081b: "ecdsa_brainpoolP384r1tls13_sha384", 0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
		0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
	}, unknown: "0x%04x"}
	tlsAlertLevels       = nameTable{names: map[uint16]string{1: "warning", 2: "fatal"}, unknown: "level %d"}
	tlsAlertDescriptions = nameTable{names: map[uint16]string{
		0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
		40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
		46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
		60: "export_restriction", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
		100: "no_renegotiation", 109: "missing_extension", 110: "unsupported_extension", 111: "certificate_unobtainable", 112: "unrecognized_name",
		113: "bad_certificate_status_response", 114: "bad_certificate_hash_value", 115: "unknown_psk_identity", 116: "certificate_required",
		120: "no_application_protocol", 121: "ech_required",
	}, unknown: "description %d"}
	tlsPointFormats      = nameTable{names: map[uint16]string{0: "uncompressed", 1: "ansiX962_compressed_prime", 2: "ansiX962_compressed_char2"}, unknown: "format %d"}
	tlsPSKModes          = nameTable{names: map[uint16]string{0: "psk_ke", 1: "psk_dhe_ke"}, unknown: "mode %d"}
	tlsCompressions      = nameTable{names: map[uint16]string{0: "null", 1: "DEFLATE"}, unknown: "method %d"}
	tlsCertCompressions  = nameTable{names: map[uint16]string{1: "zlib", 2: "brotli", 3: "zstd"}, unknown: "0x%04x"}
	tlsCurveTypes        = nameTable{names: map[uint16]string{1: "explicit_prime", 2: "explicit_char2", 3: "named_curve"}, unknown: "type %d"}
	tlsStatusTypes       = nameTable{names: map[uint16]string{1: "ocsp", 2: "ocsp_multi"}, unknown: "type %d"}
	tlsKeyUpdates        = nameTable{names: map[uint16]string{0: "update_not_requested", 1: "update_requested"}, unknown: "%d"}
	tlsServerNameTypes   = nameTable{names: map[uint16]string{0: "host_name"}, unknown: "type %d"}
	tlsMaxFragments      = nameTable{names: map[uint16]string{1: "512", 2: "1024", 3: "2048", 4: "4096"}, unknown: "%d"}
	tlsHPKEKDFs          = nameTable{names: map[uint16]string{1: "HKDF-SHA256", 2: "HKDF-SHA384", 3: "HKDF-SHA512"}, unknown: "0x%04x"}
	tlsHPKEAEADs         = nameTable{names: map[uint16]string{1: "AES-128-GCM", 2: "AES-256-GCM", 3: "ChaCha20Poly1305"}, unknown: "0x%04x"}
	tlsECHTypes          = nameTable{names: map[uint16]string{0: "outer", 1: "inner"}, unknown: "type %d"}
	tlsChangeCipherSpecs = nameTable{names: map[uint16]string{1: "change_cipher_spec"}, unknown: "%d"}
)

// a GREASE value of RFC 8701: both bytes alike, each 0x?a
func isGREASE(value uint16) (isGrease bool) {
	isGrease = (value&0x0f0f == 0x0a0a) && (value>>8 == value&0xff)
	return
}

// the name with the value in hex, as the TLS registries write them: TLS_AES_128_GCM_SHA256 (0x1301); GREASE by its name
func hexNameOf(table nameTable, value uint16) (name string) {
	known, isKnown := table.names[value]

	switch {
	case isKnown:
		name = fmt.Sprintf("%s (0x%04x)", known, value)
	case isGREASE(value):
		name = fmt.Sprintf("GREASE (0x%04x)", value)
	default:
		name = fmt.Sprintf("Unknown (0x%04x)", value)
	}

	return
}

// a name alone, GREASE by its name
func tlsShortName(table nameTable, value uint16) (name string) {
	name = shortName(table, value)

	if _, isKnown := table.names[value]; !isKnown && isGREASE(value) {
		name = "GREASE"
	}

	return
}
