// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
)

// the values of the IANA DNS parameters registries (types, classes, opcodes, rcodes, EDNS options, SVCB keys) and the DNSSEC algorithm numbers
var (
	dnsTypes = nameTable{names: map[uint16]string{
		1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX",
		16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT",
		42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA",
		53: "SMIMEA", 55: "HIP", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF", 249: "TKEY",
		250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ANY", 256: "URI", 257: "CAA", 32769: "DLV",
	}, unknown: "TYPE%d"}
	dnsClasses = nameTable{names: map[uint16]string{1: "IN", 2: "CS", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}, unknown: "CLASS%d"}
	dnsOpcodes = nameTable{names: map[uint16]string{0: "Standard", 1: "Inverse", 2: "Status", 4: "Notify", 5: "Update", 6: "DSO"}, unknown: "Opcode %d"}
	dnsRcodes  = nameTable{names: map[uint16]string{
		0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented", 5: "Refused", 6: "Name exists", 7: "RRset exists",
		8: "RRset does not exist", 9: "Not authoritative", 10: "Name not in zone", 11: "DSO type not implemented", 16: "Bad version or signature", 17: "Bad key",
		18: "Bad time", 19: "Bad mode", 20: "Duplicate key name", 21: "Bad algorithm", 22: "Bad truncation", 23: "Bad cookie",
	}, unknown: "Rcode %d"}
	ednsOptions = nameTable{names: map[uint16]string{
		1: "LLQ", 2: "Update Lease", 3: "NSID", 5: "DAU", 6: "DHU", 7: "N3U", 8: "Client Subnet", 9: "Expire", 10: "Cookie", 11: "TCP Keepalive", 12: "Padding",
		13: "Chain", 14: "Key Tag", 15: "Extended DNS Error", 16: "Client Tag", 17: "Server Tag", 18: "Report Channel", 19: "Zone Version",
	}, unknown: "Option %d"}
	ednsErrors = nameTable{names: map[uint16]string{
		0: "Other", 1: "Unsupported DNSKEY Algorithm", 2: "Unsupported DS Digest Type", 3: "Stale Answer", 4: "Forged Answer", 5: "DNSSEC Indeterminate",
		6: "DNSSEC Bogus", 7: "Signature Expired", 8: "Signature Not Yet Valid", 9: "DNSKEY Missing", 10: "RRSIGs Missing", 11: "No Zone Key Bit Set",
		12: "NSEC Missing", 13: "Cached Error", 14: "Not Ready", 15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited", 19: "Stale NXDOMAIN Answer",
		20: "Not Authoritative", 21: "Not Supported", 22: "No Reachable Authority", 23: "Network Error", 24: "Invalid Data",
	}, unknown: "Error %d"}
	svcbKeys = nameTable{names: map[uint16]string{
		0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port", 4: "ipv4hint", 5: "ech", 6: "ipv6hint", 7: "dohpath", 8: "ohttp", 9: "tls-supported-groups",
	}, unknown: "key%d"}
	dnssecAlgorithms = nameTable{names: map[uint16]string{
		1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512", 12: "ECC-GOST", 13: "ECDSAP256SHA256",
		14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448",
	}, unknown: "Algorithm %d"}
	digestTypes    = nameTable{names: map[uint16]string{1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}, unknown: "Digest %d"}
	subnetFamilies = nameTable{names: map[uint16]string{1: "IPv4", 2: "IPv6"}, unknown: "Family %d"}
)

// the name of a value, or the table's form for an unknown one
func shortName(table nameTable, value uint16) (name string) {
	name, isKnown := table.names[value]

	if !isKnown {
		name = fmt.Sprintf(table.unknown, value)
	}

	return
}

// the name with the number: A (1)
func nameOf(table nameTable, value uint16) (name string) {
	name = fmt.Sprintf("%s (%d)", shortName(table, value), value)
	return
}
