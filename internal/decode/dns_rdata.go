// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/decerter/decerter/internal/output"
)

// the typed fields of the rdata of a record: RFC 1035 3.3 (A, NS, CNAME, SOA, PTR, HINFO, MX, TXT), RFC 3596 (AAAA), RFC 2782 (SRV), RFC 8659 (CAA),
// RFC 9460 (SVCB, HTTPS), RFC 6891 (OPT), RFC 4034 (DNSKEY, RRSIG, NSEC, DS) and RFC 7344 (CDS, CDNSKEY); any other type is its rdata in hex
// value is a short form for the record's label and the summary
func dnsRdata(tree *Tree, recordNode *node, message dnsMessage, record dnsResource) (value string) {
	reader := &rdataReader{tree: tree, parent: recordNode, message: message, offset: record.rdata, end: record.end, isShort: false}

	switch record.rrType {
	case 1:
		value = reader.address("dns.a", "Address", 4)
	case 28:
		value = reader.address("dns.aaaa", "Address", 16)
	case 2, 3, 4, 5, 7, 8, 9, 12, 39:
		names := map[uint16]string{2: "dns.ns", 5: "dns.cname", 12: "dns.ptr", 39: "dns.dname"}
		fieldName, isNamed := names[record.rrType]

		if !isNamed {
			fieldName = "dns.rr.target"
		}

		value = reader.name(fieldName, "Target")
	case 15, 36:
		preference := reader.uint16Field("dns.mx.preference", "Preference")
		value = strconv.Itoa(int(preference)) + " " + reader.name("dns.mx.exchange", "Exchange")
	case 16, 99:
		texts := []string{}

		for (reader.offset < reader.end) && !reader.isShort && !tree.isFull {
			texts = append(texts, `"`+reader.text("dns.txt", "Text")+`"`)
		}

		value = strings.Join(texts, " ")
	case 13:
		value = reader.text("dns.hinfo.cpu", "CPU") + " " + reader.text("dns.hinfo.os", "OS")
	case 6:
		value = reader.name("dns.soa.mname", "Primary name server")
		reader.name("dns.soa.rname", "Responsible mailbox")
		reader.uint32Field("dns.soa.serial", "Serial number", false)
		reader.uint32Field("dns.soa.refresh", "Refresh interval", true)
		reader.uint32Field("dns.soa.retry", "Retry interval", true)
		reader.uint32Field("dns.soa.expire", "Expire limit", true)
		reader.uint32Field("dns.soa.minimum", "Minimum TTL", true)
	case 33:
		priority := reader.uint16Field("dns.srv.priority", "Priority")
		weight := reader.uint16Field("dns.srv.weight", "Weight")
		port := reader.uint16Field("dns.srv.port", "Port")
		value = fmt.Sprintf("%d %d %d %s", priority, weight, port, reader.name("dns.srv.target", "Target"))
	case 257:
		value = reader.caa()
	case 64, 65:
		value = reader.svcb()
	case optType:
		reader.options()
	case 43, 59:
		keyTag := reader.uint16Field("dns.ds.key_tag", "Key tag")
		algorithm := reader.uint8Named("dns.ds.algorithm", "Algorithm", dnssecAlgorithms)
		reader.uint8Named("dns.ds.digest_type", "Digest type", digestTypes)
		reader.rest("dns.ds.digest", "Digest", false)
		value = fmt.Sprintf("key tag %d, %s", keyTag, shortName(dnssecAlgorithms, uint16(algorithm)))
	case 48, 60:
		value = reader.dnskey(record)
	case 46:
		value = reader.rrsig()
	case 47:
		value = reader.name("dns.nsec.next_domain_name", "Next domain name")
		reader.typeBitmaps("dns.nsec.types")
	default:
		reader.rest("dns.rr.rdata", "Data", false)
	}

	reader.finish()
	return
}

// count bytes at the reader's offset; the first field that does not fit fails the record and stops the reader
func (reader *rdataReader) take(label string, count int) (data []byte, start int, ok bool) {
	if reader.isShort {
		return
	}

	if (count < 0) || (reader.offset+count > reader.end) {
		reader.isShort = true
		reader.tree.fail(reader.parent, fmt.Sprintf("%s: %s", label, errFieldShort.Error()))
		return
	}

	start = reader.offset
	data = reader.message.data[start : start+count]
	reader.offset += count
	ok = true
	return
}

// a field node at start, in payload offsets
func (reader *rdataReader) add(name string, label string, value string, start int, length int) (child *node) {
	child = reader.tree.add(reader.parent, name, label, value, reader.message.base+start, length)
	return
}

func (reader *rdataReader) uint8Field(name string, label string) (value uint8) {
	data, start, ok := reader.take(label, 1)

	if ok {
		value = data[0]
		reader.add(name, label, strconv.Itoa(int(value)), start, 1)
	}

	return
}

func (reader *rdataReader) uint8Named(name string, label string, table nameTable) (value uint8) {
	data, start, ok := reader.take(label, 1)

	if ok {
		value = data[0]
		reader.add(name, label, nameOf(table, uint16(value)), start, 1)
	}

	return
}

func (reader *rdataReader) uint16Field(name string, label string) (value uint16) {
	data, start, ok := reader.take(label, 2)

	if ok {
		value = binary.BigEndian.Uint16(data)
		reader.add(name, label, strconv.Itoa(int(value)), start, 2)
	}

	return
}

// isDuration adds the seconds in days, hours and minutes
func (reader *rdataReader) uint32Field(name string, label string, isDuration bool) (value uint32) {
	data, start, ok := reader.take(label, 4)

	if !ok {
		return
	}

	value = binary.BigEndian.Uint32(data)
	text := strconv.FormatUint(uint64(value), 10)

	if isDuration {
		text = ttlText(value)
	}

	reader.add(name, label, text, start, 4)
	return
}

// an RFC 4034 3.1.5 time: seconds since 1970 modulo 2^32, shown as a UTC time
func (reader *rdataReader) timeField(name string, label string) (value uint32) {
	data, start, ok := reader.take(label, 4)

	if ok {
		value = binary.BigEndian.Uint32(data)
		reader.add(name, label, time.Unix(int64(value), 0).UTC().Format(time.RFC3339), start, 4)
	}

	return
}

// an address of size bytes, the whole rdata
func (reader *rdataReader) address(name string, label string, size int) (value string) {
	if reader.end-reader.offset != size {
		reader.isShort = true
		reader.tree.fail(reader.parent, fmt.Sprintf("the address has %d bytes, the rdata %d", size, reader.end-reader.offset))
		reader.add("dns.rr.rdata", "Data", hexValue(reader.message.data[reader.offset:reader.end]), reader.offset, reader.end-reader.offset)
		return
	}

	data, start, _ := reader.take(label, size)
	address, _ := netip.AddrFromSlice(data)
	value = address.String()
	reader.add(name, label, value, start, size)
	return
}

// a domain name in the rdata, compressed or not: RFC 3597 and RFC 4034 forbid compression in the newer types, a pointer there is still followed
func (reader *rdataReader) name(fieldName string, label string) (value string) {
	if reader.isShort {
		return
	}

	value, length, nameErr := reader.message.name(reader.offset)

	if (nameErr == nil) && (reader.offset+length > reader.end) {
		nameErr = errFieldShort
	}

	if nameErr != nil {
		reader.isShort = true
		reader.tree.fail(reader.parent, label+": "+nameErr.Error())
		value = ""
		return
	}

	reader.add(fieldName, label, value, reader.offset, length)
	reader.offset += length
	return
}

// a character-string: a length byte and that many bytes, escaped
func (reader *rdataReader) text(name string, label string) (value string) {
	lengthData, start, ok := reader.take(label, 1)

	if !ok {
		return
	}

	data, _, ok := reader.take(label, int(lengthData[0]))

	if !ok {
		return
	}

	value = output.Escape(data)
	reader.add(name, label, value, start, 1+len(data))
	return
}

// the bytes up to the end of the rdata, as hex or as base64 (keys and signatures, the way zone files write them)
func (reader *rdataReader) rest(name string, label string, isBase64 bool) (data []byte) {
	data, start, ok := reader.take(label, reader.end-reader.offset)

	if !ok {
		return
	}

	value := hexValue(data)

	if isBase64 {
		value = base64Value(data)
	}

	reader.add(name, label, value, start, len(data))
	return
}

// bytes after the last field of a known type
func (reader *rdataReader) finish() {
	if !reader.isShort && (reader.offset < reader.end) {
		reader.tree.fail(reader.parent, fmt.Sprintf("%s: %d bytes", errRdataTrailer.Error(), reader.end-reader.offset))
	}
}

// RFC 8659 4.1: flags, the tag and the value up to the end
func (reader *rdataReader) caa() (value string) {
	flagsData, start, ok := reader.take("Flags", 1)

	if !ok {
		return
	}

	flags := reader.add("dns.caa.flags", "Flags", fmt.Sprintf("0x%02x", flagsData[0]), start, 1)
	reader.tree.addBits(flags, "dns.caa.flags.critical", "Issuer critical", yesNo(flagsData[0]&0x80 != 0), reader.message.base+start, 1, 0x80)
	tagLength := reader.uint8Field("dns.caa.tag_length", "Tag length")
	tagData, tagStart, ok := reader.take("Tag", int(tagLength))

	if !ok {
		return
	}

	tag := output.Escape(tagData)
	reader.add("dns.caa.tag", "Tag", tag, tagStart, len(tagData))
	valueData, valueStart, _ := reader.take("Value", reader.end-reader.offset)
	text := output.Escape(valueData)
	reader.add("dns.caa.value", "Value", text, valueStart, len(valueData))
	value = fmt.Sprintf(`%d %s "%s"`, flagsData[0], tag, text)
	return
}

// RFC 9460 2.2: priority, target and the SvcParams, each key, length and value
func (reader *rdataReader) svcb() (value string) {
	priority := reader.uint16Field("dns.svcb.priority", "Priority")
	target := reader.name("dns.svcb.target", "Target")
	parts := []string{strconv.Itoa(int(priority)), target}
	mode := "service mode"

	if priority == 0 {
		mode = "alias mode"
	}

	if reader.isShort {
		return
	}

	for (reader.offset < reader.end) && !reader.isShort && !reader.tree.isFull {
		start := reader.offset
		header, _, ok := reader.take("SvcParam", 4)

		if !ok {
			break
		}

		key := binary.BigEndian.Uint16(header)
		length := int(binary.BigEndian.Uint16(header[2:]))
		data, dataStart, ok := reader.take(shortName(svcbKeys, key), length)

		if !ok {
			break
		}

		param := reader.add("dns.svcb.param", "SvcParam", "", start, 4+length)
		paramReader := &rdataReader{tree: reader.tree, parent: param, message: reader.message, offset: start, end: start + 4 + length, isShort: false}
		paramReader.add("dns.svcb.param.key", "Key", nameOf(svcbKeys, key), start, 2)
		paramReader.add("dns.svcb.param.length", "Length", strconv.Itoa(length), start+2, 2)
		paramReader.offset = dataStart
		text := paramReader.svcbValue(key, data)
		label := shortName(svcbKeys, key)

		if text != "" {
			label += "=" + text
		}

		reader.tree.setLabel(param, label)
		parts = append(parts, label)

		paramReader.finish()
	}

	value = strings.Join(parts, " ") + " (" + mode + ")"
	return
}

// the value of one SvcParam (RFC 9460 7, RFC 9461 for dohpath), the reader is at its first byte; unknown keys are hex
func (reader *rdataReader) svcbValue(key uint16, data []byte) (text string) {
	values := []string{}

	switch key {
	case 0:
		for (reader.offset < reader.end) && !reader.isShort {
			keyData, start, ok := reader.take("Mandatory key", 2)

			if ok {
				name := shortName(svcbKeys, binary.BigEndian.Uint16(keyData))
				reader.add("dns.svcb.param.mandatory.key", "Mandatory key", name, start, 2)
				values = append(values, name)
			}
		}
	case 1:
		for (reader.offset < reader.end) && !reader.isShort {
			values = append(values, reader.text("dns.svcb.param.alpn", "ALPN"))
		}
	case 2, 8:
	case 3:
		values = append(values, strconv.Itoa(int(reader.uint16Field("dns.svcb.param.port", "Port"))))
	case 4, 6:
		size, name := 4, "dns.svcb.param.ipv4hint.ip"

		if key == 6 {
			size, name = 16, "dns.svcb.param.ipv6hint.ip"
		}

		for (reader.offset < reader.end) && !reader.isShort {
			addressData, start, ok := reader.take("Address", size)

			if ok {
				address, _ := netip.AddrFromSlice(addressData)
				reader.add(name, "Address", address.String(), start, size)
				values = append(values, address.String())
			}
		}
	case 5:
		reader.rest("dns.svcb.param.ech", "ECHConfigList", true)
		values = append(values, base64Value(data))
	case 7:
		dataStart := reader.offset
		reader.offset = reader.end
		values = append(values, output.Escape(data))
		reader.add("dns.svcb.param.dohpath", "DoH path", output.Escape(data), dataStart, len(data))
	case 9:
		for (reader.offset < reader.end) && !reader.isShort {
			values = append(values, strconv.Itoa(int(reader.uint16Field("dns.svcb.param.tls_supported_groups.group", "Group"))))
		}
	default:
		reader.rest("dns.svcb.param.value", "Value", false)
		values = append(values, hexValue(data))
	}

	text = strings.Join(values, ",")
	return
}

// RFC 6891 6.1.2 to 6.1.3: the class is the UDP payload size the sender takes, the TTL the extended reply code, the version and the flags
func dnsOPTHeader(tree *Tree, recordNode *node, message dnsMessage, record dnsResource, fixed int) {
	base := message.base
	extended := uint16(record.ttl>>24)<<4 | uint16(message.rcode)
	tree.add(recordNode, "dns.rr.udp_payload_size", "UDP payload size", strconv.Itoa(int(record.class)), base+fixed+2, 2)
	tree.add(recordNode, "dns.rr.ext_rcode", "Extended reply code", fmt.Sprintf("%d (with the header: %s)", record.ttl>>24, nameOf(dnsRcodes, extended)), base+fixed+4, 1)
	tree.add(recordNode, "dns.rr.edns_version", "EDNS version", strconv.Itoa(int(record.ttl>>16&0xff)), base+fixed+5, 1)
	flags := tree.add(recordNode, "dns.rr.edns_flags", "Flags", fmt.Sprintf("0x%04x", record.ttl&0xffff), base+fixed+6, 2)
	tree.addBits(flags, "dns.rr.edns_flags.do", "DNSSEC OK", yesNo(record.ttl&0x8000 != 0), base+fixed+6, 2, 0x8000)
	tree.addBits(flags, "dns.rr.edns_flags.z", "Z (reserved)", fmt.Sprintf("0x%04x", record.ttl&0x7fff), base+fixed+6, 2, 0x7fff)
}

// the EDNS options of an OPT record: code, length and the data of each, typed for the common ones
func (reader *rdataReader) options() {
	for (reader.offset < reader.end) && !reader.isShort && !reader.tree.isFull {
		start := reader.offset
		header, _, ok := reader.take("Option", 4)

		if !ok {
			return
		}

		code := binary.BigEndian.Uint16(header)
		length := int(binary.BigEndian.Uint16(header[2:]))
		data, dataStart, ok := reader.take(shortName(ednsOptions, code), length)

		if !ok {
			return
		}

		option := reader.add("dns.opt", "Option: "+shortName(ednsOptions, code), "", start, 4+length)
		optionReader := &rdataReader{tree: reader.tree, parent: option, message: reader.message, offset: start, end: start + 4 + length, isShort: false}
		optionReader.add("dns.opt.code", "Code", nameOf(ednsOptions, code), start, 2)
		optionReader.add("dns.opt.len", "Length", strconv.Itoa(length), start+2, 2)
		optionReader.offset = dataStart
		optionReader.option(code, data)
		optionReader.finish()
	}
}

// the data of one EDNS option, the reader is at its first byte
func (reader *rdataReader) option(code uint16, data []byte) {
	switch code {
	case 3:
		reader.rest("dns.opt.nsid", "NSID", false)
		reader.tree.setValue(reader.parent, output.Escape(data))
	case 5, 6, 7:
		names := []string{}

		for (reader.offset < reader.end) && !reader.isShort {
			names = append(names, shortName(dnssecAlgorithms, uint16(reader.uint8Named("dns.opt.algorithm", "Algorithm", dnssecAlgorithms))))
		}

		reader.tree.setValue(reader.parent, strings.Join(names, ", "))
	case 8:
		reader.clientSubnet()
	case 9:
		if len(data) == 4 {
			reader.uint32Field("dns.opt.expire", "Expire", true)
		}
	case 10:
		client, start, ok := reader.take("Client cookie", min(8, len(data)))

		if !ok {
			return
		}

		reader.add("dns.opt.cookie.client", "Client cookie", hex.EncodeToString(client), start, len(client))

		if reader.offset < reader.end {
			reader.rest("dns.opt.cookie.server", "Server cookie", false)
		}

		if (len(data) != 8) && ((len(data) < 16) || (len(data) > 40)) {
			reader.tree.fail(reader.parent, fmt.Sprintf("a cookie has 8 bytes or 16 to 40 (RFC 7873), this one %d", len(data)))
		}
	case 11:
		if len(data) == 2 {
			timeout := reader.uint16Field("dns.opt.tcp_keepalive.timeout", "Timeout (100 ms)")
			reader.tree.setValue(reader.parent, fmt.Sprintf("%.1f s", float64(timeout)/10))
		}
	case 12:
		reader.offset = reader.end
		reader.tree.setValue(reader.parent, fmt.Sprintf("%d bytes", len(data)))
		reader.add("dns.opt.padding", "Padding", fmt.Sprintf("%d bytes", len(data)), reader.end-len(data), len(data))
	case 15:
		infoCode := reader.uint16Field("dns.opt.ede.info_code", "Info code")

		if reader.isShort {
			return
		}

		reader.tree.setValue(reader.parent, nameOf(ednsErrors, infoCode))
		textData, start, _ := reader.take("Extra text", reader.end-reader.offset)

		if len(textData) > 0 {
			reader.add("dns.opt.ede.extra_text", "Extra text", output.Escape(textData), start, len(textData))
			reader.tree.setValue(reader.parent, reader.parent.value+": "+output.Escape(textData))
		}
	}

	if reader.offset < reader.end {
		reader.rest("dns.opt.data", "Data", false)
	}
}

// RFC 7871 6: the family, the source and scope prefix lengths and as many bytes of the address as the source prefix needs
func (reader *rdataReader) clientSubnet() {
	familyData, familyStart, ok := reader.take("Family", 2)

	if !ok {
		return
	}

	family := binary.BigEndian.Uint16(familyData)
	reader.add("dns.opt.client.family", "Family", nameOf(subnetFamilies, family), familyStart, 2)
	source := reader.uint8Field("dns.opt.client.netmask", "Source prefix length")
	reader.uint8Field("dns.opt.client.scope", "Scope prefix length")
	addressData, start, ok := reader.take("Address", reader.end-reader.offset)

	if !ok {
		return
	}

	size := map[uint16]int{1: 4, 2: 16}[family]

	if (size == 0) || (len(addressData) > size) || (len(addressData) != (int(source)+7)/8) {
		reader.add("dns.opt.client.addr", "Address", hexValue(addressData), start, len(addressData))
		reader.tree.fail(reader.parent, fmt.Sprintf("the address has %d bytes, the family and source prefix length %d need %d", len(addressData), source, (int(source)+7)/8))
		return
	}

	full := make([]byte, size)
	copy(full, addressData)
	address, _ := netip.AddrFromSlice(full)
	prefix := netip.PrefixFrom(address, int(source)).String()
	reader.add("dns.opt.client.addr", "Address", prefix, start, len(addressData))
	reader.tree.setValue(reader.parent, prefix)
}

// RFC 4034 2.1: flags, protocol, algorithm and the public key; the key tag (appendix B) is computed over the whole rdata
func (reader *rdataReader) dnskey(record dnsResource) (value string) {
	flagsData, start, ok := reader.take("Flags", 2)

	if !ok {
		return
	}

	flagsValue := binary.BigEndian.Uint16(flagsData)
	base := reader.message.base + start
	flags := reader.add("dns.dnskey.flags", "Flags", fmt.Sprintf("0x%04x", flagsValue), start, 2)
	reader.tree.addBits(flags, "dns.dnskey.flags.zone_key", "Zone key", yesNo(flagsValue&0x0100 != 0), base, 2, 0x0100)
	reader.tree.addBits(flags, "dns.dnskey.flags.key_revoked", "Revoked", yesNo(flagsValue&0x0080 != 0), base, 2, 0x0080)
	reader.tree.addBits(flags, "dns.dnskey.flags.secure_entry_point", "Secure entry point", yesNo(flagsValue&0x0001 != 0), base, 2, 0x0001)
	protocol := reader.uint8Field("dns.dnskey.protocol", "Protocol")
	algorithm := reader.uint8Named("dns.dnskey.algorithm", "Algorithm", dnssecAlgorithms)
	reader.rest("dns.dnskey.public_key", "Public key", true)

	if reader.isShort {
		return
	}

	if protocol != 3 {
		reader.tree.fail(reader.parent, fmt.Sprintf("the protocol is %d, RFC 4034 2.1.2 says 3", protocol))
	}

	keyTag := dnskeyTag(reader.message.data[record.rdata:record.end])
	reader.add("dns.dnskey.key_id", "Key tag", strconv.Itoa(int(keyTag)), record.rdata, record.rdLength)
	value = fmt.Sprintf("key tag %d, %s", keyTag, shortName(dnssecAlgorithms, uint16(algorithm)))

	if flagsValue&0x0001 != 0 {
		value += ", KSK"
	}

	return
}

// RFC 4034 appendix B: the sum of the rdata as 16-bit words with the carry folded in
func dnskeyTag(rdata []byte) (tag uint16) {
	sum := uint32(0)

	for index, value := range rdata {
		if index&1 == 0 {
			sum += uint32(value) << 8
		} else {
			sum += uint32(value)
		}
	}

	sum += sum >> 16 & 0xffff
	tag = uint16(sum)
	return
}

// RFC 4034 3.1: the covered type, algorithm, labels, original TTL, the validity, key tag, signer and the signature
func (reader *rdataReader) rrsig() (value string) {
	typeData, start, ok := reader.take("Type covered", 2)

	if !ok {
		return
	}

	covered := binary.BigEndian.Uint16(typeData)
	reader.add("dns.rrsig.type_covered", "Type covered", nameOf(dnsTypes, covered), start, 2)
	algorithm := reader.uint8Named("dns.rrsig.algorithm", "Algorithm", dnssecAlgorithms)
	reader.uint8Field("dns.rrsig.labels", "Labels")
	reader.uint32Field("dns.rrsig.original_ttl", "Original TTL", true)
	reader.timeField("dns.rrsig.signature_expiration", "Signature expiration")
	reader.timeField("dns.rrsig.signature_inception", "Signature inception")
	keyTag := reader.uint16Field("dns.rrsig.key_tag", "Key tag")
	signer := reader.name("dns.rrsig.signers_name", "Signer's name")
	reader.rest("dns.rrsig.signature", "Signature", true)
	value = fmt.Sprintf("%s %s, key tag %d, %s", shortName(dnsTypes, covered), shortName(dnssecAlgorithms, uint16(algorithm)), keyTag, signer)
	return
}

// RFC 4034 4.1.2: windows of up to 256 types, each a window number, a bitmap length of 1 to 32 and the bitmap, the most significant bit first
func (reader *rdataReader) typeBitmaps(name string) {
	types := []string{}
	start := reader.offset
	previous := -1

	for (reader.offset < reader.end) && !reader.isShort {
		header, _, ok := reader.take("Type bitmap", 2)

		if !ok {
			return
		}

		window, length := int(header[0]), int(header[1])

		if (length < 1) || (length > 32) || (window <= previous) {
			reader.tree.fail(reader.parent, fmt.Sprintf("type bitmap window %d with %d bytes: RFC 4034 4.1.2 needs 1 to 32 bytes and increasing windows", window, length))
		}

		previous = window
		bitmap, _, ok := reader.take("Type bitmap", length)

		if !ok {
			return
		}

		for index, value := range bitmap {
			for bit := range 8 {
				if value&(0x80>>bit) != 0 {
					types = append(types, shortName(dnsTypes, uint16(window*256+index*8+bit)))
				}
			}
		}
	}

	reader.add(name, "Types", strings.Join(slices.Compact(types), " "), start, reader.offset-start)
}

// at most maxValueBytes of data in hex, the length after it when there is more
func hexValue(data []byte) (value string) {
	value = hex.EncodeToString(data[:min(len(data), maxValueBytes)])

	if len(data) > maxValueBytes {
		value += fmt.Sprintf("... (%d bytes)", len(data))
	}

	return
}

func base64Value(data []byte) (value string) {
	value = base64.StdEncoding.EncodeToString(data[:min(len(data), maxValueBytes)])

	if len(data) > maxValueBytes {
		value += fmt.Sprintf("... (%d bytes)", len(data))
	}

	return
}
