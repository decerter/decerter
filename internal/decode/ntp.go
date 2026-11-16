// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	v1 "github.com/decerter/decerter/api"
)

// NTP from RFC 5905 (the packet header, timestamps, extension fields and the MAC) and RFC 7822 (extension fields); control (mode 6) and private (mode 7)
// messages show their header and the rest as bytes
const (
	ntpProtocol    string = "ntp"
	ntpTitle       string = "Network Time Protocol"
	ntpHeaderBytes int    = 48
	ntpPort        uint16 = 123
	// the seconds from the NTP era 0 (1900) to the Unix epoch
	ntpUnixOffset int64 = 2208988800
	// a timestamp below this is taken as era 1 (from 2036 on), as RFC 4330 3 suggests
	ntpEraPivot uint32 = 0x80000000
)

var (
	ntpModes = nameTable{names: map[uint16]string{0: "reserved", 1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server", 5: "broadcast", 6: "control", 7: "private"}, unknown: "mode %d"}
	ntpLeaps = nameTable{names: map[uint16]string{0: "no warning", 1: "last minute of the day has 61 seconds", 2: "last minute of the day has 59 seconds", 3: "unknown (clock unsynchronized)"}, unknown: "%d"}
)

func init() {
	register(decoder{
		Protocol:   ntpProtocol,
		Title:      ntpTitle,
		Ports:      []Port{{Layer: v1.UDPLayer, Number: ntpPort}},
		hint:       noHint,
		sniff:      ntpSniff,
		decode:     ntpDecode,
		fromTarget: nil,
	})
}

// a header of version 1 to 4 and a known mode; a packet of 48 bytes, or 48 with extension fields and a MAC that add up, is likely
func ntpSniff(data []byte, context Context) (score int) {
	if (context.Transport != DatagramTransport) || (len(data) < ntpHeaderBytes) {
		return
	}

	version, mode := (data[0]>>3)&7, data[0]&7

	if (version < 1) || (version > 4) || (mode == 0) || (mode >= 6) || (data[1] > 16) {
		return
	}

	score = 30

	if ntpTrailerFits(data[ntpHeaderBytes:]) {
		score = 70
	}

	return
}

// extension fields (a length that is a multiple of 4, at least 16) and then a MAC of 4+16 or 4+20 bytes, or nothing
func ntpTrailerFits(data []byte) (fits bool) {
	for {
		switch len(data) {
		case 0, 20, 24:
			fits = true
			return
		}

		if len(data) < 16 {
			return
		}

		length := int(binary.BigEndian.Uint16(data[2:]))

		if (length < 16) || (length%4 != 0) || (length > len(data)) {
			return
		}

		data = data[length:]
	}
}

func ntpDecode(tree *Tree, data []byte, context Context) {
	root := tree.add(nil, ntpProtocol, ntpTitle, "", 0, len(data))

	if len(data) < 4 {
		tree.fail(root, fmt.Sprintf("an NTP header has %d bytes, the packet %d", ntpHeaderBytes, len(data)))
		tree.addSummary("Malformed NTP packet")
		return
	}

	first := data[0]
	leap, version, mode := first>>6, (first>>3)&7, first&7
	root.label = fmt.Sprintf("%s, version %d (%s)", ntpTitle, version, shortName(ntpModes, uint16(mode)))
	flags := tree.add(root, "ntp.flags", "Flags", fmt.Sprintf("0x%02x", first), 0, 1)
	tree.addBits(flags, "ntp.flags.li", "Leap indicator", nameOf(ntpLeaps, uint16(leap)), 0, 1, 0xc0)
	tree.addBits(flags, "ntp.flags.vn", "Version", strconv.Itoa(int(version)), 0, 1, 0x38)
	tree.addBits(flags, "ntp.flags.mode", "Mode", nameOf(ntpModes, uint16(mode)), 0, 1, 0x07)
	reader := fieldsOf(tree, root, data, 1, len(data))

	if mode >= 6 {
		reader.bytesField("ntp.control", "Control or private message", reader.left())
		tree.addSummary(fmt.Sprintf("NTP version %d, %s", version, shortName(ntpModes, uint16(mode))))
		return
	}

	stratum, _ := reader.number("ntp.stratum", "Peer clock stratum", 1, ntpStratumText)
	reader.number("ntp.ppoll", "Peer polling interval", 1, func(value uint32) (text string) { text = log2Text(int8(value)); return })
	reader.number("ntp.precision", "Peer clock precision", 1, func(value uint32) (text string) { text = log2Text(int8(value)); return })
	reader.number("ntp.rootdelay", "Root delay", 4, shortFormatText)
	reader.number("ntp.rootdispersion", "Root dispersion", 4, shortFormatText)

	if referenceData, start, ok := reader.take("Reference ID", 4); ok {
		reader.add("ntp.refid", "Reference ID", ntpReferenceText(referenceData, stratum), start, 4)
	}

	reader.number64("ntp.reftime", "Reference timestamp", ntpTimeText)
	reader.number64("ntp.org", "Origin timestamp", ntpTimeText)
	reader.number64("ntp.rec", "Receive timestamp", ntpTimeText)
	transmit, _ := reader.number64("ntp.xmt", "Transmit timestamp", ntpTimeText)

	// extension fields while more than a MAC is left
	for (reader.left() > 24) && !reader.isShort && !tree.isFull {
		fieldStart := reader.offset
		length := int(binary.BigEndian.Uint16(data[fieldStart+2:]))
		field := tree.add(root, "ntp.ext", "Extension field", "", fieldStart, min(max(length, 4), reader.left()))
		inner := reader.vector(field, "Extension field", max(length, 4))
		fieldType, _ := inner.number("ntp.ext.fieldtype", "Field type", 2, func(value uint32) (text string) { text = fmt.Sprintf("0x%04x", value); return })
		inner.number("ntp.ext.length", "Length", 2, nil)
		inner.bytesField("ntp.ext.value", "Value", inner.left())
		field.value = fmt.Sprintf("type 0x%04x, %d bytes", fieldType, length)

		if (length < 16) || (length%4 != 0) {
			tree.fail(field, "an extension field has a length of at least 16 that is a multiple of 4")
		}
	}

	if reader.left() >= 4 {
		mac := tree.add(root, "ntp.mac", "Message authentication code", "", reader.offset, reader.left())
		inner := reader.vector(mac, "MAC", reader.left())
		inner.number("ntp.keyid", "Key ID", 4, hexWord)
		inner.bytesField("ntp.mac.digest", "Digest", inner.left())
	}

	reader.finish()
	tree.addSummary(fmt.Sprintf("NTP version %d, %s, stratum %d, transmit %s", version, shortName(ntpModes, uint16(mode)), stratum, ntpTimeText(transmit)))
}

func ntpStratumText(value uint32) (text string) {
	switch {
	case value == 0:
		text = "0 (unspecified or invalid)"
	case value == 1:
		text = "1 (primary reference)"
	case value <= 15:
		text = fmt.Sprintf("%d (secondary reference)", value)
	case value == 16:
		text = "16 (unsynchronized)"
	default:
		text = fmt.Sprintf("%d (reserved)", value)
	}

	return
}

// a power of two in seconds: 6 (64 s), -20 (0.000001 s)
func log2Text(exponent int8) (text string) {
	seconds := 1.0

	for range min(int(exponent), 62) {
		seconds *= 2
	}

	for range min(-int(exponent), 62) {
		seconds /= 2
	}

	text = fmt.Sprintf("%d (%g s)", exponent, seconds)
	return
}

// the NTP short format: 16.16 seconds
func shortFormatText(value uint32) (text string) {
	text = fmt.Sprintf("%.6f s", float64(value)/65536)
	return
}

// a kiss code or the clock source of stratum 0 and 1 as text, an IPv4 address (or the start of an IPv6 address's MD5) above
func ntpReferenceText(data []byte, stratum uint32) (text string) {
	if stratum <= 1 {
		end := len(data)

		for (end > 0) && (data[end-1] == 0) {
			end--
		}

		text = textValue(data[:end])
		return
	}

	text = netip.AddrFrom4([4]byte(data)).String()
	return
}

// an NTP timestamp: seconds since 1900 (era 1 from 2036 on) and a fraction, in RFC 3339; zero means not set
func ntpTimeText(value uint64) (text string) {
	if value == 0 {
		text = "0 (not set)"
		return
	}

	seconds, fraction := uint32(value>>32), uint32(value)
	unix := int64(seconds) - ntpUnixOffset

	if seconds < ntpEraPivot {
		unix += 1 << 32
	}

	moment := time.Unix(unix, int64((uint64(fraction)*1e9)>>32)).UTC()
	text = moment.Format(time.RFC3339Nano)
	return
}
