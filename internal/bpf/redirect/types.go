// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"net/netip"
	"strconv"
)

// IPProtocol is IPPROTO_TCP or IPPROTO_UDP
type DestinationPort struct {
	Port       uint16
	IPProtocol uint8
}

// a process is selected if its uid is in UIDs or its tgid in Tgids, with both empty no process is selected
// a flow of a selected process is in scope if its destination matches every destination filter that is set: any of DestinationCIDRs and any of DestinationPorts, an empty one passes everything
type Filter struct {
	UIDs             []uint32
	Tgids            []uint32
	DestinationCIDRs []netip.Prefix
	DestinationPorts []DestinationPort
}

// Mark is the SO_MARK of the app's socket, on Android netd's fwmark of the app's network, 0 when the socket has none
type Flow struct {
	OriginalDestination netip.AddrPort
	IPProtocol          uint8
	Redirected          bool
	Tgid                uint32
	UID                 uint32
	CgroupID            uint64
	Comm                string
	Mark                uint32
	Client              netip.AddrPort
}

func (destinationPort DestinationPort) String() (text string) {
	text = ProtocolName(destinationPort.IPProtocol) + "/" + strconv.Itoa(int(destinationPort.Port))
	return
}
