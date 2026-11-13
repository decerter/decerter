// SPDX-License-Identifier: AGPL-3.0-only

package capture

const (
	// INGRESS of capture.h
	ingressDirection uint8 = 1
)

// one packet of a recorded socket as the cgroup_skb programs saw it
// Cookie is the socket that sent or got it, FlowCookie the flow in flow_map it belongs to: the same socket in capture mode, the app's socket an upstream socket of the proxy carries in run mode
// TimestampNs is CLOCK_BOOTTIME, Length the bytes of the packet from the IP header on and Data the first snaplen bytes of them
// a GSO or GRO packet is one packet here, an egress packet can have a partial checksum
type Packet struct {
	Cookie      uint64
	FlowCookie  uint64
	TimestampNs uint64
	Length      uint32
	IsIngress   bool
	Data        []byte
}
