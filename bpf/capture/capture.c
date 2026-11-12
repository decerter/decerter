// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "capture.h"

//Copy the packets recorded sockets send into packet_map, every packet passes
SEC("cgroup_skb/egress")
int capture_egress(struct __sk_buff *skb)
{
	switch (capture_packet(skb, EGRESS))
	{
	case OK:
		return SKB_PASS;
	default:
		return SKB_PASS;
	}
}

//Copy the packets recorded sockets receive into packet_map, every packet passes
SEC("cgroup_skb/ingress")
int capture_ingress(struct __sk_buff *skb)
{
	switch (capture_packet(skb, INGRESS))
	{
	case OK:
		return SKB_PASS;
	default:
		return SKB_PASS;
	}
}
