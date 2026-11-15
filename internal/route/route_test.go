// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package route

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// one route of a dump: Destination is nil for a default route, Length is dst_len
type routeMessage struct {
	Family      uint8
	Length      uint8
	Table       uint8
	Type        uint8
	Destination []byte
}

var (
	// the tables of a host with a policy route: main, local, a VPN table 100 that blackholes 10/8 and a table 200 that routes it
	dumpMessages = []routeMessage{
		{Family: syscall.AF_INET, Length: 0, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: nil},
		// dst_len 24 with host bits set, the prefix is masked
		{Family: syscall.AF_INET, Length: 24, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: []byte{192, 168, 1, 5}},
		{Family: syscall.AF_INET, Length: 8, Table: syscall.RT_TABLE_LOCAL, Type: syscall.RTN_LOCAL, Destination: []byte{127, 0, 0, 0}},
		{Family: syscall.AF_INET, Length: 32, Table: syscall.RT_TABLE_LOCAL, Type: syscall.RTN_BROADCAST, Destination: []byte{192, 168, 1, 255}},
		{Family: syscall.AF_INET, Length: 8, Table: 100, Type: syscall.RTN_BLACKHOLE, Destination: []byte{10, 0, 0, 0}},
		// a broadcast address is never routable for the proxy, also when another table has a unicast route for it
		{Family: syscall.AF_INET, Length: 32, Table: syscall.RT_TABLE_LOCAL, Type: syscall.RTN_BROADCAST, Destination: []byte{10, 0, 0, 255}},
		{Family: syscall.AF_INET, Length: 32, Table: 200, Type: syscall.RTN_UNICAST, Destination: []byte{10, 0, 0, 255}},
		{Family: syscall.AF_INET, Length: 8, Table: 200, Type: syscall.RTN_UNICAST, Destination: []byte{10, 0, 0, 0}},
		{Family: syscall.AF_INET, Length: 12, Table: 100, Type: syscall.RTN_PROHIBIT, Destination: []byte{172, 16, 0, 0}},
		{Family: syscall.AF_INET, Length: 24, Table: 100, Type: syscall.RTN_THROW, Destination: []byte{172, 17, 0, 0}},
		{Family: syscall.AF_INET6, Length: 0, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: nil},
		{Family: syscall.AF_INET6, Length: 64, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: netip.MustParseAddr("fe80::").AsSlice()},
		{Family: syscall.AF_INET6, Length: 32, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNREACHABLE, Destination: netip.MustParseAddr("2001:db8::").AsSlice()},
		{Family: syscall.AF_INET6, Length: 128, Table: syscall.RT_TABLE_LOCAL, Type: syscall.RTN_LOCAL, Destination: netip.IPv6Loopback().AsSlice()},
		{Family: syscall.AF_INET6, Length: 8, Table: syscall.RT_TABLE_LOCAL, Type: syscall.RTN_MULTICAST, Destination: netip.MustParseAddr("ff00::").AsSlice()},
		// a family that is neither IPv4 nor IPv6
		{Family: syscall.AF_BRIDGE, Length: 0, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: nil},
	}
	dumpRoutes = map[netip.Prefix]bool{
		netip.MustParsePrefix("0.0.0.0/0"):        true,
		netip.MustParsePrefix("192.168.1.0/24"):   true,
		netip.MustParsePrefix("127.0.0.0/8"):      true,
		netip.MustParsePrefix("10.0.0.0/8"):       true,
		netip.MustParsePrefix("172.16.0.0/12"):    false,
		netip.MustParsePrefix("192.168.1.255/32"): false,
		netip.MustParsePrefix("10.0.0.255/32"):    false,
		netip.MustParsePrefix("::/0"):             true,
		netip.MustParsePrefix("fe80::/64"):        true,
		netip.MustParsePrefix("2001:db8::/32"):    false,
		netip.MustParsePrefix("::1/128"):          true,
	}
)

// Test if route.parseRoutes returns with the expected output.
func TestParseRoutesPositive(state *testing.T) {
	reversed := []routeMessage{}

	for index := range dumpMessages {
		reversed = append(reversed, dumpMessages[len(dumpMessages)-1-index])
	}

	// the order of the tables does not matter, a link message and a message too short for rtmsg are skipped, NLMSG_DONE ends the dump
	positiveCases := [][]byte{
		dump(dumpMessages),
		dump(reversed),
		append(append(netlinkMessage(syscall.RTM_NEWLINK, make([]byte, syscall.SizeofIfInfomsg)), netlinkMessage(syscall.RTM_NEWROUTE, []byte{syscall.AF_INET, 0})...), dump(dumpMessages)...),
	}

	for index, positive := range positiveCases {
		routes, err := parseRoutes(positive)

		if (err != nil) || !maps.Equal(routes, dumpRoutes) {
			state.Errorf("Test of route.parseRoutes function failed, case %d, routes should be %v, routes: %v, error: %v", index, dumpRoutes, routes, err)
			return
		}
	}

	// an empty dump has no route
	routes, err := parseRoutes(netlinkMessage(syscall.NLMSG_DONE, make([]byte, 4)))

	if (err != nil) || (len(routes) != 0) {
		state.Errorf("Test of route.parseRoutes function failed, routes should be empty, routes: %v, error: %v", routes, err)
		return
	}
}

// Test if route.parseRoutes returns with the expected errors.
func TestParseRoutesNegative(state *testing.T) {
	valid := dump(dumpMessages[:1])
	// an attribute whose length runs past the message
	badAttribute := netlinkMessage(syscall.RTM_NEWROUTE, append(rtmsg(routeMessage{Family: syscall.AF_INET, Length: 24, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST}), 0x40, 0, syscall.RTA_DST, 0, 10, 0, 0, 0))
	negativeCases := [][]byte{
		// a netlink header that claims more bytes than there are
		valid[:len(valid)-2],
		badAttribute,
		// a prefix longer than the address
		dump([]routeMessage{{Family: syscall.AF_INET, Length: 33, Table: syscall.RT_TABLE_MAIN, Type: syscall.RTN_UNICAST, Destination: []byte{10, 0, 0, 0}}}),
	}

	for index, negative := range negativeCases {
		_, err := parseRoutes(negative)

		if !errors.Is(err, ErrRouteDump) {
			state.Errorf("Test of route.parseRoutes function failed, case %d, error should be %v, error: %v", index, ErrRouteDump, err)
			return
		}
	}
}

// Test if route.Watch returns with the expected output: one event per datagram with a route message, nothing for others, and it ends with the context.
func TestWatchPositive(state *testing.T) {
	subscription, sender, err := datagramPair()

	if err != nil {
		state.Fatalf("Test of route.Watch failed, cannot create socket pair, error: %s", err.Error())
	}

	defer func() {
		if closeErr := sender.Close(); closeErr != nil {
			state.Errorf("Test of route.Watch failed, cannot close socket, error: %s", closeErr.Error())
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eventChannel := make(chan EventType, 5)
	doneChannel := make(chan struct{})
	ctx, cancel := context.WithCancel(state.Context())

	// route watcher
	go func() {
		Watch(ctx, subscription, eventChannel, logger)
		close(doneChannel)
	}()

	datagrams := [][]byte{
		// a link change is no route change
		netlinkMessage(syscall.RTM_NEWLINK, make([]byte, syscall.SizeofIfInfomsg)),
		netlinkMessage(syscall.RTM_DELROUTE, rtmsg(dumpMessages[1])),
		// a datagram that can't be parsed could have been a route change: its header claims more bytes than came
		netlinkMessage(syscall.RTM_NEWLINK, make([]byte, syscall.SizeofIfInfomsg))[:syscall.SizeofNlMsghdr+4],
		append(netlinkMessage(syscall.RTM_NEWADDR, make([]byte, syscall.SizeofIfAddrmsg)), dump(dumpMessages[8:9])...),
	}

	for _, datagram := range datagrams {
		_, err = sender.Write(datagram)

		if err != nil {
			cancel()
			state.Fatalf("Test of route.Watch failed, cannot send, error: %s", err.Error())
		}
	}

	for range 3 {
		select {
		case event := <-eventChannel:
			if event != ChangedEventType {
				cancel()
				state.Fatalf("Test of route.Watch function failed, event should be %s, event: %s", ChangedEventType, event)
			}
		case <-time.After(10 * time.Second):
			cancel()
			state.Fatalf("Test of route.Watch function failed, no event")
		}
	}

	cancel()
	<-doneChannel

	if len(eventChannel) != 0 {
		state.Errorf("Test of route.Watch function failed, events should be 3, events left: %d", len(eventChannel))
		return
	}

	// Watch closed the subscription
	if _, readErr := subscription.Read(make([]byte, 1)); !errors.Is(readErr, os.ErrClosed) {
		state.Errorf("Test of route.Watch function failed, subscription should be closed, error: %v", readErr)
		return
	}
}

// a non-blocking unix datagram socket pair, the first end as a subscription is for Watch
func datagramPair() (subscription *os.File, sender *os.File, err error) {
	fileDescriptors, socketErr := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)

	if err = socketErr; err != nil {
		return
	}

	subscription = os.NewFile(uintptr(fileDescriptors[0]), "subscription")
	sender = os.NewFile(uintptr(fileDescriptors[1]), "sender")
	return
}

// the route messages of a dump and NLMSG_DONE
func dump(routes []routeMessage) (data []byte) {
	for _, current := range routes {
		body := rtmsg(current)
		body = attribute(body, syscall.RTA_TABLE, binary.NativeEndian.AppendUint32(nil, uint32(current.Table)))

		if current.Destination != nil {
			body = attribute(body, syscall.RTA_DST, current.Destination)
		}

		body = attribute(body, syscall.RTA_OIF, binary.NativeEndian.AppendUint32(nil, 2))
		data = append(data, netlinkMessage(syscall.RTM_NEWROUTE, body)...)
	}

	data = append(data, netlinkMessage(syscall.NLMSG_DONE, make([]byte, 4))...)
	return
}

// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
func rtmsg(current routeMessage) (body []byte) {
	body = []byte{current.Family, current.Length, 0, 0, current.Table, syscall.RTPROT_KERNEL, syscall.RT_SCOPE_UNIVERSE, current.Type, 0, 0, 0, 0}
	return
}

// struct rtattr: length, type, value padded to 4 bytes
func attribute(body []byte, attributeType uint16, value []byte) (result []byte) {
	result = binary.NativeEndian.AppendUint16(body, uint16(syscall.SizeofRtAttr+len(value)))
	result = binary.NativeEndian.AppendUint16(result, attributeType)
	result = append(result, value...)
	result = append(result, make([]byte, (4-len(value)%4)%4)...)
	return
}

// struct nlmsghdr: length, type, flags, sequence, port id, then the body padded to 4 bytes
func netlinkMessage(messageType uint16, body []byte) (message []byte) {
	message = binary.NativeEndian.AppendUint32(nil, uint32(syscall.SizeofNlMsghdr+len(body)))
	message = binary.NativeEndian.AppendUint16(message, messageType)
	message = binary.NativeEndian.AppendUint16(message, syscall.NLM_F_MULTI)
	message = binary.NativeEndian.AppendUint32(message, 1)
	message = binary.NativeEndian.AppendUint32(message, 0)
	message = append(message, body...)
	message = append(message, make([]byte, (4-len(body)%4)%4)...)
	return
}
