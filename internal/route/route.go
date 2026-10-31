// SPDX-License-Identifier: AGPL-3.0-only

package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// rtnetlink messages are at most a page, a datagram can hold several of them
	receiveBufferSize int           = 64 * 1024
	readBackoff       time.Duration = time.Second
)

// every routing table is read, policy rules are not evaluated: a prefix is routable if any table can send on it
func List() (routes map[netip.Prefix]bool, err error) {
	ribBytes, ribErr := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)

	if err = ribErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrRouteDump, err)
		return
	}

	messages, parseErr := syscall.ParseNetlinkMessage(ribBytes)

	if err = parseErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrRouteDump, err)
		return
	}

	routes = map[netip.Prefix]bool{}

	for _, message := range messages {
		if (message.Header.Type != syscall.RTM_NEWROUTE) || (len(message.Data) < syscall.SizeofRtMsg) {
			continue
		}

		// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
		family, prefixLength, routeType := message.Data[0], int(message.Data[1]), message.Data[7]
		routable := false

		switch routeType {
		case
			syscall.RTN_UNICAST,
			syscall.RTN_LOCAL,
			syscall.RTN_ANYCAST:
			routable = true
		case
			syscall.RTN_BLACKHOLE,
			syscall.RTN_UNREACHABLE,
			syscall.RTN_PROHIBIT:
			routable = false
		default:
			// broadcast, multicast and throw routes say nothing about a TCP destination
			continue
		}

		// a default route has no RTA_DST
		address := netip.Addr{}

		switch family {
		case syscall.AF_INET:
			address = netip.IPv4Unspecified()
		case syscall.AF_INET6:
			address = netip.IPv6Unspecified()
		default:
			continue
		}

		attributes, attributeErr := syscall.ParseNetlinkRouteAttr(&message)

		if err = attributeErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrRouteDump, err)
			return
		}

		for _, attribute := range attributes {
			if attribute.Attr.Type != syscall.RTA_DST {
				continue
			}

			destination, ok := netip.AddrFromSlice(attribute.Value)

			if ok {
				address = destination
			}
		}

		prefix, prefixErr := address.Prefix(prefixLength)

		if err = prefixErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrRouteDump, err)
			return
		}

		// a routable entry wins over an unroutable one for the same prefix in another table
		routes[prefix] = routes[prefix] || routable
	}

	return
}

// the subscription is opened before the first dump, so a route change between dump and Watch is still queued on the socket
func Subscribe() (subscription *os.File, err error) {
	fileDescriptor, socketErr := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)

	if err = socketErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrRouteSubscribe, err)
		return
	}

	err = errors.Join(
		unix.Bind(fileDescriptor, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pad: 0, Pid: 0, Groups: 0}),
		unix.SetsockoptInt(fileDescriptor, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_IPV4_ROUTE),
		unix.SetsockoptInt(fileDescriptor, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_IPV6_ROUTE),
	)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrRouteSubscribe, errors.Join(err, unix.Close(fileDescriptor)))
		return
	}

	// a non-blocking descriptor goes to the runtime poller, so Close unblocks a pending Read
	subscription = os.NewFile(uintptr(fileDescriptor), "rtnetlink-route")
	return
}

// one event per datagram with route messages, until the subscription is closed by the context
func Watch(ctx context.Context, subscription *os.File, eventChannel chan<- EventType, logger *slog.Logger) {
	closeSubscription := func() {
		closeErr := subscription.Close()

		if closeErr != nil {
			logger.Error("Could not close route subscription", "error", closeErr)
		}
	}
	// subscription closer
	stop := context.AfterFunc(ctx, closeSubscription)

	defer func() {
		if stop() {
			closeSubscription()
		}
	}()

	buffer := make([]byte, receiveBufferSize)

	for {
		event := ChangedEventType
		length, readErr := subscription.Read(buffer)

		switch {
		case readErr == nil:
			if !hasRouteMessage(buffer[:length]) {
				continue
			}
		case errors.Is(readErr, os.ErrClosed):
			logger.Debug("Route subscription closed")
			return
		case errors.Is(readErr, unix.ENOBUFS):
			// the socket buffer overflowed, the lost messages can only be recovered by a full dump
			logger.Warn("Lost route events, resyncing all routes", "error", readErr)
			event = LostEventType
		default:
			logger.Error("Could not read route events", "error", readErr)

			select {
			case <-ctx.Done():
				return
			case <-time.After(readBackoff):
			}

			// events can be missing after a failed read
			event = LostEventType
		}

		select {
		case <-ctx.Done():
			return
		case eventChannel <- event:
		}
	}
}

func hasRouteMessage(datagram []byte) (found bool) {
	messages, parseErr := syscall.ParseNetlinkMessage(datagram)

	if parseErr != nil {
		// an unparsable datagram could have been a route change
		found = true
		return
	}

	for _, message := range messages {
		switch message.Header.Type {
		case
			syscall.RTM_NEWROUTE,
			syscall.RTM_DELROUTE:
			found = true
			return
		default:
		}
	}

	return
}
