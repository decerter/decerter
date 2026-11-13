// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	quicPort       string        = "443"
	udpReadTimeout time.Duration = 2 * time.Second
)

// Test if --block-quic makes udp 443 of the test user fail with EPERM at connect and at sendto over IPv4 and IPv6 in run and in capture mode,
// nothing reaches the servers, and udp to another port still gets its echo.
func TestBlockQuicPositive(state *testing.T) {
	for _, mode := range []decerterMode{RelayDecerterMode, CaptureDecerterMode} {
		state.Run(string(mode), func(state *testing.T) {
			testBlockQuic(state, mode)
		})
	}
}

func testBlockQuic(state *testing.T, mode decerterMode) {
	startBlockingAPIDecerter(state, mode, nil, true)
	_, received := startUDPEchoServerAt(state, net.JoinHostPort(destinationPrefix.Addr().String(), quicPort))
	_, receivedIPv6 := startUDPEchoServerAt(state, net.JoinHostPort(netip.IPv6Loopback().String(), quicPort))
	otherPort, otherReceived := startUDPEchoServer(state)
	clientPath := copyClient(state)
	cases := []struct {
		Target   string
		Expected string
		Received chan string
	}{
		{Target: net.JoinHostPort(destinationPrefix.Addr().String(), quicPort), Expected: "connect=EPERM sendto=EPERM", Received: nil},
		{Target: net.JoinHostPort(netip.IPv6Loopback().String(), quicPort), Expected: "connect=EPERM sendto=EPERM", Received: nil},
		{Target: net.JoinHostPort(destinationPrefix.Addr().String(), otherPort), Expected: "connect=ok:connect sendto=ok:sendto", Received: otherReceived},
	}

	for _, testCase := range cases {
		output, err := runGoClient(state.Context(), clientPath, "udp", testCase.Target)

		if (err != nil) || (output != testCase.Expected) {
			state.Errorf("Test of --block-quic in %s mode failed for %s, expected: %q, output: %q, error: %v", mode, testCase.Target, testCase.Expected, output, err)
			continue
		}

		if testCase.Received != nil {
			got := []string{<-testCase.Received, <-testCase.Received}

			if strings.Join(got, " ") != "connect sendto" {
				state.Errorf("Test of --block-quic failed for %s, the server should get both datagrams, got: %q", testCase.Target, got)
			}
		}
	}

	// a blocked datagram never leaves the host
	select {
	case datagram := <-received:
		state.Errorf("Test of --block-quic failed, the IPv4 server got %q", datagram)
	case datagram := <-receivedIPv6:
		state.Errorf("Test of --block-quic failed, the IPv6 server got %q", datagram)
	default:
	}
}

// Test if udp 443 of the test user is relayed as a flow without --block-quic and the server gets the datagrams.
func TestBlockQuicNegative(state *testing.T) {
	client := startBlockingAPIDecerter(state, RelayDecerterMode, nil, false)
	_, received := startUDPEchoServerAt(state, net.JoinHostPort(destinationPrefix.Addr().String(), quicPort))
	target := net.JoinHostPort(destinationPrefix.Addr().String(), quicPort)
	output, err := runGoClient(state.Context(), copyClient(state), "udp", target)

	if (err != nil) || (output != "connect=ok:connect sendto=ok:sendto") {
		state.Fatalf("Test of udp 443 without --block-quic failed, it should be relayed, output: %q, error: %v", output, err)
	}

	if got := []string{<-received, <-received}; strings.Join(got, " ") != "connect sendto" {
		state.Errorf("Test of udp 443 without --block-quic failed, the server should get both datagrams, got: %q", got)
	}

	flows := v1.FlowList{}
	status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)
	relayed := 0

	for _, flow := range flows.Flows {
		if (flow.Protocol == "udp") && (flow.Destination == target) {
			relayed++
		}
	}

	if (err != nil) || (status != http.StatusOK) || (relayed != 2) {
		state.Errorf("Test of udp 443 without --block-quic failed, expected 2 relayed udp flows to %s, got %d, status: %d, error: %v", target, relayed, status, err)
	}
}

// the test user's udp client: one datagram on a connected socket and one with sendto on an unconnected one, each prints ok and the echo or the errno
func sendUDP(target string) (output string) {
	address, err := netip.ParseAddrPort(target)

	if err != nil {
		output = "target=" + err.Error()
		return
	}

	network := "udp4"

	if address.Addr().Is6() {
		network = "udp6"
	}

	connected := udpResult(func() (echo string, err error) {
		connection, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(address))

		if err != nil {
			return
		}

		defer func() {
			err = errors.Join(err, connection.Close())
		}()

		echo, err = exchangeUDP(connection, func(payload []byte) (err error) {
			_, err = connection.Write(payload)
			return
		}, "connect")
		return
	})
	unconnected := udpResult(func() (echo string, err error) {
		connection, err := net.ListenPacket(network, "")

		if err != nil {
			return
		}

		defer func() {
			err = errors.Join(err, connection.Close())
		}()

		echo, err = exchangeUDP(connection, func(payload []byte) (err error) {
			_, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(address))
			return
		}, "sendto")
		return
	})
	output = fmt.Sprintf("connect=%s sendto=%s", connected, unconnected)
	return
}

// send the payload and read its echo
func exchangeUDP(connection net.PacketConn, send func(payload []byte) error, payload string) (echo string, err error) {
	err = send([]byte(payload))

	if err != nil {
		return
	}

	err = connection.SetReadDeadline(time.Now().Add(udpReadTimeout))

	if err != nil {
		return
	}

	buffer := make([]byte, 1500)
	count, _, err := connection.ReadFrom(buffer)

	if err != nil {
		return
	}

	echo = string(buffer[:count])
	return
}

// ok and the echo, EPERM when the hook rejected it, or the error
func udpResult(run func() (echo string, err error)) (result string) {
	echo, err := run()

	switch {
	case errors.Is(err, syscall.EPERM):
		result = "EPERM"
	case err != nil:
		result = strings.ReplaceAll(err.Error(), " ", "_")
	default:
		result = "ok:" + echo
	}

	return
}
