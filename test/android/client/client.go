// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

// the static test client the Android e2e tests push to the device:
//
//	client tcp <host:port> <line>   send the line over TCP, print the peer and the answer of the echo server
//	client udp <host:port> <line>   send the line in one datagram from an unconnected socket, print where the answer came from and the answer
//	client query                    print the attach list of /sys/fs/cgroup for every attach type, one line per type with programs
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cgroupRoot    string        = "/sys/fs/cgroup"
	ioTimeout     time.Duration = 10 * time.Second
	queryCommand  uintptr       = 16
	maxPrograms   int           = 64
	maxAttachType uint32        = 63
)

var (
	errUsage = errors.New("usage: client tcp|udp <host:port> <line> | client query")
)

// union bpf_attr of BPF_PROG_QUERY, the kernel accepts a larger attr as long as the rest is zero
type queryAttr struct {
	targetFd    uint32
	attachType  uint32
	queryFlags  uint32
	attachFlags uint32
	progIDs     uint64
	progCount   uint32
	padding     uint32
	rest        [4]uint64
}

func main() {
	err := run(os.Args[1:])

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(arguments []string) (err error) {
	switch {
	case (len(arguments) == 1) && (arguments[0] == "query"):
		err = query()
	case (len(arguments) == 3) && (arguments[0] == "tcp"):
		err = echoTCP(arguments[1], arguments[2])
	case (len(arguments) == 3) && (arguments[0] == "udp"):
		err = echoUDP(arguments[1], arguments[2])
	default:
		err = errUsage
	}

	return
}

// the peer is what getpeername returns, decerter rewrites it back to the original destination
func echoTCP(address string, line string) (err error) {
	connection, dialErr := net.DialTimeout("tcp", address, ioTimeout)

	if err = dialErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	err = connection.SetDeadline(time.Now().Add(ioTimeout))

	if err != nil {
		return
	}

	_, err = io.WriteString(connection, line+"\n")

	if err != nil {
		return
	}

	answer, readErr := bufio.NewReader(connection).ReadString('\n')

	if err = readErr; err != nil {
		return
	}

	fmt.Printf("peer=%s answer=%q\n", connection.RemoteAddr().String(), answer)
	return
}

// an unconnected socket: sendmsg carries the destination, recvmsg says where the answer came from
func echoUDP(address string, line string) (err error) {
	destination, resolveErr := net.ResolveUDPAddr("udp", address)

	if err = resolveErr; err != nil {
		return
	}

	connection, listenErr := net.ListenUDP("udp", nil)

	if err = listenErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	err = connection.SetDeadline(time.Now().Add(ioTimeout))

	if err != nil {
		return
	}

	_, err = connection.WriteTo([]byte(line+"\n"), destination)

	if err != nil {
		return
	}

	buffer := make([]byte, 2048)
	count, source, readErr := connection.ReadFrom(buffer)

	if err = readErr; err != nil {
		return
	}

	fmt.Printf("peer=%s answer=%q\n", source.String(), string(buffer[:count]))
	return
}

// a raw BPF_PROG_QUERY per attach type, cilium/ebpf's query does not return the attach flags; types that are not cgroup types fail and are left out
func query() (err error) {
	cgroup, openErr := os.Open(cgroupRoot)

	if err = openErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, cgroup.Close())
	}()

	for attachType := range maxAttachType + 1 {
		programIDs := make([]uint32, maxPrograms)
		attr := queryAttr{
			targetFd:    uint32(cgroup.Fd()),
			attachType:  attachType,
			queryFlags:  0,
			attachFlags: 0,
			progIDs:     uint64(uintptr(unsafe.Pointer(&programIDs[0]))),
			progCount:   uint32(maxPrograms),
			padding:     0,
			rest:        [4]uint64{},
		}
		_, _, errno := unix.Syscall(unix.SYS_BPF, queryCommand, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))

		if (errno != 0) || (attr.progCount == 0) {
			continue
		}

		fmt.Printf("type=%d flags=%d programs=%v\n", attachType, attr.attachFlags, programIDs[:attr.progCount])
	}

	return
}
