// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/output"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" bpf ../../../bpf/redirect/redirect.c -- -I../../../bpf -I../../../bpf/include

const (
	CidrMap              bpf.BpfMapName     = 0  // value: "cidr_map"
	ClientMap            bpf.BpfMapName     = 1  // value: "client_map"
	CommMap              bpf.BpfMapName     = 2  // value: "comm_map"
	FilterMap            bpf.BpfMapName     = 3  // value: "filter_map"
	FlowMap              bpf.BpfMapName     = 4  // value: "flow_map"
	PortMap              bpf.BpfMapName     = 5  // value: "port_map"
	PrefixLengthsMap     bpf.BpfMapName     = 6  // value: "prefix_lengths_map"
	RouteMap             bpf.BpfMapName     = 7  // value: "route_map"
	TgidMap              bpf.BpfMapName     = 8  // value: "tgid_map"
	UidMap               bpf.BpfMapName     = 9  // value: "uid_map"
	ClientSockops        bpf.BpfProgramName = 0  // value: "client_sockops"
	ForgetReleasedSocket bpf.BpfProgramName = 1  // value: "forget_released_socket"
	LearnUdpClient       bpf.BpfProgramName = 2  // value: "learn_udp_client"
	RedirectConnect4     bpf.BpfProgramName = 3  // value: "redirect_connect4"
	RedirectConnect6     bpf.BpfProgramName = 4  // value: "redirect_connect6"
	RedirectSendmsg4     bpf.BpfProgramName = 5  // value: "redirect_sendmsg4"
	RedirectSendmsg6     bpf.BpfProgramName = 6  // value: "redirect_sendmsg6"
	RestoreGetpeername4  bpf.BpfProgramName = 7  // value: "restore_getpeername4"
	RestoreGetpeername6  bpf.BpfProgramName = 8  // value: "restore_getpeername6"
	RestoreRecvmsg4      bpf.BpfProgramName = 9  // value: "restore_recvmsg4"
	RestoreRecvmsg6      bpf.BpfProgramName = 10 // value: "restore_recvmsg6"
	// keys of prefix_lengths_map, ROUTE_LENGTHS and CIDR_LENGTHS in C
	routeLengths uint32 = 0
	cidrLengths  uint32 = 1
)

// the volatile consts of the object by their bpf2go names, with the C types' sizes: bools are uint8 1 or 0
func loadTimeVariables(proxyPort uint16, proxyTgid uint32, recordOnly bool, blockQuic bool) (variables map[string]any) {
	flag := func(value bool) (byteValue uint8) {
		if value {
			byteValue = 1
		}

		return
	}
	variables = map[string]any{
		bpfVarProxyTgid:  proxyTgid,
		bpfVarProxyPort:  proxyPort,
		bpfVarRecordOnly: flag(recordOnly),
		bpfVarBlockQuic:  flag(blockQuic),
	}
	return
}

// recordOnly is capture mode: connect and sendmsg only record the flows, nothing is redirected to the proxy
// blockQuic is --block-quic: UDP connects and sends of the selected processes to port 443 fail with EPERM, so QUIC falls back to TLS over TCP
func LoadBpfObjects(proxyPort uint16, proxyTgid uint32, recordOnly bool, blockQuic bool) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
	err = rlimit.RemoveMemlock()

	if err != nil {
		err = fmt.Errorf("remove memlock: %w", err)
		return
	}

	spec, loadErr := loadBpf()

	if err = loadErr; err != nil {
		err = fmt.Errorf("load bpf spec: %w", err)
		return
	}

	// load-time constants have to be set before the programs are loaded
	variables := loadTimeVariables(proxyPort, proxyTgid, recordOnly, blockQuic)

	for name, value := range variables {
		err = spec.Variables[name].Set(value)

		if err != nil {
			err = fmt.Errorf("set %s: %w", name, err)
			return
		}
	}

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, nil)

	if err != nil {
		err = fmt.Errorf("load bpf objects: %w", err)
		return
	}

	bpfMaps = map[bpf.BpfMapName]*ebpf.Map{
		CidrMap:          objs.CidrMap,
		ClientMap:        objs.ClientMap,
		CommMap:          objs.CommMap,
		FilterMap:        objs.FilterMap,
		FlowMap:          objs.FlowMap,
		PortMap:          objs.PortMap,
		PrefixLengthsMap: objs.PrefixLengthsMap,
		RouteMap:         objs.RouteMap,
		TgidMap:          objs.TgidMap,
		UidMap:           objs.UidMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		ClientSockops:        objs.ClientSockops,
		ForgetReleasedSocket: objs.ForgetReleasedSocket,
		LearnUdpClient:       objs.LearnUdpClient,
		RedirectConnect4:     objs.RedirectConnect4,
		RedirectConnect6:     objs.RedirectConnect6,
		RedirectSendmsg4:     objs.RedirectSendmsg4,
		RedirectSendmsg6:     objs.RedirectSendmsg6,
		RestoreGetpeername4:  objs.RestoreGetpeername4,
		RestoreGetpeername6:  objs.RestoreGetpeername6,
		RestoreRecvmsg4:      objs.RestoreRecvmsg4,
		RestoreRecvmsg6:      objs.RestoreRecvmsg6,
	}
	closeFunction = objs.Close
	return
}

// the sets of the filter are only added to, nothing is removed from the maps
// filter_map is written last: the programs can't ask if cidr_map or port_map is empty, they only read a set after its switch is on
func UpdateBpfMaps(filter Filter, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	for _, uid := range filter.UIDs {
		err = bpfMaps[UidMap].Update(uid, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s uid %d: %w", bpfMapUidMap, uid, err)
			return
		}
	}

	for _, tgid := range filter.Tgids {
		err = bpfMaps[TgidMap].Update(tgid, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s tgid %d: %w", bpfMapTgidMap, tgid, err)
			return
		}
	}

	// the lengths of the new prefixes join the ones in use before the prefixes are added, the programs search only the lengths in use
	cidrKeys := []bpfPrefixKey{}

	for _, destinationCIDR := range filter.DestinationCIDRs {
		cidrKeys = append(cidrKeys, prefixToKey(destinationCIDR))
	}

	inUse, err := readPrefixLengths(bpfMaps[PrefixLengthsMap], cidrLengths)

	if err != nil {
		return
	}

	err = writePrefixLengths(bpfMaps[PrefixLengthsMap], cidrLengths, addPrefixLengths(inUse, cidrKeys))

	if err != nil {
		return
	}

	for index, destinationCIDR := range filter.DestinationCIDRs {
		err = bpfMaps[CidrMap].Update(cidrKeys[index], uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s %s: %w", bpfMapCidrMap, destinationCIDR, err)
			return
		}
	}

	for _, destinationPort := range filter.DestinationPorts {
		key := bpfPortKey{
			Port:       destinationPort.Port,
			IpProtocol: destinationPort.IPProtocol,
			Padding:    0,
		}
		err = bpfMaps[PortMap].Update(key, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s %s: %w", bpfMapPortMap, destinationPort, err)
			return
		}
	}

	for _, comm := range filter.Comms {
		err = bpfMaps[CommMap].Update(commToKey(comm), uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s %q: %w", bpfMapCommMap, comm, err)
			return
		}
	}

	filterConfig := bpfFilterConfig{
		CidrFilter: 0,
		PortFilter: 0,
		CommFilter: 0,
		Padding:    0,
	}

	if len(filter.DestinationCIDRs) > 0 {
		filterConfig.CidrFilter = 1
	}

	if len(filter.DestinationPorts) > 0 {
		filterConfig.PortFilter = 1
	}

	if len(filter.Comms) > 0 {
		filterConfig.CommFilter = 1
	}

	err = bpfMaps[FilterMap].Update(uint32(0), filterConfig, ebpf.UpdateAny)

	if err != nil {
		err = fmt.Errorf("update %s: %w", bpfMapFilterMap, err)
		return
	}

	return
}

// the lengths of the new routes are added to the lengths in use first, then new routes are written before the stale ones are deleted, so a still
// routed prefix never disappears in between; the lengths of the new routes alone are written last
func UpdateRouteMap(routes map[netip.Prefix]bool, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	var (
		key   bpfPrefixKey
		value uint8
	)

	wanted := routeValues(routes)
	staleKeys := []bpfPrefixKey{}
	iterator := bpfMaps[RouteMap].Iterate()

	for iterator.Next(&key, &value) {
		if _, ok := wanted[key]; !ok {
			staleKeys = append(staleKeys, key)
		}
	}

	err = iterator.Err()

	if err != nil {
		err = fmt.Errorf("iterate %s: %w", bpfMapRouteMap, err)
		return
	}

	inUse, err := readPrefixLengths(bpfMaps[PrefixLengthsMap], routeLengths)

	if err != nil {
		return
	}

	err = writePrefixLengths(bpfMaps[PrefixLengthsMap], routeLengths, addPrefixLengths(inUse, slices.Collect(maps.Keys(wanted))))

	if err != nil {
		return
	}

	for wantedKey, wantedValue := range wanted {
		err = bpfMaps[RouteMap].Update(wantedKey, wantedValue, ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s %s: %w", bpfMapRouteMap, keyToPrefix(wantedKey), err)
			return
		}
	}

	for _, staleKey := range staleKeys {
		err = bpfMaps[RouteMap].Delete(staleKey)

		if err != nil {
			err = fmt.Errorf("delete %s %s: %w", bpfMapRouteMap, keyToPrefix(staleKey), err)
			return
		}
	}

	err = writePrefixLengths(bpfMaps[PrefixLengthsMap], routeLengths, addPrefixLengths(bpfPrefixLengths{}, slices.Collect(maps.Keys(wanted))))
	return
}

// the route_map value of each prefix: 1 routable, 0 not
func routeValues(routes map[netip.Prefix]bool) (values map[bpfPrefixKey]uint8) {
	values = make(map[bpfPrefixKey]uint8, len(routes))

	for prefix, routable := range routes {
		var value uint8

		if routable {
			value = 1
		}

		values[prefixToKey(prefix)] = value
	}

	return
}

// the prefix lengths a prefix map has keys of, at key lengthsKey of prefix_lengths_map
func readPrefixLengths(lengthsMap *ebpf.Map, lengthsKey uint32) (lengths bpfPrefixLengths, err error) {
	err = lengthsMap.Lookup(lengthsKey, &lengths)

	if err != nil {
		err = fmt.Errorf("lookup %s %d: %w", bpfMapPrefixLengthsMap, lengthsKey, err)
	}

	return
}

func writePrefixLengths(lengthsMap *ebpf.Map, lengthsKey uint32, lengths bpfPrefixLengths) (err error) {
	err = lengthsMap.Update(lengthsKey, lengths, ebpf.UpdateAny)

	if err != nil {
		err = fmt.Errorf("update %s %d: %w", bpfMapPrefixLengthsMap, lengthsKey, err)
	}

	return
}

// lengths with the prefix length of every key set: bit length%64 of Bits[length/64], like the programs read it
func addPrefixLengths(lengths bpfPrefixLengths, keys []bpfPrefixKey) (added bpfPrefixLengths) {
	added = lengths

	for _, key := range keys {
		added.Bits[key.Prefixlen/64] |= 1 << (key.Prefixlen % 64)
	}

	return
}

// the client endpoint is the peer address of the accepted connection or received datagram, sockops and the egress program store it IPv4-mapped
func FlowByClient(clientAddressPort netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (cookie uint64, flow Flow, err error) {
	var bpfFlow bpfFlow

	err = bpfMaps[ClientMap].Lookup(endpointToKey(clientAddressPort, ipProtocol), &cookie)

	if err != nil {
		err = fmt.Errorf("%w: %s %s: %w", ErrUnknownClient, bpfMapClientMap, clientAddressPort, err)
		return
	}

	err = bpfMaps[FlowMap].Lookup(cookie, &bpfFlow)

	if err != nil {
		err = fmt.Errorf("%w: %s cookie %d: %w", ErrUnknownFlow, bpfMapFlowMap, cookie, err)
		return
	}

	flow = flowFromBpf(bpfFlow)
	return
}

// the capture writer reads the flow of a packet's socket, the cookie is in every packet_map record
func FlowByCookie(cookie uint64, flowMap *ebpf.Map) (flow Flow, err error) {
	var bpfFlow bpfFlow

	err = flowMap.Lookup(cookie, &bpfFlow)

	if err != nil {
		err = fmt.Errorf("%w: %s cookie %d: %w", ErrUnknownFlow, bpfMapFlowMap, cookie, err)
		return
	}

	flow = flowFromBpf(bpfFlow)
	return
}

// sock_release only marks a redirected UDP flow released, a bpf_timer callback panics kernels with kCFI (Android 15)
// the flow is kept releaseDelay after the close, because datagrams the socket sent before can still wait in the proxy socket and need it
// in capture mode every recorded flow is marked, by sock_release or by sockops at TCP_CLOSE, so the packets of the close are still captured; such a flow has no client endpoint
func ForgetReleasedFlows(releaseDelay time.Duration, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	var (
		cookie  uint64
		bpfFlow bpfFlow
		now     unix.Timespec
	)

	// released_ns is bpf_ktime_get_ns, which is CLOCK_MONOTONIC
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &now)

	if err != nil {
		err = fmt.Errorf("read monotonic clock: %w", err)
		return
	}

	// collected first, deleting while iterating can restart the iteration
	releasedClients := map[uint64]bpfEndpoint{}
	iterator := bpfMaps[FlowMap].Iterate()

	for iterator.Next(&cookie, &bpfFlow) {
		if (bpfFlow.ReleasedNs != 0) && (now.Nano()-int64(bpfFlow.ReleasedNs) >= releaseDelay.Nanoseconds()) {
			releasedClients[cookie] = bpfFlow.Client
		}
	}

	err = iterator.Err()

	if err != nil {
		err = fmt.Errorf("iterate %s: %w", bpfMapFlowMap, err)
		return
	}

	for releasedCookie, client := range releasedClients {
		err = forgetUDPFlow(releasedCookie, client, bpfMaps)

		if err != nil {
			return
		}
	}

	return
}

// remove the flow_map entry and the client_map entry of a released UDP socket, a client endpoint with port 0 was never learned
// the client entry is taken out with one lookup and delete and put back when a newer socket on the same client port owns it by now, a lookup then delete could remove an entry written in between for good
func forgetUDPFlow(cookie uint64, client bpfEndpoint, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	var clientCookie uint64

	if client.Port != 0 {
		err = bpfMaps[ClientMap].LookupAndDelete(client, &clientCookie)

		switch {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			// nothing to take out, err is set again by the flow_map delete below
		case err != nil:
			err = fmt.Errorf("lookup and delete %s cookie %d: %w", bpfMapClientMap, cookie, err)
			return
		case clientCookie != cookie:
			// the newer socket can have written its entry again in between, that one is newer still and stays
			err = bpfMaps[ClientMap].Update(client, clientCookie, ebpf.UpdateNoExist)

			if errors.Is(err, ebpf.ErrKeyExist) {
				err = nil
			}

			if err != nil {
				err = fmt.Errorf("restore %s cookie %d: %w", bpfMapClientMap, clientCookie, err)
				return
			}
		default:
		}
	}

	err = bpfMaps[FlowMap].Delete(cookie)

	// LRU can have evicted it already
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		err = nil
	}

	if err != nil {
		err = fmt.Errorf("delete %s cookie %d: %w", bpfMapFlowMap, cookie, err)
		return
	}

	return
}

// For debugging, the table goes to writer every 5 seconds until the context is cancelled or writer can't be written
func Read(ctx context.Context, flowMap *ebpf.Map, writer io.Writer) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var (
				cookie  uint64
				bpfFlow bpfFlow
			)

			flows := map[uint64]Flow{}
			iterator := flowMap.Iterate()

			for iterator.Next(&cookie, &bpfFlow) {
				flows[cookie] = flowFromBpf(bpfFlow)
			}

			_, writeErr := io.WriteString(writer, flowTable(flows, iterator.Err()))

			if writeErr != nil {
				return
			}
		}
	}
}

// the debug table of Read, one row per flow by cookie; comm is the process's own choice and is escaped like in every other line
func flowTable(flows map[uint64]Flow, iterateErr error) (table string) {
	builder := strings.Builder{}

	if iterateErr != nil {
		fmt.Fprintf(&builder, "%s iterate error: %s\n", bpfMapFlowMap, iterateErr)
		table = builder.String()
		return
	}

	fmt.Fprintf(&builder, "\n%-20s %-5s %-47s %-10s %-8s %-8s %-16s %-10s %-10s %-47s\n", "Cookie", "Proto", "Destination", "Redirected", "PID", "UID", "Comm", "Cgroup ID", "Mark", "UDP Client")

	for _, sortedCookie := range slices.SortedFunc(maps.Keys(flows), cmp.Compare) {
		flow := flows[sortedCookie]
		client := "-"

		// only UDP flows carry the client endpoint
		if flow.Client.IsValid() {
			client = flow.Client.String()
		}

		fmt.Fprintf(&builder, "%-20d %-5s %-47s %-10t %-8d %-8d %-16s %-10d %#-10x %-47s\n", sortedCookie, ProtocolName(flow.IPProtocol), flow.OriginalDestination, flow.Redirected, flow.Tgid, flow.UID, output.EscapeField(flow.Comm), flow.CgroupID, flow.Mark, client)
	}

	table = builder.String()
	return
}

func flowFromBpf(bpfFlow bpfFlow) (flow Flow) {
	flow = Flow{
		OriginalDestination: netip.AddrPortFrom(keyToIP(bpfFlow.Ip), bpfFlow.Port),
		IPProtocol:          bpfFlow.IpProtocol,
		Redirected:          (bpfFlow.Redirected == 1),
		Tgid:                bpfFlow.Tgid,
		UID:                 bpfFlow.Uid,
		GID:                 bpfFlow.Gid,
		CgroupID:            bpfFlow.CgroupId,
		Comm:                commToString(bpfFlow.Comm),
		Mark:                bpfFlow.Mark,
		Client:              netip.AddrPort{},
	}

	// only UDP flows carry the client endpoint, from their first datagram to the proxy
	if bpfFlow.Client.Port != 0 {
		flow.Client = netip.AddrPortFrom(keyToIP(bpfFlow.Client.Ip), bpfFlow.Client.Port)
	}

	return
}

// comm is NUL terminated inside the array, a name of the full 15 characters still has its NUL at the end
func commToString(comm [16]int8) (name string) {
	commBytes := make([]byte, 0, len(comm))

	for _, character := range comm {
		if character == 0 {
			break
		}

		commBytes = append(commBytes, byte(character))
	}

	name = string(commBytes)
	return
}

// the kernel compares all 16 bytes, a name is NUL padded like struct flow's comm; a name of more than 15 bytes is cut like the kernel cuts it
func commToKey(comm string) (key bpfCommKey) {
	for index := range min(len(comm), len(key.Comm)-1) {
		key.Comm[index] = int8(comm[index])
	}

	return
}

func endpointToKey(addressPort netip.AddrPort, ipProtocol uint8) (key bpfEndpoint) {
	key = bpfEndpoint{
		Ip:         ipToKey(addressPort.Addr()),
		Port:       addressPort.Port(),
		IpProtocol: ipProtocol,
		Padding:    0,
	}
	return
}

// IPv4 prefixes are stored IPv4-mapped, so their length grows by the 96 bits of ::ffff:0:0/96; the address is masked to the prefix, the programs
// look a destination up by its masked address per prefix length
func prefixToKey(prefix netip.Prefix) (key bpfPrefixKey) {
	prefix = prefix.Masked()
	prefixLength := prefix.Bits()

	if prefix.Addr().Is4() {
		prefixLength += 96
	}

	key = bpfPrefixKey{
		Prefixlen: uint32(prefixLength),
		Ip:        ipToKey(prefix.Addr()),
	}
	return
}

func keyToPrefix(key bpfPrefixKey) (prefix netip.Prefix) {
	address := keyToIP(key.Ip)
	prefixLength := int(key.Prefixlen)

	if address.Is4() {
		prefixLength -= 96
	}

	prefix = netip.PrefixFrom(address, prefixLength)
	return
}

// IPv4 is stored IPv4-mapped like in the C structs: As16 gives ::ffff:a.b.c.d for both plain and mapped IPv4
func ipToKey(address netip.Addr) (key [4]uint32) {
	addressBytes := address.As16()

	for index := range key {
		key[index] = binary.NativeEndian.Uint32(addressBytes[index*4 : index*4+4])
	}

	return
}

// the C side keeps the address bytes in network order inside each uint32, IPv4 is IPv4-mapped
func keyToIP(ip [4]uint32) (address netip.Addr) {
	var addressBytes [16]byte

	for index, part := range ip {
		binary.NativeEndian.PutUint32(addressBytes[index*4:index*4+4], part)
	}

	address = netip.AddrFrom16(addressBytes).Unmap()
	return
}

func ProtocolName(ipProtocol uint8) (name string) {
	switch ipProtocol {
	case syscall.IPPROTO_TCP:
		name = "tcp"
	case syscall.IPPROTO_UDP:
		name = "udp"
	default:
		name = strconv.Itoa(int(ipProtocol))
	}

	return
}
