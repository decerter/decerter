// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" bpf ../../../bpf/redirect/redirect.c -- -I../../../bpf -I../../../bpf/include

const (
	CidrMap              bpf.BpfMapName     = 0  // value: "cidr_map"
	ClientMap            bpf.BpfMapName     = 1  // value: "client_map"
	FilterMap            bpf.BpfMapName     = 2  // value: "filter_map"
	FlowMap              bpf.BpfMapName     = 3  // value: "flow_map"
	PortMap              bpf.BpfMapName     = 4  // value: "port_map"
	ReleaseMap           bpf.BpfMapName     = 5  // value: "release_map"
	RouteMap             bpf.BpfMapName     = 6  // value: "route_map"
	TgidMap              bpf.BpfMapName     = 7  // value: "tgid_map"
	UidMap               bpf.BpfMapName     = 8  // value: "uid_map"
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
)

func LoadBpfObjects(proxyPort uint16, proxyTgid uint32, releaseDelay time.Duration) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
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
	variables := map[string]any{
		bpfVarProxyTgid:      proxyTgid,
		bpfVarProxyPort:      proxyPort,
		bpfVarReleaseDelayNs: uint64(releaseDelay.Nanoseconds()),
	}

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
		CidrMap:    objs.CidrMap,
		ClientMap:  objs.ClientMap,
		FilterMap:  objs.FilterMap,
		FlowMap:    objs.FlowMap,
		PortMap:    objs.PortMap,
		ReleaseMap: objs.ReleaseMap,
		RouteMap:   objs.RouteMap,
		TgidMap:    objs.TgidMap,
		UidMap:     objs.UidMap,
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

	for _, destinationCIDR := range filter.DestinationCIDRs {
		// bits after the prefix length are not part of the key, masked so the map shows the prefix as given
		err = bpfMaps[CidrMap].Update(prefixToKey(destinationCIDR.Masked()), uint8(1), ebpf.UpdateAny)

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

	filterConfig := bpfFilterConfig{
		CidrFilter: 0,
		PortFilter: 0,
		Padding:    0,
	}

	if len(filter.DestinationCIDRs) > 0 {
		filterConfig.CidrFilter = 1
	}

	if len(filter.DestinationPorts) > 0 {
		filterConfig.PortFilter = 1
	}

	err = bpfMaps[FilterMap].Update(uint32(0), filterConfig, ebpf.UpdateAny)

	if err != nil {
		err = fmt.Errorf("update %s: %w", bpfMapFilterMap, err)
		return
	}

	return
}

// new routes are written before the stale ones are deleted, so a still routed prefix never disappears in between
func UpdateRouteMap(routes map[netip.Prefix]bool, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	var (
		key   bpfPrefixKey
		value uint8
	)

	staleKeys := []bpfPrefixKey{}
	iterator := bpfMaps[RouteMap].Iterate()

	for iterator.Next(&key, &value) {
		if _, ok := routes[keyToPrefix(key)]; !ok {
			staleKeys = append(staleKeys, key)
		}
	}

	err = iterator.Err()

	if err != nil {
		err = fmt.Errorf("iterate %s: %w", bpfMapRouteMap, err)
		return
	}

	for prefix, routable := range routes {
		value = 0

		if routable {
			value = 1
		}

		err = bpfMaps[RouteMap].Update(prefixToKey(prefix), value, ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s %s: %w", bpfMapRouteMap, prefix, err)
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

// For debugging
func Read(ctx context.Context, flowMap *ebpf.Map) {
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

			if err := iterator.Err(); err != nil {
				fmt.Printf("%s iterate error: %s\n", bpfMapFlowMap, err)
				continue
			}

			fmt.Printf("\n%-20s %-5s %-47s %-10s %-8s %-8s %-16s %-10s %-47s\n", "Cookie", "Proto", "Destination", "Redirected", "PID", "UID", "Comm", "Cgroup ID", "UDP Client")

			for _, sortedCookie := range slices.SortedFunc(maps.Keys(flows), cmp.Compare) {
				flow := flows[sortedCookie]
				client := "-"

				// only UDP flows carry the client endpoint
				if flow.Client.IsValid() {
					client = flow.Client.String()
				}

				fmt.Printf("%-20d %-5s %-47s %-10t %-8d %-8d %-16s %-10d %-47s\n", sortedCookie, ProtocolName(flow.IPProtocol), flow.OriginalDestination, flow.Redirected, flow.Tgid, flow.UID, flow.Comm, flow.CgroupID, client)
			}
		}
	}
}

func flowFromBpf(bpfFlow bpfFlow) (flow Flow) {
	flow = Flow{
		OriginalDestination: netip.AddrPortFrom(keyToIP(bpfFlow.Ip), bpfFlow.Port),
		IPProtocol:          bpfFlow.IpProtocol,
		Redirected:          (bpfFlow.Redirected == 1),
		Tgid:                bpfFlow.Tgid,
		UID:                 bpfFlow.Uid,
		CgroupID:            bpfFlow.CgroupId,
		Comm:                commToString(bpfFlow.Comm),
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

func endpointToKey(addressPort netip.AddrPort, ipProtocol uint8) (key bpfEndpoint) {
	key = bpfEndpoint{
		Ip:         ipToKey(addressPort.Addr()),
		Port:       addressPort.Port(),
		IpProtocol: ipProtocol,
		Padding:    0,
	}
	return
}

// IPv4 prefixes are stored IPv4-mapped, so their length grows by the 96 bits of ::ffff:0:0/96
func prefixToKey(prefix netip.Prefix) (key bpfPrefixKey) {
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
