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
	ClientMap           bpf.BpfMapName     = 0 // value: "client_map"
	FlowMap             bpf.BpfMapName     = 1 // value: "flow_map"
	RouteMap            bpf.BpfMapName     = 2 // value: "route_map"
	UidMap              bpf.BpfMapName     = 3 // value: "uid_map"
	ClientSockops       bpf.BpfProgramName = 0 // value: "client_sockops"
	RedirectConnect4    bpf.BpfProgramName = 1 // value: "redirect_connect4"
	RedirectConnect6    bpf.BpfProgramName = 2 // value: "redirect_connect6"
	RedirectSendmsg4    bpf.BpfProgramName = 3 // value: "redirect_sendmsg4"
	RedirectSendmsg6    bpf.BpfProgramName = 4 // value: "redirect_sendmsg6"
	RestoreGetpeername4 bpf.BpfProgramName = 5 // value: "restore_getpeername4"
	RestoreGetpeername6 bpf.BpfProgramName = 6 // value: "restore_getpeername6"
)

func LoadBpfObjects(tcpProxyPort uint16, proxyTgid uint32) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
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
		bpfVarProxyTgid:    proxyTgid,
		bpfVarTcpProxyPort: tcpProxyPort,
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
		ClientMap: objs.ClientMap,
		FlowMap:   objs.FlowMap,
		RouteMap:  objs.RouteMap,
		UidMap:    objs.UidMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		ClientSockops:       objs.ClientSockops,
		RedirectConnect4:    objs.RedirectConnect4,
		RedirectConnect6:    objs.RedirectConnect6,
		RedirectSendmsg4:    objs.RedirectSendmsg4,
		RedirectSendmsg6:    objs.RedirectSendmsg6,
		RestoreGetpeername4: objs.RestoreGetpeername4,
		RestoreGetpeername6: objs.RestoreGetpeername6,
	}
	closeFunction = objs.Close
	return
}

// an empty uid set matches no process, nothing is recorded
func UpdateBpfMaps(uids []uint32, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	for _, uid := range uids {
		err = bpfMaps[UidMap].Update(uid, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s uid %d: %w", bpfMapUidMap, uid, err)
			return
		}
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

// the client endpoint is the peer address of the accepted proxy connection, sockops stores it IPv4-mapped
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

			fmt.Printf("\n%-20s %-5s %-47s %-10s %-8s %-8s %-16s %-10s\n", "Cookie", "Proto", "Destination", "Redirected", "PID", "UID", "Comm", "Cgroup ID")

			for _, sortedCookie := range slices.SortedFunc(maps.Keys(flows), cmp.Compare) {
				flow := flows[sortedCookie]
				fmt.Printf("%-20d %-5s %-47s %-10t %-8d %-8d %-16s %-10d\n", sortedCookie, ProtocolName(flow.IPProtocol), flow.OriginalDestination, flow.Redirected, flow.Tgid, flow.UID, flow.Comm, flow.CgroupID)
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

// IPv4 is stored IPv4-mapped like in the C structs: As16 gives ::ffff:a.b.c.d for both plain and mapped IPv4
func endpointToKey(addressPort netip.AddrPort, ipProtocol uint8) (key bpfEndpoint) {
	address := addressPort.Addr().As16()
	key = bpfEndpoint{
		Ip:         [4]uint32{},
		Port:       addressPort.Port(),
		IpProtocol: ipProtocol,
		Padding:    0,
	}

	for index := range key.Ip {
		key.Ip[index] = binary.NativeEndian.Uint32(address[index*4 : index*4+4])
	}

	return
}

// IPv4 prefixes are stored IPv4-mapped, so their length grows by the 96 bits of ::ffff:0:0/96
func prefixToKey(prefix netip.Prefix) (key bpfPrefixKey) {
	address := prefix.Addr().As16()
	prefixLength := prefix.Bits()

	if prefix.Addr().Is4() {
		prefixLength += 96
	}

	key = bpfPrefixKey{
		Prefixlen: uint32(prefixLength),
		Ip:        [4]uint32{},
	}

	for index := range key.Ip {
		key.Ip[index] = binary.NativeEndian.Uint32(address[index*4 : index*4+4])
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
