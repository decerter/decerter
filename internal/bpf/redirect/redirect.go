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
	FlowMap          bpf.BpfMapName     = 0 // value: "flow_map"
	UidMap           bpf.BpfMapName     = 1 // value: "uid_map"
	RedirectConnect4 bpf.BpfProgramName = 0 // value: "redirect_connect4"
	RedirectConnect6 bpf.BpfProgramName = 1 // value: "redirect_connect6"
	RedirectSendmsg4 bpf.BpfProgramName = 2 // value: "redirect_sendmsg4"
	RedirectSendmsg6 bpf.BpfProgramName = 3 // value: "redirect_sendmsg6"
)

func LoadBpfObjects(proxyTgid uint32) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
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
	err = spec.Variables[bpfVarProxyTgid].Set(proxyTgid)

	if err != nil {
		err = fmt.Errorf("set %s: %w", bpfVarProxyTgid, err)
		return
	}

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, nil)

	if err != nil {
		err = fmt.Errorf("load bpf objects: %w", err)
		return
	}

	bpfMaps = map[bpf.BpfMapName]*ebpf.Map{
		FlowMap: objs.FlowMap,
		UidMap:  objs.UidMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		RedirectConnect4: objs.RedirectConnect4,
		RedirectConnect6: objs.RedirectConnect6,
		RedirectSendmsg4: objs.RedirectSendmsg4,
		RedirectSendmsg6: objs.RedirectSendmsg6,
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

			fmt.Printf("\n%-20s %-5s %-47s %-8s %-8s %-10s\n", "Cookie", "Proto", "Destination", "PID", "UID", "Cgroup ID")

			for _, sortedCookie := range slices.SortedFunc(maps.Keys(flows), cmp.Compare) {
				flow := flows[sortedCookie]
				fmt.Printf("%-20d %-5s %-47s %-8d %-8d %-10d\n", sortedCookie, protocolName(flow.IPProtocol), flow.OriginalDestination, flow.Tgid, flow.UID, flow.CgroupID)
			}
		}
	}
}

func flowFromBpf(bpfFlow bpfFlow) (flow Flow) {
	flow = Flow{
		OriginalDestination: netip.AddrPortFrom(keyToIP(bpfFlow.Ip), bpfFlow.Port),
		IPProtocol:          bpfFlow.IpProtocol,
		Tgid:                bpfFlow.Tgid,
		UID:                 bpfFlow.Uid,
		CgroupID:            bpfFlow.CgroupId,
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

func protocolName(ipProtocol uint8) (name string) {
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
