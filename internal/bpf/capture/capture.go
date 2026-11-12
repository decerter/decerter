// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" bpf ../../../bpf/capture/capture.c -- -I../../../bpf -I../../../bpf/include

const (
	DropMap        bpf.BpfMapName     = 0 // value: "drop_map"
	FlowMap        bpf.BpfMapName     = 1 // value: "flow_map"
	PacketMap      bpf.BpfMapName     = 2 // value: "packet_map"
	TgidMap        bpf.BpfMapName     = 3 // value: "tgid_map"
	UidMap         bpf.BpfMapName     = 4 // value: "uid_map"
	CaptureEgress  bpf.BpfProgramName = 0 // value: "capture_egress"
	CaptureIngress bpf.BpfProgramName = 1 // value: "capture_ingress"
)

const (
	// MAX_SNAPLEN of capture.h, the largest packet a packet_map record can hold
	MaxSnaplen uint32 = 262144
)

// the capture object shares the flow_map of the redirect object, so the scope decision of connect and sendmsg carries over to every packet of the socket
// shared.h also gives it uid_map and tgid_map, which it does not read, they are shared too so the kernel does not get a second pair
func LoadBpfObjects(snaplen uint32, sharedFlowMap *ebpf.Map, sharedUidMap *ebpf.Map, sharedTgidMap *ebpf.Map) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
	if (snaplen == 0) || (snaplen > MaxSnaplen) {
		err = fmt.Errorf("%w: %d", ErrSnaplen, snaplen)
		return
	}

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
	err = spec.Variables[bpfVarSnaplen].Set(snaplen)

	if err != nil {
		err = fmt.Errorf("set %s: %w", bpfVarSnaplen, err)
		return
	}

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			bpfMapFlowMap: sharedFlowMap,
			bpfMapUidMap:  sharedUidMap,
			bpfMapTgidMap: sharedTgidMap,
		},
	})

	if err != nil {
		err = fmt.Errorf("load bpf objects: %w", err)
		return
	}

	bpfMaps = map[bpf.BpfMapName]*ebpf.Map{
		DropMap:   objs.DropMap,
		FlowMap:   objs.FlowMap,
		PacketMap: objs.PacketMap,
		TgidMap:   objs.TgidMap,
		UidMap:    objs.UidMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		CaptureEgress:  objs.CaptureEgress,
		CaptureIngress: objs.CaptureIngress,
	}
	closeFunction = objs.Close
	return
}

// a packet_map record is a struct packet_header and the captured bytes of the packet behind it
// Data points into rawSample, a reader that uses its record again has to copy what it keeps
func ParsePacket(rawSample []byte) (packet Packet, err error) {
	var header bpfPacketHeader

	headerLength, decodeErr := binary.Decode(rawSample, binary.NativeEndian, &header)

	if err = decodeErr; err != nil {
		err = fmt.Errorf("%w: %d bytes: %w", ErrShortRecord, len(rawSample), err)
		return
	}

	if uint64(len(rawSample)-headerLength) < uint64(header.CapturedLength) {
		err = fmt.Errorf("%w: %d bytes for a packet of %d", ErrShortRecord, len(rawSample), header.CapturedLength)
		return
	}

	packet = Packet{
		Cookie:      header.Cookie,
		TimestampNs: header.TimestampNs,
		Length:      header.Length,
		IsIngress:   (header.Direction == ingressDirection),
		Data:        rawSample[headerLength : headerLength+int(header.CapturedLength)],
	}
	return
}

// packets of recorded sockets that found packet_map full, the programs count them per CPU
func ReadDropped(bpfMaps map[bpf.BpfMapName]*ebpf.Map) (dropped uint64, err error) {
	var perCPU []uint64

	err = bpfMaps[DropMap].Lookup(uint32(0), &perCPU)

	if err != nil {
		err = fmt.Errorf("lookup %s: %w", bpfMapDropMap, err)
		return
	}

	for _, count := range perCPU {
		dropped += count
	}

	return
}

// a recorded socket stays in flow_map until a moment after it closed, found tells the capture writer that it is still open
func HasFlow(cookie uint64, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (found bool, err error) {
	var flow bpfFlow

	err = bpfMaps[FlowMap].Lookup(cookie, &flow)

	if errors.Is(err, ebpf.ErrKeyNotExist) {
		err = nil
		return
	}

	if err != nil {
		err = fmt.Errorf("lookup %s: %w", bpfMapFlowMap, err)
		return
	}

	found = true
	return
}
