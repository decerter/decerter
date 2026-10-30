// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" bpf ../../../bpf/redirect/redirect.c -- -I../../../bpf -I../../../bpf/include

const (
	CounterMap    bpf.BpfMapName     = 0 // value: "counter_map"
	CountConnect4 bpf.BpfProgramName = 0 // value: "count_connect4"
)

func LoadBpfObjects() (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
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

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, nil)

	if err != nil {
		err = fmt.Errorf("load bpf objects: %w", err)
		return
	}

	bpfMaps = map[bpf.BpfMapName]*ebpf.Map{
		CounterMap: objs.CounterMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		CountConnect4: objs.CountConnect4,
	}
	closeFunction = objs.Close
	return
}

// For debugging
func Read(ctx context.Context, counterMap *ebpf.Map) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var (
				uid   uint32
				count uint64
			)

			counts := map[uint32]uint64{}
			iterator := counterMap.Iterate()

			for iterator.Next(&uid, &count) {
				counts[uid] = count
			}

			if err := iterator.Err(); err != nil {
				fmt.Printf("%s iterate error: %s\n", bpfMapCounterMap, err)
				continue
			}

			fmt.Printf("\n%-10s %-10s\n", "UID", "Connects")

			for _, sortedUID := range slices.Sorted(maps.Keys(counts)) {
				fmt.Printf("%-10d %-10d\n", sortedUID, counts[sortedUID])
			}
		}
	}
}
