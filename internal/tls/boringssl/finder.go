// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"golang.org/x/arch/x86/x86asm"
)

const (
	// x86_64 instructions are decoded from a label's lea on, arm64 words are read from the add on; the call comes within a few instructions
	callSearchInstructions int = 24
	// arm64: the add that completes an adrp's address may be scheduled a few words later
	addSearchWords int = 8
	// the function that gets the most labels wins, with at least this many of them, so one stray reference can't decide
	minimumLabelVotes int = 3
)

// the key log labels BoringSSL passes to ssl_log_secret as its second argument, each call site loads one of these strings right before the call
// stripped static builds (Flutter, Chrome, Cronet) have no symbol, but the strings stay in .rodata and the call sites are found through them
var logSecretLabels = []string{
	"CLIENT_RANDOM",
	"CLIENT_EARLY_TRAFFIC_SECRET",
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	"SERVER_HANDSHAKE_TRAFFIC_SECRET",
	"CLIENT_TRAFFIC_SECRET_0",
	"SERVER_TRAFFIC_SECRET_0",
	"EXPORTER_SECRET",
}

// one PT_LOAD segment of the library, read into memory
type segment struct {
	address uint64
	data    []byte
}

// the file offset of ssl_log_secret in a stripped ELF that links BoringSSL statically, found through the cross references to its labels:
// every call site loads a label's address (x86_64: lea reg, [rip+disp32]; arm64: adrp + add, or adr) and calls or tail-calls the function within a few
// instructions; each label votes for the call targets after its loads, and the target most labels reach is ssl_log_secret
// the offset is relative to the start of the ELF, for a library inside an APK the entry's data offset is added by the caller; labels is the number of labels that led to it
func FindLogSecretByLabels(file *elf.File) (address uint64, labels int, err error) {
	readOnly, code, err := readSegments(file)

	if err != nil {
		return
	}

	address, labels, err = findLogSecret(file, readOnly, code)
	return
}

func findLogSecret(file *elf.File, readOnly []segment, code []segment) (address uint64, labels int, err error) {
	switch file.Machine {
	case
		elf.EM_X86_64,
		elf.EM_AARCH64:
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedMachine, file.Machine)
		return
	}

	addresses := labelAddresses(readOnly)

	if len(addresses) == 0 {
		err = ErrNoLabels
		return
	}

	votes := map[uint64]map[int]bool{}

	vote := func(label int, target uint64) {
		if votes[target] == nil {
			votes[target] = map[int]bool{}
		}

		votes[target][label] = true
	}

	for _, current := range code {
		switch file.Machine {
		case elf.EM_X86_64:
			scanX86(current, addresses, vote)
		default:
			scanARM64(current, addresses, vote)
		}
	}

	target, labels, err := electTarget(votes)

	if err != nil {
		return
	}

	address, found := fileOffset(file, target)

	if !found {
		err = fmt.Errorf("%w: 0x%x", ErrNotLoaded, target)
		return
	}

	return
}

// the loaded segments without write access, where .rodata is, and the executable ones, where .text is; a segment can be both
func readSegments(file *elf.File) (readOnly []segment, code []segment, err error) {
	for _, program := range file.Progs {
		if (program.Type != elf.PT_LOAD) || ((program.Flags & elf.PF_W) != 0) || (program.Filesz == 0) {
			continue
		}

		data, readErr := io.ReadAll(program.Open())

		if err = readErr; err != nil {
			err = fmt.Errorf("%w: segment at 0x%x: %w", ErrReadSegment, program.Vaddr, err)
			return
		}

		current := segment{address: program.Vaddr, data: data}
		readOnly = append(readOnly, current)

		if (program.Flags & elf.PF_X) != 0 {
			code = append(code, current)
		}
	}

	return
}

// the addresses of every NUL terminated copy of each label, also the tail of a longer string (the linker merges suffixes), mapped to the label's index
func labelAddresses(readOnly []segment) (labels map[uint64]int) {
	labels = map[uint64]int{}

	for index, label := range logSecretLabels {
		needle := append([]byte(label), 0)

		for _, current := range readOnly {
			start := 0

			for {
				found := bytes.Index(current.data[start:], needle)

				if found < 0 {
					break
				}

				labels[current.address+uint64(start+found)] = index
				start += found + 1
			}
		}
	}

	return
}

// x86_64: every lea r64, [rip+disp32] (REX.W 8D, ModRM mod 00 rm 101) whose address is a label, then the direct calls and jumps of the next instructions
func scanX86(current segment, labels map[uint64]int, vote func(label int, target uint64)) {
	data := current.data

	for index := 0; index+7 <= len(data); index++ {
		if ((data[index] != 0x48) && (data[index] != 0x4c)) || (data[index+1] != 0x8d) || ((data[index+2] & 0xc7) != 0x05) {
			continue
		}

		next := current.address + uint64(index) + 7
		displacement := int32(binary.LittleEndian.Uint32(data[index+3:]))
		label, isLabel := labels[next+uint64(int64(displacement))]

		if !isLabel {
			continue
		}

		for _, target := range callsAfterX86(current, index+7) {
			vote(label, target)
		}
	}
}

// the targets of the direct calls from position on, up to an unconditional jump (a tail call, also taken as a target) or a return
func callsAfterX86(current segment, position int) (targets []uint64) {
	for range callSearchInstructions {
		if position >= len(current.data) {
			return
		}

		instruction, decodeErr := x86asm.Decode(current.data[position:], 64)

		if decodeErr != nil {
			return
		}

		next := current.address + uint64(position+instruction.Len)
		position += instruction.Len

		switch instruction.Op {
		case x86asm.CALL:
			if relative, isRelative := instruction.Args[0].(x86asm.Rel); isRelative {
				targets = append(targets, next+uint64(int64(relative)))
			}
		case x86asm.JMP:
			if relative, isRelative := instruction.Args[0].(x86asm.Rel); isRelative {
				targets = append(targets, next+uint64(int64(relative)))
			}

			return
		case
			x86asm.RET,
			x86asm.UD2,
			x86asm.INT:
			return
		default:
		}
	}

	return
}

// arm64: every adrp whose page holds a label, completed by an add of the label's low 12 bits to the same register, and every adr of a label,
// then the bl and b of the next words
func scanARM64(current segment, labels map[uint64]int, vote func(label int, target uint64)) {
	pages := map[uint64]bool{}

	for address := range labels {
		pages[address&^0xfff] = true
	}

	data := current.data

	for index := 0; index+4 <= len(data); index += 4 {
		word := binary.LittleEndian.Uint32(data[index:])
		pc := current.address + uint64(index)

		switch word & 0x9f000000 {
		case 0x10000000:
			// adr xd, label
			label, isLabel := labels[pc+uint64(adrImmediate(word))]

			if isLabel {
				for _, target := range callsAfterARM64(current, index+4) {
					vote(label, target)
				}
			}
		case 0x90000000:
			// adrp xd, page
			page := (pc &^ 0xfff) + uint64(adrImmediate(word)<<12)

			if !pages[page] {
				continue
			}

			register := word & 0x1f

			for offset := 4; (offset <= 4*addSearchWords) && (index+offset+4 <= len(data)); offset += 4 {
				add := binary.LittleEndian.Uint32(data[index+offset:])

				// add xd, xn, #imm12 (64 bit, no shift) with xn the adrp's register
				if ((add & 0xffc00000) != 0x91000000) || (((add >> 5) & 0x1f) != register) {
					continue
				}

				label, isLabel := labels[page+uint64((add>>10)&0xfff)]

				if isLabel {
					for _, target := range callsAfterARM64(current, index+offset+4) {
						vote(label, target)
					}
				}

				break
			}
		default:
		}
	}
}

// the targets of the bl from position on, up to a b (a tail call, also taken as a target) or a return; the machine outliner puts calls to
// OUTLINED_FUNCTION_* between the label and the call, those get votes from one or two labels only
func callsAfterARM64(current segment, position int) (targets []uint64) {
	for count := range callSearchInstructions {
		index := position + 4*count

		if index+4 > len(current.data) {
			return
		}

		word := binary.LittleEndian.Uint32(current.data[index:])
		pc := current.address + uint64(index)
		// imm26 words, sign extended
		offset := int64(int32(word<<6)>>6) * 4

		switch {
		case (word & 0xfc000000) == 0x94000000:
			targets = append(targets, pc+uint64(offset))
		case (word & 0xfc000000) == 0x14000000:
			targets = append(targets, pc+uint64(offset))
			return
		case
			(word & 0xfffffc1f) == 0xd65f0000,
			(word == 0xd65f0bff),
			(word == 0xd65f0fff):
			// ret, retaa, retab
			return
		default:
		}
	}

	return
}

// the 21 bit signed immediate of adr and adrp, immhi:immlo
func adrImmediate(word uint32) (immediate int64) {
	value := ((word >> 5) & 0x7ffff << 2) | ((word >> 29) & 0x3)
	immediate = int64(int32(value<<11) >> 11)
	return
}

// the call target with the most labels, it needs minimumLabelVotes and a clear lead over the next one
func electTarget(votes map[uint64]map[int]bool) (target uint64, labels int, err error) {
	type candidate struct {
		target uint64
		count  int
	}

	candidates := []candidate{}

	for current, labels := range votes {
		candidates = append(candidates, candidate{target: current, count: len(labels)})
	}

	slices.SortFunc(candidates, func(first candidate, second candidate) (order int) {
		order = second.count - first.count

		if order == 0 {
			order = compareAddress(first.target, second.target)
		}

		return
	})

	if (len(candidates) == 0) || (candidates[0].count < minimumLabelVotes) {
		best := 0

		if len(candidates) > 0 {
			best = candidates[0].count
		}

		err = fmt.Errorf("%w: the best call target is reached from %d of %d labels, %d needed", ErrNoLabelCalls, best, len(logSecretLabels), minimumLabelVotes)
		return
	}

	if (len(candidates) > 1) && (candidates[1].count == candidates[0].count) {
		err = fmt.Errorf("%w: 0x%x and 0x%x are both reached from %d labels", ErrAmbiguousLabelCalls, candidates[0].target, candidates[1].target, candidates[0].count)
		return
	}

	target = candidates[0].target
	labels = candidates[0].count
	return
}

func compareAddress(first uint64, second uint64) (order int) {
	switch {
	case first < second:
		order = -1
	case first > second:
		order = 1
	default:
		order = 0
	}

	return
}
