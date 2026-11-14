// SPDX-License-Identifier: AGPL-3.0-only

// usage: go run ./tools/bpfdrift <committed.o> <generated.o> [<committed.o> <generated.o> …]
//
// Compares BPF objects by content, not byte for byte: clang orders the BTF types and strings of the same source
// differently when it is built from another path, so make check-bpf-objects (tools/bpfdrift/check.sh) can't use cmp.
// Two objects are the same when their programs (instructions with their source lines, function info and CO-RE
// relocations without the local type id), maps, variables and the sorted list of their BTF types print the same.
// Exit status 1 names every pair that differs and its first differing line.
package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// how deep nested BTF types are printed, deep enough to reach the members of a member's struct
const typeDepth int = 4

var errUsage = errors.New("usage: bpfdrift <committed.o> <generated.o> [<committed.o> <generated.o> …]")

func main() {
	arguments := os.Args[1:]

	if (len(arguments) == 0) || (len(arguments)%2 != 0) {
		fmt.Fprintln(os.Stderr, errUsage.Error())
		os.Exit(2)
	}

	status := 0

	for index := 0; index < len(arguments); index += 2 {
		difference, err := compare(arguments[index], arguments[index+1])

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not compare %s with %s: %s\n", arguments[index], arguments[index+1], err.Error())
			os.Exit(2)
		}

		if difference != "" {
			fmt.Fprintf(os.Stderr, "%s differs from %s: %s\n", arguments[index+1], arguments[index], difference)
			status = 1
		}
	}

	os.Exit(status)
}

// the first line where the descriptions of the two objects differ, empty when they are the same
func compare(committedPath string, generatedPath string) (difference string, err error) {
	committed, err := describe(committedPath)

	if err != nil {
		return
	}

	generated, err := describe(generatedPath)

	if err != nil {
		return
	}

	committedLines := strings.Split(committed, "\n")
	generatedLines := strings.Split(generated, "\n")

	for index := range max(len(committedLines), len(generatedLines)) {
		committedLine := lineAt(committedLines, index)
		generatedLine := lineAt(generatedLines, index)

		if committedLine != generatedLine {
			difference = fmt.Sprintf("line %d: committed %q, generated %q", index+1, committedLine, generatedLine)
			return
		}
	}

	return
}

func lineAt(lines []string, index int) (line string) {
	if index < len(lines) {
		line = lines[index]
	} else {
		line = "(end of object)"
	}

	return
}

// a text form of the object that doesn't depend on where clang put its BTF strings
func describe(path string) (description string, err error) {
	spec, err := ebpf.LoadCollectionSpec(path)

	if err != nil {
		return
	}

	builder := strings.Builder{}
	fmt.Fprintf(&builder, "byte order %s\n", spec.ByteOrder)

	for _, name := range slices.Sorted(maps.Keys(spec.Maps)) {
		mapSpec := spec.Maps[name]
		fmt.Fprintf(&builder, "map %s type=%s key=%d value=%d entries=%d flags=%d pinning=%d inner=%v\n", name, mapSpec.Type, mapSpec.KeySize, mapSpec.ValueSize, mapSpec.MaxEntries, mapSpec.Flags, mapSpec.Pinning, mapSpec.InnerMap != nil)
		fmt.Fprintf(&builder, "\tkey %*v\n\tvalue %*v\n", typeDepth, mapSpec.Key, typeDepth, mapSpec.Value)

		for _, content := range mapSpec.Contents {
			fmt.Fprintf(&builder, "\tcontent %v = %v\n", content.Key, content.Value)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(spec.Variables)) {
		variable := spec.Variables[name]
		fmt.Fprintf(&builder, "variable %s section=%s offset=%d value=%x type=%*v\n", name, variable.SectionName, variable.Offset, variable.Value, typeDepth, variable.Type)
	}

	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		program := spec.Programs[name]
		fmt.Fprintf(&builder, "program %s type=%s attach=%s to=%q section=%s license=%s flags=%d\n", name, program.Type, program.AttachType, program.AttachTo, program.SectionName, program.License, program.Flags)

		for index := range program.Instructions {
			instruction := &program.Instructions[index]

			if source := instruction.Source(); source != nil {
				fmt.Fprintf(&builder, "\t; %s\n", strings.TrimSpace(source.String()))
			}

			fmt.Fprintf(&builder, "\t%v", *instruction)

			if function := btf.FuncMetadata(instruction); function != nil {
				fmt.Fprintf(&builder, " func=%*v", typeDepth, function)
			}

			// the local id is the type's place in the BTF, which is what moves
			if relocation := btf.CORERelocationMetadata(instruction); relocation != nil {
				relocationText, _, _ := strings.Cut(relocation.String(), ", local_id=")
				fmt.Fprintf(&builder, " %s)", relocationText)
			}

			builder.WriteString("\n")
		}
	}

	types := []string{}

	if spec.Types != nil {
		for typ, typeErr := range spec.Types.All() {
			if err = typeErr; err != nil {
				return
			}

			types = append(types, fmt.Sprintf("type %*v\n", typeDepth, typ))
		}
	}

	slices.Sort(types)
	builder.WriteString(strings.Join(types, ""))
	description = builder.String()
	return
}
