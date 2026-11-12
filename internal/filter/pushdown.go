// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"cmp"
	"net/netip"
	"slices"
	"syscall"
)

// a destination port of the kernel's port filter, IPProtocol is IPPROTO_TCP or IPPROTO_UDP
type Port struct {
	Port       uint16
	IPProtocol uint8
}

// what the kernel prefilter checks in connect and sendmsg: the four parts are and-ed, a part that is not constrained passes every flow and a constrained part with an empty set passes none
// process: the uid is in UIDs or the tgid in Tgids; comm: the process name is one of Comms; destination: the original destination is in one of DestinationCIDRs; port: the destination port and protocol are one of DestinationPorts
type Selection struct {
	HasProcess       bool
	UIDs             []uint32
	Tgids            []uint32
	HasComm          bool
	Comms            []string
	HasDestination   bool
	DestinationCIDRs []netip.Prefix
	HasPort          bool
	DestinationPorts []Port
}

var (
	// an IPv4 destination is IPv4-mapped in the kernel's CIDR trie, ipv6.dst has no IPv4 flow in Go
	ipv4MappedPrefix = netip.MustParsePrefix("::ffff:0:0/96")
)

// the kernel part of the filter: the terms of its top-level && chain that a kernel map can check, an || of terms of the same map included
// isExact is true when the kernel decides the whole filter, Go does not need to look at the flows then; otherwise the kernel lets more flows through than the filter and Go decides
// the selection is never narrower than the filter: a term under !, != or an || of different maps stays in Go, and a part that two terms constrain in a way one map can't hold keeps the first term
func (filter Filter) Pushdown() (selection Selection, isExact bool) {
	isExact = true

	if filter.root == nil {
		return
	}

	for _, conjunct := range conjunctsOf(filter.root) {
		part, isPushed, isPartExact := constraintOf(conjunct)

		if !isPushed {
			isExact = false
			continue
		}

		merged, isMergeExact := Intersect(selection, part)
		selection = merged
		isExact = isExact && isPartExact && isMergeExact
	}

	return
}

// the operands of the top-level && chain, an && in parentheses is part of it
func conjunctsOf(current *node) (conjuncts []*node) {
	if current.kind != andNodeKind {
		conjuncts = []*node{current}
		return
	}

	for _, child := range current.children {
		conjuncts = append(conjuncts, conjunctsOf(child)...)
	}

	return
}

// the selection a term implies, isPushed is false when no kernel map can check it, isExact when the map checks exactly what the term says
func constraintOf(current *node) (part Selection, isPushed bool, isExact bool) {
	switch current.kind {
	case compareNodeKind:
		if (current.operator != equalOperator) && (current.operator != allEqualOperator) {
			return
		}

		part, isPushed, isExact = setConstraint(current.field, current.values)
	case setNodeKind:
		if current.isNegated {
			return
		}

		part, isPushed, isExact = setConstraint(current.field, current.values)
	case orNodeKind:
		isExact = true

		for index, child := range current.children {
			childPart, isChildPushed, isChildExact := constraintOf(child)

			if !isChildPushed || ((index > 0) && !samePart(part, childPart)) {
				isPushed = false
				isExact = false
				return
			}

			part = union(part, childPart)
			isExact = isExact && isChildExact
		}

		isPushed = true
	default:
	}

	return
}

// field == value or field in {values} for a field with a kernel map, a number range stays in Go
func setConstraint(info FieldInfo, values []value) (part Selection, isPushed bool, isExact bool) {
	for _, literal := range values {
		if (info.Type == NumberFieldType) && (literal.high != literal.number) {
			return
		}
	}

	isPushed = true
	isExact = true

	switch info.Name {
	case UIDField:
		part.HasProcess = true

		for _, literal := range values {
			part.UIDs = append(part.UIDs, uint32(literal.number))
		}
	case PIDField:
		part.HasProcess = true

		for _, literal := range values {
			part.Tgids = append(part.Tgids, uint32(literal.number))
		}
	case CommField:
		part.HasComm = true

		for _, literal := range values {
			part.Comms = append(part.Comms, literal.text)
		}
	case
		IPDestField,
		IPv6DestField:
		part.HasDestination = true

		for _, literal := range values {
			part.DestinationCIDRs = append(part.DestinationCIDRs, literal.prefix)

			// the trie holds IPv4 as ::ffff:a.b.c.d, an IPv6 prefix over that range lets IPv4 flows through that ipv6.dst does not match
			if (info.Name == IPv6DestField) && literal.prefix.Overlaps(ipv4MappedPrefix) {
				isExact = false
			}
		}
	case
		TCPDstPortField,
		UDPDstPortField:
		part.HasPort = true
		ipProtocol := uint8(syscall.IPPROTO_TCP)

		if info.Name == UDPDstPortField {
			ipProtocol = syscall.IPPROTO_UDP
		}

		for _, literal := range values {
			part.DestinationPorts = append(part.DestinationPorts, Port{Port: uint16(literal.number), IPProtocol: ipProtocol})
		}
	default:
		isPushed = false
		isExact = false
	}

	part = part.normalized()
	return
}

// both constrain the same one part
func samePart(first Selection, second Selection) (isSame bool) {
	isSame = (first.HasProcess == second.HasProcess) && (first.HasComm == second.HasComm) && (first.HasDestination == second.HasDestination) && (first.HasPort == second.HasPort)
	return
}

// the selection that passes what either passes, for two selections of the same one part
func union(first Selection, second Selection) (result Selection) {
	result = Selection{
		HasProcess:       first.HasProcess || second.HasProcess,
		UIDs:             slices.Concat(first.UIDs, second.UIDs),
		Tgids:            slices.Concat(first.Tgids, second.Tgids),
		HasComm:          first.HasComm || second.HasComm,
		Comms:            slices.Concat(first.Comms, second.Comms),
		HasDestination:   first.HasDestination || second.HasDestination,
		DestinationCIDRs: slices.Concat(first.DestinationCIDRs, second.DestinationCIDRs),
		HasPort:          first.HasPort || second.HasPort,
		DestinationPorts: slices.Concat(first.DestinationPorts, second.DestinationPorts),
	}
	result = result.normalized()
	return
}

// the kernel selection of both: every part constrained by both is narrowed to what both pass where one map can hold it
// the result never passes a flow first does not pass, and passes every flow both pass; isExact is true when it passes no other flow
// the process part of a uid set and a pid set can't be narrowed in uid_map and tgid_map, it keeps first's then
func Intersect(first Selection, second Selection) (result Selection, isExact bool) {
	isExact = true
	result = first

	switch {
	case !second.HasProcess:
	case !first.HasProcess:
		result.HasProcess = true
		result.UIDs = second.UIDs
		result.Tgids = second.Tgids
	case isSubset(first.UIDs, second.UIDs) && isSubset(first.Tgids, second.Tgids):
	case isSubset(second.UIDs, first.UIDs) && isSubset(second.Tgids, first.Tgids):
		result.UIDs = second.UIDs
		result.Tgids = second.Tgids
	case (len(first.Tgids) == 0) && (len(second.Tgids) == 0):
		result.UIDs = intersectSets(first.UIDs, second.UIDs)
	case (len(first.UIDs) == 0) && (len(second.UIDs) == 0):
		result.Tgids = intersectSets(first.Tgids, second.Tgids)
	default:
		isExact = false
	}

	switch {
	case !second.HasComm:
	case !first.HasComm:
		result.HasComm = true
		result.Comms = second.Comms
	default:
		result.Comms = intersectSets(first.Comms, second.Comms)
	}

	switch {
	case !second.HasDestination:
	case !first.HasDestination:
		result.HasDestination = true
		result.DestinationCIDRs = second.DestinationCIDRs
	default:
		result.DestinationCIDRs = intersectPrefixes(first.DestinationCIDRs, second.DestinationCIDRs)
	}

	switch {
	case !second.HasPort:
	case !first.HasPort:
		result.HasPort = true
		result.DestinationPorts = second.DestinationPorts
	default:
		result.DestinationPorts = intersectSets(first.DestinationPorts, second.DestinationPorts)
	}

	result = result.normalized()
	return
}

// no flow passes: a constrained part has nothing in its set
func (selection Selection) IsEmpty() (isEmpty bool) {
	isEmpty = (selection.HasProcess && (len(selection.UIDs) == 0) && (len(selection.Tgids) == 0)) || (selection.HasComm && (len(selection.Comms) == 0)) || (selection.HasDestination && (len(selection.DestinationCIDRs) == 0)) || (selection.HasPort && (len(selection.DestinationPorts) == 0))
	return
}

// sorted and without duplicates, so equal selections look equal
func (selection Selection) normalized() (result Selection) {
	result = selection
	result.UIDs = sortedSet(selection.UIDs, cmp.Compare[uint32])
	result.Tgids = sortedSet(selection.Tgids, cmp.Compare[uint32])
	result.Comms = sortedSet(selection.Comms, cmp.Compare[string])
	result.DestinationCIDRs = sortedSet(selection.DestinationCIDRs, func(first netip.Prefix, second netip.Prefix) int {
		return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
	})
	result.DestinationPorts = sortedSet(selection.DestinationPorts, func(first Port, second Port) int {
		return cmp.Or(cmp.Compare(first.IPProtocol, second.IPProtocol), cmp.Compare(first.Port, second.Port))
	})
	return
}

func sortedSet[Element comparable](set []Element, compare func(first Element, second Element) int) (sorted []Element) {
	if len(set) == 0 {
		return
	}

	sorted = slices.Clone(set)
	slices.SortFunc(sorted, compare)
	sorted = slices.Compact(sorted)
	return
}

func isSubset[Element comparable](subset []Element, set []Element) (isSubset bool) {
	isSubset = true

	for _, element := range subset {
		isSubset = isSubset && slices.Contains(set, element)
	}

	return
}

func intersectSets[Element comparable](first []Element, second []Element) (result []Element) {
	for _, element := range first {
		if slices.Contains(second, element) {
			result = append(result, element)
		}
	}

	return
}

// two prefixes that overlap are one inside the other, the narrower is what both pass; IPv4 and IPv4-mapped IPv6 are the same addresses as in the kernel's trie
func intersectPrefixes(first []netip.Prefix, second []netip.Prefix) (result []netip.Prefix) {
	for _, firstPrefix := range first {
		for _, secondPrefix := range second {
			firstMapped := mappedPrefix(firstPrefix)
			secondMapped := mappedPrefix(secondPrefix)

			if !firstMapped.Overlaps(secondMapped) {
				continue
			}

			if secondMapped.Bits() > firstMapped.Bits() {
				result = append(result, secondPrefix)
			} else {
				result = append(result, firstPrefix)
			}
		}
	}

	return
}

func mappedPrefix(prefix netip.Prefix) (mapped netip.Prefix) {
	mapped = prefix

	if prefix.Addr().Is4() {
		mapped = netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), prefix.Bits()+96)
	}

	return
}
