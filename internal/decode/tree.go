// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

func newTree() (tree *Tree) {
	tree = &Tree{
		roots:       nil,
		count:       0,
		size:        0,
		isFull:      false,
		errors:      0,
		summary:     nil,
		sink:        &node{},
		moreSummary: 0,
	}
	return
}

// a node under parent, a root for nil; past a limit the tree is full and the node is the sink, which keeps no children, so a decoder goes on without checks
func (tree *Tree) add(parent *node, name string, label string, value string, offset int, length int) (child *node) {
	depth := 0

	if parent != nil {
		depth = parent.depth + 1
	}

	size := len(name) + len(label) + len(value) + nodeOverheadBytes

	if (parent == tree.sink) || (tree.count >= MaxNodes) || (depth >= MaxDepth) || (tree.size+size > MaxOutputBytes) {
		tree.isFull = true
		child = tree.sink
		return
	}

	child = &node{name: name, label: label, value: value, err: "", offset: offset, length: length, mask: 0, depth: depth, children: nil}
	tree.count++
	tree.size += size

	if parent == nil {
		tree.roots = append(tree.roots, child)
	} else {
		parent.children = append(parent.children, child)
	}

	return
}

// add for a field smaller than its bytes
func (tree *Tree) addBits(parent *node, name string, label string, value string, offset int, length int, mask uint32) (child *node) {
	child = tree.add(parent, name, label, value, offset, length)

	if child != tree.sink {
		child.mask = mask
	}

	return
}

// what is wrong with a field, a second error is added to the first
func (tree *Tree) fail(target *node, message string) {
	tree.errors++

	if target == tree.sink {
		return
	}

	tree.size += len(message) + 2

	if target.err != "" {
		target.err += "; " + message
		return
	}

	target.err = message
}

// one line of the summary per PDU, they are joined with "; "; past maxSummaryLines they are only counted
func (tree *Tree) addSummary(line string) {
	if len(tree.summary) >= maxSummaryLines {
		tree.moreSummary++
		return
	}

	tree.summary = append(tree.summary, line)
}

func (tree *Tree) summaryText() (text string) {
	text = strings.Join(tree.summary, "; ")

	if tree.moreSummary > 0 {
		text += fmt.Sprintf("; %d more", tree.moreSummary)
	}

	return
}

// the tree as the API gives it, with every string passed through sanitize
func (tree *Tree) view() (nodes []v1.DecodeNode) {
	nodes = viewOf(tree.roots)

	if nodes == nil {
		nodes = []v1.DecodeNode{}
	}

	return
}

func viewOf(children []*node) (nodes []v1.DecodeNode) {
	for _, child := range children {
		nodes = append(nodes, v1.DecodeNode{
			Name:     sanitize(child.name),
			Label:    sanitize(child.label),
			Value:    sanitize(child.value),
			Offset:   child.offset,
			Length:   child.length,
			Mask:     child.mask,
			Error:    sanitize(child.err),
			Children: viewOf(child.children),
		})
	}

	return
}

// the last pass over every string of a tree: a decoder escapes what comes from the traffic itself, this makes sure no byte outside printable ASCII
// leaves even when one did not; a backslash stays, so an escaped string is not escaped twice
func sanitize(text string) (clean string) {
	index := 0

	for (index < len(text)) && (text[index] >= ' ') && (text[index] <= '~') {
		index++
	}

	if index == len(text) {
		clean = text
		return
	}

	builder := strings.Builder{}
	builder.Grow(len(text) + 8)
	builder.WriteString(text[:index])

	for _, value := range []byte(text[index:]) {
		if (value >= ' ') && (value <= '~') {
			builder.WriteByte(value)
			continue
		}

		builder.WriteString(`\x`)
		builder.WriteByte(hexDigits[value>>4])
		builder.WriteByte(hexDigits[value&0x0f])
	}

	clean = builder.String()
	return
}
