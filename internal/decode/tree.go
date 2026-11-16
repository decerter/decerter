// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
	"io"
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
		inflated:    new(int),
	}
	return
}

// a tree of its own for a decode nested in this one (TLS after STARTTLS, a WebSocket message's protocol), it inflates from the same budget; adopt
// takes its limits back after its nodes are grafted
func (tree *Tree) nested() (inner *Tree) {
	inner = newTree()
	inner.inflated = tree.inflated
	return
}

func (tree *Tree) adopt(inner *Tree) {
	tree.isFull = tree.isFull || inner.isFull
}

// a node under parent, a root for nil; past a limit the tree is full and the node is the sink, which keeps no children, so a decoder goes on without checks
func (tree *Tree) add(parent *node, name string, label string, value string, offset int, length int) (child *node) {
	depth := 0

	if parent != nil {
		depth = parent.depth + 1
	}

	name, label, value = capText(sanitize(name), maxStringBytes), capText(sanitize(label), maxStringBytes), capText(sanitize(value), maxStringBytes)
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

	if target.err != "" {
		message = target.err + "; " + message
	}

	tree.replace(target, &target.err, message)
}

// the name, label or value of a node after add: these and fail write through replace, which keeps the string and the tree in their limits
func (tree *Tree) setName(target *node, name string) {
	tree.replace(target, &target.name, name)
}

func (tree *Tree) setLabel(target *node, label string) {
	tree.replace(target, &target.label, label)
}

func (tree *Tree) setValue(target *node, value string) {
	tree.replace(target, &target.value, value)
}

// a string of target, sanitized, cut to maxStringBytes and charged to the size; past MaxOutputBytes the tree is full and the string stays as it was;
// the sink keeps no strings
func (tree *Tree) replace(target *node, field *string, text string) {
	if target == tree.sink {
		return
	}

	text = capText(sanitize(text), maxStringBytes)
	grown := len(text) - len(*field)

	if tree.size+grown > MaxOutputBytes {
		tree.isFull = true
		return
	}

	tree.size += grown
	*field = text
}

// text of printable ASCII at most limit bytes long: a longer one is cut before an escape it would split (\\, \n, \xNN) and ends with "..."
func capText(text string, limit int) (capped string) {
	capped = text

	if len(text) <= limit {
		return
	}

	cut := limit - len("...")

	if slash := strings.LastIndexByte(text[max(0, cut-3):cut], '\\'); slash >= 0 {
		slash += max(0, cut-3)
		run := 0

		for (slash-run >= 0) && (text[slash-run] == '\\') {
			run++
		}

		// an odd run of backslashes ends with the start of an escape: \\ is 2 bytes, \xNN 4
		escapeLength := 2

		if (slash+1 < len(text)) && (text[slash+1] == 'x') {
			escapeLength = 4
		}

		if (run%2 == 1) && (slash+escapeLength > cut) {
			cut = slash
		}
	}

	capped = text[:cut] + "..."
	return
}

// what reader inflates to: at most maxInflatedBytes of one payload and what is left of maxDecodeInflatedBytes for the whole decode; once that is spent
// the tree is full and the decode stops
func (tree *Tree) inflate(reader io.Reader) (inflated []byte, err error) {
	limit := min(maxInflatedBytes, maxDecodeInflatedBytes-*tree.inflated)

	if limit <= 0 {
		tree.isFull = true
		err = fmt.Errorf("the decode inflated %d bytes already, its limit", maxDecodeInflatedBytes)
		return
	}

	inflated, err = io.ReadAll(io.LimitReader(reader, int64(limit)+1))

	if (err == nil) && (len(inflated) > limit) {
		inflated = inflated[:limit]
		err = fmt.Errorf("it inflates to more than %d bytes", maxInflatedBytes)

		if limit < maxInflatedBytes {
			tree.isFull = true
			err = fmt.Errorf("the decode inflated %d bytes, its limit", maxDecodeInflatedBytes)
		}
	}

	*tree.inflated += len(inflated)
	return
}

// one line of the summary per PDU, sanitized and cut to maxSummaryBytes; the lines are joined with "; ", past maxSummaryLines they are only counted
func (tree *Tree) addSummary(line string) {
	if len(tree.summary) >= maxSummaryLines {
		tree.moreSummary++
		return
	}

	tree.summary = append(tree.summary, capText(sanitize(line), maxSummaryBytes))
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
