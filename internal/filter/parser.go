// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type nodeKind string

const (
	andNodeKind nodeKind = "and"
	orNodeKind  nodeKind = "or"
	notNodeKind nodeKind = "not"
	// a bare field: true when the flow has it
	existsNodeKind nodeKind = "exists"
	// field operator value
	compareNodeKind nodeKind = "compare"
	// field in {…}, field not in {…}
	setNodeKind nodeKind = "set"
)

type operator string

const (
	// any value equal, Wireshark's == and any_eq
	equalOperator operator = "=="
	// every value equal, Wireshark's === and all_eq
	allEqualOperator operator = "==="
	// every value different, Wireshark's != and all_ne
	notEqualOperator operator = "!="
	// any value different, Wireshark's !== and any_ne
	anyNotEqualOperator  operator = "!=="
	lessOperator         operator = "<"
	lessEqualOperator    operator = "<="
	greaterOperator      operator = ">"
	greaterEqualOperator operator = ">="
	containsOperator     operator = "contains"
	matchesOperator      operator = "matches"
)

var (
	// the words and symbols of each operator, Wireshark's spellings
	operatorSpellings = map[string]operator{
		"==": equalOperator, "eq": equalOperator, "any_eq": equalOperator,
		"===": allEqualOperator, "all_eq": allEqualOperator,
		"!=": notEqualOperator, "ne": notEqualOperator, "all_ne": notEqualOperator,
		"!==": anyNotEqualOperator, "any_ne": anyNotEqualOperator,
		"<": lessOperator, "lt": lessOperator,
		"<=": lessEqualOperator, "le": lessEqualOperator,
		">": greaterOperator, "gt": greaterOperator,
		">=": greaterEqualOperator, "ge": greaterEqualOperator,
		"contains": containsOperator,
		"matches":  matchesOperator, "~": matchesOperator,
	}
)

// one literal of a comparison or a set
// number is a number, number..high a range of a set, a single number has high == number
// prefix is an address as a /32 or /128, or a CIDR prefix, masked
type value struct {
	number uint64
	high   uint64
	text   string
	prefix netip.Prefix
}

// and and or have two or more children, not one
// isNegated is a not in set, which is false for a flow without the field, as in Wireshark
// regex is the compiled pattern of matches
type node struct {
	kind      nodeKind
	children  []*node
	field     FieldInfo
	operator  operator
	values    []value
	isNegated bool
	regex     *regexp.Regexp
}

// a parsed filter, the zero value is no filter: everything is in scope
// fields are the fields it uses, pushdown and exact what the kernel can decide of it
type Filter struct {
	text   string
	root   *node
	fields map[Field]bool
}

type parser struct {
	text     string
	tokens   []token
	position int
	fields   map[Field]bool
}

// parse a filter of the Wireshark display filter subset, an error is a *PositionError with the column of the problem
func Parse(text string) (filter Filter, err error) {
	tokens, lexErr := lex(text)

	if err = lexErr; err != nil {
		return
	}

	currentParser := parser{
		text:     text,
		tokens:   tokens,
		position: 0,
		fields:   map[Field]bool{},
	}

	if currentParser.peek().kind == endTokenKind {
		err = newPositionError(text, 0, len(text), fmt.Errorf("%w: empty filter", ErrSyntax))
		return
	}

	root, parseErr := currentParser.parseOr()

	if err = parseErr; err != nil {
		return
	}

	if next := currentParser.peek(); next.kind != endTokenKind {
		err = currentParser.unexpected(next, "&&, || or the end of the filter")
		return
	}

	filter = Filter{
		text:   text,
		root:   root,
		fields: currentParser.fields,
	}
	return
}

func (filter Filter) String() (text string) {
	text = filter.text
	return
}

// isUsed tells if the filter reads the field
func (filter Filter) Uses(field Field) (isUsed bool) {
	isUsed = filter.fields[field]
	return
}

// isUsed tells if the filter reads a field of the source, a filter with a ClientHello field can decide a flow only after its first client bytes
func (filter Filter) UsesSource(source SourceType) (isUsed bool) {
	for field := range filter.fields {
		if fields[field].Source == source {
			isUsed = true
			return
		}
	}

	return
}

func (currentParser *parser) peek() (next token) {
	next = currentParser.tokens[currentParser.position]
	return
}

func (currentParser *parser) next() (current token) {
	current = currentParser.tokens[currentParser.position]

	if current.kind != endTokenKind {
		currentParser.position++
	}

	return
}

// a punctuation or a keyword, keywords are case sensitive like in Wireshark
func isKeyword(current token, punctuation string, word string) (isMatch bool) {
	isMatch = ((current.kind == punctuationTokenKind) && (current.text == punctuation)) || ((current.kind == wordTokenKind) && (current.text == word))
	return
}

func (currentParser *parser) unexpected(current token, expected string) (err error) {
	if current.kind == endTokenKind {
		err = newPositionError(currentParser.text, current.offset, 0, fmt.Errorf("%w: unexpected end of filter, expected %s", ErrSyntax, expected))
		return
	}

	err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: unexpected %q, expected %s", ErrSyntax, currentParser.text[current.offset:current.offset+current.length], expected))
	return
}

// or_expr = and_expr { ( "||" | "or" ) and_expr }
func (currentParser *parser) parseOr() (result *node, err error) {
	result, err = currentParser.parseAnd()

	if err != nil {
		return
	}

	for isKeyword(currentParser.peek(), "||", "or") {
		currentParser.next()
		right, rightErr := currentParser.parseAnd()

		if err = rightErr; err != nil {
			return
		}

		result = join(orNodeKind, result, right)
	}

	return
}

// and_expr = unary { ( "&&" | "and" ) unary }, and binds tighter than or as in Wireshark
func (currentParser *parser) parseAnd() (result *node, err error) {
	result, err = currentParser.parseUnary()

	if err != nil {
		return
	}

	for isKeyword(currentParser.peek(), "&&", "and") {
		currentParser.next()
		right, rightErr := currentParser.parseUnary()

		if err = rightErr; err != nil {
			return
		}

		result = join(andNodeKind, result, right)
	}

	return
}

// a chain of the same operator is one node with every operand as a child, the push-down reads an && chain from it
func join(kind nodeKind, left *node, right *node) (joined *node) {
	if left.kind == kind {
		left.children = append(left.children, right)
		joined = left
		return
	}

	joined = &node{kind: kind, children: []*node{left, right}}
	return
}

// unary = [ "!" | "not" ] primary, repeated negations are allowed
func (currentParser *parser) parseUnary() (result *node, err error) {
	if !isKeyword(currentParser.peek(), "!", "not") {
		result, err = currentParser.parsePrimary()
		return
	}

	currentParser.next()
	child, childErr := currentParser.parseUnary()

	if err = childErr; err != nil {
		return
	}

	result = &node{kind: notNodeKind, children: []*node{child}}
	return
}

// primary = "(" expression ")" | comparison | field
func (currentParser *parser) parsePrimary() (result *node, err error) {
	current := currentParser.next()

	if isKeyword(current, "(", "") {
		result, err = currentParser.parseOr()

		if err != nil {
			return
		}

		if closing := currentParser.next(); !isKeyword(closing, ")", "") {
			err = currentParser.unexpected(closing, "\")\" closing the \"(\" at column "+strconv.Itoa(newPositionError(currentParser.text, current.offset, 1, nil).Column))
			return
		}

		return
	}

	if current.kind != wordTokenKind {
		err = currentParser.unexpected(current, "a field, \"(\" or \"!\"")
		return
	}

	info, found := LookupField(current.text)

	if !found {
		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %q is not a field of the filter", ErrUnknownField, current.text))
		return
	}

	currentParser.fields[info.Name] = true
	result, err = currentParser.parseComparison(current, info)
	return
}

// comparison = field operator value | field [ "not" ] "in" "{" value { [ "," ] value } "}", a field alone is a test for the field
func (currentParser *parser) parseComparison(fieldToken token, info FieldInfo) (result *node, err error) {
	next := currentParser.peek()
	isNegatedSet := isKeyword(next, "", "not") && isKeyword(currentParser.tokens[min(currentParser.position+1, len(currentParser.tokens)-1)], "", "in")

	if isKeyword(next, "", "in") || isNegatedSet {
		if isNegatedSet {
			currentParser.next()
		}

		currentParser.next()
		result, err = currentParser.parseSet(fieldToken, info)

		if err == nil {
			result.isNegated = isNegatedSet
		}

		return
	}

	comparisonOperator, isOperator := operatorOf(next)

	if !isOperator {
		result = &node{kind: existsNodeKind, field: info}
		return
	}

	currentParser.next()

	if info.Type == ProtocolFieldType {
		err = newPositionError(currentParser.text, next.offset, next.length, fmt.Errorf("%w: %s is a protocol, it is only tested on its own, as in \"%s\"", ErrOperator, info.Name, info.Name))
		return
	}

	err = checkOperator(currentParser.text, next, info, comparisonOperator)

	if err != nil {
		return
	}

	valueToken := currentParser.next()
	literal, valueErr := currentParser.parseValue(valueToken, info, comparisonOperator, false)

	if err = valueErr; err != nil {
		return
	}

	result = &node{kind: compareNodeKind, field: info, operator: comparisonOperator, values: []value{literal}}

	if comparisonOperator != matchesOperator {
		return
	}

	// Wireshark's matches ignores case unless the pattern says (?-i), RE2 takes the same flag
	regex, compileErr := regexp.Compile("(?i)" + literal.text)

	if compileErr != nil {
		err = newPositionError(currentParser.text, valueToken.offset, valueToken.length, fmt.Errorf("%w: %w", ErrRegex, compileErr))
		return
	}

	result.regex = regex
	return
}

func operatorOf(current token) (comparisonOperator operator, isOperator bool) {
	if (current.kind != punctuationTokenKind) && (current.kind != wordTokenKind) {
		return
	}

	comparisonOperator, isOperator = operatorSpellings[current.text]
	return
}

// contains and matches are for strings, the order of an address only for a single address (checked with the value)
func checkOperator(text string, operatorToken token, info FieldInfo, comparisonOperator operator) (err error) {
	switch comparisonOperator {
	case
		containsOperator,
		matchesOperator:
		if info.Type != StringFieldType {
			err = newPositionError(text, operatorToken.offset, operatorToken.length, fmt.Errorf("%w: %s is for strings, %s is a %s field", ErrOperator, comparisonOperator, info.Name, info.Type))
			return
		}
	default:
	}

	return
}

// the values of a set, separated by commas as in Wireshark or by spaces; numbers may be ranges a..b
func (currentParser *parser) parseSet(fieldToken token, info FieldInfo) (result *node, err error) {
	if info.Type == ProtocolFieldType {
		err = newPositionError(currentParser.text, fieldToken.offset, fieldToken.length, fmt.Errorf("%w: %s is a protocol, it is only tested on its own", ErrOperator, info.Name))
		return
	}

	if opening := currentParser.next(); !isKeyword(opening, "{", "") {
		err = currentParser.unexpected(opening, "\"{\"")
		return
	}

	result = &node{kind: setNodeKind, field: info}

	for {
		current := currentParser.next()

		if isKeyword(current, "}", "") && (len(result.values) > 0) {
			return
		}

		literal, valueErr := currentParser.parseValue(current, info, equalOperator, true)

		if err = valueErr; err != nil {
			return
		}

		result.values = append(result.values, literal)

		if isKeyword(currentParser.peek(), ",", "") {
			currentParser.next()

			if isKeyword(currentParser.peek(), "}", "") {
				err = currentParser.unexpected(currentParser.peek(), "a value after \",\"")
				return
			}
		}
	}
}

// read the literal for a field of info, the type is checked here: a number for a number field, a quoted string for a string field, an address or a prefix of the right family for an address field
func (currentParser *parser) parseValue(current token, info FieldInfo, comparisonOperator operator, isInSet bool) (literal value, err error) {
	if (current.kind != wordTokenKind) && (current.kind != stringTokenKind) {
		err = currentParser.unexpected(current, "a value")
		return
	}

	typeError := func(message string) (positionErr error) {
		positionErr = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s is a %s field, %s", ErrType, info.Name, info.Type, message))
		return
	}

	switch info.Type {
	case NumberFieldType:
		if current.kind == stringTokenKind {
			err = typeError("a number is written without quotes")
			return
		}

		literal, err = currentParser.parseNumber(current, info, isInSet)
	case StringFieldType:
		if current.kind != stringTokenKind {
			err = typeError("its value is a string in double quotes")
			return
		}

		literal = value{text: current.text}

		// the kernel's name of a process has at most 15 bytes, a longer one is never equal to it
		if (info.Name == CommField) && (comparisonOperator != containsOperator) && (comparisonOperator != matchesOperator) && (len(current.text) > maxCommLength) {
			err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %q has %d", ErrCommLength, current.text, len(current.text)))
			return
		}
	case
		IPv4FieldType,
		IPv6FieldType:
		if current.kind == stringTokenKind {
			err = typeError("an address or a prefix is written without quotes")
			return
		}

		literal, err = currentParser.parseAddress(current, info, comparisonOperator)
	default:
		err = typeError("it has no value to compare")
	}

	return
}

// decimal, 0x hex, 0o or leading-zero octal and 0b binary like Wireshark, at most the field's largest value
func (currentParser *parser) parseNumber(current token, info FieldInfo, isInSet bool) (literal value, err error) {
	lowText, highText, isRange := strings.Cut(current.text, "..")

	if isRange && !isInSet {
		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: a range is only allowed in a set, %s in {%s}", ErrSyntax, info.Name, current.text))
		return
	}

	low, lowErr := currentParser.parseUint(lowText, current, info)

	if err = lowErr; err != nil {
		return
	}

	high := low

	if isRange {
		high, err = currentParser.parseUint(highText, current, info)

		if err != nil {
			return
		}

		if high < low {
			err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: range %s ends before it starts", ErrSyntax, current.text))
			return
		}
	}

	literal = value{number: low, high: high}
	return
}

func (currentParser *parser) parseUint(text string, current token, info FieldInfo) (number uint64, err error) {
	// Go's base 0 takes underscores, Wireshark doesn't
	parsed, parseErr := strconv.ParseUint(text, 0, 64)

	if (parseErr != nil) || strings.Contains(text, "_") {
		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s is a number field, %q is not a number", ErrType, info.Name, text))
		return
	}

	if parsed > info.maximum {
		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s is at most %d, not %d", ErrRange, info.Name, info.maximum, parsed))
		return
	}

	number = parsed
	return
}

// an address is a prefix of its full length; a CIDR prefix only fits ==, !=, === and !== and sets, which test the address for being inside it
func (currentParser *parser) parseAddress(current token, info FieldInfo, comparisonOperator operator) (literal value, err error) {
	var prefix netip.Prefix
	var parseErr error
	isPrefix := strings.Contains(current.text, "/")

	if isPrefix {
		prefix, parseErr = netip.ParsePrefix(current.text)
	} else {
		address, addressErr := netip.ParseAddr(current.text)
		parseErr = addressErr

		if (addressErr == nil) && (address.Zone() == "") {
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
	}

	if (parseErr != nil) || !prefix.IsValid() {
		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s is an %s field, %q is not an address or a CIDR prefix", ErrType, info.Name, info.Type, current.text))
		return
	}

	isIPv4 := prefix.Addr().Is4()

	if (info.Type == IPv4FieldType) != isIPv4 {
		family := "IPv6"

		if isIPv4 {
			family = "IPv4"
		}

		err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s is an %s field, %s is an %s address", ErrType, info.Name, info.Type, current.text, family))
		return
	}

	switch comparisonOperator {
	case
		lessOperator,
		lessEqualOperator,
		greaterOperator,
		greaterEqualOperator:
		if isPrefix {
			err = newPositionError(currentParser.text, current.offset, current.length, fmt.Errorf("%w: %s orders single addresses, not a prefix", ErrOperator, comparisonOperator))
			return
		}
	default:
	}

	literal = value{prefix: prefix.Masked()}
	return
}
