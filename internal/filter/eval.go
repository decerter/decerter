// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"cmp"
	"net/netip"
	"strings"
	"syscall"
)

// the decision about a flow, unknown while it needs a field that is not known yet: the ClientHello of a flow that sent nothing
type Result string

const (
	TrueResult    Result = "true"
	FalseResult   Result = "false"
	UnknownResult Result = "unknown"
)

// whether the flow started with a ClientHello
type TLSState string

const (
	// the client sent nothing yet
	UnknownTLSState TLSState = "unknown"
	// the first client bytes are no ClientHello, or the server spoke first: the tls fields are not there
	AbsentTLSState TLSState = "absent"
	// the first client bytes are a TLS ClientHello, or the first datagram a DTLS one; the fields it had are filled
	PresentTLSState TLSState = "present"
)

// everything a filter can ask about one flow
// Source is the local end of the client's socket, Destination the original destination; an IPv4 address may be IPv4-mapped
// IPProtocol is IPPROTO_TCP or IPPROTO_UDP; Cmdline and Exe are empty when /proc was not read or the process is gone
// TLSVersion is the highest version the ClientHello offers (supported_versions, or the legacy version without it), 0 when it could not be read
type Values struct {
	PID         uint32
	UID         uint32
	GID         uint32
	Comm        string
	Cmdline     string
	Exe         string
	IPProtocol  uint8
	Source      netip.AddrPort
	Destination netip.AddrPort
	TLS         TLSState
	TLSVersion  uint16
	ServerName  string
	Protocols   []string
	HTTP        *HTTPValues
}

// what the HTTP layer read: every value a field had, in the order they came; nil in Values is a flow or message without HTTP
// Codes are the status codes of the responses, a request has none
type HTTPValues struct {
	Methods    []string
	URIs       []string
	Hosts      []string
	Codes      []uint16
	UserAgents []string
}

// the values with the ClientHello fields: isTLS is false when the first client bytes were no ClientHello or the server spoke first, a ClientHello that could not be read is TLS without its fields
func (values Values) WithClientHello(isTLS bool, version uint16, serverName string, protocols []string) (result Values) {
	result = values
	result.TLS = AbsentTLSState

	if !isTLS {
		return
	}

	result.TLS = PresentTLSState
	result.TLSVersion = version
	result.ServerName = serverName
	result.Protocols = protocols
	return
}

// whether a flow has a field
type presence string

const (
	presentPresence presence = "present"
	absentPresence  presence = "absent"
	unknownPresence presence = "unknown"
)

// decide the flow, comparisons on a field the flow does not have are false like in Wireshark (also != and not in), a field that is not known yet makes them unknown
// and, or and not follow three-valued logic: false && unknown is false, true || unknown is true
func (filter Filter) Evaluate(values Values) (result Result) {
	if filter.root == nil {
		result = TrueResult
		return
	}

	result = evaluate(filter.root, values)
	return
}

func evaluate(current *node, values Values) (result Result) {
	switch current.kind {
	case andNodeKind:
		result = TrueResult

		for _, child := range current.children {
			switch evaluate(child, values) {
			case FalseResult:
				result = FalseResult
				return
			case UnknownResult:
				result = UnknownResult
			default:
			}
		}
	case orNodeKind:
		result = FalseResult

		for _, child := range current.children {
			switch evaluate(child, values) {
			case TrueResult:
				result = TrueResult
				return
			case UnknownResult:
				result = UnknownResult
			default:
			}
		}
	case notNodeKind:
		switch evaluate(current.children[0], values) {
		case TrueResult:
			result = FalseResult
		case FalseResult:
			result = TrueResult
		default:
			result = UnknownResult
		}
	default:
		fieldValues, fieldPresence := valuesOf(current.field.Name, values)

		switch fieldPresence {
		case unknownPresence:
			result = UnknownResult
		case absentPresence:
			result = FalseResult
		default:
			result = toResult(test(current, fieldValues))
		}
	}

	return
}

func toResult(isTrue bool) (result Result) {
	result = FalseResult

	if isTrue {
		result = TrueResult
	}

	return
}

// the field is there, isTrue is the comparison over its values: == and the order operators are true for any value, === for every value, != when every value differs, !== when any does
func test(current *node, fieldValues []value) (isTrue bool) {
	switch current.kind {
	case existsNodeKind:
		isTrue = true
	case setNodeKind:
		isIn := false

		for _, fieldValue := range fieldValues {
			for _, element := range current.values {
				if inElement(current.field.Type, fieldValue, element) {
					isIn = true
				}
			}
		}

		isTrue = isIn != current.isNegated
	default:
		literal := current.values[0]

		switch current.operator {
		case allEqualOperator:
			isTrue = true

			for _, fieldValue := range fieldValues {
				isTrue = isTrue && compare(current, fieldValue, literal)
			}
		case notEqualOperator:
			isTrue = true

			for _, fieldValue := range fieldValues {
				isTrue = isTrue && !compare(current, fieldValue, literal)
			}
		case anyNotEqualOperator:
			for _, fieldValue := range fieldValues {
				isTrue = isTrue || !compare(current, fieldValue, literal)
			}
		default:
			for _, fieldValue := range fieldValues {
				isTrue = isTrue || compare(current, fieldValue, literal)
			}
		}
	}

	return
}

// one value of the field against the literal; the equality operators all ask for equality here, the caller turns it around
// an address is equal to a prefix it is inside of
func compare(current *node, fieldValue value, literal value) (isTrue bool) {
	switch current.operator {
	case containsOperator:
		isTrue = strings.Contains(fieldValue.text, literal.text)
		return
	case matchesOperator:
		isTrue = current.regex.MatchString(fieldValue.text)
		return
	default:
	}

	order := 0

	switch current.field.Type {
	case NumberFieldType:
		order = cmp.Compare(fieldValue.number, literal.number)
	case StringFieldType:
		order = strings.Compare(fieldValue.text, literal.text)
	default:
		if current.operator.isEquality() {
			isTrue = literal.prefix.Contains(fieldValue.prefix.Addr())
			return
		}

		order = fieldValue.prefix.Addr().Compare(literal.prefix.Addr())
	}

	switch current.operator {
	case lessOperator:
		isTrue = order < 0
	case lessEqualOperator:
		isTrue = order <= 0
	case greaterOperator:
		isTrue = order > 0
	case greaterEqualOperator:
		isTrue = order >= 0
	default:
		isTrue = order == 0
	}

	return
}

func (comparisonOperator operator) isEquality() (isEquality bool) {
	switch comparisonOperator {
	case
		equalOperator,
		allEqualOperator,
		notEqualOperator,
		anyNotEqualOperator:
		isEquality = true
	default:
	}

	return
}

// a number in a range, an address in a prefix, an equal string
func inElement(fieldType FieldType, fieldValue value, element value) (isIn bool) {
	switch fieldType {
	case NumberFieldType:
		isIn = (fieldValue.number >= element.number) && (fieldValue.number <= element.high)
	case StringFieldType:
		isIn = fieldValue.text == element.text
	default:
		isIn = element.prefix.Contains(fieldValue.prefix.Addr())
	}

	return
}

// the values of a field in the flow, IPv4 is told from IPv6 by the destination: an IPv4-mapped one is IPv4
func valuesOf(field Field, values Values) (fieldValues []value, fieldPresence presence) {
	fieldPresence = presentPresence
	destination := values.Destination.Addr().Unmap()
	source := values.Source.Addr().Unmap()
	isIPv4 := destination.Is4()
	isIPv6 := destination.Is6()
	isTCP := values.IPProtocol == syscall.IPPROTO_TCP
	isUDP := values.IPProtocol == syscall.IPPROTO_UDP

	switch field {
	case PIDField:
		fieldValues = []value{numberValue(uint64(values.PID))}
	case UIDField:
		fieldValues = []value{numberValue(uint64(values.UID))}
	case GIDField:
		fieldValues = []value{numberValue(uint64(values.GID))}
	case CommField:
		fieldValues = []value{{text: values.Comm}}
	case CmdlineField:
		fieldValues, fieldPresence = textValues(values.Cmdline)
	case ExeField:
		fieldValues, fieldPresence = textValues(values.Exe)
	case IPField:
		fieldPresence = present(isIPv4)
	case IPSourceField:
		fieldValues, fieldPresence = addressValues(isIPv4 && source.Is4(), source)
	case IPDestField:
		fieldValues, fieldPresence = addressValues(isIPv4, destination)
	case IPAddrField:
		fieldValues, fieldPresence = addressValues(isIPv4, destination)

		if (fieldPresence == presentPresence) && source.Is4() {
			fieldValues = append(fieldValues, addressValue(source))
		}
	case IPv6Field:
		fieldPresence = present(isIPv6)
	case IPv6SourceField:
		fieldValues, fieldPresence = addressValues(isIPv6 && source.Is6(), source)
	case IPv6DestField:
		fieldValues, fieldPresence = addressValues(isIPv6, destination)
	case IPv6AddrField:
		fieldValues, fieldPresence = addressValues(isIPv6, destination)

		if (fieldPresence == presentPresence) && source.Is6() {
			fieldValues = append(fieldValues, addressValue(source))
		}
	case TCPField:
		fieldPresence = present(isTCP)
	case TCPSrcPortField:
		fieldValues, fieldPresence = portValues(isTCP, values.Source.Port())
	case TCPDstPortField:
		fieldValues, fieldPresence = portValues(isTCP, values.Destination.Port())
	case TCPPortField:
		fieldValues, fieldPresence = portValues(isTCP, values.Source.Port(), values.Destination.Port())
	case UDPField:
		fieldPresence = present(isUDP)
	case UDPSrcPortField:
		fieldValues, fieldPresence = portValues(isUDP, values.Source.Port())
	case UDPDstPortField:
		fieldValues, fieldPresence = portValues(isUDP, values.Destination.Port())
	case UDPPortField:
		fieldValues, fieldPresence = portValues(isUDP, values.Source.Port(), values.Destination.Port())
	case
		HTTPField,
		HTTPMethodField,
		HTTPURIField,
		HTTPHostField,
		HTTPCodeField,
		HTTPAgentField:
		fieldValues, fieldPresence = httpValues(field, values.HTTP)
	default:
		fieldValues, fieldPresence = tlsValues(field, values)
	}

	return
}

// the HTTP fields: absent without HTTP, a field without a value is absent too
func httpValues(field Field, http *HTTPValues) (fieldValues []value, fieldPresence presence) {
	fieldPresence = present(http != nil)

	if http == nil {
		return
	}

	texts := []string(nil)

	switch field {
	case HTTPField:
		return
	case HTTPMethodField:
		texts = http.Methods
	case HTTPURIField:
		texts = http.URIs
	case HTTPHostField:
		texts = http.Hosts
	case HTTPAgentField:
		texts = http.UserAgents
	case HTTPCodeField:
		for _, code := range http.Codes {
			fieldValues = append(fieldValues, numberValue(uint64(code)))
		}
	default:
	}

	for _, text := range texts {
		fieldValues = append(fieldValues, value{text: text})
	}

	fieldPresence = present(len(fieldValues) > 0)
	return
}

// the ClientHello fields: unknown until the first client bytes, absent when they are no ClientHello or did not have the field
func tlsValues(field Field, values Values) (fieldValues []value, fieldPresence presence) {
	switch values.TLS {
	case PresentTLSState:
	case AbsentTLSState:
		fieldPresence = absentPresence
		return
	default:
		fieldPresence = unknownPresence
		return
	}

	fieldPresence = presentPresence

	switch field {
	case TLSVersionField:
		fieldPresence = present(values.TLSVersion != 0)
		fieldValues = []value{numberValue(uint64(values.TLSVersion))}
	case TLSServerField:
		fieldValues, fieldPresence = textValues(values.ServerName)
	case TLSProtocolField:
		fieldPresence = present(len(values.Protocols) > 0)

		for _, protocol := range values.Protocols {
			fieldValues = append(fieldValues, value{text: protocol})
		}
	default:
	}

	return
}

func present(isPresent bool) (fieldPresence presence) {
	fieldPresence = absentPresence

	if isPresent {
		fieldPresence = presentPresence
	}

	return
}

func numberValue(number uint64) (fieldValue value) {
	fieldValue = value{number: number, high: number}
	return
}

func textValues(text string) (fieldValues []value, fieldPresence presence) {
	fieldPresence = present(text != "")
	fieldValues = []value{{text: text}}
	return
}

func addressValue(address netip.Addr) (fieldValue value) {
	fieldValue = value{prefix: netip.PrefixFrom(address, address.BitLen())}
	return
}

func addressValues(isPresent bool, address netip.Addr) (fieldValues []value, fieldPresence presence) {
	fieldPresence = present(isPresent)

	if isPresent {
		fieldValues = []value{addressValue(address)}
	}

	return
}

func portValues(isPresent bool, ports ...uint16) (fieldValues []value, fieldPresence presence) {
	fieldPresence = present(isPresent)

	if !isPresent {
		return
	}

	for _, port := range ports {
		fieldValues = append(fieldValues, numberValue(uint64(port)))
	}

	return
}
