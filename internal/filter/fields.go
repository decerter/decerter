// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"cmp"
	"math"
	"slices"
)

// the name of a field as it is written in a filter
type Field string

const (
	PIDField         Field = "proc.pid"
	UIDField         Field = "proc.uid"
	GIDField         Field = "proc.gid"
	CommField        Field = "proc.comm"
	CmdlineField     Field = "proc.cmdline"
	ExeField         Field = "proc.exe"
	IPField          Field = "ip"
	IPSourceField    Field = "ip.src"
	IPDestField      Field = "ip.dst"
	IPAddrField      Field = "ip.addr"
	IPv6Field        Field = "ipv6"
	IPv6SourceField  Field = "ipv6.src"
	IPv6DestField    Field = "ipv6.dst"
	IPv6AddrField    Field = "ipv6.addr"
	TCPField         Field = "tcp"
	TCPSrcPortField  Field = "tcp.srcport"
	TCPDstPortField  Field = "tcp.dstport"
	TCPPortField     Field = "tcp.port"
	UDPField         Field = "udp"
	UDPSrcPortField  Field = "udp.srcport"
	UDPDstPortField  Field = "udp.dstport"
	UDPPortField     Field = "udp.port"
	TLSField         Field = "tls"
	TLSVersionField  Field = "tls.version"
	TLSServerField   Field = "tls.sni"
	TLSProtocolField Field = "tls.alpn"
	HTTPField        Field = "http"
	HTTPMethodField  Field = "http.request.method"
	HTTPURIField     Field = "http.request.uri"
	HTTPHostField    Field = "http.host"
	HTTPCodeField    Field = "http.response.code"
	HTTPAgentField   Field = "http.user_agent"
)

// what the values of a field are
type FieldType string

const (
	NumberFieldType   FieldType = "number"
	StringFieldType   FieldType = "string"
	IPv4FieldType     FieldType = "ipv4"
	IPv6FieldType     FieldType = "ipv6"
	ProtocolFieldType FieldType = "protocol"
)

// where the value of a field comes from, which says when it is known
type SourceType string

const (
	// flow_map, the kernel's record of the socket, and the client endpoint: known when the proxy accepts or the first packet is read
	FlowSourceType SourceType = "flow"
	// /proc/<tgid> of the process, read once per flow; empty when the process is gone
	ProcSourceType SourceType = "proc"
	// the TLS or DTLS ClientHello the client sends first, known only after it
	ClientHelloSourceType SourceType = "clienthello"
	// the HTTP/1 heads the HTTP layer read: a message of layer http has the fields of its request (and a response its code), a flow of the history every value of its exchanges
	// a flow is in scope or not before any of them is known, so the scope and capture filters refuse them
	HTTPSourceType SourceType = "http"
)

// IsMulti fields have more than one value per flow (ip.addr is ip.src and ip.dst), == is true when any value matches, != when every value differs
// Pushdown names the kernel map an == or in of the field becomes, empty when Go decides it
type FieldInfo struct {
	Name     Field
	Type     FieldType
	IsMulti  bool
	Source   SourceType
	Pushdown string
	maximum  uint64
}

const (
	// TASK_COMM_LEN is 16 with the NUL, the kernel cuts a longer process name
	maxCommLength int = 15
)

var (
	// the fields a filter may use, a subset of Wireshark's with the same meaning plus the process and ClientHello fields of decerter
	fields = map[Field]FieldInfo{
		PIDField:         {Name: PIDField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "tgid_map", maximum: math.MaxUint32},
		UIDField:         {Name: UIDField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "uid_map", maximum: math.MaxUint32},
		GIDField:         {Name: GIDField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: math.MaxUint32},
		CommField:        {Name: CommField, Type: StringFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "comm_map", maximum: 0},
		CmdlineField:     {Name: CmdlineField, Type: StringFieldType, IsMulti: false, Source: ProcSourceType, Pushdown: "", maximum: 0},
		ExeField:         {Name: ExeField, Type: StringFieldType, IsMulti: false, Source: ProcSourceType, Pushdown: "", maximum: 0},
		IPField:          {Name: IPField, Type: ProtocolFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		IPSourceField:    {Name: IPSourceField, Type: IPv4FieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		IPDestField:      {Name: IPDestField, Type: IPv4FieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "cidr_map", maximum: 0},
		IPAddrField:      {Name: IPAddrField, Type: IPv4FieldType, IsMulti: true, Source: FlowSourceType, Pushdown: "", maximum: 0},
		IPv6Field:        {Name: IPv6Field, Type: ProtocolFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		IPv6SourceField:  {Name: IPv6SourceField, Type: IPv6FieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		IPv6DestField:    {Name: IPv6DestField, Type: IPv6FieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "cidr_map", maximum: 0},
		IPv6AddrField:    {Name: IPv6AddrField, Type: IPv6FieldType, IsMulti: true, Source: FlowSourceType, Pushdown: "", maximum: 0},
		TCPField:         {Name: TCPField, Type: ProtocolFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		TCPSrcPortField:  {Name: TCPSrcPortField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: math.MaxUint16},
		TCPDstPortField:  {Name: TCPDstPortField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "port_map", maximum: math.MaxUint16},
		TCPPortField:     {Name: TCPPortField, Type: NumberFieldType, IsMulti: true, Source: FlowSourceType, Pushdown: "", maximum: math.MaxUint16},
		UDPField:         {Name: UDPField, Type: ProtocolFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: 0},
		UDPSrcPortField:  {Name: UDPSrcPortField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "", maximum: math.MaxUint16},
		UDPDstPortField:  {Name: UDPDstPortField, Type: NumberFieldType, IsMulti: false, Source: FlowSourceType, Pushdown: "port_map", maximum: math.MaxUint16},
		UDPPortField:     {Name: UDPPortField, Type: NumberFieldType, IsMulti: true, Source: FlowSourceType, Pushdown: "", maximum: math.MaxUint16},
		TLSField:         {Name: TLSField, Type: ProtocolFieldType, IsMulti: false, Source: ClientHelloSourceType, Pushdown: "", maximum: 0},
		TLSVersionField:  {Name: TLSVersionField, Type: NumberFieldType, IsMulti: false, Source: ClientHelloSourceType, Pushdown: "", maximum: math.MaxUint16},
		TLSServerField:   {Name: TLSServerField, Type: StringFieldType, IsMulti: false, Source: ClientHelloSourceType, Pushdown: "", maximum: 0},
		TLSProtocolField: {Name: TLSProtocolField, Type: StringFieldType, IsMulti: true, Source: ClientHelloSourceType, Pushdown: "", maximum: 0},
		HTTPField:        {Name: HTTPField, Type: ProtocolFieldType, IsMulti: false, Source: HTTPSourceType, Pushdown: "", maximum: 0},
		HTTPMethodField:  {Name: HTTPMethodField, Type: StringFieldType, IsMulti: true, Source: HTTPSourceType, Pushdown: "", maximum: 0},
		HTTPURIField:     {Name: HTTPURIField, Type: StringFieldType, IsMulti: true, Source: HTTPSourceType, Pushdown: "", maximum: 0},
		HTTPHostField:    {Name: HTTPHostField, Type: StringFieldType, IsMulti: true, Source: HTTPSourceType, Pushdown: "", maximum: 0},
		HTTPCodeField:    {Name: HTTPCodeField, Type: NumberFieldType, IsMulti: true, Source: HTTPSourceType, Pushdown: "", maximum: 999},
		HTTPAgentField:   {Name: HTTPAgentField, Type: StringFieldType, IsMulti: true, Source: HTTPSourceType, Pushdown: "", maximum: 0},
	}
)

// every field a filter may use, sorted by name
func Fields() (infos []FieldInfo) {
	for _, info := range fields {
		infos = append(infos, info)
	}

	slices.SortFunc(infos, func(first FieldInfo, second FieldInfo) int {
		return cmp.Compare(first.Name, second.Name)
	})
	return
}

// found is false for a name that is not a field of the filter language
func LookupField(name string) (info FieldInfo, found bool) {
	info, found = fields[Field(name)]
	return
}
