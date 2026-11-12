// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package filter_test

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/decerter/decerter/internal/filter"
)

var (
	// curl of uid 1001 to 10.1.2.3:443 over TCP, a TLS 1.3 ClientHello for example.com with h2 and http/1.1
	curlValues = filter.Values{
		PID:         4242,
		UID:         1001,
		GID:         1001,
		Comm:        "curl",
		Cmdline:     "curl -s https://example.com/",
		Exe:         "/usr/bin/curl",
		IPProtocol:  syscall.IPPROTO_TCP,
		Source:      netip.MustParseAddrPort("[::ffff:192.168.1.10]:50000"),
		Destination: netip.MustParseAddrPort("10.1.2.3:443"),
		TLS:         filter.PresentTLSState,
		TLSVersion:  0x0304,
		ServerName:  "example.com",
		Protocols:   []string{"h2", "http/1.1"},
	}
	// dig of uid 1002 over IPv6 UDP to port 53, no ClientHello
	digValues = filter.Values{
		PID:         777,
		UID:         1002,
		GID:         1002,
		Comm:        "dig",
		Cmdline:     "",
		Exe:         "",
		IPProtocol:  syscall.IPPROTO_UDP,
		Source:      netip.MustParseAddrPort("[2001:db8::10]:40000"),
		Destination: netip.MustParseAddrPort("[2001:db8::53]:53"),
		TLS:         filter.AbsentTLSState,
		TLSVersion:  0,
		ServerName:  "",
		Protocols:   nil,
	}
	// wget of uid 1001 to 127.0.0.1:8080 whose first bytes did not come yet
	wgetValues = filter.Values{
		PID:         5000,
		UID:         1001,
		GID:         1001,
		Comm:        "wget",
		Cmdline:     "wget -qO- http://127.0.0.1:8080/",
		Exe:         "/usr/bin/wget",
		IPProtocol:  syscall.IPPROTO_TCP,
		Source:      netip.MustParseAddrPort("127.0.0.1:41000"),
		Destination: netip.MustParseAddrPort("127.0.0.1:8080"),
		TLS:         filter.UnknownTLSState,
		TLSVersion:  0,
		ServerName:  "",
		Protocols:   nil,
	}
)

// Test if filter.Parse returns with the expected output.
func TestParsePositive(state *testing.T) {
	positiveCases := []string{
		`proc.comm == "curl"`,
		`proc.comm eq "curl" and proc.uid == 1001`,
		`ip.addr == 10.0.0.0/8 && tcp.dstport in {443 8443} && proc.uid == 1000 && proc.cmdline matches "^curl"`,
		`tcp.port in {80, 443, 8000..8080}`,
		`tcp.port not in {80, 443}`,
		`!(udp || ipv6) || not tls`,
		`tls.sni matches r"\.example\.(com|org)$"`,
		`tls.sni == "a\x62\143d\"\\"`,
		`tls.version >= 0x0303 && tls.alpn === "h2" && tls.alpn !== "x" && tls.alpn any_ne "x" && ip.dst all_ne 1.1.1.1`,
		`ipv6.dst == ::1 || ipv6.addr == fe80::/10 || ip.src < 10.0.0.1 || proc.comm ~ "^cu"`,
	}

	for _, positive := range positiveCases {
		_, err := filter.Parse(positive)

		if err != nil {
			state.Errorf("Test of filter.Parse function failed, filter: %s, error: %v", positive, err)
			return
		}
	}
}

// Test if filter.Parse returns with the expected errors.
func TestParseNegative(state *testing.T) {
	negativeCases := []struct {
		Filter string
		Column int
		Err    error
	}{
		{Filter: ``, Column: 1, Err: filter.ErrSyntax},
		{Filter: `proc.comm = "curl"`, Column: 11, Err: filter.ErrSyntax},
		{Filter: `proc.cmd == "curl"`, Column: 1, Err: filter.ErrUnknownField},
		{Filter: `proc.uid == 1001 && foo.bar`, Column: 21, Err: filter.ErrUnknownField},
		{Filter: `proc.uid == "1001"`, Column: 13, Err: filter.ErrType},
		{Filter: `proc.comm == curl`, Column: 14, Err: filter.ErrType},
		{Filter: `ip.dst == ::1`, Column: 11, Err: filter.ErrType},
		{Filter: `ipv6.dst == 10.0.0.1`, Column: 13, Err: filter.ErrType},
		{Filter: `ip.dst == 10.0.0.0/33`, Column: 11, Err: filter.ErrType},
		{Filter: `ip.dst < 10.0.0.0/8`, Column: 10, Err: filter.ErrOperator},
		{Filter: `tcp.port contains "80"`, Column: 10, Err: filter.ErrOperator},
		{Filter: `tcp == 1`, Column: 5, Err: filter.ErrOperator},
		{Filter: `ip.dst ~ "x"`, Column: 8, Err: filter.ErrOperator},
		{Filter: `tcp.port == 65536`, Column: 13, Err: filter.ErrRange},
		{Filter: `tcp.port == 80..90`, Column: 13, Err: filter.ErrSyntax},
		{Filter: `tcp.port in {}`, Column: 14, Err: filter.ErrSyntax},
		{Filter: `tcp.port in {80,}`, Column: 17, Err: filter.ErrSyntax},
		{Filter: `proc.comm == "a-very-long-name-1"`, Column: 14, Err: filter.ErrCommLength},
		{Filter: `proc.comm in {"curl" "a-very-long-name-1"}`, Column: 22, Err: filter.ErrCommLength},
		{Filter: `tls.sni matches "\w+"`, Column: 18, Err: filter.ErrEscape},
		{Filter: `tls.sni matches "(x"`, Column: 17, Err: filter.ErrRegex},
		{Filter: `tls.sni == "example`, Column: 12, Err: filter.ErrSyntax},
		{Filter: `(tcp || udp`, Column: 12, Err: filter.ErrSyntax},
		{Filter: `tcp udp`, Column: 5, Err: filter.ErrSyntax},
		{Filter: `tcp ||`, Column: 7, Err: filter.ErrSyntax},
		{Filter: `tls.sni == "ü" && x`, Column: 19, Err: filter.ErrUnknownField},
		{Filter: `tls.sni == 'x'`, Column: 12, Err: filter.ErrSyntax},
	}

	for _, negative := range negativeCases {
		_, err := filter.Parse(negative.Filter)
		positionErr, ok := errors.AsType[*filter.PositionError](err)

		if !ok || !errors.Is(err, negative.Err) || (positionErr.Column != negative.Column) {
			state.Errorf("Test of filter.Parse function failed, filter: %s, error should be %v at column %d, error: %v", negative.Filter, negative.Err, negative.Column, err)
			return
		}
	}
}

// Test if filter.Evaluate returns with the expected output.
func TestEvaluatePositive(state *testing.T) {
	positiveCases := []struct {
		Filter string
		Values filter.Values
		Result filter.Result
	}{
		{Filter: `proc.comm == "curl"`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `proc.comm == "curl"`, Values: wgetValues, Result: filter.FalseResult},
		{Filter: `proc.uid == 1001 && proc.gid == 1001 && proc.pid == 4242`, Values: curlValues, Result: filter.TrueResult},
		// and binds tighter than or
		{Filter: `tcp || udp && ipv6`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `(tcp || udp) && ipv6`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `!tcp && !udp`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `not not tcp`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.addr == 10.0.0.0/8`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.addr == 192.168.1.10`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.dst == 192.168.1.10`, Values: curlValues, Result: filter.FalseResult},
		// != is true when every value differs, === when every value is equal
		{Filter: `ip.addr != 10.1.2.3`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `ip.addr != 9.9.9.9`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.addr !== 10.1.2.3`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.addr === 10.1.2.3`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `tcp.port == 50000 && tcp.srcport == 50000 && tcp.dstport > 442 && tcp.dstport <= 443`, Values: curlValues, Result: filter.TrueResult},
		// a field the flow does not have is false for every comparison, != and not in too, but its negation is true
		{Filter: `ip.addr != 9.9.9.9`, Values: digValues, Result: filter.FalseResult},
		{Filter: `!(ip.addr == 9.9.9.9)`, Values: digValues, Result: filter.TrueResult},
		{Filter: `tcp.port not in {1, 2}`, Values: digValues, Result: filter.FalseResult},
		{Filter: `udp.port not in {1, 2}`, Values: digValues, Result: filter.TrueResult},
		{Filter: `udp.dstport in {50..60}`, Values: digValues, Result: filter.TrueResult},
		{Filter: `ipv6.dst == 2001:db8::/32 && ipv6.src == 2001:db8::10 && ipv6.addr == 2001:db8::53`, Values: digValues, Result: filter.TrueResult},
		{Filter: `proc.cmdline contains "example"`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `proc.cmdline contains "EXAMPLE"`, Values: curlValues, Result: filter.FalseResult},
		// matches ignores case unless the pattern says (?-i)
		{Filter: `proc.cmdline matches "^CURL "`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `proc.cmdline matches "(?-i)^CURL "`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `proc.cmdline`, Values: digValues, Result: filter.FalseResult},
		{Filter: `proc.exe == "/usr/bin/curl"`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `proc.comm > "cu" && proc.comm < "cv"`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `tls && tls.sni == "example.com" && tls.alpn == "http/1.1" && tls.version == 0x0304`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `tls.alpn === "h2"`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `tls.sni == "example.com"`, Values: digValues, Result: filter.FalseResult},
		{Filter: `!tls`, Values: digValues, Result: filter.TrueResult},
		// a ClientHello field before the first bytes is unknown, unless the rest decides
		{Filter: `tls.sni == "example.com"`, Values: wgetValues, Result: filter.UnknownResult},
		{Filter: `!tls`, Values: wgetValues, Result: filter.UnknownResult},
		{Filter: `proc.comm == "curl" && tls`, Values: wgetValues, Result: filter.FalseResult},
		{Filter: `proc.comm == "wget" || tls`, Values: wgetValues, Result: filter.TrueResult},
		{Filter: `proc.comm == "wget" && tls`, Values: wgetValues, Result: filter.UnknownResult},
		{Filter: `proc.comm == "wget" && !tls`, Values: wgetValues.WithClientHello(false, 0, "", nil), Result: filter.TrueResult},
		{Filter: `tls && !tls.sni`, Values: wgetValues.WithClientHello(true, 0x0303, "", nil), Result: filter.TrueResult},
		{Filter: `tls.sni == "a\x62\143d\"\\"`, Values: curlValues.WithClientHello(true, 0x0304, "abcd\"\\", nil), Result: filter.TrueResult},
		{Filter: `tls.sni matches r"^a\.b$"`, Values: curlValues.WithClientHello(true, 0x0304, "a.b", nil), Result: filter.TrueResult},
		{Filter: `tls.sni matches r"^a\.b$"`, Values: curlValues.WithClientHello(true, 0x0304, "axb", nil), Result: filter.FalseResult},
	}

	for _, positive := range positiveCases {
		parsed, err := filter.Parse(positive.Filter)

		if err != nil {
			state.Errorf("Test of filter.Evaluate function failed, filter: %s, error: %s", positive.Filter, err.Error())
			return
		}

		result := parsed.Evaluate(positive.Values)

		if result != positive.Result {
			state.Errorf("Test of filter.Evaluate function failed, filter: %s, values: %s, result should be %v, result: %v", positive.Filter, positive.Values.Comm, positive.Result, result)
			return
		}
	}

	// the zero filter is no filter
	if (filter.Filter{}).Evaluate(digValues) != filter.TrueResult {
		state.Errorf("Test of filter.Evaluate function failed, the zero filter should be %v", filter.TrueResult)
		return
	}
}

// Test if filter.Pushdown returns with the expected output.
func TestPushdownPositive(state *testing.T) {
	err := testPushdownSelections()

	if err != nil {
		state.Errorf("Test of filter.Pushdown failed, error: %s", err.Error())
		return
	}

	err = testPushdownNeverNarrower()

	if err != nil {
		state.Errorf("Test of filter.Pushdown failed, error: %s", err.Error())
		return
	}
}

// Test if filter.Intersect returns with the expected output.
func TestIntersectPositive(state *testing.T) {
	flags := filter.Selection{
		HasProcess:       true,
		UIDs:             []uint32{1001},
		HasDestination:   true,
		DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	positiveCases := []struct {
		Filter   string
		Expected filter.Selection
		IsExact  bool
	}{
		{
			Filter:   `proc.comm == "curl"`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasComm: true, Comms: []string{"curl"}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  true,
		},
		{
			Filter:   `proc.uid in {1001 1002} && ip.dst == 127.0.0.0/8`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  true,
		},
		{
			Filter:   `proc.uid == 1002`,
			Expected: filter.Selection{HasProcess: true, UIDs: nil, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  true,
		},
		// a pid can't narrow a uid set in the maps, the flags stay and Go decides the pid
		{
			Filter:   `proc.pid == 4242`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  false,
		},
		{
			Filter:   `proc.uid == 1001 || proc.pid == 4242`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  true,
		},
		{
			Filter:   `ipv6.dst == ::ffff:127.0.0.0/104`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			IsExact:  false,
		},
		{
			Filter:   `ip.dst == 10.0.0.0/8`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasDestination: true, DestinationCIDRs: nil},
			IsExact:  true,
		},
	}

	for _, positive := range positiveCases {
		parsed, err := filter.Parse(positive.Filter)

		if err != nil {
			state.Errorf("Test of filter.Intersect function failed, filter: %s, error: %s", positive.Filter, err.Error())
			return
		}

		pushed, isPushExact := parsed.Pushdown()
		result, isExact := filter.Intersect(flags, pushed)

		if !reflect.DeepEqual(result, positive.Expected) || ((isExact && isPushExact) != positive.IsExact) {
			state.Errorf("Test of filter.Intersect function failed, filter: %s, result should be %+v exact %v, result: %+v exact %v", positive.Filter, positive.Expected, positive.IsExact, result, isExact && isPushExact)
			return
		}
	}

	// a part with an empty set passes nothing
	empty, _ := filter.Intersect(flags, filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	if !empty.IsEmpty() {
		state.Errorf("Test of filter.Intersect function failed, IsEmpty should be %v, selection: %+v", true, empty)
		return
	}
}

// Test if filter.Fields and filter.LookupField return with the expected output.
func TestFieldsPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Type     filter.FieldType
		IsMulti  bool
		Source   filter.SourceType
		Pushdown string
	}{
		{Name: "proc.uid", Type: filter.NumberFieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "uid_map"},
		{Name: "proc.pid", Type: filter.NumberFieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "tgid_map"},
		{Name: "proc.comm", Type: filter.StringFieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "comm_map"},
		{Name: "proc.cmdline", Type: filter.StringFieldType, IsMulti: false, Source: filter.ProcSourceType, Pushdown: ""},
		{Name: "ip.addr", Type: filter.IPv4FieldType, IsMulti: true, Source: filter.FlowSourceType, Pushdown: ""},
		{Name: "ip.dst", Type: filter.IPv4FieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "cidr_map"},
		{Name: "ipv6.dst", Type: filter.IPv6FieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "cidr_map"},
		{Name: "tcp.port", Type: filter.NumberFieldType, IsMulti: true, Source: filter.FlowSourceType, Pushdown: ""},
		{Name: "udp.dstport", Type: filter.NumberFieldType, IsMulti: false, Source: filter.FlowSourceType, Pushdown: "port_map"},
		{Name: "tls", Type: filter.ProtocolFieldType, IsMulti: false, Source: filter.ClientHelloSourceType, Pushdown: ""},
		{Name: "tls.alpn", Type: filter.StringFieldType, IsMulti: true, Source: filter.ClientHelloSourceType, Pushdown: ""},
	}

	for _, positive := range positiveCases {
		info, found := filter.LookupField(positive.Name)

		if !found || (info.Type != positive.Type) || (info.IsMulti != positive.IsMulti) || (info.Source != positive.Source) || (info.Pushdown != positive.Pushdown) {
			state.Errorf("Test of filter.LookupField function failed, field: %s, info: %+v, found: %v", positive.Name, info, found)
			return
		}
	}

	if _, found := filter.LookupField("frame.len"); found {
		state.Errorf("Test of filter.LookupField function failed, frame.len should not be found")
		return
	}

	infos := filter.Fields()

	isSorted := slices.IsSortedFunc(infos, func(first filter.FieldInfo, second filter.FieldInfo) int {
		return cmp.Compare(first.Name, second.Name)
	})

	if !isSorted || (len(infos) != 26) {
		state.Errorf("Test of filter.Fields function failed, fields: %d", len(infos))
		return
	}

	parsed, err := filter.Parse(`proc.uid == 1001 && (proc.exe contains "curl" || tls.sni == "x")`)

	if (err != nil) || !parsed.Uses(filter.ExeField) || parsed.Uses(filter.CmdlineField) || !parsed.UsesSource(filter.ClientHelloSourceType) || !parsed.UsesSource(filter.ProcSourceType) {
		state.Errorf("Test of filter.Uses function failed, error: %v", err)
		return
	}
}

func testPushdownSelections() (err error) {
	positiveCases := []struct {
		Filter   string
		Expected filter.Selection
		IsExact  bool
	}{
		{Filter: `proc.comm == "curl"`, Expected: filter.Selection{HasComm: true, Comms: []string{"curl"}}, IsExact: true},
		{
			Filter:   `proc.uid in {1001, 1002} && proc.comm in {"curl" "wget"} && ip.dst == 10.0.0.0/8 && tcp.dstport in {443 8443}`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001, 1002}, HasComm: true, Comms: []string{"curl", "wget"}, HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, HasPort: true, DestinationPorts: []filter.Port{{Port: 443, IPProtocol: syscall.IPPROTO_TCP}, {Port: 8443, IPProtocol: syscall.IPPROTO_TCP}}},
			IsExact:  true,
		},
		// a flow is never tcp and udp, the port part passes nothing
		{Filter: `tcp.dstport == 443 && udp.dstport == 53`, Expected: filter.Selection{HasPort: true}, IsExact: true},
		{
			Filter:   `proc.uid == 1001 && (tcp.dstport == 443 || udp.dstport == 53) && (proc.comm == "curl" || proc.comm == "dig")`,
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, HasComm: true, Comms: []string{"curl", "dig"}, HasPort: true, DestinationPorts: []filter.Port{{Port: 443, IPProtocol: syscall.IPPROTO_TCP}, {Port: 53, IPProtocol: syscall.IPPROTO_UDP}}},
			IsExact:  true,
		},
		{Filter: `proc.uid == 1001 || proc.pid == 5`, Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}, Tgids: []uint32{5}}, IsExact: true},
		{Filter: `proc.uid == 1001 && proc.pid == 5`, Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}}, IsExact: false},
		{Filter: `proc.uid == 1001 && proc.uid == 1002`, Expected: filter.Selection{HasProcess: true}, IsExact: true},
		{Filter: `proc.uid == 1001 && tls.sni == "x"`, Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}}, IsExact: false},
		// under || of different maps, !, != and ranges nothing goes into the kernel
		{Filter: `proc.uid == 1001 || proc.comm == "curl"`, Expected: filter.Selection{}, IsExact: false},
		{Filter: `!(proc.uid == 1001)`, Expected: filter.Selection{}, IsExact: false},
		{Filter: `proc.uid != 1001`, Expected: filter.Selection{}, IsExact: false},
		{Filter: `tcp.dstport in {1..1024}`, Expected: filter.Selection{}, IsExact: false},
		{Filter: `ip.addr == 10.0.0.0/8 || tcp.port == 443`, Expected: filter.Selection{}, IsExact: false},
		{Filter: `proc.uid == 1001 && !(proc.comm == "wget")`, Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}}, IsExact: false},
		{Filter: `ipv6.dst == 2001:db8::/32`, Expected: filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}, IsExact: true},
		{Filter: `ipv6.dst == ::/0`, Expected: filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("::/0")}}, IsExact: false},
	}

	for _, positive := range positiveCases {
		parsed, parseErr := filter.Parse(positive.Filter)

		if err = parseErr; err != nil {
			return
		}

		selection, isExact := parsed.Pushdown()

		if !reflect.DeepEqual(selection, positive.Expected) || (isExact != positive.IsExact) {
			err = fmt.Errorf("%s: Pushdown return value was not %+v exact %v instead: %+v exact %v", positive.Filter, positive.Expected, positive.IsExact, selection, isExact)
			return
		}
	}

	return
}

// every flow the filter takes passes the kernel selection, and with an exact push-down the kernel passes no other flow
func testPushdownNeverNarrower() (err error) {
	filters := []string{
		`proc.comm == "curl"`,
		`proc.uid == 1001 && !(proc.comm == "wget")`,
		`proc.uid == 1001 || proc.comm == "dig"`,
		`(proc.uid == 1001 || proc.pid == 777) && (tcp.dstport == 443 || udp.dstport == 53)`,
		`proc.uid in {1001 1002} && ip.dst == 10.0.0.0/8`,
		`proc.uid == 1002 && ipv6.dst == 2001:db8::/32`,
		`!(tcp.dstport == 443) && proc.uid == 1001`,
		`ip.addr == 192.168.0.0/16 && proc.uid == 1001`,
		`tcp.port == 50000 && proc.comm in {"curl" "dig"}`,
		`proc.uid == 1001 && proc.pid == 4242 && tls.sni == "example.com"`,
		`ipv6.dst == ::/0 && udp.dstport == 53`,
		`proc.uid == 1001 && proc.uid != 1001`,
	}
	flows := []filter.Values{curlValues, digValues, wgetValues.WithClientHello(false, 0, "", nil), curlValues.WithClientHello(false, 0, "", nil)}

	// the same flows with every other combination of process, address and port
	for _, base := range slices.Clone(flows) {
		for _, other := range []filter.Values{curlValues, digValues, wgetValues} {
			mixed := base
			mixed.UID = other.UID
			mixed.Destination = netip.AddrPortFrom(other.Destination.Addr(), base.Destination.Port())
			flows = append(flows, mixed)
		}
	}

	for _, text := range filters {
		parsed, parseErr := filter.Parse(text)

		if err = parseErr; err != nil {
			return
		}

		selection, isExact := parsed.Pushdown()

		for _, values := range flows {
			isTaken := parsed.Evaluate(values) == filter.TrueResult
			isPassed := passes(selection, values)

			if isTaken && !isPassed {
				err = fmt.Errorf("%s: the kernel selection %+v leaves out a flow the filter takes: %+v", text, selection, values)
				return
			}

			if isExact && isPassed && !isTaken {
				err = fmt.Errorf("%s: the exact kernel selection %+v passes a flow the filter leaves out: %+v", text, selection, values)
				return
			}
		}
	}

	return
}

// what check_flow does with the maps of the selection
func passes(selection filter.Selection, values filter.Values) (isPassed bool) {
	if selection.HasProcess && !slices.Contains(selection.UIDs, values.UID) && !slices.Contains(selection.Tgids, values.PID) {
		return
	}

	if selection.HasComm && !slices.Contains(selection.Comms, values.Comm) {
		return
	}

	if selection.HasPort && !slices.Contains(selection.DestinationPorts, filter.Port{Port: values.Destination.Port(), IPProtocol: values.IPProtocol}) {
		return
	}

	if selection.HasDestination {
		// the trie holds IPv4 as IPv4-mapped
		destination := netip.AddrFrom16(values.Destination.Addr().As16())
		isIn := false

		for _, prefix := range selection.DestinationCIDRs {
			mapped := prefix

			if prefix.Addr().Is4() {
				mapped = netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), prefix.Bits()+96)
			}

			isIn = isIn || mapped.Contains(destination)
		}

		if !isIn {
			return
		}
	}

	isPassed = true
	return
}

// Test if filter.Parse returns with the expected output for every escape of a string.
func TestEscapePositive(state *testing.T) {
	positiveCases := []struct {
		Filter   string
		Expected string
	}{
		{Filter: `tls.sni == "\a\b\f\n\r\t\v\'"`, Expected: "\a\b\f\n\r\t\v'"},
		{Filter: `tls.sni == "\101\x41ü\U0001F600"`, Expected: "AAü😀"},
		// an octal escape takes at most three digits, the fourth is a character of its own
		{Filter: `tls.sni == "\1011"`, Expected: "A1"},
		// a raw string keeps every backslash
		{Filter: `tls.sni == r"a\n\"b"`, Expected: `a\n\"b`},
	}

	for _, positive := range positiveCases {
		parsed, err := filter.Parse(positive.Filter)

		if err != nil {
			state.Errorf("Test of filter.Parse function failed, filter: %s, error: %s", positive.Filter, err.Error())
			return
		}

		result := parsed.Evaluate(curlValues.WithClientHello(true, 0x0304, positive.Expected, nil))

		if result != filter.TrueResult {
			state.Errorf("Test of filter.Parse function failed, filter: %s, result for %q should be %v, result: %v", positive.Filter, positive.Expected, filter.TrueResult, result)
			return
		}
	}
}

// Test if filter.Parse returns with the expected errors for wrong escapes and slips.
func TestEscapeNegative(state *testing.T) {
	negativeCases := []struct {
		Filter string
		Column int
		Length int
		Err    error
	}{
		{Filter: `tls.sni == "\400"`, Column: 13, Length: 4, Err: filter.ErrEscape},
		{Filter: `tls.sni == "\xg"`, Column: 13, Length: 2, Err: filter.ErrEscape},
		{Filter: `tls.sni == "\u12"`, Column: 13, Length: 4, Err: filter.ErrEscape},
		{Filter: `tls.sni == "\UFFFFFFFF"`, Column: 13, Length: 10, Err: filter.ErrEscape},
		{Filter: `tls.sni == "\uD800"`, Column: 13, Length: 6, Err: filter.ErrEscape},
		{Filter: `tls.sni == "\é"`, Column: 13, Length: 2, Err: filter.ErrEscape},
		{Filter: `tls.sni == "x\`, Column: 12, Length: 3, Err: filter.ErrSyntax},
		{Filter: `tcp & udp`, Column: 5, Length: 1, Err: filter.ErrSyntax},
		{Filter: `tcp | udp`, Column: 5, Length: 1, Err: filter.ErrSyntax},
		{Filter: `tcp $ udp`, Column: 5, Length: 1, Err: filter.ErrSyntax},
	}

	for _, negative := range negativeCases {
		_, err := filter.Parse(negative.Filter)
		positionErr, ok := errors.AsType[*filter.PositionError](err)

		if !ok || !errors.Is(err, negative.Err) || (positionErr.Column != negative.Column) || (positionErr.Length != negative.Length) {
			state.Errorf("Test of filter.Parse function failed, filter: %s, error should be %v at column %d length %d, error: %v %+v", negative.Filter, negative.Err, negative.Column, negative.Length, err, positionErr)
			return
		}
	}
}

// Test if filter.PositionError returns with the expected output.
func TestPositionErrorPositive(state *testing.T) {
	positiveCases := []struct {
		Filter  string
		Message string
		Marker  string
	}{
		{Filter: `proc.comm = "curl"`, Message: `column 11: syntax error: unexpected "=", equality is ==`, Marker: "proc.comm = \"curl\"\n          ^"},
		{Filter: `proc.cmd == "curl"`, Message: `column 1: unknown field: "proc.cmd" is not a field of the filter`, Marker: "proc.cmd == \"curl\"\n^~~~~~~~"},
		// columns count characters, not bytes
		{Filter: `tls.sni == "ü" && x`, Message: `column 19: unknown field: "x" is not a field of the filter`, Marker: "tls.sni == \"ü\" && x\n                  ^"},
	}

	for _, positive := range positiveCases {
		_, err := filter.Parse(positive.Filter)
		positionErr, ok := errors.AsType[*filter.PositionError](err)

		if !ok {
			state.Errorf("Test of filter.PositionError failed, filter: %s, error should be a position error, error: %v", positive.Filter, err)
			return
		}

		if (positionErr.Error() != positive.Message) || (positionErr.Marker() != positive.Marker) {
			state.Errorf("Test of filter.PositionError failed, filter: %s, message should be %q marker %q, message: %q marker: %q", positive.Filter, positive.Message, positive.Marker, positionErr.Error(), positionErr.Marker())
			return
		}
	}

	parsed, err := filter.Parse(`tcp  &&  udp`)

	if (err != nil) || (parsed.String() != `tcp  &&  udp`) {
		state.Errorf("Test of filter.Filter.String function failed, text should be %q, text: %q, error: %v", `tcp  &&  udp`, parsed.String(), err)
		return
	}
}

// Test if filter.ReadCmdline and filter.ReadExe return with the expected output.
func TestReadProcessPositive(state *testing.T) {
	tgid := uint32(os.Getpid())
	cmdline, err := filter.ReadCmdline(tgid)

	if err != nil {
		state.Errorf("Test of filter.ReadCmdline function failed, error: %s", err.Error())
		return
	}

	// the arguments are joined by spaces, without the trailing NUL
	if cmdline != strings.Join(os.Args, " ") {
		state.Errorf("Test of filter.ReadCmdline function failed, cmdline should be %q, cmdline: %q", strings.Join(os.Args, " "), cmdline)
		return
	}

	exe, err := filter.ReadExe(tgid)

	if err != nil {
		state.Errorf("Test of filter.ReadExe function failed, error: %s", err.Error())
		return
	}

	executable, err := os.Executable()

	if (err != nil) || (exe != executable) {
		state.Errorf("Test of filter.ReadExe function failed, exe should be %q, exe: %q, error: %v", executable, exe, err)
		return
	}
}

// Test if filter.ReadCmdline and filter.ReadExe return with the expected errors.
func TestReadProcessNegative(state *testing.T) {
	// no process has this tgid, the kernel's pid_max is at most 2^22
	_, err := filter.ReadCmdline(math.MaxUint32)

	if !errors.Is(err, filter.ErrProcess) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of filter.ReadCmdline function failed, error should be %v, error: %v", filter.ErrProcess, err)
		return
	}

	_, err = filter.ReadExe(math.MaxUint32)

	if !errors.Is(err, filter.ErrProcess) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of filter.ReadExe function failed, error should be %v, error: %v", filter.ErrProcess, err)
		return
	}
}
