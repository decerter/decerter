// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package filter_test

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/decerter/decerter/internal/filter"
)

// Test if filter.Evaluate returns with the expected output for the address orderings and sets, the ip field alone and an || left unknown.
func TestEvaluateAddressPositive(state *testing.T) {
	positiveCases := []struct {
		Filter string
		Values filter.Values
		Result filter.Result
	}{
		{Filter: `ip.dst >= 10.0.0.0 && ip.dst > 10.1.2.2 && ip.dst <= 10.1.2.3 && ip.dst < 10.1.2.4`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.dst >= 10.1.2.4`, Values: curlValues, Result: filter.FalseResult},
		{Filter: `ip.dst in {192.168.0.0/16, 10.0.0.0/8}`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip.dst in {192.168.0.0/16 172.16.0.0/12}`, Values: curlValues, Result: filter.FalseResult},
		// the source is IPv4-mapped, it is an IPv4 address
		{Filter: `ip && ip.src == 192.168.1.10`, Values: curlValues, Result: filter.TrueResult},
		{Filter: `ip`, Values: digValues, Result: filter.FalseResult},
		{Filter: `udp && udp.srcport == 40000`, Values: digValues, Result: filter.TrueResult},
		// false || unknown is unknown
		{Filter: `proc.comm == "curl" || tls`, Values: wgetValues, Result: filter.UnknownResult},
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
}

// Test if filter.Parse returns with the expected errors inside negations, parentheses and sets, for quoted addresses, ranges and numbers with
// underscores, and for an unterminated raw string.
func TestParseValueNegative(state *testing.T) {
	negativeCases := []struct {
		Filter string
		Column int
		Err    error
	}{
		{Filter: `!foo.bar`, Column: 2, Err: filter.ErrUnknownField},
		{Filter: `(foo.bar)`, Column: 2, Err: filter.ErrUnknownField},
		{Filter: `tcp in {1}`, Column: 1, Err: filter.ErrOperator},
		{Filter: `tcp.port in 80`, Column: 13, Err: filter.ErrSyntax},
		{Filter: `ip.dst == "10.0.0.1"`, Column: 11, Err: filter.ErrType},
		{Filter: `tcp.port in {80..x}`, Column: 14, Err: filter.ErrType},
		{Filter: `tcp.port in {90..80}`, Column: 14, Err: filter.ErrSyntax},
		{Filter: `tcp.port == 1_000`, Column: 13, Err: filter.ErrType},
		{Filter: `tls.sni == r"abc`, Column: 13, Err: filter.ErrSyntax},
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

// Test if filter.Pushdown returns with the expected output for no filter and a negated set: nothing to push, exact only without a filter.
func TestPushdownNegatedPositive(state *testing.T) {
	selection, isExact := filter.Filter{}.Pushdown()

	if !isExact || !reflect.DeepEqual(selection, filter.Selection{}) {
		state.Errorf("Test of filter.Pushdown function failed, the zero filter should push nothing exactly, selection: %+v, exact: %v", selection, isExact)
		return
	}

	parsed, err := filter.Parse(`proc.uid not in {1001 1002}`)

	if err != nil {
		state.Fatalf("Test of filter.Pushdown failed, cannot parse, error: %s", err.Error())
	}

	selection, isExact = parsed.Pushdown()

	if isExact || selection.HasProcess {
		state.Errorf("Test of filter.Pushdown function failed, a negated set should stay in Go, selection: %+v, exact: %v", selection, isExact)
		return
	}
}

// Test if filter.Intersect returns with the expected output for narrower processes, pid sets, comm sets and nested prefixes, sorted.
func TestIntersectSetsPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		First    filter.Selection
		Second   filter.Selection
		Expected filter.Selection
		IsExact  bool
	}{
		{
			Name:     "a narrower uid set",
			First:    filter.Selection{HasProcess: true, UIDs: []uint32{1002, 1001}},
			Second:   filter.Selection{HasProcess: true, UIDs: []uint32{1001}},
			Expected: filter.Selection{HasProcess: true, UIDs: []uint32{1001}},
			IsExact:  true,
		},
		{
			Name:     "two pid sets",
			First:    filter.Selection{HasProcess: true, Tgids: []uint32{1, 2}},
			Second:   filter.Selection{HasProcess: true, Tgids: []uint32{3, 2}},
			Expected: filter.Selection{HasProcess: true, Tgids: []uint32{2}},
			IsExact:  true,
		},
		{
			Name:     "two comm sets",
			First:    filter.Selection{HasComm: true, Comms: []string{"wget", "curl"}},
			Second:   filter.Selection{HasComm: true, Comms: []string{"wget", "dig"}},
			Expected: filter.Selection{HasComm: true, Comms: []string{"wget"}},
			IsExact:  true,
		},
		{
			Name:     "a prefix inside another, sorted",
			First:    filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.0.0.0/8")}},
			Second:   filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("192.168.0.0/16")}},
			Expected: filter.Selection{HasDestination: true, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("192.168.0.0/16")}},
			IsExact:  true,
		},
	}

	for _, positive := range positiveCases {
		result, isExact := filter.Intersect(positive.First, positive.Second)

		if !reflect.DeepEqual(result, positive.Expected) || (isExact != positive.IsExact) {
			state.Errorf("Test of filter.Intersect function failed, case %q, result should be %+v exact %v, result: %+v exact %v", positive.Name, positive.Expected, positive.IsExact, result, isExact)
		}
	}
}
