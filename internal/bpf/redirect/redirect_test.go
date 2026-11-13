// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package redirect

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"reflect"
	"syscall"
	"testing"
)

// Test if redirect.ipToKey and redirect.keyToIP return with the expected output: the address bytes in network order in memory, IPv4 IPv4-mapped.
func TestIPKeyPositive(state *testing.T) {
	positiveCases := []struct {
		Address netip.Addr
		Memory  string
	}{
		{Address: netip.MustParseAddr("10.1.2.3"), Memory: "00000000000000000000ffff0a010203"},
		{Address: netip.MustParseAddr("::ffff:10.1.2.3"), Memory: "00000000000000000000ffff0a010203"},
		{Address: netip.MustParseAddr("2001:db8::1"), Memory: "20010db8000000000000000000000001"},
		{Address: netip.IPv6Unspecified(), Memory: "00000000000000000000000000000000"},
	}

	for _, positive := range positiveCases {
		key := ipToKey(positive.Address)
		memory := []byte{}

		for _, part := range key {
			memory = binary.NativeEndian.AppendUint32(memory, part)
		}

		if hex.EncodeToString(memory) != positive.Memory {
			state.Errorf("Test of redirect.ipToKey function failed, address %s, memory should be %s, memory: %x", positive.Address, positive.Memory, memory)
			return
		}

		// a mapped address comes back as the plain IPv4 address
		if back := keyToIP(key); back != positive.Address.Unmap() {
			state.Errorf("Test of redirect.keyToIP function failed, address should be %s, address: %s", positive.Address.Unmap(), back)
			return
		}
	}
}

// Test if redirect.prefixToKey and redirect.keyToPrefix return with the expected output: an IPv4 prefix is 96 bits longer in the trie.
func TestPrefixKeyPositive(state *testing.T) {
	positiveCases := []struct {
		Prefix    netip.Prefix
		Prefixlen uint32
	}{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Prefixlen: 96},
		{Prefix: netip.MustParsePrefix("127.0.0.1/32"), Prefixlen: 128},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Prefixlen: 104},
		{Prefix: netip.MustParsePrefix("::/0"), Prefixlen: 0},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Prefixlen: 32},
	}

	for _, positive := range positiveCases {
		key := prefixToKey(positive.Prefix)

		if (key.Prefixlen != positive.Prefixlen) || (key.Ip != ipToKey(positive.Prefix.Addr())) || (keyToPrefix(key) != positive.Prefix) {
			state.Errorf("Test of redirect.prefixToKey function failed, prefix %s, length should be %d, length: %d, back: %s", positive.Prefix, positive.Prefixlen, key.Prefixlen, keyToPrefix(key))
			return
		}
	}
}

// Test if redirect.commToKey and redirect.commToString return with the expected output: NUL padded, cut to 15 bytes like the kernel cuts a name.
func TestCommPositive(state *testing.T) {
	positiveCases := []struct {
		Comm     string
		Expected string
	}{
		{Comm: "curl", Expected: "curl"},
		{Comm: "", Expected: ""},
		{Comm: "fifteen-chars-x", Expected: "fifteen-chars-x"},
		{Comm: "sixteen-chars-xy", Expected: "sixteen-chars-x"},
	}

	for _, positive := range positiveCases {
		key := commToKey(positive.Comm)

		if (key.Comm[15] != 0) || (commToString(key.Comm) != positive.Expected) {
			state.Errorf("Test of redirect.commToKey function failed, comm %q, name should be %q, name: %q", positive.Comm, positive.Expected, commToString(key.Comm))
			return
		}

		for index := len(positive.Expected); index < len(key.Comm); index++ {
			if key.Comm[index] != 0 {
				state.Errorf("Test of redirect.commToKey function failed, comm %q is not NUL padded: %v", positive.Comm, key.Comm)
				return
			}
		}
	}

	// the bytes behind the first NUL are not part of the name
	if name := commToString([16]int8{'a', 'b', 0, 'c'}); name != "ab" {
		state.Errorf("Test of redirect.commToString function failed, name should be %q, name: %q", "ab", name)
		return
	}
}

// Test if redirect.flowFromBpf returns with the expected output.
func TestFlowFromBpfPositive(state *testing.T) {
	comm := commToKey("dig").Comm
	positiveCases := []struct {
		Flow     bpfFlow
		Expected Flow
	}{
		// a redirected UDP flow with the client endpoint its first datagram to the proxy gave
		{
			Flow:     bpfFlow{Ip: ipToKey(netip.MustParseAddr("9.9.9.9")), Port: 53, IpProtocol: syscall.IPPROTO_UDP, Redirected: 1, Tgid: 10, Uid: 1001, Mark: 0x10064, CgroupId: 77, Comm: comm, Client: endpointToKey(netip.MustParseAddrPort("127.0.0.1:41000"), syscall.IPPROTO_UDP), Gid: 1002, ReleasedNs: 5},
			Expected: Flow{OriginalDestination: netip.MustParseAddrPort("9.9.9.9:53"), IPProtocol: syscall.IPPROTO_UDP, Redirected: true, Tgid: 10, UID: 1001, GID: 1002, CgroupID: 77, Comm: "dig", Mark: 0x10064, Client: netip.MustParseAddrPort("127.0.0.1:41000")},
		},
		// a TCP flow that is only recorded has no client endpoint
		{
			Flow:     bpfFlow{Ip: ipToKey(netip.MustParseAddr("2001:db8::1")), Port: 443, IpProtocol: syscall.IPPROTO_TCP, Redirected: 0, Tgid: 20, Uid: 0, Mark: 0, CgroupId: 1, Comm: comm, Client: bpfEndpoint{}, Gid: 0, ReleasedNs: 0},
			Expected: Flow{OriginalDestination: netip.MustParseAddrPort("[2001:db8::1]:443"), IPProtocol: syscall.IPPROTO_TCP, Redirected: false, Tgid: 20, UID: 0, GID: 0, CgroupID: 1, Comm: "dig", Mark: 0, Client: netip.AddrPort{}},
		},
	}

	for _, positive := range positiveCases {
		if flow := flowFromBpf(positive.Flow); flow != positive.Expected {
			state.Errorf("Test of redirect.flowFromBpf function failed, flow should be %+v, flow: %+v", positive.Expected, flow)
			return
		}
	}

	key := endpointToKey(netip.MustParseAddrPort("[::1]:8080"), syscall.IPPROTO_TCP)

	if (key.Port != 8080) || (key.IpProtocol != syscall.IPPROTO_TCP) || (keyToIP(key.Ip) != netip.IPv6Loopback()) {
		state.Errorf("Test of redirect.endpointToKey function failed, key: %+v", key)
		return
	}
}

// Test if redirect.ProtocolName and redirect.DestinationPort.String return with the expected output.
func TestProtocolNamePositive(state *testing.T) {
	positiveCases := []struct {
		Port     DestinationPort
		Expected string
	}{
		{Port: DestinationPort{Port: 443, IPProtocol: syscall.IPPROTO_TCP}, Expected: "tcp/443"},
		{Port: DestinationPort{Port: 53, IPProtocol: syscall.IPPROTO_UDP}, Expected: "udp/53"},
		{Port: DestinationPort{Port: 0, IPProtocol: syscall.IPPROTO_SCTP}, Expected: "132/0"},
	}

	for _, positive := range positiveCases {
		if text := positive.Port.String(); text != positive.Expected {
			state.Errorf("Test of redirect.DestinationPort.String function failed, text should be %s, text: %s", positive.Expected, text)
			return
		}
	}
}

// Test if redirect.loadTimeVariables returns with the expected output: --block-quic and capture mode as 1 or 0, and every value fits its volatile
// const in the object's spec.
func TestLoadTimeVariablesPositive(state *testing.T) {
	positiveCases := []struct {
		RecordOnly bool
		BlockQuic  bool
		Expected   map[string]any
	}{
		{RecordOnly: false, BlockQuic: true, Expected: map[string]any{bpfVarProxyTgid: uint32(42), bpfVarProxyPort: uint16(15001), bpfVarRecordOnly: uint8(0), bpfVarBlockQuic: uint8(1)}},
		{RecordOnly: true, BlockQuic: true, Expected: map[string]any{bpfVarProxyTgid: uint32(42), bpfVarProxyPort: uint16(15001), bpfVarRecordOnly: uint8(1), bpfVarBlockQuic: uint8(1)}},
		{RecordOnly: false, BlockQuic: false, Expected: map[string]any{bpfVarProxyTgid: uint32(42), bpfVarProxyPort: uint16(15001), bpfVarRecordOnly: uint8(0), bpfVarBlockQuic: uint8(0)}},
	}

	for _, positive := range positiveCases {
		variables := loadTimeVariables(15001, 42, positive.RecordOnly, positive.BlockQuic)

		if !reflect.DeepEqual(variables, positive.Expected) {
			state.Errorf("Test of redirect.loadTimeVariables function failed, variables should be %v, variables: %v", positive.Expected, variables)
			continue
		}

		spec, err := loadBpf()

		if err != nil {
			state.Fatalf("Test of redirect.loadTimeVariables failed, cannot read the bpf spec, error: %s", err.Error())
		}

		for name, value := range variables {
			variable, isVariable := spec.Variables[name]

			if !isVariable {
				state.Errorf("Test of redirect.loadTimeVariables function failed, %s is no volatile const of the object", name)
				continue
			}

			if setErr := variable.Set(value); setErr != nil {
				state.Errorf("Test of redirect.loadTimeVariables function failed, %s can't be set to %v, error: %s", name, value, setErr.Error())
			}
		}
	}
}

// Test if the volatile consts of the redirect object refuse values of another size: block_quic is a uint8, a bool or a uint32 does not fit.
func TestLoadTimeVariablesNegative(state *testing.T) {
	spec, err := loadBpf()

	if err != nil {
		state.Fatalf("Test of redirect.loadTimeVariables failed, cannot read the bpf spec, error: %s", err.Error())
	}

	for _, value := range []any{uint32(1), uint16(1)} {
		if setErr := spec.Variables[bpfVarBlockQuic].Set(value); setErr == nil {
			state.Errorf("Test of the block_quic volatile const failed, a %T should not fit", value)
		}
	}

	if _, isVariable := spec.Variables["block_quic_typo"]; isVariable {
		state.Errorf("Test of the redirect spec failed, an unknown name should not be a variable")
	}
}
