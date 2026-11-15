// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/decerter/decerter/internal/pcapng"
)

// Test if the key log and pcapng counters return with the expected output: lines and sessions of a key log, packets and secrets blocks of a pcapng in either byte order, whatever the writes cut.
func TestCountersPositive(state *testing.T) {
	keyLog := "# a comment\nCLIENT_HANDSHAKE_TRAFFIC_SECRET aa 11\nSERVER_HANDSHAKE_TRAFFIC_SECRET aa 22\nCLIENT_RANDOM bb 33\n\nCLIENT_RANDOM cc 44"

	for step := 1; step <= len(keyLog); step += 7 {
		counter := &keylogCounter{sessions: map[string]bool{}, lines: 0, line: nil}

		for start := 0; start < len(keyLog); start += step {
			_, _ = counter.Write([]byte(keyLog[start:min(start+step, len(keyLog))]))
		}

		counter.add()

		if (counter.lines != 4) || (len(counter.sessions) != 3) {
			state.Errorf("Test of mcp.keylogCounter failed, writes of %d bytes should count 4 lines of 3 sessions, lines: %d, sessions: %v", step, counter.lines, counter.sessions)
			return
		}
	}

	buffer := &bytes.Buffer{}
	writer, err := pcapng.New(buffer, 65535, false)

	if err != nil {
		state.Fatalf("Could not start the pcapng, error: %s", err.Error())
	}

	for index := range 3 {
		err = writer.WritePacket(pcapng.Packet{Timestamp: uint64(index), Direction: pcapng.OutboundDirection, OriginalLength: 5, Data: []byte("hello"), Comment: "a comment"})

		if err != nil {
			state.Fatalf("Could not write a packet, error: %s", err.Error())
		}
	}

	err = writer.WriteSecrets([]byte("CLIENT_RANDOM bb 33\n"))

	if err == nil {
		err = writer.Flush()
	}

	if err != nil {
		state.Fatalf("Could not write the pcapng, error: %s", err.Error())
	}

	// the same blocks in big endian: type, length and magic swapped, the rest is not read
	little := buffer.Bytes()
	big := bytes.Clone(little)

	for offset := 0; offset+pcapngHeaderBytes <= len(big); {
		length := int(binary.LittleEndian.Uint32(little[offset+4:]))
		binary.BigEndian.PutUint32(big[offset:], binary.LittleEndian.Uint32(little[offset:]))
		binary.BigEndian.PutUint32(big[offset+4:], uint32(length))
		binary.BigEndian.PutUint32(big[offset+length-4:], uint32(length))

		if offset == 0 {
			binary.BigEndian.PutUint32(big[8:], byteOrderMagic)
		}

		offset += length
	}

	for _, data := range [][]byte{little, big} {
		for _, step := range []int{1, 5, 12, 13, len(data)} {
			counter := &pcapngCounter{}

			for start := 0; start < len(data); start += step {
				_, _ = counter.Write(data[start:min(start+step, len(data))])
			}

			if (counter.packets != 3) || (counter.secrets != 1) || (counter.skip != 0) || (len(counter.header) != 0) {
				state.Errorf("Test of mcp.pcapngCounter failed, writes of %d bytes should count 3 packets and 1 secrets block, counter: %+v", step, counter)
				return
			}
		}
	}
}
