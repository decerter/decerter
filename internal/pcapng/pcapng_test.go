// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package pcapng_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/pcapng"
)

const (
	snaplen            uint32 = 64
	sectionHeaderType  uint32 = 0x0A0D0D0A
	interfaceType      uint32 = 0x00000001
	enhancedPacketType uint32 = 0x00000006
	secretsType        uint32 = 0x0000000A
	byteOrderMagic     uint32 = 0x1A2B3C4D
	linkTypeRaw        uint16 = 101
	tlsKeyLogType      uint32 = 0x544C534B
	timestamp          uint64 = 1794456844702912486
	keyLog             string = "CLIENT_RANDOM 00 11\n"
	comment            string = "decerter: note"
)

type block struct {
	Type uint32
	Body []byte
}

type packetCase struct {
	Packet pcapng.Packet
	Flags  uint32
}

// a writer that takes nothing
type fullWriter struct{}

func (fullWriter fullWriter) Write(data []byte) (count int, err error) {
	err = io.ErrShortWrite
	return
}

// a writer that keeps every write on its own, to see what reached the output and when
type writeRecorder struct {
	writes [][]byte
}

func (writeRecorder *writeRecorder) Write(data []byte) (count int, err error) {
	writeRecorder.writes = append(writeRecorder.writes, bytes.Clone(data))
	count = len(data)
	return
}

// walk the blocks of a section: every block is a multiple of 32 bits long and has its total length at both ends
func readBlocks(data []byte) (blocks []block, err error) {
	for len(data) > 0 {
		if len(data) < 12 {
			err = fmt.Errorf("%d bytes left are too short for a block", len(data))
			return
		}

		totalLength := binary.LittleEndian.Uint32(data[4:8])

		if (totalLength%4 != 0) || (totalLength < 12) || (int(totalLength) > len(data)) {
			err = fmt.Errorf("block total length was %d with %d bytes left", totalLength, len(data))
			return
		}

		if trailingLength := binary.LittleEndian.Uint32(data[totalLength-4 : totalLength]); trailingLength != totalLength {
			err = fmt.Errorf("trailing block total length was not %d instead: %d", totalLength, trailingLength)
			return
		}

		blocks = append(blocks, block{
			Type: binary.LittleEndian.Uint32(data[0:4]),
			Body: data[8 : totalLength-4],
		})
		data = data[totalLength:]
	}

	return
}

func write(packets []pcapng.Packet, keyLogs []string) (blocks []block, err error) {
	output := bytes.Buffer{}
	writer, newErr := pcapng.New(&output, snaplen, false)

	if err = newErr; err != nil {
		return
	}

	for _, secrets := range keyLogs {
		err = writer.WriteSecrets([]byte(secrets))

		if err != nil {
			return
		}
	}

	for _, packet := range packets {
		err = writer.WritePacket(packet)

		if err != nil {
			return
		}
	}

	err = writer.Flush()

	if err != nil {
		return
	}

	blocks, err = readBlocks(output.Bytes())
	return
}

func testNewHeader() (err error) {
	blocks, writeErr := write(nil, nil)

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 2 {
		err = fmt.Errorf("block count was not %d instead: %d", 2, len(blocks))
		return
	}

	section := blocks[0]

	if (section.Type != sectionHeaderType) || (binary.LittleEndian.Uint32(section.Body[0:4]) != byteOrderMagic) || (binary.LittleEndian.Uint16(section.Body[4:6]) != 1) || (binary.LittleEndian.Uint16(section.Body[6:8]) != 0) || (binary.LittleEndian.Uint64(section.Body[8:16]) != 0xFFFFFFFFFFFFFFFF) {
		err = fmt.Errorf("section header block was not as expected: type 0x%08x body %x", section.Type, section.Body)
		return
	}

	// the options of a block end with opt_endofopt, 4 zero bytes
	if !bytes.HasSuffix(section.Body, []byte{0, 0, 0, 0}) {
		err = fmt.Errorf("section header options do not end with opt_endofopt: %x", section.Body)
		return
	}

	description := blocks[1]

	if (description.Type != interfaceType) || (binary.LittleEndian.Uint16(description.Body[0:2]) != linkTypeRaw) || (binary.LittleEndian.Uint32(description.Body[4:8]) != snaplen) {
		err = fmt.Errorf("interface description block was not as expected: type 0x%08x body %x", description.Type, description.Body)
		return
	}

	// if_tsresol (code 9, length 1) with value 9: nanoseconds, padded to 32 bits
	if !bytes.Contains(description.Body[8:], []byte{9, 0, 1, 0, 9, 0, 0, 0}) {
		err = fmt.Errorf("interface description has no nanosecond if_tsresol option: %x", description.Body)
		return
	}

	return
}

func testWritePacket() (err error) {
	positiveCases := []packetCase{
		{Packet: pcapng.Packet{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 5, Data: []byte{0x45, 1, 2, 3, 4}}, Flags: 2},
		{Packet: pcapng.Packet{Timestamp: timestamp + 1, Direction: pcapng.InboundDirection, OriginalLength: 4000, Data: bytes.Repeat([]byte{0x60}, int(snaplen))}, Flags: 1},
		{Packet: pcapng.Packet{Timestamp: timestamp + 2, Direction: pcapng.InboundDirection, OriginalLength: 0, Data: nil}, Flags: 1},
		{Packet: pcapng.Packet{Timestamp: timestamp + 3, Direction: pcapng.OutboundDirection, OriginalLength: 5, Data: []byte{0x45, 1, 2, 3, 4}, Comment: comment}, Flags: 2},
	}
	packets := []pcapng.Packet{}

	for _, positive := range positiveCases {
		packets = append(packets, positive.Packet)
	}

	blocks, writeErr := write(packets, nil)

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 2+len(positiveCases) {
		err = fmt.Errorf("block count was not %d instead: %d", 2+len(positiveCases), len(blocks))
		return
	}

	for index, positive := range positiveCases {
		packetBlock := blocks[2+index]
		capturedLength := len(positive.Packet.Data)
		paddedLength := (capturedLength + 3) / 4 * 4

		if packetBlock.Type != enhancedPacketType {
			err = fmt.Errorf("block type was not 0x%08x instead: 0x%08x", enhancedPacketType, packetBlock.Type)
			return
		}

		expectedOptions := []byte{}

		// opt_comment (code 1) with the text padded to 32 bits, only when the packet has a comment
		if positive.Packet.Comment != "" {
			expectedOptions = append(expectedOptions, 1, 0, byte(len(positive.Packet.Comment)), 0)
			expectedOptions = append(expectedOptions, positive.Packet.Comment...)
			expectedOptions = append(expectedOptions, make([]byte, (4-len(positive.Packet.Comment)%4)%4)...)
		}

		expectedOptions = binary.LittleEndian.AppendUint32(append(expectedOptions, 2, 0, 4, 0), positive.Flags)
		expectedOptions = append(expectedOptions, 0, 0, 0, 0)

		// interface id, timestamp high and low, captured length, original length, data, the options: opt_comment, epb_flags, opt_endofopt
		if len(packetBlock.Body) != 20+paddedLength+len(expectedOptions) {
			err = fmt.Errorf("enhanced packet block body length was not %d instead: %d", 20+paddedLength+len(expectedOptions), len(packetBlock.Body))
			return
		}

		gotTimestamp := uint64(binary.LittleEndian.Uint32(packetBlock.Body[4:8]))<<32 | uint64(binary.LittleEndian.Uint32(packetBlock.Body[8:12]))

		if (binary.LittleEndian.Uint32(packetBlock.Body[0:4]) != 0) || (gotTimestamp != positive.Packet.Timestamp) || (binary.LittleEndian.Uint32(packetBlock.Body[12:16]) != uint32(capturedLength)) || (binary.LittleEndian.Uint32(packetBlock.Body[16:20]) != positive.Packet.OriginalLength) {
			err = fmt.Errorf("enhanced packet block header was not as expected: %x", packetBlock.Body[:20])
			return
		}

		if !bytes.Equal(packetBlock.Body[20:20+capturedLength], positive.Packet.Data) {
			err = fmt.Errorf("packet data was not %x instead: %x", positive.Packet.Data, packetBlock.Body[20:20+capturedLength])
			return
		}

		if !bytes.Equal(packetBlock.Body[20+paddedLength:], expectedOptions) {
			err = fmt.Errorf("packet options were not %x instead: %x", expectedOptions, packetBlock.Body[20+paddedLength:])
			return
		}
	}

	return
}

func testWriteSecrets() (err error) {
	blocks, writeErr := write(nil, []string{keyLog})

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 3 {
		err = fmt.Errorf("block count was not %d instead: %d", 3, len(blocks))
		return
	}

	secrets := blocks[2]
	paddedLength := (len(keyLog) + 3) / 4 * 4

	if (secrets.Type != secretsType) || (binary.LittleEndian.Uint32(secrets.Body[0:4]) != tlsKeyLogType) || (binary.LittleEndian.Uint32(secrets.Body[4:8]) != uint32(len(keyLog))) || (len(secrets.Body) != 8+paddedLength) {
		err = fmt.Errorf("decryption secrets block was not as expected: type 0x%08x body %x", secrets.Type, secrets.Body)
		return
	}

	if string(secrets.Body[8:8+len(keyLog)]) != keyLog {
		err = fmt.Errorf("key log was not %q instead: %q", keyLog, secrets.Body[8:8+len(keyLog)])
		return
	}

	return
}

// every block has to reach the output on its own when it is written, the reader of a pipe gets nothing else
func testStream() (err error) {
	output := writeRecorder{writes: nil}
	writer, newErr := pcapng.New(&output, snaplen, true)

	if err = newErr; err != nil {
		return
	}

	err = writer.WriteSecrets([]byte(keyLog))

	if err != nil {
		return
	}

	err = writer.WritePacket(pcapng.Packet{Timestamp: timestamp, Direction: pcapng.InboundDirection, OriginalLength: 3, Data: []byte{1, 2, 3}, Comment: ""})

	if err != nil {
		return
	}

	expectedTypes := []uint32{sectionHeaderType, interfaceType, secretsType, enhancedPacketType}

	if len(output.writes) != len(expectedTypes) {
		err = fmt.Errorf("write count was not %d instead: %d", len(expectedTypes), len(output.writes))
		return
	}

	for index, data := range output.writes {
		blocks, readErr := readBlocks(data)

		if err = readErr; err != nil {
			return
		}

		if (len(blocks) != 1) || (blocks[0].Type != expectedTypes[index]) {
			err = fmt.Errorf("write %d was not one block of type 0x%08x instead: %d blocks", index, expectedTypes[index], len(blocks))
			return
		}
	}

	// a file is buffered until Flush
	output = writeRecorder{writes: nil}
	writer, err = pcapng.New(&output, snaplen, false)

	if err != nil {
		return
	}

	if len(output.writes) != 0 {
		err = fmt.Errorf("write count of a file before Flush was not 0 instead: %d", len(output.writes))
		return
	}

	return
}

// Test if pcapng.New returns with the expected output.
func TestNewPositive(state *testing.T) {
	err := testNewHeader()

	if err != nil {
		state.Errorf("Test of pcapng.New failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.New returns with the expected errors.
func TestNewNegative(state *testing.T) {
	_, err := pcapng.New(&bytes.Buffer{}, 0, false)

	if !errors.Is(err, pcapng.ErrSnaplen) {
		state.Errorf("Test of pcapng.New function failed, error should be %v, error: %v", pcapng.ErrSnaplen, err)
		return
	}
}

// Test if pcapng.Writer.WritePacket returns with the expected output.
func TestWritePacketPositive(state *testing.T) {
	err := testWritePacket()

	if err != nil {
		state.Errorf("Test of pcapng.Writer.WritePacket failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.Writer.WritePacket returns with the expected errors.
func TestWritePacketNegative(state *testing.T) {
	negativeCases := []pcapng.Packet{
		{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 2, Data: []byte{1, 2, 3}},
		{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 4000, Data: bytes.Repeat([]byte{1}, int(snaplen)+1)},
	}

	for _, negative := range negativeCases {
		_, err := write([]pcapng.Packet{negative}, nil)

		if !errors.Is(err, pcapng.ErrPacketSize) {
			state.Errorf("Test of pcapng.Writer.WritePacket function failed, error should be %v, error: %v", pcapng.ErrPacketSize, err)
			return
		}
	}

	// the length of an option is 16 bits
	_, err := write([]pcapng.Packet{{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 1, Data: []byte{1}, Comment: strings.Repeat("c", 65536)}}, nil)

	if !errors.Is(err, pcapng.ErrCommentSize) {
		state.Errorf("Test of pcapng.Writer.WritePacket function failed, error should be %v, error: %v", pcapng.ErrCommentSize, err)
		return
	}
}

// Test if pcapng.Writer.WriteSecrets returns with the expected output.
func TestWriteSecretsPositive(state *testing.T) {
	err := testWriteSecrets()

	if err != nil {
		state.Errorf("Test of pcapng.Writer.WriteSecrets failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.Writer in stream mode returns with the expected output.
func TestStreamPositive(state *testing.T) {
	err := testStream()

	if err != nil {
		state.Errorf("Test of pcapng.Writer stream mode failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.Writer.Flush returns with the expected errors.
func TestFlushNegative(state *testing.T) {
	writer, err := pcapng.New(fullWriter{}, snaplen, false)

	if err != nil {
		state.Errorf("Test of pcapng.Writer.Flush failed, cannot create writer, error: %s", err.Error())
		return
	}

	err = writer.Flush()

	if !errors.Is(err, pcapng.ErrWrite) {
		state.Errorf("Test of pcapng.Writer.Flush function failed, error should be %v, error: %v", pcapng.ErrWrite, err)
		return
	}
}

// Test if pcapng.Writer in stream mode returns with the expected errors, and a block longer than the buffer reaches the output in one write.
func TestStreamNegative(state *testing.T) {
	_, err := pcapng.New(fullWriter{}, snaplen, true)

	if !errors.Is(err, pcapng.ErrWrite) {
		state.Errorf("Test of pcapng.New function failed, a stream should write the section header at once, error should be %v, error: %v", pcapng.ErrWrite, err)
		return
	}

	// a file is buffered, a block longer than the buffer goes to the output when it is written
	writer, err := pcapng.New(fullWriter{}, snaplen, false)

	if err != nil {
		state.Fatalf("Test of pcapng.Writer.WriteSecrets failed, cannot create writer, error: %s", err.Error())
	}

	err = writer.WriteSecrets(bytes.Repeat([]byte("CLIENT_RANDOM 00 11\n"), 4000))

	if !errors.Is(err, pcapng.ErrWrite) {
		state.Errorf("Test of pcapng.Writer.WriteSecrets function failed, error should be %v, error: %v", pcapng.ErrWrite, err)
		return
	}

	output := writeRecorder{writes: nil}
	writer, err = pcapng.New(&output, snaplen, true)

	if err != nil {
		state.Fatalf("Test of pcapng.Writer.WriteSecrets failed, cannot create writer, error: %s", err.Error())
	}

	err = writer.WriteSecrets(bytes.Repeat([]byte("CLIENT_RANDOM 00 11\n"), 4000))

	if (err != nil) || (len(output.writes) != 3) || (len(output.writes[2]) != 12+8+80000) {
		state.Errorf("Test of pcapng.Writer.WriteSecrets function failed, the long block should be the third write, writes: %d, error: %v", len(output.writes), err)
		return
	}
}

// Test if tshark decrypts a TLS 1.3 session with the keys of the Decryption Secrets Block of a file the writer made, skipped without tshark.
func TestTsharkPositive(state *testing.T) {
	tshark, err := exec.LookPath("tshark")

	if err != nil {
		state.Skipf("Test of pcapng with tshark skipped, no tshark on this host: %s", err.Error())
	}

	packets, keyLog, err := tlsPackets()

	if err != nil {
		state.Fatalf("Test of pcapng with tshark failed, cannot record a TLS session, error: %s", err.Error())
	}

	// with the key log in the file tshark finds the request, without it only TLS records
	positiveCases := []struct {
		KeyLog   []byte
		Expected string
	}{
		{KeyLog: keyLog, Expected: "/decerter-dsb-check\n"},
		{KeyLog: nil, Expected: ""},
	}

	for _, positive := range positiveCases {
		path := filepath.Join(state.TempDir(), "capture.pcapng")
		err = writeFile(path, positive.KeyLog, packets)

		if err != nil {
			state.Fatalf("Test of pcapng with tshark failed, cannot write file, error: %s", err.Error())
		}

		// no profile and no key log file of the user, only what is in the capture
		command := exec.CommandContext(state.Context(), tshark, "-n", "-C", "Default", "-o", "tls.keylog_file:", "-r", path, "-Y", "http.request", "-T", "fields", "-e", "http.request.uri")
		stdErr := &bytes.Buffer{}
		command.Stderr = stdErr
		output, runErr := command.Output()

		if runErr != nil {
			state.Errorf("Test of pcapng with tshark failed, tshark error: %s, stderr: %s", runErr.Error(), stdErr.String())
			return
		}

		if string(output) != positive.Expected {
			state.Errorf("Test of pcapng with tshark failed, with %d bytes of key log the output should be %q, output: %q, stderr: %s", len(positive.KeyLog), positive.Expected, output, stdErr.String())
			return
		}
	}
}

// the capture as decerter writes it: the key log of the session before its packets
func writeFile(path string, keyLog []byte, packets []pcapng.Packet) (err error) {
	file, createErr := os.Create(path)

	if err = createErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	writer, newErr := pcapng.New(file, 1<<18, false)

	if err = newErr; err != nil {
		return
	}

	if keyLog != nil {
		err = writer.WriteSecrets(keyLog)

		if err != nil {
			return
		}
	}

	for _, packet := range packets {
		err = writer.WritePacket(packet)

		if err != nil {
			return
		}
	}

	err = writer.Flush()
	return
}

// a crypto/tls TLS 1.3 session over a pipe with an HTTP/1.1 request, its bytes as IPv4 TCP packets of 10.0.0.1:40000 to 10.0.0.2:443
// with a handshake in front; keyLog is what crypto/tls logged for it
func tlsPackets() (packets []pcapng.Packet, keyLog []byte, err error) {
	certificate, certificateErr := newCertificate()

	if err = certificateErr; err != nil {
		return
	}

	keyLogBuffer := &bytes.Buffer{}
	clientSide, serverSide := net.Pipe()
	chunks := &[]chunk{}
	client := tls.Client(tap{Conn: clientSide, mutex: &sync.Mutex{}, chunks: chunks}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, KeyLogWriter: keyLogBuffer})
	server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true})
	request := "GET /decerter-dsb-check HTTP/1.1\r\nHost: decerter.test\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	serverErrChannel := make(chan error, 1)

	// test tls server
	go func() {
		buffer := make([]byte, len(request))
		_, readErr := io.ReadFull(server, buffer)
		_, writeErr := server.Write([]byte(response))
		serverErrChannel <- errors.Join(readErr, writeErr)
	}()

	_, writeErr := client.Write([]byte(request))
	_, readErr := io.ReadFull(client, make([]byte, len(response)))
	err = errors.Join(writeErr, readErr, <-serverErrChannel, clientSide.Close(), serverSide.Close())

	if err != nil {
		return
	}

	keyLog = keyLogBuffer.Bytes()
	clientAddress, serverAddress := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	sequences := [2]uint32{1000, 5000}
	addPacket := func(direction pcapng.Direction, flags byte, payload []byte) {
		source, destination := clientAddress, serverAddress
		sourcePort, destinationPort := uint16(40000), uint16(443)

		if direction == pcapng.InboundDirection {
			source, destination = destination, source
			sourcePort, destinationPort = destinationPort, sourcePort
		}

		ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0}
		binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(payload)))
		ip = append(append(ip, source[:]...), destination[:]...)
		segment := binary.BigEndian.AppendUint16(nil, sourcePort)
		segment = binary.BigEndian.AppendUint16(segment, destinationPort)
		segment = binary.BigEndian.AppendUint32(segment, sequences[direction])
		segment = binary.BigEndian.AppendUint32(segment, sequences[1-direction])
		segment = append(segment, 5<<4, flags, 0xff, 0xff, 0, 0, 0, 0)
		data := append(append(ip, segment...), payload...)
		packets = append(packets, pcapng.Packet{Timestamp: timestamp + uint64(len(packets))*1000, Direction: direction, OriginalLength: uint32(len(data)), Data: data, Comment: ""})
		sequences[direction] += uint32(len(payload))

		// SYN and FIN take a sequence number
		if (flags & 0x03) != 0 {
			sequences[direction]++
		}
	}
	addPacket(pcapng.OutboundDirection, 0x02, nil)
	addPacket(pcapng.InboundDirection, 0x12, nil)
	addPacket(pcapng.OutboundDirection, 0x10, nil)

	for _, current := range *chunks {
		addPacket(current.direction, 0x18, current.data)
	}

	return
}

// one write of the client or one read of what the server sent
type chunk struct {
	direction pcapng.Direction
	data      []byte
}

// the client end of the pipe, it records the stream in the order the client sees it
type tap struct {
	net.Conn
	mutex  *sync.Mutex
	chunks *[]chunk
}

func (tap tap) Read(buffer []byte) (count int, err error) {
	count, err = tap.Conn.Read(buffer)

	if count > 0 {
		tap.mutex.Lock()
		defer tap.mutex.Unlock()
		*tap.chunks = append(*tap.chunks, chunk{direction: pcapng.InboundDirection, data: bytes.Clone(buffer[:count])})
	}

	return
}

func (tap tap) Write(buffer []byte) (count int, err error) {
	tap.mutex.Lock()
	*tap.chunks = append(*tap.chunks, chunk{direction: pcapng.OutboundDirection, data: bytes.Clone(buffer)})
	tap.mutex.Unlock()
	count, err = tap.Conn.Write(buffer)
	return
}

// a self signed ECDSA certificate
func newCertificate() (certificate tls.Certificate, err error) {
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err = keyErr; err != nil {
		return
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decerter.test"},
		DNSNames:     []string{"decerter.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, createErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	if err = createErr; err != nil {
		return
	}

	certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return
}
