// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the bounds of the history, the oldest flow goes first when one is reached
	DefaultFlows        int   = 10000
	DefaultMessages     int   = 200000
	DefaultPayloadBytes int64 = 64 << 20
	// what one flow may keep, its later messages and bytes are not kept and the flow is marked truncated
	DefaultFlowMessages     int   = 20000
	DefaultFlowPayloadBytes int64 = 1 << 20
)

// how much the history keeps: flows, messages and payload bytes in total and per flow
type Limits struct {
	Flows            int
	Messages         int
	FlowMessages     int
	PayloadBytes     int64
	FlowPayloadBytes int64
}

// what one direction of a flow sent on, given when it closes
type Counters struct {
	Bytes     int64
	Datagrams int64
}

// values is what the scope filter knew of the flow when it was decided, clientRandom the one of its ClientHello, zero without one
// session comes from the messages once the record layer has it; traffic is by tlsrecord.Direction
type flowRecord struct {
	id           uint64
	cookie       uint64
	values       filter.Values
	clientRandom [32]byte
	session      tlsrecord.Session
	layer        intercept.Layer
	opened       time.Time
	closed       time.Time
	isOpen       bool
	traffic      [2]api.Traffic
	messageIDs   []uint64
	payloadBytes int64
	isTruncated  bool
}

// payload is what went on and original what the peer sent, kept only when they differ; both can be cut short by the limits
type messageRecord struct {
	id             uint64
	flowID         uint64
	direction      tlsrecord.Direction
	layer          intercept.Layer
	time           time.Time
	origin         intercept.Origin
	verdict        intercept.Verdict
	isEdited       bool
	length         int
	originalLength int
	payload        []byte
	original       []byte
}

// the flows in scope of a run and their messages, in memory; order has the flow ids oldest first, which is also ascending
// nextMessageID numbers the observed messages of --decrypt, intercepted ones come with the id of the pipeline
// notify gets an event for every flow and message, it must not block; it is called without the mutex
type History struct {
	mutex         *sync.RWMutex
	limits        Limits
	flows         map[uint64]*flowRecord
	order         []uint64
	messages      map[uint64]*messageRecord
	nextFlowID    uint64
	nextMessageID uint64
	payloadBytes  int64
	openFlows     int
	evictedFlows  uint64
	notify        func(event api.Event)
}

func DefaultLimits() (limits Limits) {
	limits = Limits{
		Flows:            DefaultFlows,
		Messages:         DefaultMessages,
		FlowMessages:     DefaultFlowMessages,
		PayloadBytes:     DefaultPayloadBytes,
		FlowPayloadBytes: DefaultFlowPayloadBytes,
	}
	return
}
