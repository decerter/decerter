// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"github.com/decerter/decerter/internal/tlsrecord"
)

// the messages of one direction of a flow with what the history kept of them, oldest first, for a decode of the joined stream
// the slices are shared with the history and never changed, the caller must not change them either
func (history *History) DirectionMessages(flowID uint64, direction tlsrecord.Direction) (messages []StreamMessage, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.flows[flowID]

	if !found {
		return
	}

	for _, messageID := range record.messageIDs {
		message := history.messages[messageID]

		if message.direction != direction {
			continue
		}

		messages = append(messages, StreamMessage{Message: messageView(message), Payload: message.payload, Original: message.original})
	}

	return
}
