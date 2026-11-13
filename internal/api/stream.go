// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	v1 "github.com/decerter/decerter/api"
)

func NewBus() (bus *Bus) {
	bus = &Bus{
		mutex:       &sync.Mutex{},
		sequence:    0,
		subscribers: map[*subscriber]bool{},
	}
	return
}

// give the event its sequence number and time and hand it to every stream without waiting: a stream whose buffer is full is dropped and told so
// the proxy publishes from its relay goroutines, so this never blocks
func (bus *Bus) Publish(event v1.Event) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	bus.sequence++
	event.Seq = bus.sequence

	if event.Time.IsZero() {
		event.Time = time.Now()
	}

	for current := range bus.subscribers {
		select {
		case current.events <- event:
		default:
			current.lostSequence = event.Seq
			delete(bus.subscribers, current)
			close(current.overflow)
		}
	}
}

func (bus *Bus) subscribe() (current *subscriber) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	current = &subscriber{
		events:       make(chan v1.Event, eventBuffer),
		overflow:     make(chan struct{}),
		lostSequence: 0,
	}
	bus.subscribers[current] = true
	return
}

func (bus *Bus) unsubscribe(current *subscriber) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	delete(bus.subscribers, current)
}

// the first event a dropped subscriber did not get, read after overflow is closed
func (bus *Bus) lost(current *subscriber) (sequence uint64) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	sequence = current.lostSequence
	return
}

// server-sent events from now on until the client goes away or decerter stops: event is the type, id the sequence number, data the JSON event
// a comment line every eventKeepalive keeps idle connections open; a client that is eventBuffer events behind gets the events it still has, then an overflow event, and the stream ends
// there is no replay, Last-Event-ID is not read
func streamEvents(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	controller := http.NewResponseController(writer)
	current := backend.Bus.subscribe()
	defer backend.Bus.unsubscribe(current)
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	if !writeEventText(controller, writer, ": decerter events\n\n", logger) {
		return
	}

	keepalive := time.NewTicker(eventKeepalive)
	defer keepalive.Stop()

	for {
		select {
		case <-request.Context().Done():
			return
		case event := <-current.events:
			if !writeEvent(controller, writer, event, logger) {
				return
			}
		case <-current.overflow:
			// what the buffer still has, then why the stream ends
			for len(current.events) > 0 {
				if !writeEvent(controller, writer, <-current.events, logger) {
					return
				}
			}

			lost := backend.Bus.lost(current)
			logger.Warn("Api event stream too slow, dropping it", "lostSequence", lost)
			writeEvent(controller, writer, v1.Event{Seq: lost, Type: v1.OverflowEventType, Time: time.Now(), Reason: fmt.Sprintf("the client read too slowly, events from seq %d on were lost; subscribe again and read the state with the other endpoints", lost)}, logger)
			return
		case <-keepalive.C:
			if !writeEventText(controller, writer, ": keepalive\n\n", logger) {
				return
			}
		}
	}
}

func writeEvent(controller *http.ResponseController, writer http.ResponseWriter, event v1.Event, logger *slog.Logger) (isWritten bool) {
	data, err := json.Marshal(event)

	if err != nil {
		logger.Error("Could not encode api event", "error", err)
		return
	}

	isWritten = writeEventText(controller, writer, fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.Type, data), logger)
	return
}

// a write that does not finish in eventWriteTimeout ends the stream, isWritten is false then
func writeEventText(controller *http.ResponseController, writer http.ResponseWriter, text string, logger *slog.Logger) (isWritten bool) {
	err := controller.SetWriteDeadline(time.Now().Add(eventWriteTimeout))

	if err == nil {
		_, err = fmt.Fprint(writer, text)
	}

	if err == nil {
		err = controller.Flush()
	}

	if err != nil {
		logger.Debug("Could not write api event", "error", err)
		return
	}

	isWritten = true
	return
}
