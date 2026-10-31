// SPDX-License-Identifier: AGPL-3.0-only

package route

type EventType string

const (
	ChangedEventType EventType = "changed"
	LostEventType    EventType = "lost"
)
