// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

func New(output io.Writer, level slog.Level) (logger Logger) {
	logger.level = &slog.LevelVar{}
	logger.level.Set(level)
	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		AddSource:   true,
		Level:       logger.level,
		ReplaceAttr: replaceAttr,
	})
	logger.logger = slog.New(handler)
	return
}

func ParseLevel(levelString string) (level slog.Level, err error) {
	if strings.EqualFold(levelString, "trace") {
		level = TraceLevel
		return
	}

	unmarshalErr := level.UnmarshalText([]byte(levelString))

	if unmarshalErr != nil {
		err = fmt.Errorf("%w: %w", ErrLogLevel, unmarshalErr)
		return
	}

	return
}

// print TraceLevel as "TRACE" instead of "DEBUG-4", and a duration as "30s" instead of its nanoseconds
func replaceAttr(groups []string, attr slog.Attr) (newAttr slog.Attr) {
	newAttr = attr

	if (len(groups) == 0) && (attr.Key == slog.LevelKey) {
		if level, ok := attr.Value.Any().(slog.Level); ok && (level == TraceLevel) {
			newAttr.Value = slog.StringValue("TRACE")
		}
	}

	if attr.Value.Kind() == slog.KindDuration {
		newAttr.Value = slog.StringValue(attr.Value.Duration().String())
	}

	return
}
