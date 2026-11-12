// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package logging_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/decerter/decerter/pkg/internal/logging"
)

// what a test reads of one JSON log line
type logLine struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Timeout string `json:"timeout"`
	Group   struct {
		Wait string `json:"wait"`
	} `json:"group"`
	Flow   string `json:"flow"`
	Source struct {
		File     string `json:"file"`
		Function string `json:"function"`
	} `json:"source"`
}

// Test if logging.ParseLevel returns with the expected output.
func TestParseLevelPositive(state *testing.T) {
	positiveCases := []struct {
		Input string
		Level slog.Level
	}{
		{Input: "trace", Level: logging.TraceLevel},
		{Input: "TRACE", Level: logging.TraceLevel},
		{Input: "debug", Level: slog.LevelDebug},
		{Input: "info", Level: slog.LevelInfo},
		{Input: "Warn", Level: slog.LevelWarn},
		{Input: "error", Level: slog.LevelError},
		// slog's offsets are taken as they are
		{Input: "info+2", Level: slog.LevelInfo + 2},
	}

	for _, positive := range positiveCases {
		level, err := logging.ParseLevel(positive.Input)

		if (err != nil) || (level != positive.Level) {
			state.Errorf("Test of logging.ParseLevel function failed, input %q, level should be %v, level: %v, error: %v", positive.Input, positive.Level, level, err)
			return
		}
	}
}

// Test if logging.ParseLevel returns with the expected errors.
func TestParseLevelNegative(state *testing.T) {
	negativeCases := []string{"", "loud", "tracer", "5"}

	for _, negative := range negativeCases {
		_, err := logging.ParseLevel(negative)

		if !errors.Is(err, logging.ErrLogLevel) {
			state.Errorf("Test of logging.ParseLevel function failed, input %q, error should be %v, error: %v", negative, logging.ErrLogLevel, err)
			return
		}
	}
}

// Test if logging.Logger returns with the expected output: levels, TRACE, durations as text and the source of the caller.
func TestLoggerPositive(state *testing.T) {
	output := &bytes.Buffer{}
	logger := logging.New(output, slog.LevelInfo)
	child := logger.With("flow", "f1")
	logger.Trace("hidden trace")
	logger.Debug("hidden debug")
	logger.Info("shown info", "timeout", 30*time.Second, slog.Group("group", "wait", 1500*time.Millisecond))
	// the child shares the level of its parent
	logger.ChangeLogLevel(logging.TraceLevel)
	child.Trace("shown trace")
	child.Warn("shown warn")
	logger.Slog().Error("shown error")
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	parsedLines := []logLine{}

	for _, line := range lines {
		parsed := logLine{}
		err := json.Unmarshal([]byte(line), &parsed)

		if err != nil {
			state.Fatalf("Test of logging.Logger failed, line %q is not JSON, error: %s", line, err.Error())
		}

		parsedLines = append(parsedLines, parsed)
	}

	results := []string{}

	for _, line := range parsedLines {
		results = append(results, fmt.Sprintf("%s %s %s %s %s", line.Level, line.Message, line.Timeout, line.Group.Wait, line.Flow))

		// the line of the caller, not the one of the wrapper
		if !strings.HasSuffix(line.Source.File, "logging_test.go") || !strings.HasSuffix(line.Source.Function, "TestLoggerPositive") {
			state.Errorf("Test of logging.Logger function failed, source should be this test, source: %+v", line.Source)
			return
		}
	}

	expected := []string{"INFO shown info 30s 1.5s ", "TRACE shown trace   f1", "WARN shown warn   f1", "ERROR shown error   "}

	if !slices.Equal(results, expected) {
		state.Errorf("Test of logging.Logger function failed, lines should be %q, lines: %q", expected, results)
		return
	}
}
