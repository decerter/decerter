// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

const (
	TraceLevel slog.Level = slog.LevelDebug - 4
)

type Logger struct {
	logger *slog.Logger
	level  *slog.LevelVar
}

// child logger with extra fields, shares the level with its parent
func (logger *Logger) With(args ...any) (child Logger) {
	child.level = logger.level
	child.logger = logger.logger.With(args...)
	return
}

func (logger *Logger) ChangeLogLevel(level slog.Level) {
	logger.level.Set(level)
}

// for the packages outside pkg/ that log through a *slog.Logger: the same handler and level, slog reports their own source lines
func (logger *Logger) Slog() (slogLogger *slog.Logger) {
	slogLogger = logger.logger
	return
}

func (logger *Logger) Trace(message string, args ...any) {
	logger.log(TraceLevel, message, args...)
}

func (logger *Logger) Debug(message string, args ...any) {
	logger.log(slog.LevelDebug, message, args...)
}

func (logger *Logger) Info(message string, args ...any) {
	logger.log(slog.LevelInfo, message, args...)
}

func (logger *Logger) Warn(message string, args ...any) {
	logger.log(slog.LevelWarn, message, args...)
}

func (logger *Logger) Error(message string, args ...any) {
	logger.log(slog.LevelError, message, args...)
}

// source attribute points to the caller of Trace/Debug/Info/Warn/Error, not to this wrapper
func (logger *Logger) log(level slog.Level, message string, args ...any) {
	ctx := context.Background()

	if !logger.logger.Enabled(ctx, level) {
		return
	}

	var programCounters [1]uintptr
	// skip runtime.Callers, log and the level method
	runtime.Callers(3, programCounters[:])
	record := slog.NewRecord(time.Now(), level, message, programCounters[0])
	record.Add(args...)
	// slog.Logger drops handler errors the same way
	_ = logger.logger.Handler().Handle(ctx, record)
}
