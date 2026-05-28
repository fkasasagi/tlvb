// Package common holds cross-cutting types used by mcp/agents/synthesizer/etc.
package common

import (
	"log/slog"
	"os"
)

// Logger is the interface every package depends on. Wraps slog so we can
// redirect output (stderr in stdio MCP mode — stdout is reserved for protocol).
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewStderrLogger writes JSON Lines to stderr — required for stdio MCP servers
// where stdout carries the protocol.
func NewStderrLogger(level slog.Level) Logger {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}
