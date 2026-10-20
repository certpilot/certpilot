package main

import (
	"io"
	"log/slog"

	"github.com/certpilot/certpilot/pkg/config"
)

// newLogger builds the logger the configuration asks for.
//
// logging.level and logging.format were documented and parsed for a long time
// and never applied: the core wrote text at debug level whatever the file
// said, so a deployment that asked for JSON to feed its log pipeline got lines
// it could not parse, and one that asked for warnings got every gateway dial.
// The configuration is validated before this runs, so an unreadable level
// cannot reach here; it falls back to info rather than to debug regardless.
func newLogger(cfg config.LoggingConfig, w io.Writer) *slog.Logger {
	level, err := cfg.SlogLevel()
	if err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.JSON() {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
