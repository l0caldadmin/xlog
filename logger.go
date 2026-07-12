package xlog

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/term"
)

// Logger wraps slog.Logger with level-aware logging and optional log deduplication.
type Logger struct {
	handler              slog.Handler
	level                LogLevel
	debuggingInformation bool
	exitFunc             func(int)
	errorStack           bool
}

// LoggerOption configures NewLogger behavior.
type LoggerOption func(*loggerConfig)

type loggerConfig struct {
	dedup      *bool // nil = auto-detect terminal, true = force on, false = force off
	writer     io.Writer
	redactKeys map[string]struct{}
	redactMask string // default: "****"
	omitRedact bool   // when true, omission takes precedence over masking
	exitFunc   func(int)
	errorStack bool
}

// WithDedup forces log deduplication on, regardless of whether output is a terminal.
func WithDedup() LoggerOption {
	return func(c *loggerConfig) {
		v := true
		c.dedup = &v
	}
}

// WithoutDedup forces log deduplication off, even when output is a terminal.
func WithoutDedup() LoggerOption {
	return func(c *loggerConfig) {
		v := false
		c.dedup = &v
	}
}

// WithWriter sets the destination writer for logger output.
// Useful for tests and for routing logs to custom sinks.
func WithWriter(w io.Writer) LoggerOption {
	return func(c *loggerConfig) {
		if w == nil {
			c.writer = io.Discard
			return
		}
		c.writer = w
	}
}

// WithRedactedKeys masks matching attributes (case-insensitive) with a replacement value.
func WithRedactedKeys(keys ...string) LoggerOption {
	return func(c *loggerConfig) {
		// Clone before mutating so options never mutate a shared map instance.
		cloned := make(map[string]struct{}, len(c.redactKeys)+(2*len(keys)))
		for k := range c.redactKeys {
			cloned[k] = struct{}{}
		}
		for _, k := range keys {
			if k == "" {
				continue
			}
			cloned[k] = struct{}{}
			cloned[strings.ToLower(k)] = struct{}{}
		}
		c.redactKeys = cloned
	}
}

// WithRedactionMask sets the replacement text used by WithRedactedKeys.
func WithRedactionMask(mask string) LoggerOption {
	return func(c *loggerConfig) {
		c.redactMask = mask
	}
}

// WithOmittedRedactedKeys drops attributes matching WithRedactedKeys.
// If both masking and omission are configured, omission takes precedence.
func WithOmittedRedactedKeys() LoggerOption {
	return func(c *loggerConfig) {
		c.omitRedact = true
	}
}

// WithExitFunc sets the exit behavior used by Fatal.
// Useful for tests and for applications that need custom shutdown semantics.
func WithExitFunc(fn func(int)) LoggerOption {
	return func(c *loggerConfig) {
		c.exitFunc = fn
	}
}

// WithErrorStackTraces enables stack trace capture for Error and Fatal logs.
func WithErrorStackTraces() LoggerOption {
	return func(c *loggerConfig) {
		c.errorStack = true
	}
}

// NewLogger creates a new Logger with the given level and format.
// By default, consecutive identical log lines are automatically deduplicated
// when output is a terminal. Use WithDedup() or WithoutDedup() to override.
func NewLogger(level LogLevel, format string, opts ...LoggerOption) *Logger {
	var cfg loggerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.writer == nil {
		cfg.writer = os.Stdout
	}
	if cfg.redactMask == "" {
		cfg.redactMask = "****"
	}
	if cfg.exitFunc == nil {
		cfg.exitFunc = os.Exit
	}

	handlerOpts := &slog.HandlerOptions{
		Level: level.ToSlogLevel(),
	}

	if len(cfg.redactKeys) > 0 {
		handlerOpts.ReplaceAttr = func(_ []string, a slog.Attr) slog.Attr {
			if !containsRedactedKey(cfg.redactKeys, a.Key) {
				return a
			}
			// Omission mode intentionally wins over masking.
			if cfg.omitRedact {
				return slog.Attr{}
			}
			return slog.String(a.Key, cfg.redactMask)
		}
	}

	handler := NewHandler(format, cfg.writer, handlerOpts)

	enableDedup := false
	if cfg.dedup != nil {
		enableDedup = *cfg.dedup
	} else {
		enableDedup = isTerminalWriter(cfg.writer)
	}

	if enableDedup {
		handler = NewDeduplicatingHandler(handler, cfg.writer)
	}

	return &Logger{
		handler:              handler,
		level:                level,
		debuggingInformation: level.ToSlogLevel() == slog.LevelDebug,
		exitFunc:             cfg.exitFunc,
		errorStack:           cfg.errorStack,
	}
}

// NewHandler creates an slog.Handler for the given format and options.
// This allows callers to build custom handler chains (e.g., wrapping with middleware).
func NewHandler(format string, w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	switch strings.ToLower(format) {
	case JSONFormat:
		return slog.NewJSONHandler(w, opts)
	case TextFormat:
		return slog.NewTextHandler(w, opts)
	default:
		return newColorTextHandler(w, opts)
	}
}

// NewLoggerWithHandler creates a Logger using a pre-built slog.Handler.
// No automatic deduplication is applied — the caller controls the handler chain.
func NewLoggerWithHandler(handler slog.Handler, level LogLevel) *Logger {
	return &Logger{
		handler:              handler,
		level:                level,
		debuggingInformation: level.ToSlogLevel() == slog.LevelDebug,
		exitFunc:             os.Exit,
	}
}

func containsRedactedKey(keys map[string]struct{}, key string) bool {
	if _, ok := keys[key]; ok {
		return true
	}
	if _, ok := keys[strings.ToLower(key)]; ok {
		return true
	}
	return false
}

func (l *Logger) _log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l.handler == nil || !l.handler.Enabled(ctx, level) {
		return
	}

	pc, file, line, _ := runtime.Caller(3)
	r := slog.NewRecord(time.Now(), level, msg, pc)
	r.Add(args...)

	if l.debuggingInformation {
		group := slog.Group(
			"caller",
			slog.Attr{
				Key:   "file",
				Value: slog.AnyValue(file),
			},
			slog.Attr{
				Key:   "L",
				Value: slog.AnyValue(line),
			},
		)
		r.AddAttrs(group)
	}

	if l.errorStack && level >= slog.LevelError {
		r.AddAttrs(slog.String("stack", string(debug.Stack())))
	}

	_ = l.handler.Handle(ctx, r)
}

func (l *Logger) Info(msg string, args ...any) {
	l._log(context.Background(), slog.LevelInfo, msg, args...)
}

func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l._log(ctx, slog.LevelInfo, msg, args...)
}

func (l *Logger) Debug(msg string, args ...any) {
	l._log(context.Background(), slog.LevelDebug, msg, args...)
}

func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l._log(ctx, slog.LevelDebug, msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l._log(context.Background(), slog.LevelError, msg, args...)
}

func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l._log(ctx, slog.LevelError, msg, args...)
}

func (l *Logger) Warn(msg string, args ...any) {
	l._log(context.Background(), slog.LevelWarn, msg, args...)
}

func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l._log(ctx, slog.LevelWarn, msg, args...)
}

func (l *Logger) Fatal(msg string, args ...any) {
	l._log(context.Background(), slog.LevelError, msg, args...)
	l.exitFunc(1)
}

func (l *Logger) FatalContext(ctx context.Context, msg string, args ...any) {
	l._log(ctx, slog.LevelError, msg, args...)
	l.exitFunc(1)
}

// isTerminalWriter checks if the given writer is connected to a terminal.
func isTerminalWriter(w io.Writer) bool {
	if f, ok := w.(interface{ Fd() uintptr }); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}
