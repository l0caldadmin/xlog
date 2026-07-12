package xlog

import (
	"context"
	"os"
)

const (
	EnvLogLevel  = "LOG_LEVEL"
	EnvLogFormat = "LOG_FORMAT"

	JSONFormat    = "json"
	TextFormat    = "text"
	DefaultFormat = "default"
)

var logger *Logger

func init() {
	logger = NewLogger(LogLevel(os.Getenv(EnvLogLevel)), os.Getenv(EnvLogFormat))
}

func SetLogger(l *Logger) {
	logger = l
}

func Info(msg string, args ...any) {
	logger.Info(msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	logger.InfoContext(ctx, msg, args...)
}

func Debug(msg string, args ...any) {
	logger.Debug(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	logger.DebugContext(ctx, msg, args...)
}

func Error(msg string, args ...any) {
	logger.Error(msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	logger.ErrorContext(ctx, msg, args...)
}

func Warn(msg string, args ...any) {
	logger.Warn(msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	logger.WarnContext(ctx, msg, args...)
}

func Fatal(msg string, args ...any) {
	logger.Fatal(msg, args...)
}

func FatalContext(ctx context.Context, msg string, args ...any) {
	logger.FatalContext(ctx, msg, args...)
}
