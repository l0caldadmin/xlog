package xlog_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/mudler/xlog"
)

type contextCaptureHandler struct {
	mu       sync.Mutex
	contexts []context.Context
	records  []slog.Record
}

func (h *contextCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *contextCaptureHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.contexts = append(h.contexts, ctx)
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *contextCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *contextCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func TestLogger_InfoContext_PropagatesContext(t *testing.T) {
	h := &contextCaptureHandler{}
	l := xlog.NewLoggerWithHandler(h, xlog.LogLevelInfo)

	type ctxKey string
	const key ctxKey = "trace_id"
	ctx := context.WithValue(context.Background(), key, "trace-123")

	l.InfoContext(ctx, "hello")

	if len(h.contexts) != 1 {
		t.Fatalf("expected 1 context captured, got %d", len(h.contexts))
	}
	if got, _ := h.contexts[0].Value(key).(string); got != "trace-123" {
		t.Fatalf("context value mismatch: got %q", got)
	}
}

func TestLogger_Fatal_UsesInjectedExitFunc(t *testing.T) {
	exitCode := -1
	l := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.TextFormat,
		xlog.WithWriter(discardWriter{}),
		xlog.WithoutDedup(),
		xlog.WithExitFunc(func(code int) { exitCode = code }),
	)

	// Fatal must not terminate process in test; injected hook captures code.
	l.Fatal("fatal-event")
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (n int, err error) { return len(p), nil }

func TestLogger_ErrorStackTrace_EnabledAddsStackAttr(t *testing.T) {
	// Assert via rendered text output that stack attr is emitted.
	var b strings.Builder
	stackLogger := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.TextFormat,
		xlog.WithWriter(&builderWriter{b: &b}),
		xlog.WithoutDedup(),
		xlog.WithErrorStackTraces(),
	)
	stackLogger.Error("boom")
	out := b.String()
	if !strings.Contains(out, "stack=") {
		t.Fatalf("expected stack attribute in error log output, got: %q", out)
	}
}

type builderWriter struct{ b *strings.Builder }

func (w *builderWriter) Write(p []byte) (n int, err error) {
	return w.b.Write(p)
}
