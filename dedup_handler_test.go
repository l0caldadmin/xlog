package xlog_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/l0caldadmin/xlog"
)

// captureHandler records all log records passed to it.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]string
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{}
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	cr := capturedRecord{
		Level:   r.Level,
		Message: r.Message,
		Attrs:   make(map[string]string),
	}
	r.Attrs(func(a slog.Attr) bool {
		cr.Attrs[a.Key] = a.Value.String()
		return true
	})
	h.records = append(h.records, cr)
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(name string) slog.Handler       { return h }

func (h *captureHandler) Records() []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]capturedRecord, len(h.records))
	copy(result, h.records)
	return result
}

func makeRecord(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(time.Now(), level, msg, 0)
	r.AddAttrs(attrs...)
	return r
}

func TestDedup_FirstRecordPassesThrough(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "hello"))

	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Message != "hello" {
		t.Fatalf("unexpected message: %s", records[0].Message)
	}
	// No ANSI output for first record.
	if buf.Len() != 0 {
		t.Fatalf("expected no terminal output, got: %q", buf.String())
	}
}

func TestDedup_DuplicateWritesRepeatLine(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "poll"))
	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "poll"))

	// Only the first record should go to the inner handler.
	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// Terminal output should have "repeated 1x".
	output := buf.String()
	if !strings.Contains(output, "repeated 1x") {
		t.Fatalf("expected 'repeated 1x' in output, got: %q", output)
	}
}

func TestDedup_MultipleRepeatsOverwriteLine(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	for i := 0; i < 5; i++ {
		handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "poll"))
	}

	// Only first record to inner handler.
	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// Output should contain ANSI move-up codes and "repeated 4x" (the last update).
	output := buf.String()
	if !strings.Contains(output, "repeated 4x") {
		t.Fatalf("expected 'repeated 4x' in output, got: %q", output)
	}
	// Should contain ANSI escape for overwriting previous line.
	if !strings.Contains(output, "\033[1A") {
		t.Fatalf("expected ANSI move-up code in output")
	}
}

func TestDedup_DifferentRecordResetsCount(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "A"))
	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "A"))
	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "B"))
	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "B"))

	records := capture.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Message != "A" || records[1].Message != "B" {
		t.Fatalf("unexpected messages: %v, %v", records[0].Message, records[1].Message)
	}
}

func TestDedup_DifferentAttributesAreDistinct(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "msg", slog.String("k", "v1")))
	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "msg", slog.String("k", "v2")))

	records := capture.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestDedup_DifferentLevelsAreDistinct(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "msg"))
	handler.Handle(context.Background(), makeRecord(slog.LevelWarn, "msg"))

	records := capture.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestDedup_ConcurrentSendsNoPanic(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	handler := xlog.NewDeduplicatingHandler(capture, &buf)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.Handle(context.Background(), makeRecord(slog.LevelInfo, "concurrent"))
		}()
	}
	wg.Wait()

	// Only the first record goes to inner handler; rest are "repeated" lines.
	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}
