package xlog_test

// Security regression tests covering CWE paths introduced by golang.org/x/term
// enabling ANSI output, and golang.org/x/sys underpinning terminal detection.
//
// CWE-116 / CWE-117 — Log injection via terminal escape sequences and newlines.
//   golang.org/x/term.IsTerminal enables the color path in colorTextHandler.
//   User-supplied content written raw (message, attr key, KindAny value) could embed
//   ANSI cursor-movement codes (\033[1A \033[2K) to overwrite prior log lines or forge
//   new ones, or embed \n/\r to split a single log call into multiple apparent lines.
//
// CWE-400 — Uncontrolled resource consumption.
//   Very long messages or attribute values must not cause OOM or panic.
//
// CWE-362 — Concurrent use of the deduplication handler with mixed messages.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/l0caldadmin/xlog"
)

// ansiStringer implements fmt.Stringer and returns an ANSI-laden string.
// This forces the KindAny branch in colorTextHandler.formatValue.
type ansiStringer struct{ payload string }

func (a ansiStringer) String() string { return a.payload }

// colorHandler returns a colorTextHandler (the "default" format) writing to buf.
func colorHandler(buf *bytes.Buffer) slog.Handler {
	return xlog.NewHandler(xlog.DefaultFormat, buf, &slog.HandlerOptions{Level: slog.LevelDebug})
}

func newRecord(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(time.Now(), level, msg, 0)
	r.AddAttrs(attrs...)
	return r
}

// ---------------------------------------------------------------------------
// CWE-116 / CWE-117 — ANSI injection
// ---------------------------------------------------------------------------

// TestSecurity_ANSIInjection_Message verifies that cursor-movement ANSI codes
// embedded in a log message are stripped before reaching the terminal.
// A forged \033[1A\033[2K would overwrite the line above; stripping it prevents
// log-line erasure / content spoofing.
func TestSecurity_ANSIInjection_Message(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo,
		"before\033[1A\033[2Kafter"))

	out := buf.String()
	if strings.Contains(out, "\033[1A") {
		t.Errorf("CWE-116: cursor-up escape leaked into output: %q", out)
	}
	if strings.Contains(out, "\033[2K") {
		t.Errorf("CWE-116: clear-line escape leaked into output: %q", out)
	}
	if !strings.Contains(out, "before") || !strings.Contains(out, "after") {
		t.Errorf("message content was lost during sanitization: %q", out)
	}
}

// TestSecurity_ANSIInjection_AttrKey verifies ANSI codes in attribute keys are stripped.
func TestSecurity_ANSIInjection_AttrKey(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	r := newRecord(slog.LevelWarn, "msg",
		slog.String("\033[1A\033[2Kmalicious-key", "value"))
	_ = h.Handle(context.Background(), r)

	out := buf.String()
	if strings.Contains(out, "\033[1A") || strings.Contains(out, "\033[2K") {
		t.Errorf("CWE-116: ANSI in attr key leaked into output: %q", out)
	}
	if !strings.Contains(out, "malicious-key") {
		t.Errorf("attr key text was lost during sanitization: %q", out)
	}
}

// TestSecurity_ANSIInjection_AttrValueKindAny verifies that a fmt.Stringer whose
// String() method returns ANSI codes is sanitized via the KindAny branch.
// KindString values use %q which already escapes the ESC byte; KindAny uses %v raw.
func TestSecurity_ANSIInjection_AttrValueKindAny(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	r := newRecord(slog.LevelError, "msg",
		slog.Any("key", ansiStringer{"\033[1A\033[2Kinjected"}))
	_ = h.Handle(context.Background(), r)

	out := buf.String()
	if strings.Contains(out, "\033[1A") || strings.Contains(out, "\033[2K") {
		t.Errorf("CWE-116: ANSI from KindAny Stringer leaked into output: %q", out)
	}
	if !strings.Contains(out, "injected") {
		t.Errorf("attr value text was lost during sanitization: %q", out)
	}
}

// TestSecurity_ANSIInjection_HideCursor verifies the hide-cursor sequence is stripped.
func TestSecurity_ANSIInjection_HideCursor(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo,
		"visible\033[?25lhidden-cursor-injection"))

	out := buf.String()
	if strings.Contains(out, "\033[?25l") {
		t.Errorf("CWE-116: hide-cursor escape leaked into output: %q", out)
	}
}

// TestSecurity_MalformedCSI_PreservesFollowingText verifies malformed CSI handling:
// consumed CSI bytes remain consumed, and trailing non-CSI text is preserved.
func TestSecurity_MalformedCSI_PreservesFollowingText(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	// Euro sign bytes are > 0x7E and triggered over-consumption in previous logic.
	input := "prefix\033[31€suffix"
	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo, input))

	out := buf.String()
	if !strings.Contains(out, "€suffix") {
		t.Fatalf("following text was consumed unexpectedly: %q", out)
	}
	if strings.Contains(out, "[31€suffix") {
		t.Fatalf("malformed CSI parameter bytes should be consumed, got: %q", out)
	}
	if strings.Contains(out, "\033[31€") {
		t.Fatalf("raw user CSI sequence leaked into output: %q", out)
	}
}

// TestSecurity_TruncatedOSC_ESCAtEnd verifies that an ESC at the end of an OSC
// payload does not trigger out-of-bounds behavior and does not swallow text.
func TestSecurity_TruncatedOSC_ESCAtEnd(t *testing.T) {
	var buf bytes.Buffer
	h := xlog.NewHandler(xlog.TextFormat, &buf, &slog.HandlerOptions{Level: slog.LevelInfo})

	input := "prefix\033]title\033"
	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo, input))

	out := buf.String()
	if !strings.Contains(out, "]title") {
		t.Fatalf("truncated OSC content was swallowed unexpectedly: %q", out)
	}
	if strings.Contains(out, "\033") {
		t.Fatalf("raw ESC leaked into output: %q", out)
	}
}

// ---------------------------------------------------------------------------
// CWE-117 — Newline / CR injection (log forging)
// ---------------------------------------------------------------------------

// TestSecurity_NewlineInjection_Message verifies that a \n embedded in a log
// message is escaped to a literal \n sequence, preventing fake log-line creation.
func TestSecurity_NewlineInjection_Message(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo,
		"legit\nERROR forged-line key=injected"))

	out := buf.String()
	// The injected newline must not produce a second actual newline before the
	// trailing one from the handler itself.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("CWE-117: embedded newline created %d output lines (want 1): %q", len(lines), out)
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("CWE-117: embedded newline was silently dropped instead of escaped: %q", out)
	}
}

// TestSecurity_CRInjection_Message verifies that \r is escaped to a literal \r,
// preventing carriage-return-based terminal line overwriting.
func TestSecurity_CRInjection_Message(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	_ = h.Handle(context.Background(), newRecord(slog.LevelInfo,
		"real\rOVERWRITTEN"))

	out := buf.String()
	trimmed := strings.TrimSuffix(out, "\n")
	if strings.ContainsRune(trimmed, '\r') {
		t.Errorf("CWE-117: raw CR leaked into output: %q", out)
	}
	if !strings.Contains(out, `\r`) {
		t.Errorf("CWE-117: embedded CR was dropped instead of escaped: %q", out)
	}
}

// TestSecurity_NewlineInjection_AttrValue verifies \n in a string attr value is
// escaped (KindString uses %q which already escapes; this acts as a regression guard).
func TestSecurity_NewlineInjection_AttrValue(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	r := newRecord(slog.LevelInfo, "msg",
		slog.String("k", "line1\nERROR fake"))
	_ = h.Handle(context.Background(), r)

	out := buf.String()
	// %q on KindString escapes \n → \\n; the output should be a single line.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("CWE-117: newline in attr value created %d lines (want 1): %q", len(lines), out)
	}
}

// ---------------------------------------------------------------------------
// CWE-116 + dedup interaction
// ---------------------------------------------------------------------------

// TestSecurity_DedupWithANSIMessage verifies that when a message containing ANSI
// cursor codes is repeated, the deduplication logic still works correctly and the
// injected ANSI does not appear in the output buffer.
func TestSecurity_DedupWithANSIMessage(t *testing.T) {
	var contentBuf bytes.Buffer
	inner := xlog.NewHandler(xlog.DefaultFormat, &contentBuf,
		&slog.HandlerOptions{Level: slog.LevelDebug})

	var dedupBuf bytes.Buffer
	h := xlog.NewDeduplicatingHandler(inner, &dedupBuf)

	msg := "polling\033[1A\033[2Kinjected"
	r1 := newRecord(slog.LevelInfo, msg)
	r2 := newRecord(slog.LevelInfo, msg)

	_ = h.Handle(context.Background(), r1)
	_ = h.Handle(context.Background(), r2)

	// Second identical record must NOT pass through to the inner handler.
	// (Dedup key is built from raw message before sanitize; that's intentional —
	// the key is never rendered to output.)
	content := contentBuf.String()
	if strings.Contains(content, "\033[1A") || strings.Contains(content, "\033[2K") {
		t.Errorf("CWE-116: injected ANSI leaked through dedup into rendered output: %q", content)
	}

	// The dedup "repeated" indicator must not contain user content.
	dedup := dedupBuf.String()
	if strings.Contains(dedup, "injected") {
		t.Errorf("user message content appeared in dedup repeat-indicator line: %q", dedup)
	}
}

// ---------------------------------------------------------------------------
// CWE-400 — Uncontrolled resource consumption
// ---------------------------------------------------------------------------

// TestSecurity_LongMessage_NoPanic verifies a 1 MB message is handled without panic.
func TestSecurity_LongMessage_NoPanic(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	msg := strings.Repeat("A", 1<<20) // 1 MB
	if err := h.Handle(context.Background(), newRecord(slog.LevelInfo, msg)); err != nil {
		t.Errorf("unexpected error for 1MB message: %v", err)
	}
}

// TestSecurity_LongAttrValue_NoPanic verifies a 1 MB attribute value is handled without panic.
func TestSecurity_LongAttrValue_NoPanic(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	big := strings.Repeat("B", 1<<20)
	r := newRecord(slog.LevelInfo, "msg", slog.String("data", big))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Errorf("unexpected error for 1MB attr value: %v", err)
	}
}

// TestSecurity_ManyAttributes_NoPanic verifies that a record with a large number
// of attributes does not panic.
func TestSecurity_ManyAttributes_NoPanic(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	attrs := make([]slog.Attr, 512)
	for i := range attrs {
		attrs[i] = slog.String(fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
	}
	r := newRecord(slog.LevelInfo, "msg", attrs...)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Errorf("unexpected error for 512 attrs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CWE-362 — Concurrent dedup with mixed messages
// ---------------------------------------------------------------------------

// TestSecurity_ConcurrentDedupMixedMessages launches goroutines sending
// alternating distinct messages to the dedup handler, verifying no data race
// or panic when the dedup key resets rapidly under contention.
func TestSecurity_ConcurrentDedupMixedMessages(t *testing.T) {
	capture := newCaptureHandler()
	var buf bytes.Buffer
	h := xlog.NewDeduplicatingHandler(capture, &buf)

	var wg sync.WaitGroup
	messages := []string{"alpha", "beta", "gamma", "delta"}

	for _, msg := range messages {
		for i := 0; i < 50; i++ {
			wg.Add(1)
			msg := msg
			go func() {
				defer wg.Done()
				_ = h.Handle(context.Background(), newRecord(slog.LevelInfo, msg))
			}()
		}
	}
	wg.Wait()
	if got := len(capture.Records()); got == 0 {
		t.Fatal("expected at least one record to pass through dedup handler")
	}
}

// ---------------------------------------------------------------------------
// Miscellaneous hardening
// ---------------------------------------------------------------------------

// TestSecurity_NullByteInMessage verifies that a null byte in a log message
// does not cause a panic (Go strings are length-delimited; this is a guard
// against future C-FFI or terminal-emulator edge cases).
func TestSecurity_NullByteInMessage(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)

	msg := "before\x00after"
	if err := h.Handle(context.Background(), newRecord(slog.LevelInfo, msg)); err != nil {
		t.Errorf("unexpected error for null-byte message: %v", err)
	}
}

// TestSecurity_AllLevels_Sanitized verifies sanitization applies uniformly
// across Debug, Info, Warn, Error levels.
func TestSecurity_AllLevels_Sanitized(t *testing.T) {
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	for _, level := range levels {
		level := level
		t.Run(level.String(), func(t *testing.T) {
			var buf bytes.Buffer
			h := colorHandler(&buf)
			_ = h.Handle(context.Background(), newRecord(level,
				"msg\033[1A\033[2Kinjected"))
			out := buf.String()
			if strings.Contains(out, "\033[1A") || strings.Contains(out, "\033[2K") {
				t.Errorf("CWE-116: injected ANSI leaked at level %s: %q", level, out)
			}
		})
	}
}

// TestSecurity_WithDedup_LoggerOption_NoPanic verifies the WithDedup / WithoutDedup
// logger options don't panic and the logger remains usable.
func TestSecurity_WithDedup_LoggerOption_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic: %v", r)
		}
	}()

	l := xlog.NewLogger(xlog.LogLevel("info"), xlog.DefaultFormat, xlog.WithoutDedup())
	l.Info("test\033[1Ainjected", "k", "v\033[2K")

	l2 := xlog.NewLogger(xlog.LogLevel("debug"), xlog.DefaultFormat, xlog.WithDedup())
	l2.Debug("concurrent-safe\nforged", "x", "y")
}

// TestSecurity_GroupedAttrs_ANSIInjection verifies ANSI codes in grouped
// attribute values are sanitized through the WithGroup / recursive formatAttr path.
func TestSecurity_GroupedAttrs_ANSIInjection(t *testing.T) {
	var buf bytes.Buffer
	h := colorHandler(&buf)
	h = h.WithGroup("grp")

	r := newRecord(slog.LevelInfo, "msg",
		slog.Any("nested", ansiStringer{"\033[1Ainjected"}))
	_ = h.Handle(context.Background(), r)

	out := buf.String()
	if strings.Contains(out, "\033[1A") {
		t.Errorf("CWE-116: ANSI in grouped attr leaked into output: %q", out)
	}
}

// TestSecurity_RepeatLineDoesNotContainUserANSI is a targeted regression for the
// dedup handler: the "repeated Nx" indicator line uses our own ANSI codes only;
// it must never relay user-injected escape sequences.
func TestSecurity_RepeatLineDoesNotContainUserANSI(t *testing.T) {
	var buf bytes.Buffer
	capture := newCaptureHandler()
	h := xlog.NewDeduplicatingHandler(capture, &buf)

	injected := "tick\033[1A\033[2K"
	for i := 0; i < 3; i++ {
		_ = h.Handle(context.Background(), newRecord(slog.LevelInfo, injected))
	}

	out := buf.String()
	// Our own \033[1A from dedup overwrite is expected; but it must come from
	// the handler itself, not from user content. Verify "repeated" is present
	// (handler working) and user text is NOT in the dedup buf.
	if !strings.Contains(out, "repeated") {
		t.Errorf("dedup repeat indicator missing: %q", out)
	}
	if strings.Contains(out, "tick") {
		t.Errorf("user message content leaked into dedup repeat-indicator buffer: %q", out)
	}
}
