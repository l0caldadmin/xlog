package xlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mudler/xlog"
)

type failWriter struct {
	mu        sync.Mutex
	failAfter int
	writes    int
	err       error
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writes >= w.failAfter {
		return 0, w.err
	}
	w.writes++
	return len(p), nil
}

func parseJSONLines(t *testing.T, buf string) []map[string]any {
	t.Helper()
	out := strings.TrimSpace(buf)
	if out == "" {
		return nil
	}
	lines := strings.Split(out, "\n")
	result := make([]map[string]any, 0, len(lines))
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is invalid JSON: %v; line=%q", i+1, err, line)
		}
		result = append(result, m)
	}
	return result
}

func TestCWE74_JSONOutput_AlwaysValidAndEscaped(t *testing.T) {
	var buf bytes.Buffer
	h := xlog.NewHandler(xlog.JSONFormat, &buf, &slog.HandlerOptions{Level: slog.LevelInfo})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, `hello "} malicious`, 0)
	r.AddAttrs(
		slog.String("payload", `\"} malicious`),
		slog.String("raw", `line1\nline2`),
	)

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("unexpected handle error: %v", err)
	}

	entries := parseJSONLines(t, buf.String())
	if len(entries) != 1 {
		t.Fatalf("expected 1 JSON line, got %d", len(entries))
	}

	msg, _ := entries[0]["msg"].(string)
	if msg != `hello "} malicious` {
		t.Fatalf("message mismatch: got %q", msg)
	}
	payload, _ := entries[0]["payload"].(string)
	if payload != `\"} malicious` {
		t.Fatalf("payload mismatch: got %q", payload)
	}
}

func TestCWE532_RedactionAndOmission_Configurable(t *testing.T) {
	t.Run("default-mask", func(t *testing.T) {
		var buf bytes.Buffer
		l := xlog.NewLogger(
			xlog.LogLevelInfo,
			xlog.JSONFormat,
			xlog.WithWriter(&buf),
			xlog.WithoutDedup(),
			xlog.WithRedactedKeys("Password"),
		)

		l.Info("auth", "Password", "hunter2")

		entries := parseJSONLines(t, buf.String())
		if len(entries) != 1 {
			t.Fatalf("expected 1 JSON line, got %d", len(entries))
		}
		if entries[0]["Password"] != "****" {
			t.Fatalf("expected default redaction mask ****, got %#v", entries[0]["Password"])
		}
	})

	t.Run("redaction", func(t *testing.T) {
		var buf bytes.Buffer
		l := xlog.NewLogger(
			xlog.LogLevelInfo,
			xlog.JSONFormat,
			xlog.WithWriter(&buf),
			xlog.WithoutDedup(),
			xlog.WithRedactedKeys("Password", "Token", "SSN"),
			xlog.WithRedactionMask("[REDACTED]"),
		)

		l.Info("auth", "Password", "hunter2", "Token", "abc", "SSN", "111-22-3333", "User", "alice")

		entries := parseJSONLines(t, buf.String())
		if len(entries) != 1 {
			t.Fatalf("expected 1 JSON line, got %d", len(entries))
		}
		e := entries[0]
		if e["Password"] != "[REDACTED]" || e["Token"] != "[REDACTED]" || e["SSN"] != "[REDACTED]" {
			t.Fatalf("sensitive keys were not redacted: %#v", e)
		}
		if e["User"] != "alice" {
			t.Fatalf("non-sensitive key modified unexpectedly: %#v", e)
		}
	})

	t.Run("omission", func(t *testing.T) {
		var buf bytes.Buffer
		l := xlog.NewLogger(
			xlog.LogLevelInfo,
			xlog.JSONFormat,
			xlog.WithWriter(&buf),
			xlog.WithoutDedup(),
			xlog.WithRedactedKeys("Password", "Token", "SSN"),
			xlog.WithOmittedRedactedKeys(),
		)

		l.Info("auth", "Password", "hunter2", "Token", "abc", "SSN", "111-22-3333", "User", "alice")

		entries := parseJSONLines(t, buf.String())
		if len(entries) != 1 {
			t.Fatalf("expected 1 JSON line, got %d", len(entries))
		}
		e := entries[0]
		if _, ok := e["Password"]; ok {
			t.Fatalf("Password key should be omitted: %#v", e)
		}
		if _, ok := e["Token"]; ok {
			t.Fatalf("Token key should be omitted: %#v", e)
		}
		if _, ok := e["SSN"]; ok {
			t.Fatalf("SSN key should be omitted: %#v", e)
		}
		if e["User"] != "alice" {
			t.Fatalf("non-sensitive key modified unexpectedly: %#v", e)
		}
	})
}

func TestWithWriter_NilUsesDiscard_NoPanic(t *testing.T) {
	l := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.TextFormat,
		xlog.WithWriter(nil),
		xlog.WithoutDedup(),
	)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("logger panicked with nil writer option: %v", r)
		}
	}()

	l.Info("safe")
}

func TestCWE362_ConcurrentLogging_NoInterleavingCorruption(t *testing.T) {
	var buf bytes.Buffer
	l := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.DefaultFormat,
		xlog.WithWriter(&buf),
		xlog.WithoutDedup(),
	)

	const n = 1000
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			l.Info("security-event", "id", i)
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d log lines, got %d", n, len(lines))
	}
	for i, line := range lines {
		if !strings.Contains(line, "security-event") {
			t.Fatalf("line %d appears corrupted/interleaved: %q", i+1, line)
		}
	}
}

func TestCWE778_SecurityEvents_AlwaysEmitted(t *testing.T) {
	var buf bytes.Buffer
	l := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.JSONFormat,
		xlog.WithWriter(&buf),
		xlog.WithoutDedup(),
	)

	events := []string{"auth_failure", "permission_denied", "token_refresh", "rate_limit_triggered"}
	for _, event := range events {
		l.Info("security-event", "event", event, "audit", true)
	}

	entries := parseJSONLines(t, buf.String())
	if len(entries) != len(events) {
		t.Fatalf("expected %d events, got %d", len(events), len(entries))
	}
	for i, event := range events {
		if entries[i]["event"] != event {
			t.Fatalf("event %d mismatch: got %#v want %q", i+1, entries[i]["event"], event)
		}
		if entries[i]["audit"] != true {
			t.Fatalf("event %d missing audit marker: %#v", i+1, entries[i])
		}
	}
}

func TestCWE703_WriteFailure_SurfacedFromHandler(t *testing.T) {
	errWrite := errors.New("write failed")
	w := &failWriter{failAfter: 0, err: errWrite}
	h := xlog.NewHandler(xlog.TextFormat, w, &slog.HandlerOptions{Level: slog.LevelInfo})

	err := h.Handle(context.Background(), newRecord(slog.LevelInfo, "msg", slog.String("k", "v")))
	if !errors.Is(err, errWrite) {
		t.Fatalf("expected write error to surface, got: %v", err)
	}
}

func TestNotCWE_OrderPreserved_SequentialWrites(t *testing.T) {
	var buf bytes.Buffer
	l := xlog.NewLogger(
		xlog.LogLevelInfo,
		xlog.JSONFormat,
		xlog.WithWriter(&buf),
		xlog.WithoutDedup(),
	)

	for i := 0; i < 10; i++ {
		l.Info("ordered", "idx", i)
	}
	entries := parseJSONLines(t, buf.String())
	if len(entries) != 10 {
		t.Fatalf("expected 10 lines, got %d", len(entries))
	}
	for i := 0; i < 10; i++ {
		if entries[i]["idx"] != float64(i) {
			t.Fatalf("unexpected order at entry %d: got %#v want %d", i+1, entries[i]["idx"], i)
		}
	}
}

func parseSemver(t *testing.T, v string) (int, int, int) {
	t.Helper()
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		t.Fatalf("invalid semver: %q", v)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("invalid major semver segment %q: %v", parts[0], err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("invalid minor semver segment %q: %v", parts[1], err)
	}
	patchPart := parts[2]
	if i := strings.IndexByte(patchPart, '-'); i >= 0 {
		patchPart = patchPart[:i]
	}
	patch, err := strconv.Atoi(patchPart)
	if err != nil {
		t.Fatalf("invalid patch semver segment %q: %v", patchPart, err)
	}
	return major, minor, patch
}

func semverLT(aMaj, aMin, aPatch, bMaj, bMin, bPatch int) bool {
	if aMaj != bMaj {
		return aMaj < bMaj
	}
	if aMin != bMin {
		return aMin < bMin
	}
	return aPatch < bPatch
}

func TestDependencyFloor_XSys(t *testing.T) {
	var xsysVersion string
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("failed reading go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "require" {
			fields = fields[1:]
		}
		if len(fields) < 2 || fields[0] != "golang.org/x/sys" {
			continue
		}
		xsysVersion = fields[1]
		break
	}
	if xsysVersion == "" {
		t.Fatal("golang.org/x/sys not found in go.mod")
	}

	maj, min, patch := parseSemver(t, xsysVersion)
	if semverLT(maj, min, patch, 0, 44, 0) {
		t.Fatalf("golang.org/x/sys version too old: %s (need >= v0.44.0 for GO-2026-5024 fix)", xsysVersion)
	}
}
