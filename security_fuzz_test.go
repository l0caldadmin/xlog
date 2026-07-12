package xlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mudler/xlog"
)

// FuzzLogging_EncodingAndControlChars exercises encoding/control-char edge cases
// across JSON and default handlers, ensuring JSON lines remain parseable and
// default output does not leak raw ESC bytes.
func FuzzLogging_EncodingAndControlChars(f *testing.F) {
	seeds := []struct {
		msg string
		key string
		val string
	}{
		{"hello", "k", "v"},
		{"empty-key", "", "v"},
		{"\x1b[31mred\x1b[0m", "token", "abc"},
		{"msg", "\x1b[31muser_id", "42"},
		{"line1\nline2\rline3", "payload", "\x00null"},
		{"emoji-🙂-漢字", "€", "\x1b]title\x07"},
		{"quote-\"}-malicious", "json", `\"} injected`},
	}
	for _, s := range seeds {
		f.Add(s.msg, s.key, s.val)
	}

	f.Fuzz(func(t *testing.T, msg, key, val string) {
		// JSON handler must always produce valid JSON objects.
		var jsonBuf bytes.Buffer
		jh := xlog.NewHandler(xlog.JSONFormat, &jsonBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
		rJSON := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
		rJSON.AddAttrs(slog.String(key, val))
		if err := jh.Handle(context.Background(), rJSON); err != nil {
			t.Fatalf("json handle error: %v", err)
		}
		payload := strings.TrimSpace(jsonBuf.String())
		if payload == "" {
			t.Fatalf("json output is empty")
		}

		dec := json.NewDecoder(strings.NewReader(payload))
		count := 0
		for {
			var parsed map[string]any
			err := dec.Decode(&parsed)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("invalid json output: %v; payload=%q", err, payload)
			}
			count++
		}
		if count == 0 {
			t.Fatalf("no json objects decoded from payload: %q", payload)
		}

		// Build a fresh record for the text handler to avoid cross-handler state sharing.
		var defaultBuf bytes.Buffer
		dh := xlog.NewHandler(xlog.TextFormat, &defaultBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
		rText := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
		rText.AddAttrs(slog.String(key, val))
		if err := dh.Handle(context.Background(), rText); err != nil {
			t.Fatalf("text handle error: %v", err)
		}

		out := defaultBuf.String()
		hasEscInput := strings.ContainsRune(msg, '\x1b') ||
			strings.ContainsRune(key, '\x1b') ||
			strings.ContainsRune(val, '\x1b')
		if hasEscInput && strings.ContainsRune(out, '\x1b') {
			t.Fatalf("raw ESC byte leaked into text output for ESC-bearing input: %q", out)
		}
	})
}
