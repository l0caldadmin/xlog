package xlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
	colorCyan   = "\033[36m"
)

// stripANSI removes ANSI/VT100 escape sequences from s using a byte-scanning
// state machine (CWE-116). No regex is used; the logic is fully enumerable:
//
//	CSI  ESC '['  — consume until a final byte in [0x40, 0x7E].
//	OSC  ESC ']'  — consume until BEL (0x07) or ST (ESC '\').
//	Malformed     — remove only ESC and keep following bytes as plain text.
func stripANSI(s string) string {
	if !strings.ContainsRune(s, '\x1b') {
		return s // fast path — nothing to strip
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\x1b' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// ESC found. Try to consume a complete known sequence.
		if i+1 >= len(s) {
			break // trailing ESC only
		}

		next := s[i+1]
		swallowed := false

		switch next {
		case '[': // CSI: params/intermediates [0x20,0x3F]* then final [0x40,0x7E]
			j := i + 2
			for j < len(s) {
				c := s[j]
				if c >= 0x40 && c <= 0x7e {
					i = j + 1
					swallowed = true
					break
				}
				if c < 0x20 || c > 0x3f {
					// Malformed CSI: ESC '[' and consumed parameter bytes were already
					// interpreted as control sequence bytes. Preserve only the first
					// non-CSI byte and onward.
					i = j
					swallowed = true
					break
				}
				j++
			}
			if !swallowed && j >= len(s) {
				// Truncated CSI at end: consume sequence bytes through end.
				i = j
				swallowed = true
			}
		case ']': // OSC: terminated by BEL or ST (ESC '\\')
			j := i + 2
			for j < len(s) {
				if s[j] == '\x07' {
					i = j + 1
					swallowed = true
					break
				}
				if s[j] == '\x1b' {
					if j+1 < len(s) && s[j+1] == '\\' {
						i = j + 2
						swallowed = true
					}
					break // malformed ESC-in-OSC or ST handled above
				}
				j++
			}
		}

		if swallowed {
			continue
		}

		// Malformed/unknown sequence: drop only ESC, keep following bytes.
		i++
	}
	return b.String()
}

// sanitize strips ANSI escape sequences and escapes embedded newlines/carriage
// returns from user-supplied strings, preventing terminal log injection (CWE-116, CWE-117).
func sanitize(s string) string {
	s = stripANSI(s)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

type colorTextHandler struct {
	opts   slog.HandlerOptions
	w      io.Writer
	mu     *sync.Mutex
	attrs  []slog.Attr
	groups []string
}

func newColorTextHandler(w io.Writer, opts *slog.HandlerOptions) *colorTextHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &colorTextHandler{
		opts:   *opts,
		w:      w,
		mu:     &sync.Mutex{},
		attrs:  []slog.Attr{},
		groups: []string{},
	}
}

func (h *colorTextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *colorTextHandler) Handle(ctx context.Context, r slog.Record) error {
	var buf strings.Builder

	// Format timestamp in human-readable format
	timestamp := r.Time.Format("Jan 02 15:04:05")
	buf.WriteString(colorGray)
	buf.WriteString(timestamp)
	buf.WriteString(colorReset)
	buf.WriteString(" ")

	// Format level with color
	levelStr := h.formatLevel(r.Level)
	buf.WriteString(levelStr)
	buf.WriteString(" ")

	// Format message — sanitize to prevent terminal log injection (CWE-116, CWE-117).
	buf.WriteString(sanitize(r.Message))

	// Format source location if available
	if r.PC != 0 && h.opts.AddSource {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		if f.File != "" {
			file := filepath.Base(f.File)
			buf.WriteString(" ")
			buf.WriteString(colorGray)
			buf.WriteString(fmt.Sprintf("[%s:%d]", file, f.Line))
			buf.WriteString(colorReset)
		}
	}

	// Format attributes
	if len(h.attrs) > 0 || r.NumAttrs() > 0 {
		buf.WriteString(" ")
	}

	// Write pre-attached attributes
	for _, attr := range h.attrs {
		h.formatAttr(&buf, attr, h.groups)
	}

	// Write record attributes
	r.Attrs(func(a slog.Attr) bool {
		h.formatAttr(&buf, a, h.groups)
		return true
	})

	buf.WriteString("\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write([]byte(buf.String()))
	return err
}

func (h *colorTextHandler) formatLevel(level slog.Level) string {
	var color, levelStr string
	switch {
	case level >= slog.LevelError:
		color = colorRed
		levelStr = "ERROR"
	case level >= slog.LevelWarn:
		color = colorYellow
		levelStr = "WARN "
	case level >= slog.LevelInfo:
		color = colorBlue
		levelStr = "INFO "
	default:
		color = colorGray
		levelStr = "DEBUG"
	}
	return fmt.Sprintf("%s%s%s", color, levelStr, colorReset)
}

func (h *colorTextHandler) formatAttr(buf *strings.Builder, attr slog.Attr, groups []string) {
	if h.opts.ReplaceAttr != nil {
		attr = h.opts.ReplaceAttr(groups, attr)
		if attr.Key == "" {
			return
		}
	}

	key := attr.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}
	key = sanitize(key)

	buf.WriteString(colorCyan)
	buf.WriteString(key)
	buf.WriteString(colorReset)
	buf.WriteString("=")

	value := attr.Value
	if value.Kind() == slog.KindGroup {
		buf.WriteString("{")
		first := true
		for _, a := range value.Group() {
			if !first {
				buf.WriteString(" ")
			}
			h.formatAttr(buf, a, append(groups, key))
			first = false
		}
		buf.WriteString("}")
	} else {
		buf.WriteString(sanitize(h.formatValue(value)))
	}
	buf.WriteString(" ")
}

func (h *colorTextHandler) formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return fmt.Sprintf("%q", v.String())
	case slog.KindInt64:
		return fmt.Sprintf("%d", v.Int64())
	case slog.KindUint64:
		return fmt.Sprintf("%d", v.Uint64())
	case slog.KindFloat64:
		return fmt.Sprintf("%g", v.Float64())
	case slog.KindBool:
		return fmt.Sprintf("%t", v.Bool())
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindAny:
		return fmt.Sprintf("%v", v.Any())
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (h *colorTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &colorTextHandler{
		opts:   h.opts,
		w:      h.w,
		mu:     h.mu,
		attrs:  append(h.attrs, attrs...),
		groups: h.groups,
	}
}

func (h *colorTextHandler) WithGroup(name string) slog.Handler {
	return &colorTextHandler{
		opts:   h.opts,
		w:      h.w,
		mu:     h.mu,
		attrs:  h.attrs,
		groups: append(h.groups, name),
	}
}
