package suritaptraefik

import (
	"context"
	"log/slog"
)

// FuncHandler is a slog.Handler forwarding records to a function, so the
// host proxy can route the adapter's logs into its own logger with the
// right levels (Traefik: zerolog).
type FuncHandler func(level slog.Level, msg string, attrs []slog.Attr)

func (h FuncHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h FuncHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	h(r.Level, r.Message, attrs)
	return nil
}

func (h FuncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return FuncHandler(func(level slog.Level, msg string, more []slog.Attr) {
		h(level, msg, append(append([]slog.Attr(nil), attrs...), more...))
	})
}

func (h FuncHandler) WithGroup(string) slog.Handler { return h }
