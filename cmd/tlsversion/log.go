package main

import (
	"io"
	"log/slog"
)

// newAnalyticsHandler returns the handler for the per-request analytics log.
// It emits JSON so GKE's logging agent parses each line into jsonPayload.*
// fields that Cloud Logging Log Analytics queries as columns, rather than the
// opaque textPayload string a text handler would produce. The two slog
// built-in keys are renamed to the names Cloud Logging promotes to LogEntry
// fields — msg -> message, level -> severity — which is what lets a sink
// filter on jsonPayload.message="request" to isolate these lines from the
// log.Printf operator noise on the same stderr. slog's "time" key is already
// recognized as the entry timestamp.
func newAnalyticsHandler(w io.Writer) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.MessageKey:
				a.Key = "message"
			case slog.LevelKey:
				a.Key = "severity"
			}
			return a
		},
	})
}
