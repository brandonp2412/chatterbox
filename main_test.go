package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestLogFilterRedactsPII(t *testing.T) {
	var output bytes.Buffer
	log := zerolog.New(&logFilter{out: &output, redactPII: true})

	log.Info().
		Str("text", "Email Alice at alice@example.com or +64 21 123 4567").
		Int64("tid", 123456789).
		Str("status", "contact https://example.com/users/alice").
		Str("operation", "received message").
		Msg("new message")

	got := output.String()
	for _, secret := range []string{"Alice", "alice@example.com", "+64 21 123 4567", "123456789", "https://example.com/users/alice"} {
		if strings.Contains(got, secret) {
			t.Errorf("log contains PII %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, `"operation":"received message"`) || !strings.Contains(got, `"message":"new message"`) {
		t.Errorf("log lost non-PII diagnostic context: %s", got)
	}
}

func TestLogFilterKeepsPIIAtDebugLogLevel(t *testing.T) {
	var output bytes.Buffer
	log := zerolog.New(&logFilter{out: &output, redactPII: false}).Level(zerolog.DebugLevel)

	log.Info().Str("name", "Alice Example").Int64("tid", 123456789).Msg("new message")

	got := output.String()
	if !strings.Contains(got, "Alice Example") || !strings.Contains(got, "123456789") {
		t.Errorf("debug-level logging unexpectedly obscured PII: %s", got)
	}
}

func TestLogFilterRedactsNestedDependencyData(t *testing.T) {
	var output bytes.Buffer
	log := zerolog.New(&logFilter{out: &output, redactPII: true})

	log.Error().Interface("payload", map[string]any{
		"sender_jid": "123456789@s.whatsapp.net",
		"thread_key": 99887766,
		"details": map[string]any{
			"email": "alice@example.com",
			"state": "failed",
		},
	}).Msg("dependency failed")

	got := output.String()
	for _, secret := range []string{"123456789", "99887766", "alice@example.com"} {
		if strings.Contains(got, secret) {
			t.Errorf("nested dependency log contains PII %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, `"state":"failed"`) {
		t.Errorf("nested dependency log lost non-PII context: %s", got)
	}
}
