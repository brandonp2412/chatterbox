package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-meta/pkg/messagix/table"
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

func TestGenericThreadNeedsClassificationUntilMarketplaceEvidenceArrives(t *testing.T) {
	b := &bot{
		log:                      zerolog.Nop(),
		threadTypes:              make(map[int64]table.ThreadType),
		authoritativeThreadTypes: make(map[int64]bool),
		awaitingContent:          make(map[int64]*awaitingContentState),
	}
	const threadID = int64(1234)

	b.recordThreadTypes(&table.LSTable{
		LSVerifyThreadExists: []*table.LSVerifyThreadExists{{ThreadKey: threadID, ThreadType: table.GROUP_THREAD}},
	})
	if !b.threadNeedsClassification(threadID) {
		t.Fatal("generic LSVerifyThreadExists was treated as authoritative")
	}

	// A full row can still use GROUP_THREAD for a Marketplace inquiry, so it must not stop
	// classification recovery by itself.
	b.recordThreadTypes(&table.LSTable{
		LSDeleteThenInsertThread: []*table.LSDeleteThenInsertThread{{ThreadKey: threadID, ThreadType: table.GROUP_THREAD}},
	})
	if !b.threadNeedsClassification(threadID) {
		t.Fatal("generic full row was treated as proof that the thread is not Marketplace")
	}

	b.recordThreadTypes(&table.LSTable{
		LSInsertAttachmentCta: []*table.LSInsertAttachmentCta{{
			ThreadKey: threadID,
			Type_:     "marketplace_xma_call_function",
		}},
	})
	if !b.marketplaceThread(threadID) {
		t.Fatal("Marketplace CTA did not reclassify the generic thread")
	}
	if b.threadNeedsClassification(threadID) {
		t.Fatal("Marketplace-classified thread still requests classification")
	}
}

func TestClassificationResponseHelpers(t *testing.T) {
	const threadID = int64(5678)

	generic := &table.LSTable{
		LSDeleteThenInsertThread: []*table.LSDeleteThenInsertThread{{ThreadKey: threadID, ThreadType: table.GROUP_THREAD}},
	}
	if responseConfirmsNonMarketplace(generic, threadID) {
		t.Fatal("generic full row was treated as confirmed non-Marketplace")
	}
	if responseClassifiesMarketplace(generic, threadID) {
		t.Fatal("generic full row was treated as Marketplace")
	}

	marketplace := &table.LSTable{
		LSInsertAttachmentCta: []*table.LSInsertAttachmentCta{{
			ThreadKey: threadID,
			Type_:     "marketplace_xma_call_function",
		}},
	}
	if !responseClassifiesMarketplace(marketplace, threadID) {
		t.Fatal("Marketplace CTA was not recognized")
	}

	oneToOne := &table.LSTable{
		LSUpdateOrInsertThread: []*table.LSUpdateOrInsertThread{{ThreadKey: threadID, ThreadType: table.ONE_TO_ONE}},
	}
	if !responseConfirmsNonMarketplace(oneToOne, threadID) {
		t.Fatal("authoritative one-to-one thread was not confirmed non-Marketplace")
	}
}

func TestCurrentInboundMessageArmsGenericThreadClassification(t *testing.T) {
	now := time.Now()
	b := &bot{
		log:                      zerolog.Nop(),
		userID:                   99,
		startTime:                now,
		threadTypes:              map[int64]table.ThreadType{1234: table.GROUP_THREAD},
		authoritativeThreadTypes: make(map[int64]bool),
		awaitingContent:          make(map[int64]*awaitingContentState),
	}

	b.processMessage(context.Background(), &table.WrappedMessage{
		LSInsertMessage: &table.LSInsertMessage{
			ThreadKey:   1234,
			SenderId:    42,
			TimestampMs: now.UnixMilli(),
			Text:        "Is this available?",
		},
	})

	b.awaitingContentMu.Lock()
	state := b.awaitingContent[1234]
	b.awaitingContentMu.Unlock()
	if state == nil || !state.needsClassification {
		t.Fatal("current inbound message did not arm generic-thread classification")
	}
}

func TestMarketplaceGreetingFallback(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name        string
		text        string
		threadType  table.ThreadType
		senderID    int64
		timestampMs int64
		want        bool
	}{
		{
			name:        "exact standard greeting",
			text:        "Hi, is this available?",
			threadType:  table.GROUP_THREAD,
			senderID:    42,
			timestampMs: now.UnixMilli(),
			want:        true,
		},
		{
			name:        "emoji suffix",
			text:        "Hi, is this available? 😊",
			threadType:  table.GROUP_THREAD,
			senderID:    42,
			timestampMs: now.UnixMilli(),
			want:        true,
		},
		{
			name:        "phrase contained later",
			text:        "Hello! Hi, is this available? Thanks",
			threadType:  table.GROUP_THREAD,
			senderID:    42,
			timestampMs: now.UnixMilli(),
			want:        true,
		},
		{
			name:        "case sensitive",
			text:        "Hi, is this Available?",
			threadType:  table.GROUP_THREAD,
			senderID:    42,
			timestampMs: now.UnixMilli(),
			want:        false,
		},
		{
			name:        "established personal thread",
			text:        "Hi, is this available?",
			threadType:  table.ONE_TO_ONE,
			senderID:    42,
			timestampMs: now.UnixMilli(),
			want:        false,
		},
		{
			name:        "message from self",
			text:        "Hi, is this available?",
			threadType:  table.GROUP_THREAD,
			senderID:    99,
			timestampMs: now.UnixMilli(),
			want:        false,
		},
		{
			name:        "old backlog message",
			text:        "Hi, is this available?",
			threadType:  table.GROUP_THREAD,
			senderID:    42,
			timestampMs: now.Add(-3 * time.Minute).UnixMilli(),
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &bot{
				userID:                   99,
				startTime:                now,
				threadTypes:              map[int64]table.ThreadType{1234: tc.threadType},
				authoritativeThreadTypes: make(map[int64]bool),
			}
			msg := &table.WrappedMessage{LSInsertMessage: &table.LSInsertMessage{
				ThreadKey:   1234,
				SenderId:    tc.senderID,
				TimestampMs: tc.timestampMs,
				Text:        tc.text,
			}}

			if got := b.classifyMarketplaceGreeting(msg); got != tc.want {
				t.Fatalf("classifyMarketplaceGreeting() = %v, want %v", got, tc.want)
			}
			if tc.want && !b.marketplaceThread(1234) {
				t.Fatal("successful fallback did not persist Marketplace classification")
			}
		})
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

func TestParseArgs(t *testing.T) {
	opts, err := parseArgs([]string{"--dev", "--test", "123", "--dev-contact", "456", "custom.yaml"})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if !opts.selfTest || opts.testThread != 123 || opts.cfgPath != "custom.yaml" || !opts.devContactIDs[456] {
		t.Fatalf("unexpected parsed options: %+v", opts)
	}

	for _, args := range [][]string{
		{"--unknown"},
		{"--test", "0"},
		{"--test", "nope"},
		{"--dev-contact", "-4"},
		{"one.yaml", "two.yaml"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q) unexpectedly succeeded", args)
		}
	}
}

func TestLoadConfigAppliesDefaultsAndTightensPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "rules:\n  - pattern: hello\n    reply: hi\n"
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.Mode != "facebook" || cfg.LogLevel != "info" || !cfg.ReplyOnce || cfg.ReplyCooldownMinutes != 5 || cfg.ReconnectIntervalMinutes != 360 {
		t.Fatalf("documented defaults not applied: %+v", cfg)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config permissions = %o, want 600", got)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "rules:\n  - pattern: hello\n    reply: hi\nreply_onse: true\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig() accepted an unknown config field")
	}
}

func TestLoadConfigAllowsDeepseekOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("deepseek_key: test-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.DeepseekKey != "test-key" || len(cfg.Rules) != 0 {
		t.Fatalf("unexpected DeepSeek-only config: %+v", cfg)
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	for name, contents := range map[string]string{
		"bad log level":      "deepseek_key: x\nlog_level: noisy\n",
		"negative cooldown":  "deepseek_key: x\nreply_cooldown_minutes: -1\n",
		"negative reconnect": "deepseek_key: x\nreconnect_interval_minutes: -1\n",
		"empty pattern":      "rules:\n  - pattern: ''\n    reply: hi\n",
		"empty reply":        "rules:\n  - pattern: hello\n    reply: ''\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("loadConfig() unexpectedly accepted invalid configuration")
			}
		})
	}
}

func TestRepliedMessageDedupIsBounded(t *testing.T) {
	b := &bot{repliedMsgIDs: make(map[string]struct{})}
	for i := 0; i < maxRepliedMessageIDs+25; i++ {
		b.markReplied(fmt.Sprintf("message-%d", i))
	}
	if got := len(b.repliedMsgIDs); got != maxRepliedMessageIDs {
		t.Fatalf("dedup cache size = %d, want %d", got, maxRepliedMessageIDs)
	}
	if b.alreadyReplied("message-0") {
		t.Fatal("oldest dedup entry was not evicted")
	}
	if !b.alreadyReplied(fmt.Sprintf("message-%d", maxRepliedMessageIDs+24)) {
		t.Fatal("newest dedup entry was unexpectedly missing")
	}
}

func TestProcessTableHandlesNil(t *testing.T) {
	b := &bot{log: zerolog.Nop()}
	b.processTable(context.Background(), nil)
}

func TestSleepContextCancelsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepContext(ctx, time.Hour) {
		t.Fatal("sleepContext reported completion after cancellation")
	}
}

func TestWorkLoopRecoversTaskPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &bot{
		log:  zerolog.Nop(),
		ctx:  ctx,
		work: make(chan func(), 2),
	}
	done := make(chan struct{})
	go b.workLoop()
	b.enqueue(func() { panic("test panic") })
	b.enqueue(func() { close(done) })

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker stopped after a task panic")
	}
}

func TestLoadUserThreads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user_threads.txt")
	if err := os.WriteFile(path, []byte("42\n7\n42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	threads, err := loadUserThreads(path)
	if err != nil {
		t.Fatalf("loadUserThreads() error = %v", err)
	}
	if len(threads) != 2 || !threads[42] || !threads[7] {
		t.Fatalf("unexpected persisted thread set: %v", threads)
	}
}

func TestLoadRepliedRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replied_rules.json")
	if err := os.WriteFile(path, []byte(`{"42":{"(?i)hello":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	replied, err := loadRepliedRules(path)
	if err != nil {
		t.Fatalf("loadRepliedRules() error = %v", err)
	}
	if !replied[42]["(?i)hello"] {
		t.Fatalf("persisted rule state not restored: %v", replied)
	}
}
