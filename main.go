package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"go.mau.fi/whatsmeow"
	waCommon "go.mau.fi/whatsmeow/proto/waCommon"
	waConsumer "go.mau.fi/whatsmeow/proto/waConsumerApplication"
	waTypes "go.mau.fi/whatsmeow/types"
	waEvents "go.mau.fi/whatsmeow/types/events"
	pro "google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-meta/pkg/messagix"
	"go.mau.fi/mautrix-meta/pkg/messagix/cookies"
	"go.mau.fi/mautrix-meta/pkg/messagix/methods"
	"go.mau.fi/mautrix-meta/pkg/messagix/socket"
	"go.mau.fi/mautrix-meta/pkg/messagix/table"
	"go.mau.fi/mautrix-meta/pkg/messagix/types"
	"go.mau.fi/util/exhttp"
)

type rule struct {
	Pattern  string `yaml:"pattern"`
	Reply    string `yaml:"reply"`
	compiled *regexp.Regexp
}

type config struct {
	Cookies                  map[string]string `yaml:"cookies"`
	Rules                    []rule            `yaml:"rules"`
	ReplyOnce                bool              `yaml:"reply_once"`
	ReplyCooldownMinutes     int               `yaml:"reply_cooldown_minutes"`
	Mode                     string            `yaml:"mode"`
	Proxy                    string            `yaml:"proxy"`
	LogLevel                 string            `yaml:"log_level"`
	DeepseekKey              string            `yaml:"deepseek_key"`
	ReconnectIntervalMinutes int               `yaml:"reconnect_interval_minutes"`
}

type logFilter struct {
	out       io.Writer
	redactPII bool
}

func (f *logFilter) Write(p []byte) (n int, err error) {
	if f.skip(p) {
		return len(p), nil
	}
	return f.write(p, zerolog.NoLevel)
}

func (f *logFilter) WriteLevel(lvl zerolog.Level, p []byte) (n int, err error) {
	if f.skip(p) {
		return len(p), nil
	}
	return f.write(p, lvl)
}

func (f *logFilter) write(p []byte, lvl zerolog.Level) (n int, err error) {
	output := p
	if f.redactPII {
		output = redactLogPII(p)
	}

	// Writers conventionally report the number of input bytes consumed. Redaction changes the
	// output length, but the complete original event was handled even when its replacement is
	// shorter.
	var writeErr error
	if lw, ok := f.out.(zerolog.LevelWriter); ok {
		_, writeErr = lw.WriteLevel(lvl, output)
	} else {
		_, writeErr = f.out.Write(output)
	}
	return len(p), writeErr
}

var skipPatterns = [][]byte{
	[]byte("Skipping dependency with no reference"),
	[]byte("Failed to set int64"),
}

func (f *logFilter) skip(p []byte) bool {
	for _, pat := range skipPatterns {
		if bytes.Contains(p, pat) {
			return true
		}
	}
	return false
}

const redactedLogValue = "[REDACTED]"

var piiKeyParts = []string{
	"account", "address", "auth", "chat", "contact", "cookie", "email", "jid",
	"location", "name", "password", "phone", "reply", "secret", "sender", "text",
	"thread", "token", "url", "uri", "user",
}

var piiValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
	regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s"']+`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Z0-9._~+/=-]+`),
	regexp.MustCompile(`(?:\+?\d[\d ()-]{6,}\d)`),
}

// redactLogPII operates on the structured zerolog event before ConsoleWriter renders it. This
// covers application and dependency logs at one boundary, including nested dependency payloads.
func redactLogPII(p []byte) []byte {
	decoder := json.NewDecoder(bytes.NewReader(p))
	decoder.UseNumber()
	var event any
	if err := decoder.Decode(&event); err != nil {
		return []byte(redactPIIInString(string(p)))
	}

	event = redactPIIValue("", event)
	redacted, err := json.Marshal(event)
	if err != nil {
		return []byte(redactPIIInString(string(p)))
	}
	if bytes.HasSuffix(p, []byte("\n")) {
		redacted = append(redacted, '\n')
	}
	return redacted
}

func redactPIIValue(key string, value any) any {
	if isPIIKey(key) {
		return redactedLogValue
	}
	switch value := value.(type) {
	case map[string]any:
		for childKey, childValue := range value {
			value[childKey] = redactPIIValue(childKey, childValue)
		}
		return value
	case []any:
		for i, childValue := range value {
			value[i] = redactPIIValue(key, childValue)
		}
		return value
	case string:
		// Altering zerolog's standard metadata can make ConsoleWriter reject the event.
		if key == zerolog.TimestampFieldName || key == zerolog.LevelFieldName {
			return value
		}
		return redactPIIInString(value)
	default:
		return value
	}
}

func isPIIKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if normalized == "id" || normalized == "ip" || normalized == "sid" ||
		normalized == "tid" || normalized == "source" || normalized == "subtitle" ||
		normalized == "title" || normalized == "error" || normalized == "reason" ||
		normalized == "body" || normalized == "content" ||
		strings.HasSuffix(normalized, "id") || strings.HasSuffix(normalized, "_ip") {
		return true
	}
	for _, part := range piiKeyParts {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func redactPIIInString(value string) string {
	for _, pattern := range piiValuePatterns {
		value = pattern.ReplaceAllString(value, redactedLogValue)
	}
	return value
}

var defaultRules = []rule{
	{Pattern: `(?i)(?:is this|still)\s+available`, Reply: "Yes, are you interested?"},
	{Pattern: `(?i)(?:price|how much|cost)`, Reply: "The price is firm as listed in the ad."},
	{Pattern: `(?i)(?:condition|used|new)`, Reply: "It's in good condition. Let me know if you'd like more photos."},
}

const marketplaceAvailabilityGreeting = "Hi, is this available?"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "chatterbox: %v\n", err)
		os.Exit(1)
	}
}

type cliOptions struct {
	selfTest      bool
	cfgPath       string
	testThread    int64
	devContactIDs map[int64]bool
}

func parseArgs(args []string) (cliOptions, error) {
	opts := cliOptions{
		cfgPath:       "config.yaml",
		devContactIDs: make(map[int64]bool),
	}
	configPathSet := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dev":
			opts.selfTest = true
		case a == "--test":
			i++
			if i >= len(args) {
				return cliOptions{}, fmt.Errorf("--test requires a thread ID")
			}
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || v <= 0 {
				return cliOptions{}, fmt.Errorf("invalid thread ID %q: must be a positive integer", args[i])
			}
			opts.testThread = v
		case a == "--dev-contact":
			i++
			if i >= len(args) {
				return cliOptions{}, fmt.Errorf("--dev-contact requires a contact/sender ID")
			}
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || v <= 0 {
				return cliOptions{}, fmt.Errorf("invalid contact ID %q: must be a positive integer", args[i])
			}
			opts.devContactIDs[v] = true
		case strings.HasPrefix(a, "-"):
			return cliOptions{}, fmt.Errorf("unknown option %q", a)
		default:
			if configPathSet {
				return cliOptions{}, fmt.Errorf("multiple config paths provided: %q and %q", opts.cfgPath, a)
			}
			opts.cfgPath = a
			configPathSet = true
		}
	}
	return opts, nil
}

func run() error {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	selfTest := opts.selfTest
	cfgPath := opts.cfgPath
	testThread := opts.testThread
	devContactIDs := opts.devContactIDs

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	for i := range cfg.Rules {
		re, err := regexp.Compile(cfg.Rules[i].Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", cfg.Rules[i].Pattern, err)
		}
		cfg.Rules[i].compiled = re
	}

	lvl, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	if selfTest && lvl < zerolog.DebugLevel {
		lvl = zerolog.DebugLevel
	}
	redactPII := lvl > zerolog.DebugLevel
	log := zerolog.New(&logFilter{
		out:       zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "3:04PM"},
		redactPII: redactPII,
	}).Level(lvl).With().Timestamp().Logger()
	// messagix/whatsmeow are noisy at info/debug (socket internals, keepalives, dependency
	// parsing) and that noise isn't ours to fix, so normally only their warnings/errors are
	// surfaced. Set log_level to "debug" (or lower) in config.yaml to see their raw traffic
	// too - useful for diagnosing messages that go missing between a healthy-looking socket
	// and the bot's own handlers.
	libLog := log.Level(zerolog.WarnLevel)
	if lvl <= zerolog.DebugLevel {
		libLog = log
	}
	// Some messagix internals (e.g. lightspeed/decode.go) log through zerolog's package-level
	// global logger instead of the client-supplied one, bypassing libLog entirely. Route that
	// through the same filtered writer and cap it at error level - its warnings are routine
	// dependency-parsing noise, not something we can act on.
	zlog.Logger = zlog.Logger.Output(&logFilter{
		out:       zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "3:04PM"},
		redactPII: redactPII,
	}).Level(zerolog.ErrorLevel)

	mode := types.PlatformFromString(cfg.Mode)
	if mode == types.Unset {
		return fmt.Errorf("unknown mode: %q (valid: facebook, messenger, messenger-lite)", cfg.Mode)
	}

	c := &cookies.Cookies{Platform: mode}
	cookieMap := make(map[cookies.MetaCookieName]string)
	for k, v := range cfg.Cookies {
		cookieMap[cookies.MetaCookieName(k)] = v
	}
	c.UpdateValues(cookieMap)

	missing := c.GetMissingCookieNames()
	if len(missing) > 0 {
		return fmt.Errorf("missing required cookies: %v", missing)
	}

	clientSettings := exhttp.ClientSettings{}
	if cfg.Proxy != "" {
		clientSettings, err = clientSettings.WithProxy(cfg.Proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy %q: %w", cfg.Proxy, err)
		}
	}
	mc := messagix.NewClient(c, libLog, &messagix.Config{
		ClientSettings: clientSettings,
	})

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	var userInfo types.UserInfo
	var initialTable *table.LSTable
	if state, readErr := os.ReadFile(connStateFile); readErr == nil {
		if loadErr := mc.LoadState(state); loadErr != nil {
			log.Warn().Err(loadErr).Msg("cached connection state unusable, doing full login")
		} else if info, acctErr := mc.GetCurrentAccount(); acctErr != nil {
			log.Warn().Err(acctErr).Msg("no account in cached connection state, doing full login")
		} else if strconv.FormatInt(info.GetFBID(), 10) != cfg.Cookies["c_user"] {
			log.Warn().Int64("cached_id", info.GetFBID()).Msg("cached connection state is for a different account, doing full login")
		} else {
			userInfo = info
			log.Info().Msg("resumed from cached connection state")
		}
	}
	if userInfo == nil {
		userInfo, initialTable, err = mc.LoadMessagesPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to load messages page: %w", err)
		}
	}
	log.Info().Str("name", userInfo.GetName()).Int64("id", userInfo.GetFBID()).Msg("Logged in")

	devContainer, err := openDeviceStore(ctx, log, "device.db")
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer devContainer.Close()

	dev, err := getOrCreateDevice(ctx, log, devContainer)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	isNew := dev.ID == nil
	mc.SetDevice(dev)

	if isNew {
		log.Info().Msg("registering new e2ee device")
		err = mc.RegisterE2EE(ctx, userInfo.GetFBID())
		if err != nil {
			return fmt.Errorf("failed to register e2ee: %w", err)
		}
		if err := dev.Save(ctx); err != nil {
			return fmt.Errorf("failed to save e2ee device: %w", err)
		}
	}

	waClient, err := mc.PrepareE2EEClient()
	if err != nil {
		return fmt.Errorf("failed to prepare e2ee client: %w", err)
	}

	deepseekKey := cfg.DeepseekKey

	replyCooldown := time.Duration(cfg.ReplyCooldownMinutes) * time.Minute
	if replyCooldown <= 0 {
		replyCooldown = 5 * time.Minute
	}

	selfSentOtids, err := loadSelfSentIDs(selfSentIDsFile)
	if err != nil {
		return fmt.Errorf("failed to load self-sent message ids: %w", err)
	}
	log.Info().Int("count", len(selfSentOtids)).Msg("loaded self-sent message ids")

	userThreads, err := loadUserThreads(userThreadsFile)
	if err != nil {
		return fmt.Errorf("failed to load user-participated threads: %w", err)
	}
	log.Info().Int("count", len(userThreads)).Msg("loaded user-participated threads")

	repliedRules, err := loadRepliedRules(repliedRulesFile)
	if err != nil {
		return fmt.Errorf("failed to load replied rules: %w", err)
	}
	log.Info().Int("count", len(repliedRules)).Msg("loaded replied-rule threads")

	bot := &bot{
		log:                      log,
		client:                   mc,
		waClient:                 waClient,
		rules:                    cfg.Rules,
		replyOnce:                cfg.ReplyOnce && !selfTest,
		replied:                  repliedRules,
		userID:                   userInfo.GetFBID(),
		selfTest:                 selfTest,
		startTime:                time.Now(),
		userThreads:              userThreads,
		lastReplyAt:              make(map[int64]time.Time),
		replyCooldown:            replyCooldown,
		selfSentOtids:            selfSentOtids,
		repliedMsgIDs:            make(map[string]struct{}),
		listings:                 make(map[int64]*listing),
		threadTypes:              make(map[int64]table.ThreadType),
		authoritativeThreadTypes: make(map[int64]bool),
		contactNames:             make(map[int64]string),
		devContacts:              devContactIDs,
		deepseekKey:              deepseekKey,
		httpClient:               clientSettings.WithGlobalTimeout(30 * time.Second).Compile(),
		awaitingContent:          make(map[int64]*awaitingContentState),
		ctx:                      ctx,
		cancel:                   cancel,
		runErr:                   make(chan error, 1),
		work:                     make(chan func(), 64),
	}

	bot.recordThreadTypes(initialTable)

	mc.SetEventHandler(bot.handleEvent)
	waClient.AddEventHandler(bot.e2eeHandler)

	go bot.workLoop()

	go func() {
		if err := mc.Connect(ctx); err != nil && ctx.Err() == nil {
			bot.fail(fmt.Errorf("failed to connect messenger socket: %w", err))
		}
	}()

	go func() {
		if err := waClient.Connect(); err != nil {
			log.Err(err).Msg("Failed to connect e2ee socket")
		}
	}()

	go bot.contentRecoveryLoop(ctx)

	// messagix already has its own ping/pong heartbeat (10s ping, 30s pong timeout) that
	// recovers ordinary dead connections on its own, and the Event_PermanentError handler
	// above now restarts the connection when the library's own reconnect loop gives up for
	// good. This ticker is just a last-resort safety net in case some failure mode slips
	// past both of those.
	reconnectInterval := time.Duration(cfg.ReconnectIntervalMinutes) * time.Minute
	if reconnectInterval <= 0 {
		reconnectInterval = 6 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(reconnectInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Debug().Msg("periodic proactive reconnect of messenger socket")
				mc.ForceReconnect()
			}
		}
	}()

	if testThread > 0 && sleepContext(ctx, 2*time.Second) {
		log.Info().Int64("thread", testThread).Msg("injecting test message")
		bot.enqueue(func() {
			bot.processMessage(ctx, &table.WrappedMessage{
				LSInsertMessage: &table.LSInsertMessage{
					Text:      "Is this available?",
					ThreadKey: testThread,
					SenderId:  bot.userID,
				},
			})
		})
	}

	var runErr error
	select {
	case runErr = <-bot.runErr:
		cancel()
	case <-ctx.Done():
		select {
		case runErr = <-bot.runErr:
		default:
		}
	}

	log.Info().Msg("Shutting down...")
	bot.saveConnState()
	mc.Disconnect()
	waClient.Disconnect()
	return runErr
}

type listing struct {
	Title       string
	Subtitle    string
	Description string
	Source      string
	ActionURL   string
}

type bot struct {
	log       zerolog.Logger
	client    *messagix.Client
	waClient  *whatsmeow.Client
	rules     []rule
	replyOnce bool
	replied   map[int64]map[string]bool
	userID    int64
	selfTest  bool

	ctx    context.Context
	cancel context.CancelFunc
	runErr chan error
	work   chan func()

	restartMu         sync.Mutex
	restartBackoff    time.Duration
	restartInProgress bool

	lastStateSave   time.Time
	lastStateSaveMu sync.Mutex

	startTime     time.Time
	userThreads   map[int64]bool
	userThreadsMu sync.Mutex
	lastReplyAt   map[int64]time.Time
	replyCooldown time.Duration
	repliedMu     sync.Mutex
	selfSentOtids map[string]bool
	selfSentMu    sync.Mutex

	// repliedMsgIDs guards against replying twice to the same inbound message (keyed by
	// "threadID:messageID"). Cooldown alone isn't enough: a socket reconnect can redeliver
	// an already-answered message as part of its backlog resync, well after the cooldown
	// on that thread has expired.
	repliedMsgIDs     map[string]struct{}
	repliedMsgIDOrder []string
	repliedMsgIDsMu   sync.Mutex

	listings    map[int64]*listing
	listingsMu  sync.RWMutex
	threadTypes map[int64]table.ThreadType
	// authoritativeThreadTypes distinguishes complete thread metadata from the generic
	// LSVerifyThreadExists hint. Meta reports new Marketplace inquiries as GROUP_THREAD in
	// that hint, so it is not safe to reject them until CreateThreadTask returns the full row.
	authoritativeThreadTypes map[int64]bool
	threadTypesMu            sync.RWMutex
	deepseekKey              string
	httpClient               *http.Client

	contactNames   map[int64]string
	contactNamesMu sync.RWMutex
	devContacts    map[int64]bool

	// awaitingContent tracks threads just classified MARKETPLACE via the quick-reply CTA that
	// haven't had a real (non-empty-text) message show up yet. Brand-new marketplace threads'
	// first message doesn't reliably arrive live over either the mc or e2ee socket - see
	// contentRecoveryLoop, which explicitly fetches these instead of waiting on a blind
	// reconnect timer. A single recovery attempt isn't always enough (observed live: the
	// resync it triggers doesn't always happen to include the thread being recovered), so this
	// tracks armedAt/attempts to retry a bounded number of times.
	awaitingContent   map[int64]*awaitingContentState
	awaitingContentMu sync.Mutex
}

// selfEchoGracePeriod bounds how long after we send a reply we'll treat any echo of our own
// message landing in that thread as ours, even if its ID doesn't match what we sent.
const selfEchoGracePeriod = 30 * time.Second

type awaitingContentState struct {
	armedAt             time.Time
	attempts            int
	needsClassification bool
}

const connStateFile = "conn_state.json"

func (b *bot) context() context.Context {
	if b.ctx != nil {
		return b.ctx
	}
	return context.Background()
}

func (b *bot) fail(err error) {
	if err == nil {
		return
	}
	if b.runErr != nil {
		select {
		case b.runErr <- err:
		default:
		}
	}
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *bot) enqueue(f func()) {
	ctx := b.context()
	select {
	case b.work <- f:
		return
	case <-ctx.Done():
		return
	default:
	}
	b.log.Warn().Msg("work queue full, library event delivery is blocked until it drains")
	select {
	case b.work <- f:
	case <-ctx.Done():
	}
}

func (b *bot) workLoop() {
	ctx := b.context()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-b.work:
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						b.log.Error().Err(fmt.Errorf("panic: %v", recovered)).Msg("worker task panicked")
					}
				}()
				f()
			}()
		}
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (b *bot) saveConnStateLocked() {
	state, err := b.client.DumpState()
	if err != nil {
		b.log.Err(err).Msg("failed to dump connection state")
		return
	}
	if state == nil {
		return
	}
	if err := writeFileAtomic(connStateFile, state, 0600); err != nil {
		b.log.Err(err).Msg("failed to persist connection state")
		return
	}
	b.lastStateSave = time.Now()
}

func (b *bot) saveConnState() {
	b.lastStateSaveMu.Lock()
	defer b.lastStateSaveMu.Unlock()
	b.saveConnStateLocked()
}

func (b *bot) maybeSaveConnState() {
	b.lastStateSaveMu.Lock()
	defer b.lastStateSaveMu.Unlock()
	if time.Since(b.lastStateSave) < time.Minute {
		return
	}
	b.saveConnStateLocked()
}

func (b *bot) restartMessenger() {
	b.restartMu.Lock()
	if b.restartInProgress {
		b.restartMu.Unlock()
		return
	}
	b.restartInProgress = true
	b.restartMu.Unlock()
	defer func() {
		b.restartMu.Lock()
		b.restartInProgress = false
		b.restartMu.Unlock()
	}()

	ctx := b.context()
	for ctx.Err() == nil {
		b.restartMu.Lock()
		if b.restartBackoff == 0 {
			b.restartBackoff = 5 * time.Second
		} else if b.restartBackoff < 5*time.Minute {
			b.restartBackoff *= 2
		}
		backoff := b.restartBackoff
		b.restartMu.Unlock()

		b.log.Error().Dur("retry_in", backoff).Msg("restarting messenger connection")
		if !sleepContext(ctx, backoff) {
			return
		}
		if err := b.client.Connect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			b.log.Err(err).Msg("failed to restart messenger connection, retrying")
			continue
		}
		return
	}
}

func (b *bot) recordThreadTypes(tbl *table.LSTable) {
	if tbl == nil {
		return
	}
	b.log.Debug().
		Int("delete_then_insert", len(tbl.LSDeleteThenInsertThread)).
		Int("update_or_insert", len(tbl.LSUpdateOrInsertThread)).
		Int("verify_exists", len(tbl.LSVerifyThreadExists)).
		Msg("recordThreadTypes called")

	set := func(source string, threadKey int64, tt table.ThreadType) {
		existing, known := b.threadTypes[threadKey]
		if known && existing != tt && tt == table.GROUP_THREAD && existing != table.GROUP_THREAD {
			// LSVerifyThreadExists and similar lightweight "thread exists" pings report the
			// generic GROUP_THREAD type even for threads we already know a more specific type
			// for (e.g. MARKETPLACE). Don't let that clobber the specific type we already have.
			b.log.Debug().
				Str("source", source).
				Int64("tid", threadKey).
				Int64("existing_type", int64(existing)).
				Int64("ignored_type", int64(tt)).
				Msg("ignoring generic GROUP_THREAD downgrade of known thread type")
			return
		}
		if known && existing != tt {
			b.log.Debug().
				Str("source", source).
				Int64("tid", threadKey).
				Int64("old_type", int64(existing)).
				Int64("new_type", int64(tt)).
				Msg("thread type changed")
		}
		b.threadTypes[threadKey] = tt
	}

	b.threadTypesMu.Lock()
	if b.authoritativeThreadTypes == nil {
		b.authoritativeThreadTypes = make(map[int64]bool)
	}
	for _, t := range tbl.LSDeleteThenInsertThread {
		set("LSDeleteThenInsertThread", t.ThreadKey, t.ThreadType)
		if t.ThreadType != table.GROUP_THREAD {
			b.authoritativeThreadTypes[t.ThreadKey] = true
		}
	}
	for _, t := range tbl.LSUpdateOrInsertThread {
		set("LSUpdateOrInsertThread", t.ThreadKey, t.ThreadType)
		if t.ThreadType != table.GROUP_THREAD {
			b.authoritativeThreadTypes[t.ThreadKey] = true
		}
	}
	for _, cta := range tbl.LSInsertAttachmentCta {
		// Brand new marketplace threads never get a LSDeleteThenInsertThread/LSUpdateOrInsertThread
		// event over the live socket - the only thread-type signal we ever see for them is the
		// generic LSVerifyThreadExists ping (ThreadType=GROUP_THREAD). Marketplace's own "quick
		// reply" CTAs (Yes / In talks / Not available) are only ever attached to marketplace
		// inquiry threads, so treat their presence as authoritative proof of MARKETPLACE type.
		if cta.Type_ == "marketplace_xma_call_function" {
			b.log.Debug().
				Str("source", "LSInsertAttachmentCta").
				Int64("tid", cta.ThreadKey).
				Str("cta_message_id", cta.MessageId).
				Msg("marking thread as marketplace from quick-reply CTA")
			b.threadTypes[cta.ThreadKey] = table.MARKETPLACE
			b.authoritativeThreadTypes[cta.ThreadKey] = true
			b.armContentRecovery(cta.ThreadKey)
		}
	}
	for _, t := range tbl.LSVerifyThreadExists {
		set("LSVerifyThreadExists", t.ThreadKey, t.ThreadType)
	}
	b.threadTypesMu.Unlock()
}

func (b *bot) armContentRecovery(threadKey int64) {
	b.awaitingContentMu.Lock()
	if state, exists := b.awaitingContent[threadKey]; exists {
		// A Marketplace CTA is authoritative. If this recovery started only to classify a
		// generic thread, keep it armed but switch it to ordinary missing-content recovery.
		state.needsClassification = false
	} else {
		b.awaitingContent[threadKey] = &awaitingContentState{armedAt: time.Now()}
	}
	b.awaitingContentMu.Unlock()
}

func (b *bot) armClassificationRecovery(threadKey int64) {
	b.awaitingContentMu.Lock()
	if _, exists := b.awaitingContent[threadKey]; !exists {
		b.awaitingContent[threadKey] = &awaitingContentState{
			armedAt:             time.Now(),
			needsClassification: true,
		}
	}
	b.awaitingContentMu.Unlock()
}

func (b *bot) clearContentRecovery(threadKey int64) {
	b.awaitingContentMu.Lock()
	delete(b.awaitingContent, threadKey)
	b.awaitingContentMu.Unlock()
}

const (
	contentRecoveryGracePeriod = 20 * time.Second
	contentRecoveryMaxAttempts = 3
)

// contentRecoveryLoop watches for threads that were marked MARKETPLACE by the quick-reply CTA
// but never got a real message delivered live over either the mc or e2ee socket - an observed
// gap specifically for brand-new marketplace threads. Once the grace period elapses it tries a
// targeted thread fetch (what messenger web does for a thread it only has a bare reference to),
// falling back to a full resync on the final attempt.
func (b *bot) contentRecoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var due []int64
		now := time.Now()
		b.awaitingContentMu.Lock()
		for tid, state := range b.awaitingContent {
			if now.Sub(state.armedAt) >= contentRecoveryGracePeriod {
				due = append(due, tid)
			}
		}
		b.awaitingContentMu.Unlock()
		for _, tid := range due {
			b.awaitingContentMu.Lock()
			state, exists := b.awaitingContent[tid]
			if !exists {
				b.awaitingContentMu.Unlock()
				continue
			}
			state.attempts++
			attempt := state.attempts
			needsClassification := state.needsClassification
			giveUp := attempt >= contentRecoveryMaxAttempts
			if giveUp {
				delete(b.awaitingContent, tid)
			} else {
				state.armedAt = time.Now()
			}
			b.awaitingContentMu.Unlock()

			b.recoverMissingMessages(ctx, tid, attempt, needsClassification)
			if giveUp {
				b.log.Error().Int64("tid", tid).Int("attempts", attempt).Msg("giving up recovering marketplace thread content after max attempts")
			}
		}
	}
}

// recoverMissingMessages surfaces a brand-new marketplace thread's first message when it
// doesn't arrive live over either socket. FetchMessagesTask (the real mautrix-meta bridge's
// backfill call) doesn't work here: it's pure backward pagination requiring a
// MinTimestampMs/MinMessageId anchor from a LSUpsertSyncGroupThreadsRange the thread already
// has, which a genuinely brand-new thread lacks. CreateThreadTask is what the bridge sends for
// threads it only has a bare LSVerifyThreadExists for, so try that first; the final attempt
// forces a full resync via reconnect, the one mechanism confirmed live to work.
func (b *bot) recoverMissingMessages(ctx context.Context, threadKey int64, attempt int, needsClassification bool) {
	if attempt >= contentRecoveryMaxAttempts {
		b.log.Warn().Int64("tid", threadKey).Int("attempt", attempt).Msg("no message content seen for new marketplace thread after grace period, forcing a resync")
		b.client.ForceReconnect()
		return
	}
	b.log.Warn().Int64("tid", threadKey).Int("attempt", attempt).Msg("no message content seen for new marketplace thread after grace period, requesting thread directly")
	resp, err := b.client.ExecuteTasks(ctx, &socket.CreateThreadTask{
		ThreadFBID:                threadKey,
		ForceUpsert:               0,
		UseOpenMessengerTransport: 0,
		SyncGroup:                 1,
		MetadataOnly:              0,
		PreviewOnly:               0,
	})
	if err != nil {
		b.log.Err(err).Int64("tid", threadKey).Msg("failed to fetch thread for content recovery")
		return
	}
	if resp == nil {
		return
	}
	if needsClassification {
		if responseClassifiesMarketplace(resp, threadKey) {
			b.awaitingContentMu.Lock()
			if state := b.awaitingContent[threadKey]; state != nil {
				state.needsClassification = false
			}
			b.awaitingContentMu.Unlock()
		} else if responseConfirmsNonMarketplace(resp, threadKey) {
			// The full row confirms this really is a normal Messenger thread. Stop the
			// recovery without ever feeding it to the auto-reply rules.
			b.clearContentRecovery(threadKey)
			b.log.Info().Int64("tid", threadKey).Msg("confirmed non-marketplace thread")
		}
	}
	b.enqueue(func() { b.processTable(b.ctx, resp) })
}

func responseConfirmsNonMarketplace(tbl *table.LSTable, threadKey int64) bool {
	for _, thread := range tbl.LSDeleteThenInsertThread {
		if thread.ThreadKey == threadKey && thread.ThreadType != table.GROUP_THREAD && thread.ThreadType != table.MARKETPLACE {
			return true
		}
	}
	for _, thread := range tbl.LSUpdateOrInsertThread {
		if thread.ThreadKey == threadKey && thread.ThreadType != table.GROUP_THREAD && thread.ThreadType != table.MARKETPLACE {
			return true
		}
	}
	return false
}

func responseClassifiesMarketplace(tbl *table.LSTable, threadKey int64) bool {
	for _, thread := range tbl.LSDeleteThenInsertThread {
		if thread.ThreadKey == threadKey && thread.ThreadType == table.MARKETPLACE {
			return true
		}
	}
	for _, thread := range tbl.LSUpdateOrInsertThread {
		if thread.ThreadKey == threadKey && thread.ThreadType == table.MARKETPLACE {
			return true
		}
	}
	for _, cta := range tbl.LSInsertAttachmentCta {
		if cta.ThreadKey == threadKey && cta.Type_ == "marketplace_xma_call_function" {
			return true
		}
	}
	return false
}

func (b *bot) handleEvent(ctx context.Context, evt any) {
	switch e := evt.(type) {
	case *messagix.Event_PublishResponse:
		tbl := e.Table
		b.enqueue(func() { b.processTable(b.ctx, tbl) })
	case *messagix.Event_PermanentError:
		if errors.Is(e.Err, messagix.CONNECTION_REFUSED_UNAUTHORIZED) ||
			errors.Is(e.Err, messagix.CONNECTION_REFUSED_BAD_USERNAME_OR_PASSWORD) {
			// Retrying rejected credentials reconnects in a zero-backoff loop, hammering Meta
			// with doomed auth attempts. Nothing recovers without fresh cookies.
			if err := os.Remove(connStateFile); err != nil && !os.IsNotExist(err) {
				b.log.Warn().Err(err).Msg("failed to remove rejected cached connection state")
			}
			b.fail(fmt.Errorf("messenger credentials rejected by server, update cookies in config.yaml: %w", e.Err))
			return
		}
		// messagix's own reconnect loop (in Client.Connect) gives up for good after this -
		// it will never retry again on its own. We're the only thing that can bring the
		// messenger socket back.
		b.log.Error().Err(e.Err).Msg("messenger socket permanently failed")
		go b.restartMessenger()
	case *messagix.Event_SocketError:
		b.log.Warn().Err(e.Err).Int("attempt", e.ConnectionAttempts).Msg("messenger socket error, library is retrying")
	case *messagix.Event_Reconnected:
		b.restartMu.Lock()
		b.restartBackoff = 0
		b.restartMu.Unlock()
		b.log.Info().Msg("messenger socket reconnected")
	}
}

// processTable applies an LSTable to bot state and dispatches any messages in it. It's shared
// between live push events (handleEvent) and the targeted recovery fetch (recoverMissingMessages),
// since ExecuteTasks returns its response table directly rather than routing it through the event
// handler.
func (b *bot) processTable(ctx context.Context, tbl *table.LSTable) {
	if tbl == nil {
		b.log.Debug().Msg("ignoring nil table")
		return
	}
	b.recordThreadTypes(tbl)

	if len(tbl.LSVerifyContactRowExists) > 0 {
		b.contactNamesMu.Lock()
		for _, c := range tbl.LSVerifyContactRowExists {
			if c.Name != "" {
				b.contactNames[c.ContactId] = c.Name
			}
		}
		b.contactNamesMu.Unlock()
	}

	isSelfSent := func(ids ...string) bool {
		b.selfSentMu.Lock()
		defer b.selfSentMu.Unlock()
		for _, id := range ids {
			if id != "" && b.selfSentOtids[id] {
				return true
			}
		}
		return false
	}
	// Belt-and-braces on top of the MessageId/OfflineThreadingId check above: if that ID
	// tracking ever misses for some other reason, still don't mark a thread as user-participated
	// from something landing right after we know we just replied there ourselves.
	recentlySelfReplied := func(threadKey int64) bool {
		b.repliedMu.Lock()
		last, ok := b.lastReplyAt[threadKey]
		b.repliedMu.Unlock()
		return ok && time.Since(last) < selfEchoGracePeriod
	}
	// Every resync (a restart's initial backlog fetch, or any later forced reconnect) replays
	// old history, including our own past auto-replies. There's no reason for that replay to
	// affect current state - only genuinely new activity should be able to mark a thread
	// user-participated. This also covers self-sent IDs from before recordSelfSent started
	// persisting them to disk (a restart with an empty/pre-persistence ID file used to
	// re-mark old threads as user-participated purely from replaying their own history).
	isRecent := func(timestampMs int64) bool {
		return timestampMs >= b.startTime.Add(-2*time.Minute).UnixMilli()
	}
	for _, msg := range tbl.LSUpsertMessage {
		if msg.SenderId == b.userID && isRecent(msg.TimestampMs) && !isSelfSent(msg.MessageId, msg.OfflineThreadingId) && !recentlySelfReplied(msg.ThreadKey) {
			b.recordUserThread(msg.ThreadKey)
		}
	}
	for _, msg := range tbl.LSInsertMessage {
		if msg.SenderId == b.userID && isRecent(msg.TimestampMs) && !isSelfSent(msg.MessageId, msg.OfflineThreadingId) && !recentlySelfReplied(msg.ThreadKey) {
			b.recordUserThread(msg.ThreadKey)
		}
	}

	upsert, insert := tbl.WrapMessages()
	count := len(insert)
	for _, g := range upsert {
		count += len(g.Messages)
	}
	if count > 0 {
		b.log.Info().Int("count", count).Msg("received messages")
	}

	for _, msg := range insert {
		b.processMessage(ctx, msg)
		if count > 1 && !sleepContext(ctx, 500*time.Millisecond) {
			return
		}
	}
	for _, group := range upsert {
		for _, msg := range group.Messages {
			b.processMessage(ctx, msg)
			if count > 1 && !sleepContext(ctx, 500*time.Millisecond) {
				return
			}
		}
	}

	if tbl != nil {
		b.client.PostHandlePublishResponse(tbl)
	}
	b.maybeSaveConnState()
}

func (b *bot) extractListing(msg *table.WrappedMessage) *listing {
	for _, xma := range msg.XMAAttachments {
		if xma.TitleText == "" && xma.DescriptionText == "" {
			continue
		}
		l := &listing{
			Title:       xma.TitleText,
			Subtitle:    xma.SubtitleText,
			Description: xma.DescriptionText,
			Source:      xma.SourceText,
			ActionURL:   xma.ActionUrl,
		}
		if xma.CTA != nil && xma.CTA.ActionUrl != "" {
			l.ActionURL = xma.CTA.ActionUrl
		}
		return l
	}
	for _, att := range msg.Attachments {
		if att.TitleText == "" && att.DescriptionText == "" {
			continue
		}
		return &listing{
			Title:       att.TitleText,
			Subtitle:    att.SubtitleText,
			Description: att.DescriptionText,
			Source:      att.SourceText,
			ActionURL:   att.ActionUrl,
		}
	}
	return nil
}

func (b *bot) buildPrompt(threadID int64) string {
	b.listingsMu.RLock()
	lk := b.listings[threadID]
	b.listingsMu.RUnlock()

	if lk == nil {
		return "You are a helpful seller on Facebook Marketplace responding to a buyer's inquiry. Reply briefly in 1 sentence. Do NOT sign off with your name."
	}
	return fmt.Sprintf(
		"You are a helpful seller on Facebook Marketplace. You listed:\nTitle: %s\nPrice/Location: %s\nDescription: %s\nSource: %s\n\n"+
			"A buyer is messaging you. Reply briefly in 1 sentence addressing their question. Do NOT sign off with your name.",
		lk.Title, lk.Subtitle, lk.Description, lk.Source,
	)
}

const maxRepliedMessageIDs = 10000

func (b *bot) alreadyReplied(key string) bool {
	b.repliedMsgIDsMu.Lock()
	defer b.repliedMsgIDsMu.Unlock()
	_, ok := b.repliedMsgIDs[key]
	return ok
}

func (b *bot) markReplied(key string) {
	if key == "" {
		return
	}
	b.repliedMsgIDsMu.Lock()
	defer b.repliedMsgIDsMu.Unlock()
	if _, exists := b.repliedMsgIDs[key]; exists {
		return
	}
	b.repliedMsgIDs[key] = struct{}{}
	b.repliedMsgIDOrder = append(b.repliedMsgIDOrder, key)
	if len(b.repliedMsgIDOrder) <= maxRepliedMessageIDs {
		return
	}
	oldest := b.repliedMsgIDOrder[0]
	b.repliedMsgIDOrder = b.repliedMsgIDOrder[1:]
	delete(b.repliedMsgIDs, oldest)
}

func (b *bot) marketplaceThread(threadKey int64) bool {
	b.threadTypesMu.RLock()
	tt, ok := b.threadTypes[threadKey]
	b.threadTypesMu.RUnlock()
	return ok && tt == table.MARKETPLACE
}

func (b *bot) threadNeedsClassification(threadKey int64) bool {
	b.threadTypesMu.RLock()
	tt, known := b.threadTypes[threadKey]
	authoritative := b.authoritativeThreadTypes[threadKey]
	b.threadTypesMu.RUnlock()
	return known && tt == table.GROUP_THREAD && !authoritative
}

// classifyMarketplaceGreeting is a high-precision fallback for Meta dropping both the
// Marketplace thread type and its quick-reply CTA. Facebook generates this exact,
// case-sensitive phrase for Marketplace inquiries; buyers sometimes append an emoji or other
// text. Restrict it to current inbound messages on still-provisional GROUP_THREADs so an old
// backlog or an established personal conversation cannot be reclassified.
func (b *bot) classifyMarketplaceGreeting(msg *table.WrappedMessage) bool {
	if msg.SenderId == b.userID ||
		msg.TimestampMs < b.startTime.Add(-2*time.Minute).UnixMilli() ||
		!strings.Contains(msg.Text, marketplaceAvailabilityGreeting) {
		return false
	}

	b.threadTypesMu.Lock()
	defer b.threadTypesMu.Unlock()
	if b.threadTypes[msg.ThreadKey] != table.GROUP_THREAD || b.authoritativeThreadTypes[msg.ThreadKey] {
		return false
	}
	b.threadTypes[msg.ThreadKey] = table.MARKETPLACE
	b.authoritativeThreadTypes[msg.ThreadKey] = true
	return true
}

// devTestSender reports whether, in --dev testing mode, msg comes from a contact whose
// name contains "Brandon", or whose ID was explicitly allow-listed via --dev-contact -
// lets personal test messages through without a marketplace listing.
func (b *bot) devTestSender(senderId int64) bool {
	if b.devContacts[senderId] {
		return true
	}
	b.contactNamesMu.RLock()
	name := b.contactNames[senderId]
	b.contactNamesMu.RUnlock()
	return strings.Contains(strings.ToLower(name), "brandon")
}

func (b *bot) processMessage(ctx context.Context, msg *table.WrappedMessage) {
	threadID := msg.ThreadKey
	if !b.marketplaceThread(threadID) && b.classifyMarketplaceGreeting(msg) {
		b.log.Info().Int64("tid", threadID).Msg("marking generic thread as marketplace from standard availability greeting")
	}

	if !b.marketplaceThread(threadID) && !(b.selfTest && b.devTestSender(msg.SenderId)) {
		// LSVerifyThreadExists labels new Marketplace inquiries as GROUP_THREAD. When the
		// Marketplace CTA is dropped, immediately rejecting that provisional type loses the
		// inquiry forever. A current inbound text is enough reason to fetch the complete thread
		// row; replies remain blocked until that fetch proves it is Marketplace.
		if msg.Text != "" && msg.SenderId != b.userID &&
			msg.TimestampMs >= b.startTime.Add(-2*time.Minute).UnixMilli() &&
			b.threadNeedsClassification(threadID) {
			b.armClassificationRecovery(threadID)
			b.log.Info().Int64("tid", threadID).Msg("generic thread has inbound message, scheduling classification fetch")
		}
		b.threadTypesMu.RLock()
		tt, known := b.threadTypes[threadID]
		mapSize := len(b.threadTypes)
		b.threadTypesMu.RUnlock()
		b.log.Info().
			Int64("tid", threadID).
			Bool("type_known", known).
			Int64("type", int64(tt)).
			Int("known_thread_count", mapSize).
			Msg("skipping non-marketplace thread")
		return
	}

	if msg.TimestampMs < b.startTime.Add(-2*time.Minute).UnixMilli() {
		b.log.Info().Int64("tid", threadID).Int64("ts", msg.TimestampMs).Msg("skipping old message")
		return
	}

	// Some mc/legacy redelivery routes (backlog resyncs in particular) come through with an
	// empty MessageId, which used to bypass this dedup entirely and caused the same message to
	// get replied to again once the cooldown had cleared. Fall back to sender+timestamp+text:
	// redelivery preserves the original timestamp, while a genuine repeat later remains distinct.
	msgKey := fmt.Sprintf("%d:%s", threadID, msg.MessageId)
	if msg.MessageId == "" {
		// A redelivery keeps the original timestamp, while a genuine repeat of identical text
		// later has a different one. Including it avoids suppressing legitimate repeat messages
		// forever just because this delivery path omitted MessageId.
		msgKey = fmt.Sprintf("%d:%d:%d:%s", threadID, msg.SenderId, msg.TimestampMs, msg.Text)
	}
	if b.alreadyReplied(msgKey) {
		b.log.Info().Int64("tid", threadID).Str("message_id", msg.MessageId).Msg("skipping already-replied message")
		return
	}

	if !b.selfTest {
		b.userThreadsMu.Lock()
		userSent := b.userThreads[threadID]
		b.userThreadsMu.Unlock()
		if userSent {
			b.log.Info().Int64("tid", threadID).Msg("skipping user-participated thread")
			return
		}
	}

	b.repliedMu.Lock()
	last, onCooldown := b.lastReplyAt[threadID]
	b.repliedMu.Unlock()
	if onCooldown && time.Since(last) < b.replyCooldown {
		b.log.Info().Int64("tid", threadID).Time("last_reply", last).Msg("skipping thread on reply cooldown")
		return
	}

	l := b.extractListing(msg)
	if l != nil {
		b.log.Info().
			Int64("tid", threadID).
			Str("title", l.Title).
			Str("subtitle", l.Subtitle).
			Str("source", l.Source).
			Msg("found listing share")
		b.listingsMu.Lock()
		b.listings[threadID] = l
		b.listingsMu.Unlock()
	}

	if !b.selfTest && msg.SenderId == b.userID {
		b.selfSentMu.Lock()
		selfSent := (msg.MessageId != "" && b.selfSentOtids[msg.MessageId]) ||
			(msg.OfflineThreadingId != "" && b.selfSentOtids[msg.OfflineThreadingId])
		b.selfSentMu.Unlock()
		if !selfSent {
			b.recordUserThread(threadID)
		}
		return
	}

	text := msg.Text
	if text == "" {
		b.log.Info().Int64("tid", threadID).Int64("sid", msg.SenderId).Bool("admin", msg.IsAdminMessage).Msg("skipping empty message")
		return
	}
	b.clearContentRecovery(threadID)

	b.log.Info().
		Int64("sid", msg.SenderId).
		Int64("tid", threadID).
		Str("text", text).
		Msg("new message")

	// Mark read as soon as we've decided to handle this message, not only when a reply is
	// actually sent - otherwise any message that fails to match a rule (or gets an empty AI
	// reply) is left unread forever, which is exactly what still triggers the phone notification.
	b.markThreadRead(ctx, threadID, msg.TimestampMs)

	if b.deepseekKey != "" {
		reply, err := b.callDeepseek(ctx, b.buildPrompt(threadID), text)
		if err != nil {
			b.log.Err(err).Msg("deepseek call failed, falling back to rules")
		} else if reply != "" {
			b.log.Info().Str("reply", reply).Msg("deepseek reply")
			if b.sendReply(ctx, threadID, reply) {
				b.repliedMu.Lock()
				b.lastReplyAt[threadID] = time.Now()
				b.repliedMu.Unlock()
				b.markReplied(msgKey)
			}
			return
		}
	}

	for _, rule := range b.rules {
		if !rule.compiled.MatchString(text) {
			continue
		}
		if b.replyOnce && b.ruleAlreadyReplied(threadID, rule.Pattern) {
			continue
		}

		b.log.Debug().
			Int64("thread", threadID).
			Str("pattern", rule.Pattern).
			Msg("auto-replying")

		// Only record the reply (cooldown, replied-once, message-dedup) once it's actually
		// sent - marking it beforehand meant a failed send (e.g. a reconnect racing the
		// send) would permanently mark the message as handled despite never answering it.
		if b.sendReply(ctx, threadID, rule.Reply) {
			if b.replyOnce {
				b.recordRuleReply(threadID, rule.Pattern)
			}
			b.repliedMu.Lock()
			b.lastReplyAt[threadID] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
		}
		return
	}
	b.log.Info().Int64("tid", threadID).Str("text", text).Msg("no rule matched")
}

type deepseekMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type deepseekRequest struct {
	Model     string            `json:"model"`
	Messages  []deepseekMessage `json:"messages"`
	MaxTokens int               `json:"max_tokens,omitempty"`
}

type deepseekChoice struct {
	Message deepseekMessage `json:"message"`
}

type deepseekResponse struct {
	Choices []deepseekChoice `json:"choices"`
}

const deepseekMaxResponseBytes = 1 << 20

func (b *bot) callDeepseek(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	reqBody := deepseekRequest{
		Model:     "deepseek-chat",
		MaxTokens: 120,
		Messages: []deepseekMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMessage},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.deepseek.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.deepseekKey)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, deepseekMaxResponseBytes+1))
	if err != nil {
		return "", err
	}
	if len(respBody) > deepseekMaxResponseBytes {
		return "", fmt.Errorf("deepseek response exceeded %d bytes", deepseekMaxResponseBytes)
	}

	if resp.StatusCode != 200 {
		trunc := string(respBody)
		if len(trunc) > 200 {
			trunc = trunc[:200] + "..."
		}
		return "", fmt.Errorf("deepseek api error %d: %s", resp.StatusCode, trunc)
	}

	var ds deepseekResponse
	if err := json.Unmarshal(respBody, &ds); err != nil {
		return "", err
	}
	if len(ds.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return strings.TrimSpace(ds.Choices[0].Message.Content), nil
}

const (
	selfSentIDsFile  = "self_sent_ids.txt"
	userThreadsFile  = "user_threads.txt"
	repliedRulesFile = "replied_rules.json"
)

// recordSelfSent marks id as one of our own sent messages, both in memory and durably on disk.
// Persistence matters because a restart's initial backlog resync replays our own historical
// replies - without a durable record, those replays fail the self-sent check (selfSentOtids
// would be empty again) and get mistaken for Brandon manually replying, which permanently
// silences the bot on that thread. Confirmed live: this happened to two different threads
// immediately after a restart before this was added.
func (b *bot) recordSelfSent(id string) {
	if id == "" {
		return
	}
	b.selfSentMu.Lock()
	defer b.selfSentMu.Unlock()
	if b.selfSentOtids[id] {
		return
	}
	b.selfSentOtids[id] = true
	f, err := os.OpenFile(selfSentIDsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		b.log.Err(err).Msg("failed to persist self-sent message id")
		return
	}
	defer f.Close()
	if _, err := f.WriteString(id + "\n"); err != nil {
		b.log.Err(err).Msg("failed to persist self-sent message id")
	}
}

func loadSelfSentIDs(path string) (map[string]bool, error) {
	ids := make(map[string]bool)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ids[line] = true
		}
	}
	return ids, nil
}

func loadUserThreads(path string) (map[int64]bool, error) {
	threads := make(map[int64]bool)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return threads, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		threadID, err := strconv.ParseInt(line, 10, 64)
		if err != nil || threadID <= 0 {
			return nil, fmt.Errorf("invalid persisted thread ID %q", line)
		}
		threads[threadID] = true
	}
	return threads, nil
}

func (b *bot) recordUserThread(threadID int64) {
	if threadID <= 0 {
		return
	}
	b.userThreadsMu.Lock()
	defer b.userThreadsMu.Unlock()
	if b.userThreads == nil {
		b.userThreads = make(map[int64]bool)
	}
	if b.userThreads[threadID] {
		return
	}
	b.userThreads[threadID] = true

	ids := make([]int64, 0, len(b.userThreads))
	for id := range b.userThreads {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var persisted strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&persisted, "%d\n", id)
	}
	if err := writeFileAtomic(userThreadsFile, []byte(persisted.String()), 0600); err != nil {
		b.log.Err(err).Int64("tid", threadID).Msg("failed to persist user-participated thread")
	}
}

func loadRepliedRules(path string) (map[int64]map[string]bool, error) {
	replied := make(map[int64]map[string]bool)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return replied, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return replied, nil
	}
	if err := json.Unmarshal(data, &replied); err != nil {
		return nil, fmt.Errorf("failed to parse persisted replied rules: %w", err)
	}
	return replied, nil
}

func (b *bot) ruleAlreadyReplied(threadID int64, pattern string) bool {
	b.repliedMu.Lock()
	defer b.repliedMu.Unlock()
	return b.replied[threadID][pattern]
}

func (b *bot) recordRuleReply(threadID int64, pattern string) {
	if threadID <= 0 || pattern == "" {
		return
	}
	b.repliedMu.Lock()
	defer b.repliedMu.Unlock()
	if b.replied == nil {
		b.replied = make(map[int64]map[string]bool)
	}
	rules := b.replied[threadID]
	if rules == nil {
		rules = make(map[string]bool)
		b.replied[threadID] = rules
	}
	if rules[pattern] {
		return
	}
	rules[pattern] = true
	data, err := json.Marshal(b.replied)
	if err != nil {
		b.log.Err(err).Int64("tid", threadID).Msg("failed to encode replied-rule state")
		return
	}
	if err := writeFileAtomic(repliedRulesFile, data, 0600); err != nil {
		b.log.Err(err).Int64("tid", threadID).Msg("failed to persist replied-rule state")
	}
}

const markReadMaxAttempts = 3

func (b *bot) markThreadRead(ctx context.Context, threadID int64, watermarkMs int64) {
	if watermarkMs <= 0 {
		watermarkMs = time.Now().UnixMilli()
	}
	for attempt := 1; attempt <= markReadMaxAttempts; attempt++ {
		task := &socket.ThreadMarkReadTask{
			ThreadId:            threadID,
			LastReadWatermarkTs: watermarkMs,
			SyncGroup:           1,
		}
		resp, err := b.client.ExecuteTasks(ctx, task)
		if err != nil {
			b.log.Err(err).Int64("tid", threadID).Int("attempt", attempt).Msg("failed to mark thread read")
		} else if threadReadConfirmed(resp, threadID) {
			return
		} else {
			b.log.Warn().Int64("tid", threadID).Int("attempt", attempt).Msg("mark thread read not confirmed by server, retrying")
		}
		if attempt < markReadMaxAttempts && !sleepContext(ctx, time.Duration(attempt)*time.Second) {
			return
		}
	}
	b.log.Error().Int64("tid", threadID).Msg("giving up marking thread read after retries")
}

func threadReadConfirmed(resp *table.LSTable, threadID int64) bool {
	if resp == nil {
		return false
	}
	for _, r := range resp.LSMarkThreadReadV2 {
		if r.GetThreadKey() == threadID {
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func humanReplyDelay(ctx context.Context) bool {
	d := 3*time.Second + time.Duration(rand.Int63n(int64(5*time.Second)))
	return sleepContext(ctx, d)
}

// sendReply returns whether the message actually sent. Callers must only record the reply
// (cooldown, dedup, replied-once) when this returns true, so a failed send can be retried
// instead of being permanently treated as handled.
func (b *bot) sendReply(ctx context.Context, threadID int64, text string) bool {
	if !humanReplyDelay(ctx) {
		return false
	}
	otid := methods.GenerateEpochID()
	task := &socket.SendMessageTask{
		ThreadId:         threadID,
		Otid:             otid,
		Source:           table.MESSENGER_INBOX_IN_THREAD,
		InitiatingSource: table.FACEBOOK_INBOX,
		SendType:         table.TEXT,
		SyncGroup:        1,
		Text:             text,
	}

	otidStr := strconv.FormatInt(otid, 10)
	b.recordSelfSent(otidStr)

	var resp *table.LSTable
	var err error
	for range 5 {
		if werr := b.client.WaitUntilCanSendMessages(ctx, 15*time.Second); werr != nil {
			b.log.Err(werr).Msg("messenger socket not ready for sending, retrying")
			err = werr
			continue
		}
		resp, err = b.client.ExecuteTasks(ctx, task)
		if err == nil {
			break
		}
		b.log.Err(err).Msg("failed to send reply, retrying")
	}
	if err != nil {
		b.log.Err(err).Msg("Failed to send reply")
		return false
	}
	// A transport-level success can still be a server-side rejection: the send is only
	// confirmed by LSReplaceOptimsiticMessage carrying our Otid, with the real message ID.
	// That ID is also the only self-sent marker that reliably matches on replay - the
	// OfflineThreadingId on a later echoed LSInsertMessage/LSUpsertMessage doesn't reliably
	// match our Otid for a reply sent into a thread that's e2ee underneath, which was
	// silently marking the thread as user-participated and permanently killing auto-replies.
	var msgID string
	if resp != nil {
		for _, replace := range resp.LSReplaceOptimsiticMessage {
			if replace.OfflineThreadingId == otidStr {
				msgID = replace.MessageId
			}
		}
		for _, failed := range resp.LSMarkOptimisticMessageFailed {
			if failed.OTID == otidStr {
				b.log.Warn().Str("reason", failed.Message).Msg("server rejected reply")
			}
		}
		for _, failed := range resp.LSHandleFailedTask {
			if failed.OTID == otidStr {
				b.log.Warn().Str("reason", failed.Message).Msg("reply task failed server-side")
			}
		}
	}
	if msgID == "" {
		b.log.Warn().Msg("send response didn't confirm our message, treating as failure")
		return false
	}
	b.recordSelfSent(msgID)
	b.log.Info().Msg("reply sent")
	return true
}

func (b *bot) e2eeHandler(evt any) {
	b.log.Debug().Str("type", fmt.Sprintf("%T", evt)).Msg("e2ee event")
	switch evt := evt.(type) {
	case *waEvents.FBMessage:
		b.enqueue(func() { b.handleE2EEMessage(evt) })
	case *waEvents.Connected:
		b.log.Info().Msg("e2ee socket connected")
		// Marks us as an active/foreground client. Without this, delivery receipts go out as
		// "inactive" (the same signal WhatsApp Web sends when backgrounded), which is exactly
		// the kind of state Meta can use to quietly stop pushing new messages down an
		// otherwise-healthy, keepalive-passing socket.
		if err := b.waClient.SendPresence(b.context(), waTypes.PresenceAvailable); err != nil {
			b.log.Err(err).Msg("failed to send e2ee presence")
		}
	case *waEvents.LoggedOut:
		b.log.Warn().Bool("on_connect", evt.OnConnect).Int("reason", int(evt.Reason)).Msg("e2ee logged out")
	case *waEvents.Disconnected:
		b.log.Warn().Msg("e2ee socket disconnected, whatsmeow is auto-reconnecting")
	case *waEvents.StreamReplaced:
		b.log.Warn().Msg("e2ee stream replaced - session opened elsewhere, this connection is dead")
	case *waEvents.KeepAliveTimeout:
		b.log.Warn().Int("error_count", evt.ErrorCount).Time("last_success", evt.LastSuccess).Msg("e2ee keepalive timeout")
	case *waEvents.KeepAliveRestored:
		b.log.Info().Msg("e2ee keepalive restored")
	case *waEvents.ConnectFailure:
		b.log.Error().Int("reason", int(evt.Reason)).Str("message", evt.Message).Msg("e2ee connect failure")
	case *waEvents.CATRefreshError:
		b.log.Err(evt.Error).Msg("e2ee crypto auth token refresh failed")
	case *waEvents.TemporaryBan:
		b.log.Error().Int("code", int(evt.Code)).Dur("expire", evt.Expire).Msg("e2ee temporary ban")
	}
}

func (b *bot) handleE2EEMessage(fbMsg *waEvents.FBMessage) {
	b.log.Debug().
		Str("sender", fbMsg.Info.Sender.String()).
		Str("chat", fbMsg.Info.Chat.String()).
		Str("msg_type", fmt.Sprintf("%T", fbMsg.Message)).
		Msg("e2ee FBMessage")

	consumerApp := fbMsg.GetConsumerApplication()
	if consumerApp == nil {
		b.log.Debug().Str("msg_type", fmt.Sprintf("%T", fbMsg.Message)).Msg("not consumer app, skipping")
		return
	}

	sid, err := strconv.ParseInt(fbMsg.Info.Sender.User, 10, 64)
	if err != nil {
		b.log.Warn().Err(err).Str("user", fbMsg.Info.Sender.User).Msg("invalid sender JID")
		return
	}
	tid, err := strconv.ParseInt(fbMsg.Info.Chat.User, 10, 64)
	if err != nil {
		b.log.Warn().Err(err).Str("user", fbMsg.Info.Chat.User).Msg("invalid chat JID")
		return
	}

	b.contactNamesMu.RLock()
	cachedName := b.contactNames[sid]
	b.contactNamesMu.RUnlock()
	devTest := b.selfTest && (b.devTestSender(sid) || strings.Contains(strings.ToLower(fbMsg.Info.PushName), "brandon"))
	if !b.marketplaceThread(tid) && !devTest {
		b.log.Info().
			Int64("sid", sid).
			Int64("tid", tid).
			Bool("self_test", b.selfTest).
			Bool("dev_contact_match", b.devContacts[sid]).
			Int("dev_contact_count", len(b.devContacts)).
			Str("push_name", fbMsg.Info.PushName).
			Str("cached_contact_name", cachedName).
			Msg("e2ee: skipping non-marketplace/non-devtest thread")
		return
	}

	if fbMsg.Info.Timestamp.Before(b.startTime) {
		b.log.Info().Int64("tid", tid).Time("msg_ts", fbMsg.Info.Timestamp).Time("start_ts", b.startTime).Msg("e2ee: skipping old message")
		return
	}

	msgKey := fmt.Sprintf("%d:%s", tid, fbMsg.Info.ID)
	if fbMsg.Info.ID != "" && b.alreadyReplied(msgKey) {
		b.log.Info().Int64("tid", tid).Str("message_id", fbMsg.Info.ID).Msg("e2ee: skipping already-replied message")
		return
	}

	if fbMsg.Info.IsFromMe {
		b.selfSentMu.Lock()
		isOurReply := fbMsg.Info.ID != "" && b.selfSentOtids[fbMsg.Info.ID]
		b.selfSentMu.Unlock()
		if isOurReply {
			// This is the echo of a reply we just sent ourselves, not Brandon manually
			// jumping into the thread from his phone/browser. Without this check, every
			// e2ee auto-reply permanently silences the bot on that thread afterwards,
			// since the echo is indistinguishable from real self-participation otherwise.
			b.log.Debug().Int64("tid", tid).Str("message_id", fbMsg.Info.ID).Msg("e2ee: echo of our own reply, ignoring")
			return
		}
		b.log.Info().Int64("tid", tid).Msg("e2ee: message from self, marking userThreads")
		b.recordUserThread(tid)
		return
	}

	if !b.selfTest {
		b.userThreadsMu.Lock()
		userSent := b.userThreads[tid]
		b.userThreadsMu.Unlock()
		if userSent {
			b.log.Info().Int64("tid", tid).Msg("e2ee: skipping user-participated thread")
			return
		}
	}

	b.repliedMu.Lock()
	last, onCooldown := b.lastReplyAt[tid]
	b.repliedMu.Unlock()
	if onCooldown && time.Since(last) < b.replyCooldown {
		b.log.Info().Int64("tid", tid).Time("last_reply", last).Msg("e2ee: skipping thread on reply cooldown")
		return
	}

	content := consumerApp.GetPayload().GetContent()
	if content == nil {
		b.log.Info().Int64("tid", tid).Msg("e2ee: nil content, skipping")
		return
	}

	var text string
	if extended := content.GetExtendedTextMessage(); extended != nil {
		if msgText := extended.GetText(); msgText != nil {
			text = msgText.GetText()
		}
	} else if msgText := content.GetMessageText(); msgText != nil {
		text = msgText.GetText()
	}

	if text == "" {
		b.log.Info().Int64("tid", tid).Str("content_type", fmt.Sprintf("%T", content.GetContent())).Msg("e2ee: empty text, skipping")
		return
	}
	b.clearContentRecovery(tid)

	b.log.Info().
		Int64("sid", sid).
		Int64("tid", tid).
		Str("text", text).
		Msg("e2ee message")

	// Mark read as soon as we've decided to handle this message, not only when a reply is
	// actually sent - otherwise any message that fails to match a rule (or gets an empty AI
	// reply) is left unread forever, which is exactly what still triggers the phone notification.
	b.markE2EEThreadRead(tid, fbMsg.Info)

	if sid == b.userID {
		return
	}

	if b.deepseekKey != "" {
		reply, err := b.callDeepseek(b.context(), b.buildPrompt(tid), text)
		if err != nil {
			b.log.Err(err).Msg("deepseek call failed (e2ee), falling back to rules")
		} else if reply != "" {
			b.log.Info().Str("reply", reply).Msg("deepseek reply (e2ee)")
			if b.sendE2EEReply(fbMsg.Info, tid, reply) {
				b.repliedMu.Lock()
				b.lastReplyAt[tid] = time.Now()
				b.repliedMu.Unlock()
				b.markReplied(msgKey)
			}
			return
		}
	}

	for _, rule := range b.rules {
		if !rule.compiled.MatchString(text) {
			continue
		}
		if b.replyOnce && b.ruleAlreadyReplied(tid, rule.Pattern) {
			continue
		}

		b.log.Debug().
			Int64("thread", tid).
			Str("pattern", rule.Pattern).
			Msg("auto-replying (e2ee)")

		if b.sendE2EEReply(fbMsg.Info, tid, rule.Reply) {
			if b.replyOnce {
				b.recordRuleReply(tid, rule.Pattern)
			}
			b.repliedMu.Lock()
			b.lastReplyAt[tid] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
		}
		return
	}
	b.log.Info().Int64("tid", tid).Str("text", text).Msg("e2ee no rule matched")
}

// sendE2EEReply returns whether the message actually sent. Callers must only record the reply
// (cooldown, dedup, replied-once) when this returns true, so a failed send can be retried
// instead of being permanently treated as handled.
func (b *bot) sendE2EEReply(srcInfo waTypes.MessageInfo, threadID int64, text string) bool {
	if b.waClient == nil {
		b.log.Warn().Msg("no e2ee client, cannot reply")
		return false
	}
	ctx := b.context()
	if !humanReplyDelay(ctx) {
		return false
	}
	msg := &waConsumer.ConsumerApplication{
		Payload: &waConsumer.ConsumerApplication_Payload{
			Payload: &waConsumer.ConsumerApplication_Payload_Content{
				Content: &waConsumer.ConsumerApplication_Content{
					Content: &waConsumer.ConsumerApplication_Content_MessageText{
						MessageText: &waCommon.MessageText{
							Text: pro.String(text),
						},
					},
				},
			},
		},
	}
	otidStr := strconv.FormatInt(methods.GenerateEpochID(), 10)
	b.recordSelfSent(otidStr)
	var resp whatsmeow.SendResponse
	sent := false
	for attempt := range 5 {
		if !b.waClient.IsConnected() {
			b.log.Warn().Msg("e2ee socket not connected, waiting before retry")
			if !sleepContext(ctx, 3*time.Second) {
				return false
			}
			continue
		}
		var err error
		resp, err = b.waClient.SendFBMessage(ctx, srcInfo.Chat, msg, nil, whatsmeow.SendRequestExtra{ID: waTypes.MessageID(otidStr)})
		if err == nil {
			sent = true
			break
		}
		b.log.Err(err).Msg("failed to send e2ee reply, retrying")
		if !sleepContext(ctx, time.Duration(attempt+1)*time.Second) {
			return false
		}
	}
	if !sent {
		b.log.Error().Msg("Failed to send e2ee reply")
		return false
	}
	if resp.ID != "" && resp.ID != otidStr {
		b.recordSelfSent(resp.ID)
	}
	b.log.Info().Msg("e2ee reply sent")
	return true
}

func (b *bot) markE2EEThreadRead(threadID int64, srcInfo waTypes.MessageInfo) {
	if b.waClient == nil {
		return
	}
	if err := b.waClient.MarkRead(b.context(), []waTypes.MessageID{srcInfo.ID}, time.Now(), srcInfo.Chat, srcInfo.Sender); err != nil {
		b.log.Err(err).Int64("tid", threadID).Msg("failed to mark e2ee thread read")
	}
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg := &config{
			Mode:                     "facebook",
			LogLevel:                 "info",
			ReplyOnce:                true,
			ReplyCooldownMinutes:     5,
			ReconnectIntervalMinutes: 360,
			Cookies: map[string]string{
				"xs":     "",
				"c_user": "",
				"datr":   "",
			},
			Rules: defaultRules,
		}
		out, marshalErr := yaml.Marshal(cfg)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to encode default config: %w", marshalErr)
		}
		if err := writeFileAtomic(path, out, 0600); err != nil {
			return nil, fmt.Errorf("failed to write default config: %w", err)
		}
		return nil, fmt.Errorf("config file created at %s, please edit it and run again", path)
	}
	if err != nil {
		return nil, err
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, fmt.Errorf("failed to inspect config permissions: %w", statErr)
	}
	if info.Mode().Perm()&0077 != 0 {
		if chmodErr := os.Chmod(path, 0600); chmodErr != nil {
			return nil, fmt.Errorf("config contains credentials but permissions could not be tightened to 0600: %w", chmodErr)
		}
	}

	cfg := config{
		Mode:                     "facebook",
		LogLevel:                 "info",
		ReplyOnce:                true,
		ReplyCooldownMinutes:     5,
		ReconnectIntervalMinutes: 360,
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if _, err := zerolog.ParseLevel(cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("invalid log_level %q: %w", cfg.LogLevel, err)
	}
	if cfg.ReplyCooldownMinutes < 0 {
		return nil, fmt.Errorf("reply_cooldown_minutes must not be negative")
	}
	if cfg.ReconnectIntervalMinutes < 0 {
		return nil, fmt.Errorf("reconnect_interval_minutes must not be negative")
	}
	for i, rule := range cfg.Rules {
		if strings.TrimSpace(rule.Pattern) == "" {
			return nil, fmt.Errorf("rule %d has an empty pattern", i+1)
		}
		if strings.TrimSpace(rule.Reply) == "" {
			return nil, fmt.Errorf("rule %d has an empty reply", i+1)
		}
	}
	if len(cfg.Rules) == 0 && cfg.DeepseekKey == "" {
		return nil, fmt.Errorf("no reply rules configured and deepseek_key is empty")
	}

	return &cfg, nil
}
