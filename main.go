package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
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
	out io.Writer
}

func (f *logFilter) Write(p []byte) (n int, err error) {
	if f.skip(p) {
		return len(p), nil
	}
	return f.out.Write(p)
}

func (f *logFilter) WriteLevel(lvl zerolog.Level, p []byte) (n int, err error) {
	if f.skip(p) {
		return len(p), nil
	}
	if lw, ok := f.out.(zerolog.LevelWriter); ok {
		return lw.WriteLevel(lvl, p)
	}
	return f.out.Write(p)
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

var defaultRules = []rule{
	{Pattern: `(?i)(?:is this|still)\s+available`, Reply: "Yes, are you interested?"},
	{Pattern: `(?i)(?:price|how much|cost)`, Reply: "The price is firm as listed in the ad."},
	{Pattern: `(?i)(?:condition|used|new)`, Reply: "It's in good condition. Let me know if you'd like more photos."},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "chatterbox: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	selfTest := false
	cfgPath := "config.yaml"
	var testThread int64
	devContactIDs := make(map[int64]bool)

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dev":
			selfTest = true
		case a == "--test":
			i++
			if i >= len(args) {
				return fmt.Errorf("--test requires a thread ID")
			}
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid thread ID %q: %w", args[i], err)
			}
			testThread = v
		case a == "--dev-contact":
			i++
			if i >= len(args) {
				return fmt.Errorf("--dev-contact requires a contact/sender ID")
			}
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid contact ID %q: %w", args[i], err)
			}
			devContactIDs[v] = true
		default:
			cfgPath = a
		}
	}

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
	log := zerolog.New(&logFilter{out: zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "3:04PM"}}).Level(lvl).With().Timestamp().Logger()
	// messagix/whatsmeow are noisy at info/debug (socket internals, keepalives, dependency
	// parsing) and that noise isn't ours to fix - only surface their warnings/errors.
	libLog := log.Level(zerolog.WarnLevel)
	// Some messagix internals (e.g. lightspeed/decode.go) log through zerolog's package-level
	// global logger instead of the client-supplied one, bypassing libLog entirely. Route that
	// through the same filtered writer and cap it at error level - its warnings are routine
	// dependency-parsing noise, not something we can act on.
	zlog.Logger = zlog.Logger.Output(&logFilter{out: zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "3:04PM"}}).Level(zerolog.ErrorLevel)

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

	mc := messagix.NewClient(c, libLog, &messagix.Config{
		ClientSettings: exhttp.ClientSettings{},
	})

	ctx := context.Background()

	userInfo, initialTable, err := mc.LoadMessagesPage(ctx)
	if err != nil {
		return fmt.Errorf("failed to load messages page: %w", err)
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
		dev.Save(ctx)
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

	bot := &bot{
		log:           log,
		client:        mc,
		waClient:      waClient,
		rules:         cfg.Rules,
		replyOnce:     cfg.ReplyOnce && !selfTest,
		replied:       make(map[int64]map[int]bool),
		userID:        userInfo.GetFBID(),
		selfTest:      selfTest,
		startTime:     time.Now(),
		userThreads:   make(map[int64]bool),
		lastReplyAt:   make(map[int64]time.Time),
		replyCooldown: replyCooldown,
		selfSentOtids: make(map[string]bool),
		repliedMsgIDs: make(map[string]bool),
		listings:      make(map[int64]*listing),
		threadTypes:   make(map[int64]table.ThreadType),
		contactNames:  make(map[int64]string),
		devContacts:   devContactIDs,
		deepseekKey:   deepseekKey,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}

	bot.recordThreadTypes(initialTable)

	mc.SetEventHandler(bot.handleEvent)
	waClient.AddEventHandler(bot.e2eeHandler)

	go func() {
		if err := mc.Connect(ctx); err != nil {
			log.Fatal().Err(err).Msg("Failed to connect")
		}
	}()

	go func() {
		if err := waClient.Connect(); err != nil {
			log.Err(err).Msg("Failed to connect e2ee socket")
		}
	}()

	// messagix already has its own ping/pong heartbeat (10s ping, 30s pong timeout) that
	// recovers ordinary dead connections on its own, and the Event_PermanentError handler
	// above now restarts the connection when the library's own reconnect loop gives up for
	// good. This ticker is just a last-resort safety net in case some failure mode slips
	// past both of those.
	reconnectInterval := time.Duration(cfg.ReconnectIntervalMinutes) * time.Minute
	if reconnectInterval <= 0 {
		reconnectInterval = 15 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(reconnectInterval)
		defer ticker.Stop()
		for range ticker.C {
			log.Debug().Msg("periodic proactive reconnect of messenger socket")
			mc.ForceReconnect()
		}
	}()

	if testThread > 0 {
		time.Sleep(2 * time.Second)
		log.Info().Int64("thread", testThread).Msg("injecting test message")
		go bot.processMessage(ctx, &table.WrappedMessage{
			LSInsertMessage: &table.LSInsertMessage{
				Text:      "Is this available?",
				ThreadKey: testThread,
				SenderId:  bot.userID,
			},
		})
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	<-sc

	log.Info().Msg("Shutting down...")
	mc.Disconnect()
	waClient.Disconnect()
	return nil
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
	replied   map[int64]map[int]bool
	userID    int64
	selfTest  bool

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
	repliedMsgIDs   map[string]bool
	repliedMsgIDsMu sync.Mutex

	listings      map[int64]*listing
	listingsMu    sync.RWMutex
	threadTypes   map[int64]table.ThreadType
	threadTypesMu sync.RWMutex
	deepseekKey   string
	httpClient    *http.Client

	contactNames   map[int64]string
	contactNamesMu sync.RWMutex
	devContacts    map[int64]bool
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
	for _, t := range tbl.LSDeleteThenInsertThread {
		set("LSDeleteThenInsertThread", t.ThreadKey, t.ThreadType)
	}
	for _, t := range tbl.LSUpdateOrInsertThread {
		set("LSUpdateOrInsertThread", t.ThreadKey, t.ThreadType)
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
				Msg("marking thread as marketplace from quick-reply CTA")
			b.threadTypes[cta.ThreadKey] = table.MARKETPLACE
		}
	}
	for _, t := range tbl.LSVerifyThreadExists {
		set("LSVerifyThreadExists", t.ThreadKey, t.ThreadType)
	}
	b.threadTypesMu.Unlock()
}

func (b *bot) handleEvent(ctx context.Context, evt any) {
	var tbl *table.LSTable
	switch e := evt.(type) {
	case *messagix.Event_PublishResponse:
		tbl = e.Table
	case *messagix.Event_PermanentError:
		// messagix's own reconnect loop (in Client.Connect) gives up for good after this -
		// it will never retry again on its own. We're the only thing that can bring the
		// messenger socket back.
		b.log.Error().Err(e.Err).Msg("messenger socket permanently failed, restarting connection")
		go func() {
			if err := b.client.Connect(ctx); err != nil {
				b.log.Err(err).Msg("failed to restart messenger connection")
			}
		}()
		return
	case *messagix.Event_SocketError:
		b.log.Warn().Err(e.Err).Int("attempt", e.ConnectionAttempts).Msg("messenger socket error, library is retrying")
		return
	case *messagix.Event_Reconnected:
		b.log.Info().Msg("messenger socket reconnected")
		return
	default:
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

	b.selfSentMu.Lock()
	isSelfSent := func(otid string) bool {
		if otid == "" {
			return false
		}
		return b.selfSentOtids[otid]
	}
	b.userThreadsMu.Lock()
	for _, msg := range tbl.LSUpsertMessage {
		if msg.SenderId == b.userID && !isSelfSent(msg.OfflineThreadingId) {
			b.userThreads[msg.ThreadKey] = true
		}
	}
	for _, msg := range tbl.LSInsertMessage {
		if msg.SenderId == b.userID && !isSelfSent(msg.OfflineThreadingId) {
			b.userThreads[msg.ThreadKey] = true
		}
	}
	b.userThreadsMu.Unlock()
	b.selfSentMu.Unlock()

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
		if count > 1 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	for _, group := range upsert {
		for _, msg := range group.Messages {
			b.processMessage(ctx, msg)
			if count > 1 {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
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

// alreadyReplied reports whether key (a "threadID:messageID" pair) has already been replied to.
func (b *bot) alreadyReplied(key string) bool {
	b.repliedMsgIDsMu.Lock()
	defer b.repliedMsgIDsMu.Unlock()
	return b.repliedMsgIDs[key]
}

func (b *bot) markReplied(key string) {
	if key == "" {
		return
	}
	b.repliedMsgIDsMu.Lock()
	b.repliedMsgIDs[key] = true
	b.repliedMsgIDsMu.Unlock()
}

func (b *bot) marketplaceThread(threadKey int64) bool {
	b.threadTypesMu.RLock()
	tt, ok := b.threadTypes[threadKey]
	b.threadTypesMu.RUnlock()
	return ok && tt == table.MARKETPLACE
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

	if !b.marketplaceThread(threadID) && !(b.selfTest && b.devTestSender(msg.SenderId)) {
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

	msgKey := fmt.Sprintf("%d:%s", threadID, msg.MessageId)
	if msg.MessageId != "" && b.alreadyReplied(msgKey) {
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
		selfSent := msg.OfflineThreadingId != "" && b.selfSentOtids[msg.OfflineThreadingId]
		b.selfSentMu.Unlock()
		if !selfSent {
			b.userThreadsMu.Lock()
			b.userThreads[threadID] = true
			b.userThreadsMu.Unlock()
		}
		return
	}

	text := msg.Text
	if text == "" {
		b.log.Info().Int64("tid", threadID).Int64("sid", msg.SenderId).Bool("admin", msg.IsAdminMessage).Msg("skipping empty message")
		return
	}

	b.log.Info().
		Int64("sid", msg.SenderId).
		Int64("tid", threadID).
		Str("text", text).
		Msg("new message")

	if b.deepseekKey != "" {
		reply, err := b.callDeepseek(b.buildPrompt(threadID), text)
		if err != nil {
			b.log.Err(err).Msg("deepseek call failed, falling back to rules")
		} else if reply != "" {
			b.log.Info().Str("reply", reply).Msg("deepseek reply")
			b.repliedMu.Lock()
			b.lastReplyAt[threadID] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
			b.sendReply(ctx, threadID, reply)
			return
		}
	}

	for i, rule := range b.rules {
		if rule.compiled.MatchString(text) {
			if b.replyOnce {
				rset, ok := b.replied[threadID]
				if !ok {
					rset = make(map[int]bool)
					b.replied[threadID] = rset
				}
				if rset[i] {
					continue
				}
				rset[i] = true
			}

			b.log.Debug().
				Int64("thread", threadID).
				Str("pattern", rule.Pattern).
				Msg("auto-replying")

			b.repliedMu.Lock()
			b.lastReplyAt[threadID] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
			b.sendReply(ctx, threadID, rule.Reply)
			return
		}
	}
	b.log.Info().Int64("tid", threadID).Str("text", text).Msg("no rule matched")
}

type deepseekMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type deepseekRequest struct {
	Model    string            `json:"model"`
	Messages []deepseekMessage `json:"messages"`
}

type deepseekChoice struct {
	Message deepseekMessage `json:"message"`
}

type deepseekResponse struct {
	Choices []deepseekChoice `json:"choices"`
}

func (b *bot) callDeepseek(systemPrompt, userMessage string) (string, error) {
	reqBody := deepseekRequest{
		Model: "deepseek-chat",
		Messages: []deepseekMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMessage},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewReader(body))
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
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

const markReadMaxAttempts = 3

func (b *bot) markThreadRead(ctx context.Context, threadID int64) {
	for attempt := 1; attempt <= markReadMaxAttempts; attempt++ {
		task := &socket.ThreadMarkReadTask{
			ThreadId:            threadID,
			LastReadWatermarkTs: time.Now().UnixMilli(),
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
		if attempt < markReadMaxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
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

func (b *bot) sendReply(ctx context.Context, threadID int64, text string) {
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

	b.selfSentMu.Lock()
	b.selfSentOtids[strconv.FormatInt(otid, 10)] = true
	b.selfSentMu.Unlock()

	if _, err := b.client.ExecuteTasks(ctx, task); err != nil {
		b.log.Err(err).Msg("Failed to send reply")
		return
	}
	b.log.Info().Msg("reply sent")
	b.markThreadRead(ctx, threadID)
}

func (b *bot) e2eeHandler(evt any) {
	b.log.Debug().Str("type", fmt.Sprintf("%T", evt)).Msg("e2ee event")
	switch evt := evt.(type) {
	case *waEvents.FBMessage:
		b.handleE2EEMessage(evt)
	case *waEvents.Connected:
		b.log.Info().Msg("e2ee socket connected")
		// Marks us as an active/foreground client. Without this, delivery receipts go out as
		// "inactive" (the same signal WhatsApp Web sends when backgrounded), which is exactly
		// the kind of state Meta can use to quietly stop pushing new messages down an
		// otherwise-healthy, keepalive-passing socket.
		if err := b.waClient.SendPresence(context.Background(), waTypes.PresenceAvailable); err != nil {
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
		b.log.Info().Int64("tid", tid).Msg("e2ee: message from self, marking userThreads")
		b.userThreadsMu.Lock()
		b.userThreads[tid] = true
		b.userThreadsMu.Unlock()
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

	b.log.Info().
		Int64("sid", sid).
		Int64("tid", tid).
		Str("text", text).
		Msg("e2ee message")

	if sid == b.userID {
		return
	}

	if b.deepseekKey != "" {
		reply, err := b.callDeepseek(b.buildPrompt(tid), text)
		if err != nil {
			b.log.Err(err).Msg("deepseek call failed (e2ee), falling back to rules")
		} else if reply != "" {
			b.log.Info().Str("reply", reply).Msg("deepseek reply (e2ee)")
			b.repliedMu.Lock()
			b.lastReplyAt[tid] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
			b.sendE2EEReply(fbMsg.Info, tid, reply)
			return
		}
	}

	for i, rule := range b.rules {
		if rule.compiled.MatchString(text) {
			if b.replyOnce {
				rset, ok := b.replied[tid]
				if !ok {
					rset = make(map[int]bool)
					b.replied[tid] = rset
				}
				if rset[i] {
					continue
				}
				rset[i] = true
			}

			b.log.Debug().
				Int64("thread", tid).
				Str("pattern", rule.Pattern).
				Msg("auto-replying (e2ee)")

			b.repliedMu.Lock()
			b.lastReplyAt[tid] = time.Now()
			b.repliedMu.Unlock()
			b.markReplied(msgKey)
			b.sendE2EEReply(fbMsg.Info, tid, rule.Reply)
			return
		}
	}
	b.log.Info().Int64("tid", tid).Str("text", text).Msg("e2ee no rule matched")
}

func (b *bot) sendE2EEReply(srcInfo waTypes.MessageInfo, threadID int64, text string) {
	if b.waClient == nil {
		b.log.Warn().Msg("no e2ee client, cannot reply")
		return
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
	if _, err := b.waClient.SendFBMessage(context.Background(), srcInfo.Chat, msg, nil); err != nil {
		b.log.Err(err).Msg("Failed to send e2ee reply")
		return
	}
	b.log.Info().Msg("e2ee reply sent")
	if err := b.waClient.MarkRead(context.Background(), []waTypes.MessageID{srcInfo.ID}, time.Now(), srcInfo.Chat, srcInfo.Sender); err != nil {
		b.log.Err(err).Int64("tid", threadID).Msg("failed to mark e2ee thread read")
	}
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := &config{
				Mode:      "facebook",
				LogLevel:  "info",
				ReplyOnce: true,
				Cookies: map[string]string{
					"xs":     "",
					"c_user": "",
					"datr":   "",
				},
				Rules: defaultRules,
			}
			out, _ := yaml.Marshal(cfg)
			if err := os.WriteFile(path, out, 0600); err != nil {
				return nil, fmt.Errorf("failed to write default config: %w", err)
			}
			return nil, fmt.Errorf("config file created at %s, please edit it and run again", path)
		}
		return nil, err
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("no reply rules configured")
	}

	return &cfg, nil
}
