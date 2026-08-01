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
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"go.mau.fi/whatsmeow"
	waConsumer "go.mau.fi/whatsmeow/proto/waConsumerApplication"
	waCommon "go.mau.fi/whatsmeow/proto/waCommon"
	waEvents "go.mau.fi/whatsmeow/types/events"
	waTypes "go.mau.fi/whatsmeow/types"
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
	Cookies   map[string]string `yaml:"cookies"`
	Rules     []rule            `yaml:"rules"`
	ReplyOnce bool              `yaml:"reply_once"`
	Mode      string            `yaml:"mode"`
	Proxy     string            `yaml:"proxy"`
	LogLevel  string            `yaml:"log_level"`
}

var defaultRules = []rule{
	{Pattern: `(?i)(?:is this|still)\s+available`, Reply: "Hi, yes it's still available! Let me know if you have any questions."},
	{Pattern: `(?i)(?:where|location|pick.?up)`, Reply: "I'm located in [city/area]. Pickup is available most days."},
	{Pattern: `(?i)(?:price|how much|cost)`, Reply: "The price is listed in the ad. I'm open to reasonable offers."},
	{Pattern: `(?i)(?:condition|used|new)`, Reply: "It's in great condition. Let me know if you'd like more photos."},
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
			testThread, _ = strconv.ParseInt(args[i], 10, 64)
		default:
			cfgPath = a
		}
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	for i := range cfg.Rules {
		cfg.Rules[i].compiled = regexp.MustCompile(cfg.Rules[i].Pattern)
	}

	lvl, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	if selfTest && lvl < zerolog.DebugLevel {
		lvl = zerolog.DebugLevel
	}
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "3:04PM"}).Level(lvl).With().Timestamp().Logger()

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

	mc := messagix.NewClient(c, log, &messagix.Config{
		ClientSettings: exhttp.ClientSettings{},
	})

	ctx := context.Background()

	userInfo, _, err := mc.LoadMessagesPage(ctx)
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

	deepseekKey := os.Getenv("DEEPSEEK_API_KEY")

	bot := &bot{
		log:          log,
		client:       mc,
		waClient:     waClient,
		rules:        cfg.Rules,
		replyOnce:    cfg.ReplyOnce && !selfTest,
		replied:      make(map[int64]map[int]bool),
		userID:       userInfo.GetFBID(),
		selfTest:     selfTest,
		listings:     make(map[int64]*listing),
		threadTypes:  make(map[int64]table.ThreadType),
		deepseekKey:  deepseekKey,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}

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

	listings      map[int64]*listing
	listingsMu    sync.RWMutex
	threadTypes   map[int64]table.ThreadType
	threadTypesMu sync.RWMutex
	deepseekKey   string
	httpClient    *http.Client
}

func (b *bot) handleEvent(ctx context.Context, evt any) {
	tbl, ok := evt.(*table.LSTable)
	if !ok {
		return
	}

	b.threadTypesMu.Lock()
	for _, t := range tbl.LSDeleteThenInsertThread {
		b.threadTypes[t.ThreadKey] = t.ThreadType
	}
	for _, t := range tbl.LSUpdateOrInsertThread {
		b.threadTypes[t.ThreadKey] = t.ThreadType
	}
	for _, t := range tbl.LSVerifyThreadExists {
		b.threadTypes[t.ThreadKey] = t.ThreadType
	}
	b.threadTypesMu.Unlock()

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
	}
	for _, group := range upsert {
		for _, msg := range group.Messages {
			b.processMessage(ctx, msg)
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

func (b *bot) marketplaceThread(threadKey int64) bool {
	b.threadTypesMu.RLock()
	tt, ok := b.threadTypes[threadKey]
	b.threadTypesMu.RUnlock()
	return ok && tt == table.MARKETPLACE
}

func (b *bot) processMessage(ctx context.Context, msg *table.WrappedMessage) {
	threadID := msg.ThreadKey

	if !b.marketplaceThread(threadID) {
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
		return
	}

	text := msg.Text
	if text == "" && l == nil {
		b.log.Debug().Int64("tid", threadID).Int64("sid", msg.SenderId).Msg("empty text, skipped")
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

			b.log.Info().
				Int64("thread", threadID).
				Str("pattern", rule.Pattern).
				Str("message", text).
				Msg("Auto-replying")

			b.sendReply(ctx, threadID, rule.Reply)
			return
		}
	}
	b.log.Debug().Int64("tid", threadID).Str("text", text).Msg("no rule matched")
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
		return "", fmt.Errorf("deepseek api error %d: %s", resp.StatusCode, string(respBody))
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

func (b *bot) sendReply(ctx context.Context, threadID int64, text string) {
	task := &socket.SendMessageTask{
		ThreadId:         threadID,
		Otid:             methods.GenerateEpochID(),
		Source:           table.MESSENGER_INBOX_IN_THREAD,
		InitiatingSource: table.FACEBOOK_INBOX,
		SendType:         table.TEXT,
		SyncGroup:        1,
		Text:             text,
	}

	if err := b.client.ExecuteStatelessTask(ctx, task); err != nil {
		b.log.Err(err).Msg("Failed to send reply")
		return
	}
	b.log.Info().Msg("reply sent")
}

func (b *bot) e2eeHandler(evt any) {
	b.log.Debug().Str("type", fmt.Sprintf("%T", evt)).Msg("e2ee event")
	switch evt := evt.(type) {
	case *waEvents.FBMessage:
		b.handleE2EEMessage(evt)
	case *waEvents.Connected:
		b.log.Info().Msg("e2ee socket connected")
	case *waEvents.LoggedOut:
		b.log.Warn().Msg("e2ee logged out")
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

	sid, _ := strconv.ParseInt(fbMsg.Info.Sender.User, 10, 64)
	tid, _ := strconv.ParseInt(fbMsg.Info.Chat.User, 10, 64)

	if !b.marketplaceThread(tid) {
		return
	}

	content := consumerApp.GetPayload().GetContent()
	if content == nil {
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
		return
	}

	if fbMsg.Info.IsFromMe {
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
			b.sendE2EEReply(fbMsg.Info.Chat, reply)
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

			b.log.Info().
				Int64("thread", tid).
				Str("pattern", rule.Pattern).
				Str("message", text).
				Msg("Auto-replying (e2ee)")

			b.sendE2EEReply(fbMsg.Info.Chat, rule.Reply)
			return
		}
	}
	b.log.Debug().Int64("tid", tid).Str("text", text).Msg("e2ee no rule matched")
}

func (b *bot) sendE2EEReply(chatJID waTypes.JID, text string) {
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
	if _, err := b.waClient.SendFBMessage(context.Background(), chatJID, msg, nil); err != nil {
		b.log.Err(err).Msg("Failed to send e2ee reply")
		return
	}
	b.log.Info().Msg("e2ee reply sent")
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
