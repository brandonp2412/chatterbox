# chatterbox

Auto-reply bot for Facebook Marketplace messages. 

## Setup

### Prerequisites

- Go 1.26.5+
- Facebook account with access to Marketplace messages

### 1. Get your Facebook cookies

Open facebook.com or messenger.com in a browser where you're logged in.
Open DevTools → Application → Cookies, and copy the values for:

- `c_user` — your Facebook user ID
- `xs` — your session token
- `datr` — browser identifier

### 2. Configure

```bash
cp config.example.yaml config.yaml
chmod 600 config.yaml
```

Edit `config.yaml` with your cookies and custom reply rules. Chatterbox also tightens the file to
`0600` on startup if it is more permissive.

### 3. Build and run

```bash
go build -o chatterbox
./chatterbox
```

Or run directly:

```bash
go run .
```

If your config file is elsewhere:

```bash
./chatterbox /path/to/config.yaml
```

## Configuration

### Mode

```yaml
mode: "facebook"      # facebook.com cookies
# mode: "messenger"   # messenger.com cookies
# mode: "messenger-lite"  # Messenger Lite API (mobile-style)
```

### Proxy

Set `proxy` to route Meta and DeepSeek HTTP traffic through an HTTP(S) proxy. Leave it blank for
direct connections.

```yaml
proxy: "http://127.0.0.1:8080"
```

### Rules

Each rule has a `pattern` (Go regex) and a `reply` string.

```yaml
rules:
  - pattern: "(?i)is this (still )?available"
    reply: "Yes, it's available!"

  - pattern: "(?i)lowest.*price|best.*offer"
    reply: "Price is firm."

  - pattern: "(?i)ship|delivery|post"
    reply: "Pickup only, sorry."

  - pattern: "(?i)when can (?:i|we) meet"
    reply: "I'm free evenings and weekends."

  - pattern: "(?i)address|where|location"
    reply: "Near the mall. I'll send the exact address once we confirm."
```

Rules are checked in order. The first match sends a reply (and subsequent
rules are skipped for that message).

### reply_once

When `true` (default), each rule fires at most once per chat thread. Set to
`false` to reply every time the pattern matches.

```yaml
reply_once: false
```

### Logging

Logs obscure message content, names, contact details, account/thread/message identifiers, and
credentials by default. Set `log_level: "debug"` only while diagnosing an issue if raw values are
needed; debug and trace logging intentionally leave PII visible.
