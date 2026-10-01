#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

secret='e2e-proxy-secret-7f3d'
config="$tmp/config.yaml"
binary="$tmp/chatterbox"

cat >"$config" <<EOF
mode: "facebook"
proxy: "http://proxy-user:${secret}@127.0.0.1:%zz"
cookies:
  xs: "dummy-xs"
  c_user: "123456789"
  datr: "dummy-datr"
rules:
  - pattern: "(?i)available"
    reply: "Yes"
reply_once: true
log_level: "info"
EOF
chmod 600 "$config"

(
  cd "$repo_root"
  go build -o "$binary" .
)

set +e
output=$("$binary" "$config" 2>&1)
status=$?
set -e

if [[ $status -eq 0 ]]; then
  printf 'expected startup to reject malformed proxy, but it exited successfully\n' >&2
  exit 1
fi

if [[ "$output" != *"invalid proxy"* ]]; then
  printf 'test setup did not reach proxy validation; output was:\n%s\n' "$output" >&2
  exit 2
fi

if [[ "$output" == *"$secret"* ]]; then
  printf 'proxy credential leaked in startup diagnostics:\n%s\n' "$output" >&2
  exit 3
fi

printf 'proxy credentials remained redacted in startup diagnostics\n'
