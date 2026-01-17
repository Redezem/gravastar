#!/bin/sh
set -eu

if ! command -v dig >/dev/null 2>&1; then
  echo "SKIP: dig not found"
  exit 0
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 /path/to/gravastar"
  exit 1
fi

GRAVASTAR_BIN="$1"
PORT=18053
WORKDIR="$(mktemp -d)"
LOGDIR="$WORKDIR/logs"

cleanup() {
  if [ -n "${PID:-}" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

cat > "$WORKDIR/gravastar.toml" <<'CONF'
listen_addr = "127.0.0.1"
listen_port = 18053
cache_size_mb = 1
cache_ttl_sec = 30
blocklist_file = "blocklist.toml"
local_records_file = "local_records.toml"
upstreams_file = "upstreams.toml"
CONF

cat > "$WORKDIR/blocklist.toml" <<'CONF'
domains = ["ads.example.com"]
CONF

cat > "$WORKDIR/local_records.toml" <<'CONF'
[[record]]
name = "router.local"
type = "A"
value = "192.168.0.1"

[[record]]
name = "mail.local"
type = "MX"
value = "10 mailhost.local"

[[record]]
name = "info.local"
type = "TXT"
value = "hello world"

[[record]]
name = "1.0.0.127.in-addr.arpa"
type = "PTR"
value = "router.local"
CONF

cat > "$WORKDIR/upstreams.toml" <<'CONF'
udp_servers = ["9.9.9.9"]
CONF

mkdir -p "$LOGDIR"
GRAVASTAR_LOG_DIR="$LOGDIR" "$GRAVASTAR_BIN" -c "$WORKDIR" &
PID=$!

READY=0
ATTEMPTS=10
while [ "$ATTEMPTS" -gt 0 ]; do
  if dig @127.0.0.1 -p "$PORT" router.local A +time=1 +tries=1 +short >/dev/null 2>&1; then
    READY=1
    break
  fi
  ATTEMPTS=$((ATTEMPTS - 1))
  sleep 0.2
done

if [ "$READY" -ne 1 ]; then
  echo "Server did not become ready"
  exit 1
fi

LOCAL_OUT="$(dig @127.0.0.1 -p "$PORT" router.local A +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
BLOCK_OUT="$(dig @127.0.0.1 -p "$PORT" ads.example.com A +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
MX_OUT="$(dig @127.0.0.1 -p "$PORT" mail.local MX +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
TXT_OUT="$(dig @127.0.0.1 -p "$PORT" info.local TXT +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
PTR_OUT="$(dig @127.0.0.1 -p "$PORT" 1.0.0.127.in-addr.arpa PTR +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"

if [ "$LOCAL_OUT" != "192.168.0.1" ]; then
  echo "Expected local record 192.168.0.1, got: $LOCAL_OUT"
  exit 1
fi

if [ "$BLOCK_OUT" != "0.0.0.0" ]; then
  echo "Expected blocklisted record 0.0.0.0, got: $BLOCK_OUT"
  exit 1
fi

if [ "$MX_OUT" != "10 mailhost.local." ]; then
  echo "Expected MX record '10 mailhost.local.', got: $MX_OUT"
  exit 1
fi

if [ "$TXT_OUT" != "\"hello world\"" ]; then
  echo "Expected TXT record \"hello world\", got: $TXT_OUT"
  exit 1
fi

if [ "$PTR_OUT" != "router.local." ]; then
  echo "Expected PTR record router.local., got: $PTR_OUT"
  exit 1
fi

echo "integration ok"
