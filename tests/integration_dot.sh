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
PORT=18054
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
listen_port = 18054
cache_size_mb = 1
cache_ttl_sec = 30
dot_verify = false
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
udp_servers = []
dot_servers = ["cloudflare-dns.com@1.1.1.1"]
CONF

mkdir -p "$LOGDIR"
PRELOAD=""
if [ -f "/usr/lib/libressl/libssl.so.60" ] && [ -f "/usr/lib/libressl/libcrypto.so.57" ]; then
  PRELOAD="/usr/lib/libressl/libssl.so.60:/usr/lib/libressl/libcrypto.so.57"
fi
if [ -n "$PRELOAD" ]; then
  LD_PRELOAD="$PRELOAD" GRAVASTAR_LOG_DIR="$LOGDIR" "$GRAVASTAR_BIN" -d -c "$WORKDIR" >"$WORKDIR/server.out" 2>&1 &
else
  GRAVASTAR_LOG_DIR="$LOGDIR" "$GRAVASTAR_BIN" -d -c "$WORKDIR" >"$WORKDIR/server.out" 2>&1 &
fi
PID=$!

READY=0
ATTEMPTS=10
while [ "$ATTEMPTS" -gt 0 ]; do
  if dig @127.0.0.1 -p "$PORT" example.com A +time=1 +tries=1 +short >/dev/null 2>&1; then
    READY=1
    break
  fi
  ATTEMPTS=$((ATTEMPTS - 1))
  sleep 0.2
done

if [ "$READY" -ne 1 ]; then
  echo "Server did not become ready"
  if [ -f "$WORKDIR/server.out" ]; then
    cat "$WORKDIR/server.out"
  fi
  exit 1
fi

EXT_OUT="$(dig @127.0.0.1 -p "$PORT" example.com A +time=2 +tries=1 +short | awk 'NR==1{print; exit}')"
if [ -z "$EXT_OUT" ]; then
  echo "Expected DoT resolution to return an A record"
  if [ -f "$WORKDIR/server.out" ]; then
    cat "$WORKDIR/server.out"
  fi
  exit 1
fi

MX_OUT="$(dig @127.0.0.1 -p "$PORT" mail.local MX +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
TXT_OUT="$(dig @127.0.0.1 -p "$PORT" info.local TXT +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
PTR_OUT="$(dig @127.0.0.1 -p "$PORT" 1.0.0.127.in-addr.arpa PTR +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"

if [ "$MX_OUT" != "10 mailhost.local." ]; then
  echo "Expected MX record '10 mailhost.local.', got: $MX_OUT"
  if [ -f "$WORKDIR/server.out" ]; then
    cat "$WORKDIR/server.out"
  fi
  exit 1
fi

if [ "$TXT_OUT" != "\"hello world\"" ]; then
  echo "Expected TXT record \"hello world\", got: $TXT_OUT"
  if [ -f "$WORKDIR/server.out" ]; then
    cat "$WORKDIR/server.out"
  fi
  exit 1
fi

if [ "$PTR_OUT" != "router.local." ]; then
  echo "Expected PTR record router.local., got: $PTR_OUT"
  if [ -f "$WORKDIR/server.out" ]; then
    cat "$WORKDIR/server.out"
  fi
  exit 1
fi

echo "integration dot ok"
