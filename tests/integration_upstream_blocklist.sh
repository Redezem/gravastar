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
PORT=18055
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
listen_port = 18055
cache_size_mb = 1
cache_ttl_sec = 30
dot_verify = false
blocklist_file = "blocklist.toml"
local_records_file = "local_records.toml"
upstreams_file = "upstreams.toml"
CONF

cat > "$WORKDIR/blocklist.toml" <<'CONF'
domains = []
CONF

cat > "$WORKDIR/local_records.toml" <<'CONF'
[[record]]
name = "router.local"
type = "A"
value = "192.168.0.1"
CONF

cat > "$WORKDIR/upstreams.toml" <<'CONF'
udp_servers = ["9.9.9.9"]
CONF

cat > "$WORKDIR/upstream_list.txt" <<'CONF'
0.0.0.0 ads.example.com
||tracker.example.net^
CONF

cat > "$WORKDIR/upstream_blocklists.toml" <<CONF
update_interval_sec = 3600
cache_dir = "$WORKDIR/cache"
urls = ["file://$WORKDIR/upstream_list.txt"]
CONF

mkdir -p "$LOGDIR"
GRAVASTAR_LOG_DIR="$LOGDIR" "$GRAVASTAR_BIN" -c "$WORKDIR" -u "$WORKDIR/upstream_blocklists.toml" &
PID=$!

READY=0
ATTEMPTS=10
while [ "$ATTEMPTS" -gt 0 ]; do
  OUT="$(dig @127.0.0.1 -p "$PORT" ads.example.com A +time=1 +tries=1 +short | awk 'NR==1{print; exit}')"
  if [ "$OUT" = "0.0.0.0" ]; then
    READY=1
    break
  fi
  ATTEMPTS=$((ATTEMPTS - 1))
  sleep 0.2
done

if [ "$READY" -ne 1 ]; then
  echo "Upstream blocklist did not apply"
  exit 1
fi

echo "integration upstream blocklist ok"
