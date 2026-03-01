#!/bin/sh
set -eu

if ! command -v dig >/dev/null 2>&1; then
  echo "SKIP: dig not found"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not found"
  exit 0
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 /path/to/gravastar"
  exit 1
fi

GRAVASTAR_BIN="$1"
PORT=18056
WORKDIR="$(mktemp -d)"
LOGDIR="$WORKDIR/logs"
MOCK_LOG="$WORKDIR/mock_upstream.log"
SERVER_LOG="$WORKDIR/server.out"

cleanup() {
  if [ -n "${PID:-}" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  if [ -n "${UPSTREAM_PID:-}" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

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
udp_servers = ["127.0.0.1"]
CONF

cat > "$WORKDIR/mock_dns.py" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

BIND_ADDR = "127.0.0.1"
BIND_PORT = 53
RDATA = bytes([192, 168, 50, 9])


def question_end(packet):
    if len(packet) < 12:
        return None
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    while pos < len(packet):
        ln = packet[pos]
        pos += 1
        if ln == 0:
            break
        if ln & 0xC0:
            return None
        pos += ln
    if pos + 4 > len(packet):
        return None
    return pos + 4


def make_response(query):
    qend = question_end(query)
    if qend is None:
        return None
    response = bytearray()
    response.extend(query[0:2])  # transaction ID
    response.extend(struct.pack("!H", 0x8180))  # standard response, no error
    response.extend(query[4:6])  # qdcount
    response.extend(struct.pack("!H", 1))  # ancount
    response.extend(b"\x00\x00")  # nscount
    response.extend(b"\x00\x00")  # arcount
    response.extend(query[12:qend])  # original question
    response.extend(b"\xC0\x0C")  # name pointer to question
    response.extend(struct.pack("!H", 1))  # type A
    response.extend(struct.pack("!H", 1))  # class IN
    response.extend(struct.pack("!I", 60))  # ttl
    response.extend(struct.pack("!H", 4))  # rdlength
    response.extend(RDATA)
    return bytes(response)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_ADDR, BIND_PORT))
    while True:
        data, addr = sock.recvfrom(4096)
        resp = make_response(data)
        if resp is not None:
            sock.sendto(resp, addr)


if __name__ == "__main__":
    main()
PY

write_main_config() {
  REBIND="$1"
  cat > "$WORKDIR/gravastar.toml" <<CONF
listen_addr = "127.0.0.1"
listen_port = 18056
cache_size_mb = 1
cache_ttl_sec = 30
rebind_protection = $REBIND
blocklist_file = "blocklist.toml"
local_records_file = "local_records.toml"
upstreams_file = "upstreams.toml"
CONF
}

start_mock_upstream() {
  : > "$MOCK_LOG"
  python3 "$WORKDIR/mock_dns.py" >"$MOCK_LOG" 2>&1 &
  UPSTREAM_PID=$!
  sleep 0.2
  if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    echo "SKIP: unable to start mock upstream on 127.0.0.1:53"
    if [ -s "$MOCK_LOG" ]; then
      cat "$MOCK_LOG"
    fi
    exit 0
  fi
}

stop_mock_upstream() {
  if [ -n "${UPSTREAM_PID:-}" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
    UPSTREAM_PID=""
  fi
}

start_server() {
  mkdir -p "$LOGDIR"
  : > "$SERVER_LOG"
  GRAVASTAR_LOG_DIR="$LOGDIR" "$GRAVASTAR_BIN" -c "$WORKDIR" >"$SERVER_LOG" 2>&1 &
  PID=$!
}

stop_server() {
  if [ -n "${PID:-}" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=""
  fi
}

query_a() {
  dig @127.0.0.1 -p "$PORT" "$1" A +time=1 +tries=1 +short | awk 'NR==1{print; exit}'
}

wait_for_answer() {
  NAME="$1"
  EXPECTED="$2"
  ATTEMPTS=20
  while [ "$ATTEMPTS" -gt 0 ]; do
    OUT="$(query_a "$NAME")"
    if [ "$OUT" = "$EXPECTED" ]; then
      return 0
    fi
    ATTEMPTS=$((ATTEMPTS - 1))
    sleep 0.2
  done
  return 1
}

# Phase 1: rebind protection enabled, upstream private answer is rewritten and cached.
write_main_config "true"
start_mock_upstream
start_server
if ! wait_for_answer "rebind-attack.example.test" "0.0.0.0"; then
  echo "Expected protected upstream answer 0.0.0.0"
  [ -f "$SERVER_LOG" ] && cat "$SERVER_LOG"
  [ -f "$MOCK_LOG" ] && cat "$MOCK_LOG"
  exit 1
fi

stop_mock_upstream
CACHED_OUT="$(query_a "rebind-attack.example.test")"
if [ "$CACHED_OUT" != "0.0.0.0" ]; then
  echo "Expected cached protected answer 0.0.0.0, got: $CACHED_OUT"
  [ -f "$SERVER_LOG" ] && cat "$SERVER_LOG"
  exit 1
fi

LOCAL_OUT="$(query_a "router.local")"
if [ "$LOCAL_OUT" != "192.168.0.1" ]; then
  echo "Expected local private record 192.168.0.1, got: $LOCAL_OUT"
  [ -f "$SERVER_LOG" ] && cat "$SERVER_LOG"
  exit 1
fi
stop_server

# Phase 2: rebind protection disabled, upstream private answer is returned as-is.
write_main_config "false"
start_mock_upstream
start_server
if ! wait_for_answer "rebind-attack.example.test" "192.168.50.9"; then
  echo "Expected unprotected upstream answer 192.168.50.9"
  [ -f "$SERVER_LOG" ] && cat "$SERVER_LOG"
  [ -f "$MOCK_LOG" ] && cat "$MOCK_LOG"
  exit 1
fi

echo "integration rebind ok"
