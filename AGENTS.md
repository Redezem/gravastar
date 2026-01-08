# Gravastar Agent Notes

## Project Summary
Gravastar is a POSIX-friendly, C++98 DNS server providing blocklists, local DNS
records, an in-memory cache, and recursive UDP forwarding. Configuration is
TOML. Build is via CMake. Deployment targets include systemd and OpenRC.
This codebase aims to stay portable across POSIX platforms (Linux/BSD/macOS).

## State of Development
- Core DNS server flow is implemented: blocklist -> local records -> cache ->
  UDP upstream.
- DNS-over-TLS (DoT) is configured in TOML but not implemented (currently
  ignored at runtime).
- Server loop is nonblocking and uses a worker thread pool with a synchronized
  job queue.
- Cache access is protected by a mutex for thread safety.
- Unit tests and a `dig`-based integration test exist.
- DNS parser is minimal: single-question queries, no compression handling,
  basic response building for A/AAAA/CNAME only.

## Repository Layout
- `src/`: core implementation
  - `dns_server.cpp`: nonblocking UDP loop + worker pool
  - `dns_packet.cpp`: minimal DNS parsing/response building
  - `cache.cpp`: size/TTL-based cache
  - `blocklist.cpp`: domain blocklist lookup (suffix matches)
  - `local_records.cpp`: local A/AAAA/CNAME records
  - `config.cpp`: minimal TOML parser for project configs
  - `upstream_resolver.cpp`: UDP recursive resolver
- `tests/`: unit tests + integration script
  - `integration_dig.sh`: spins up server and queries via `dig`
- `config/`: sample TOML configs
- `scripts/`: service files for systemd and OpenRC

## Build and Test
- Build:
  - `cmake -S . -B build`
  - `cmake --build build`
- Unit tests:
  - `ctest --test-dir build -R gravastar_tests`
- Integration test (needs UDP socket access and `dig`):
  - `ctest --test-dir build -R gravastar_integration -V`
- Integration test creates a temp config dir under `/tmp` and binds to
  `127.0.0.1:18053`. If this port is in use, the test will fail.

## Runtime Notes
- Default config dir is `/etc/gravastar` (override with `-c`).
- Sample configs in `config/` are used for development/testing.
- DNS packets are handled by a worker pool (4 threads), with the main thread
  only reading from the UDP socket and enqueueing jobs.

## Configuration Schema (TOML)
Main config (`gravastar.toml`):
- `listen_addr` (string): bind address, default `0.0.0.0`
- `listen_port` (int): bind port, default `53`
- `cache_size_mb` (int): cache size in MB, default `100`
- `cache_ttl_sec` (int): cache TTL in seconds, default `120`
- `blocklist_file` (string): relative path to blocklist TOML
- `local_records_file` (string): relative path to local records TOML
- `upstreams_file` (string): relative path to upstreams TOML

Blocklist (`blocklist.toml`):
- `domains` (array of strings): domains to blackhole; matching is suffix-based

Local records (`local_records.toml`):
- `[[record]]` tables with:
  - `name` (string): hostname
  - `type` (string): `A`, `AAAA`, or `CNAME`
  - `value` (string): IP or hostname

Upstreams (`upstreams.toml`):
- `udp_servers` (array of strings): IPv4 upstreams, default tests use
  `9.9.9.9` and `1.1.1.1`
- `dot_servers` (array of strings): DoT hosts, currently ignored

## Request Handling Flow
1. Parse DNS header/question (single question only).
2. Blocklist: if name matches (exact or suffix), return `0.0.0.0` for A,
   `::1` for AAAA, or empty response for others.
3. Local records: if matching name/type, return A/AAAA/CNAME.
4. Cache: lookup full response packet by key `qname|qtype`.
5. Upstream: forward full query over UDP to the first upstream server, cache
   response, and return.

## Concurrency and Synchronization
- Main thread: `select` + `recvfrom` on a nonblocking UDP socket.
- Worker threads: drain a shared queue, process queries, and send responses.
- Queue is protected by `queue_mutex_` and `queue_cv_`.
- Cache uses `cache_mutex_` around `Get`/`Put`.
- `Blocklist` and `LocalRecords` are read-only after load.

## DNS Protocol Notes
- Only UDP is supported.
- Only A/AAAA/CNAME answers are generated locally.
- Answer TTLs are fixed to 60 seconds in responses.
- No response compression is implemented.
- No TCP fallback or EDNS support.

## Service/Deployment Notes
- systemd unit: `scripts/systemd/gravastar.service`
- OpenRC script: `scripts/openrc/gravastar`
- Both default to `/usr/local/bin/gravastar -c /etc/gravastar`
- Running on port 53 typically requires root or CAP_NET_BIND_SERVICE.

## Testing and Tooling Notes
- `dig` is required for integration testing.
- Sandbox environments may block UDP sockets; integration test may need
  elevated permissions.
- Integration script ensures the server is ready by polling with `dig`.

## Troubleshooting
- If the server fails to start, check bind address/port and permissions.
- If integration tests hang, ensure UDP sockets are permitted.
- If upstream resolution fails, confirm network access and upstream reachability.

## Code Style and Portability
- Stick to C++98 and POSIX APIs (pthread, sockets).
- Avoid platform-specific APIs outside POSIX.
- Prefer ASCII in files and comments.

## Concurrency and Safety
- `DnsCache` is protected by a `pthread_mutex` in `DnsServer`.
- `Blocklist` and `LocalRecords` are read-only after load.
- `UpstreamResolver` is stateless per request; uses UDP socket per query.

## Known Limitations / TODO
- DoT support is not implemented; requires a TLS library (conflicts with strict
  “standard libs only” goal, needs a design decision).
- DNS parsing/serialization is minimal: single-question queries only, no
  compression in responses, fixed TTL in answers.
- No TCP fallback or EDNS; only UDP.
- Cache eviction is oldest-first with TTL; consider memory usage of full
  response packets.
- No hot reload of configs.
 - No IPv6 listener support (server binds IPv4 only).
 - No logging beyond stderr messages.

## Suggested Next Steps
1. Decide on DoT support approach (TLS dependency or alternative).
2. Improve DNS protocol coverage (compression, multi-question handling, error
   codes, TTL configuration).
3. Consider per-thread stats/logging and structured logging.
4. Expand integration tests to cover cache hits and upstream recursion.
