# Gravastar Agent Notes

## Project Summary
Gravastar is a POSIX-friendly, C++98 DNS server providing blocklists, local DNS
records, an in-memory cache, and recursive UDP/DoT forwarding. Configuration is
TOML. Build is via CMake. Deployment targets include systemd and OpenRC.
This codebase aims to stay portable across POSIX platforms (Linux/BSD/macOS).

## State of Development
- Core DNS server flow is implemented: blocklist -> local records -> cache ->
  DoT upstream (if configured) -> UDP upstream.
- DNS-over-TLS (DoT) is implemented via LibreSSL/libtls.
- Optional upstream blocklist ingestion is implemented via libcurl.
- Server loop is nonblocking and uses a worker thread pool with a synchronized
  job queue.
- Cache access is protected by a mutex for thread safety.
- Unit tests and `dig`-based integration tests (UDP + DoT) exist.
- DNS parser is minimal: single-question queries, no compression handling,
  basic response building for A/AAAA/CNAME/MX/TXT/PTR only, PTR parsing for logging.

## Repository Layout
- `src/`: core implementation
  - `dns_server.cpp`: nonblocking UDP loop + worker pool
  - `dns_packet.cpp`: minimal DNS parsing/response building
  - `query_logger.cpp`: query logging + rotation
  - `controller_logger.cpp`: process logging + rotation
  - `cache.cpp`: size/TTL-based cache
  - `blocklist.cpp`: domain blocklist lookup (suffix matches)
  - `upstream_blocklist.cpp`: upstream blocklist ingestion (libcurl)
  - `local_records.cpp`: local A/AAAA/CNAME records
  - `config.cpp`: minimal TOML parser for project configs
  - `upstream_resolver.cpp`: UDP/DoT recursive resolver (LibreSSL)
- `tests/`: unit tests + integration script
  - `integration_dig.sh`: spins up server and queries via `dig`
  - `integration_dot.sh`: DoT-only integration test via `dig`
  - `integration_upstream_blocklist.sh`: upstream blocklist integration test
- `config/`: sample TOML configs
- `scripts/`: service files for systemd and OpenRC

## Build and Test
- Build:
  - `cmake -S . -B build`
  - `cmake --build build`
  - Requires LibreSSL (libtls) and libcurl.
- Unit tests:
  - `ctest --test-dir build -R gravastar_tests`
- Integration tests (need network access and `dig`):
  - `ctest --test-dir build -R gravastar_integration -V`
  - `ctest --test-dir build -R gravastar_integration_dot -V`
  - `ctest --test-dir build -R gravastar_integration_upstream_blocklist -V`
  - `ctest --test-dir build -R gravastar_integration_rebind -V`
- All tests (build + unit + integration):
  - `bash tests/run_all_tests.sh`
- Integration tests create a temp config dir under `/tmp` and bind to
  `127.0.0.1:18053`/`127.0.0.1:18054`/`127.0.0.1:18055`/`127.0.0.1:18056`.
  The rebind integration test also starts a mock upstream on `127.0.0.1:53`.
  If these ports are in use, tests fail (or skip for the mock upstream bind case).

## Runtime Notes
- Default config dir is `/etc/gravastar` (override with `-c`).
- Use `-u` to point to a custom `upstream_blocklists.toml`.
- Sample configs in `config/` are used for development/testing.
- DNS packets are handled by a worker pool (4 threads), with the main thread
  only reading from the UDP socket and enqueueing jobs.
- Controller logs are written to `/var/log/gravastar/controller.log` by default.

## Configuration Schema (TOML)
Main config (`gravastar.toml`):
- `listen_addr` (string): bind address, default `0.0.0.0`
- `listen_port` (int): bind port, default `53`
- `cache_size_mb` (int): cache size in MB, default `100`
- `cache_ttl_sec` (int): cache TTL in seconds, default `120`
- `dot_verify` (bool): verify DoT TLS certificates, default `true`
- `rebind_protection` (bool): rewrite upstream RFC1918 IPv4 A answers to
  `0.0.0.0`, default `true` (local records are unaffected)
- `log_level` (string): controller log level (`debug`, `info`, `warn`, `error`)
- `blocklist_file` (string): relative path to blocklist TOML
- `local_records_file` (string): relative path to local records TOML
- `upstreams_file` (string): relative path to upstreams TOML

Upstream blocklists (`upstream_blocklists.toml`):
- `update_interval_sec` (int): update interval in seconds, default `3600`
- `cache_dir` (string): cache directory, default `/var/gravastar`
- `urls` (array of strings): upstream list URLs

Blocklist (`blocklist.toml`):
- `domains` (array of strings): custom domains to blackhole; merged with upstream

Local records (`local_records.toml`):
- `[[record]]` tables with:
  - `name` (string): hostname
  - `type` (string): `A`, `AAAA`, `CNAME`, `MX`, `TXT`, or `PTR`
  - `value` (string): IP or hostname

Upstreams (`upstreams.toml`):
- `udp_servers` (array of strings): IPv4 upstreams, default tests use
  `9.9.9.9` and `1.1.1.1`
- `dot_servers` (array of strings): DoT hosts, supports `host@ip:port`

## Request Handling Flow
1. Parse DNS header/question (single question only).
2. Blocklist: if name matches (exact or suffix), return `0.0.0.0` for A,
   `::1` for AAAA, or empty response for others.
3. Local records: if matching name/type, return A/AAAA/CNAME.
4. Cache: lookup full response packet by key `qname|qtype`.
5. Upstream: forward full query over DoT to the first DoT server (if configured),
   else UDP to the first upstream server; if `rebind_protection` is enabled,
   rewrite upstream private IPv4 A records to `0.0.0.0`; then cache and return.
6. Upstream blocklist updater merges upstream domains with custom `blocklist.toml`
   and writes `/var/gravastar/blocklist.generated.toml`.

## Concurrency and Synchronization
- Main thread: `select` + `recvfrom` on a nonblocking UDP socket.
- Worker threads: drain a shared queue, process queries, and send responses.
- Queue is protected by `queue_mutex_` and `queue_cv_`.
- Cache uses `cache_mutex_` around `Get`/`Put`.
- `Blocklist` updates are protected by an RW lock; `LocalRecords` is read-only after load.

## DNS Protocol Notes
- UDP and DoT are supported for upstream recursion.
- Only A/AAAA/CNAME/MX/TXT/PTR answers are generated locally.
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
- Sandbox environments may block sockets; integration tests may need
  elevated permissions.
- Integration scripts ensure the server is ready by polling with `dig`.

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
- `Blocklist` updates are protected by an RW lock; `LocalRecords` is read-only after load.
- `UpstreamResolver` is stateless per request; uses UDP socket per query.

## Known Limitations / TODO
- DNS parsing/serialization is minimal: single-question queries only, no
  compression in responses, fixed TTL in answers.
- No TCP fallback or EDNS; only UDP.
- Cache eviction is oldest-first with TTL; consider memory usage of full
  response packets.
- No hot reload of configs.
 - No IPv6 listener support (server binds IPv4 only).
 - Logging is file-based; no structured log levels beyond query logs.
 - Upstream blocklist updater does not support per-list overrides beyond merging.

## Suggested Next Steps
1. Improve DNS protocol coverage (compression, multi-question handling, error
   codes, TTL configuration).
2. Consider per-thread stats/logging and structured logging.
3. Expand integration tests to cover cache hits and upstream recursion.
