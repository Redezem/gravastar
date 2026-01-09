# gravastar

Gravastar is a POSIX-friendly, C++98 DNS server with blocklists, local records,
an in-memory cache, and recursive UDP/DoT forwarding.

## Build

```sh
cmake -S . -B build
cmake --build build
```

LibreSSL (libtls) is required for DNS-over-TLS. libcurl is required for
upstream blocklist ingestion.

## Run

```sh
./build/gravastar -c ./config
```

Use `-u /path/to/upstream_blocklists.toml` to enable upstream blocklist updates
from a custom location.

Configuration is TOML and defaults to `/etc/gravastar` when no `-c` argument is
provided. Example configs live in `config`.

Optional upstream blocklist ingestion is enabled when
`/etc/gravastar/upstream_blocklists.toml` exists (or via `-u`).

## Install

```sh
cmake --install build
```

The install target places `gravastar` in `/usr/local/bin` and default configs in
`/etc/gravastar`. Linux installs service scripts for systemd or OpenRC when
detected.

## Logging

Query logs are written to `/var/log/gravastar` by default:
- `pass.log` for successful resolutions
- `block.log` for blocklisted queries

Log files rotate at 100MB, are gz-compressed, and keep up to 10 archives per
log type. For development/testing, set `GRAVASTAR_LOG_DIR` to redirect logs.

## Upstream blocklists

To ingest Pi-hole style upstream blocklists, create
`/etc/gravastar/upstream_blocklists.toml` (or pass `-u` with a custom path).
The updater runs at launch and then periodically (default hourly), caching
upstream files in `/var/gravastar` and rewriting `blocklist.toml`.

Example:

```toml
update_interval_sec = 3600
cache_dir = "/var/gravastar"
urls = [
  "https://example.com/hosts.txt",
  "https://example.com/domains.txt",
  "https://example.com/abp.txt",
]
```

Supported formats: hosts-style, domain-per-line, and simple ABP `||domain^`.

## Notes

- `dot_verify` in `gravastar.toml` controls TLS verification for DoT.
- For DoT, upstreams can be specified as `host@ip:port` to use SNI hostname
  while connecting to a specific IP.
