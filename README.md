<p align="center">
  <img src="Gravastar.png" alt="Gravastar" width="100%" />
</p>

<p align="center">
	<i>The alternative theory to PiHoles...</i>
</p>

# Gravastar

Gravastar is a POSIX-friendly, C++98 DNS server with blocklists, local records,
an in-memory cache, and recursive UDP/DoT forwarding. Gravastar is designed to be an alternative to PiHole for systems that won't run it/people that don't want to run it.

## But Why?

I'll be honest, I've got a year long project (CE 2026) to move as much of my homelab to OpenBSD as possible. PiHole is my home DNS server, and is also deeply reliant on the Linux ecosystem. This is fine and all, but it wasn't going to work on OpenBSD.

You know what would? A from-scratch POSIX compliant C++98 program that does roughly the same thing. So here we are.

## Build

```sh
cmake -S . -B build
cmake --build build
```

LibreSSL (libtls) is required for DNS-over-TLS. libcurl is required for
upstream blocklist ingestion.

## Test

```sh
bash tests/run_all_tests.sh
```

Optionally pass a build directory:

```sh
bash tests/run_all_tests.sh ./build
```

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

Install should also detect which kind of service system you're using (systemd/openrc... or rc.d if you're OpenBSD like me) and attach a service accordingly. YMMV.

## Releases

Are none, not planned to have any, please compile this yourself. If you can't, go use PiHole.

## Logging

Query logs are written to `/var/log/gravastar` by default:
- `pass.log` for successful resolutions
- `block.log` for blocklisted queries
- `controller.log` for process logging (level-controlled)

Log files rotate at 100MB, are gz-compressed, and keep up to 10 archives per
log type. For development/testing, set `GRAVASTAR_LOG_DIR` to redirect logs.

## Upstream blocklists

To ingest Pi-hole style upstream blocklists, create
`/etc/gravastar/upstream_blocklists.toml` (or pass `-u` with a custom path).
The updater runs at launch and then periodically (default hourly), caching
upstream files in `/var/gravastar`. The entries in `blocklist.toml` are treated
as a custom list and are merged with upstream domains. A generated combined
blocklist is written to `/var/gravastar/blocklist.generated.toml`.

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

Supported formats: hosts-style, domain-per-line, and simple ABP `||domain^`. This should allow you to drop PiHole upstream targets in to Gravastar and for it to *just work*.

## Notes

- `dot_verify` in `gravastar.toml` controls TLS verification for DoT.
- `rebind_protection` in `gravastar.toml` defaults to `true` and rewrites
  upstream RFC1918 IPv4 A answers (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) to `0.0.0.0` before responding/caching; set it to `false`
  to disable this behavior.
- Rebind protection only applies to upstream answers; local records are allowed
  to return local/private addresses.
- `log_level` in `gravastar.toml` controls controller logging verbosity
  (`debug`, `info`, `warn`, `error`), default `debug`.
- For DoT, upstreams can be specified as `host@ip:port` to use SNI hostname
  while connecting to a specific IP.
