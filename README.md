# gravastar

Gravastar is a POSIX-friendly, C++98 DNS server with blocklists, local records,
an in-memory cache, and recursive UDP/DoT forwarding.

## Build

```sh
cmake -S . -B build
cmake --build build
```

LibreSSL (libtls) is required for DNS-over-TLS.

## Run

```sh
./build/gravastar -c ./config
```

Configuration is TOML and defaults to `/etc/gravastar` when no `-c` argument is
provided. Example configs live in `config`.

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

## Notes

- `dot_verify` in `gravastar.toml` controls TLS verification for DoT.
- For DoT, upstreams can be specified as `host@ip:port` to use SNI hostname
  while connecting to a specific IP.
