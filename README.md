# gravastar

Gravastar is a POSIX-friendly, C++98 DNS server with blocklists, local records,
an in-memory cache, and recursive UDP forwarding.

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Run

```sh
./build/gravastar -c ./config
```

Configuration is TOML and defaults to `/etc/gravastar` when no `-c` argument is
provided. Example configs live in `config`.

## Notes

- DNS-over-TLS is not implemented yet; entries in `dot_servers` are currently
  ignored at runtime.
