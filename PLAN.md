# Gravastar

A from-scratch DNS server that provides similar capability to FTLDNS, DNS lookup caching, DNS and DoT recursive lookup, local DNS name hosting via A, AAAA, and CNAME records, and DNS blackholing via blocklists.

## Project Requirements
Firstly, this should be a *strictly POSIX*, C++99 standard, minimal or no prerequisite project. Ideally this is all build from scratch using only the standard C++ libraries and POSIX libs. Nothing Linux, Mac, or BSD specific. And I'm not planning on supporting Windows at *all*. 

As this is a DNS server, lookups should be optimised to be as fast as possible, so choice of data structures for the different caches is critical. 

Build processes should be handled with Cmake. Testing should be comprehensive and consist of both expected passes and expected fails. Config should be assumed to be in /etc/gravastar unless otherwise specified (eg, for testing purposes). Deployment should be multifaceted, so both systemd service files and openrc service scripts. All configuration files should be considered to be TOML format.

## DNS Server

The DNS server component should be a full featured DNS server ala BIND. Lookup priority should proceed as follows:
	1. blocklists
	2. local dns names
	3. cached dns results
	4. recursive lookup

### Blocklists

Blocklists should be configured from a configuration file containing a list of domains that should be blackholed. These should be loaded at the start of the program, and should they match a request (of any type), the result should be empty (in the case of TXT or similar requests) or resolve to 0.0.0.0 or ::1 (in the case of A or AAAA or similar results). 

### Local DNS Names

Local DNS names should be loaded from a seperate configuration file that contains objects for each item. These items should contain the hostname, the associated IPv4/IPv6/DNS address, and the associated type (A for IPv4, AAAA for IPv6, CNAME for another DNS name). Should a local DNS name match a query, it should be returned preferentially prior to cache or recursive lookup.

### Cached dns results

When a recursive DNS lookup is made, the result should be saved in the DNS lookup cache. This Cache should be configurable in terms of size and lifetime, but should default to 100 megabytes of RAM and a lifetime of 2 minutes. If the cache is full, cached results should be dropped in the order of oldest entry first, and should the lifetime expire the result should also be dropped from the cache. If an incoming DNS query doesn't match an item in the Blocklists or in the local names, it should be checked against the cache before being sent for recursive lookup. Should it match a cached entry, that entry should be returned.

### Recursive lookup

Should a query not match any locally stored results, the query should be forwarded to one of the configured recursive lookup servers. The location of these servers should be set as objects in a recursive lookup config file. The lookup process should support standard DNS and also DNS over TLS (DoT). DNS over HTTPS (DoH) is not currently planned to be supported. For testing, DNS servers 9.9.9.9 and 1.1.1.1 should be used, and DoT server dns.quad9.net should be used.