# PiHole Blocklists

Pi-hole upstream blocklists: supported file formats + specs

What “upstream blocklists” are in Pi-hole

Pi-hole’s Adlists are remote text files (usually served over HTTPS) that Pi-hole periodically downloads and “ingests” into its blocking database (a process called gravity update, e.g. pihole -g).

Important framing:
	•	Pi-hole’s gravity ingestion is domain-based. It ultimately wants a pile of domain names.
	•	Many list publishers ship their data in different “styles” (hosts-style, domain-per-line, Adblock Plus style, etc.).
	•	Pi-hole will ignore entries it can’t interpret as domains (or as a supported ABP domain rule). You’ll see this as “0 domains” from a list, or “ignored non-domain entries” during gravity update.  ￼

⸻

Format 1 — “Hosts file style” lists (classic)

This is the most common format and the one Pi-hole has supported forever.

Spec (what the file looks like)

A plain text file where each relevant line looks like:

0.0.0.0 example.com
127.0.0.1 ads.example.net

Anything after the IP is treated as hostnames/domains separated by whitespace (typical hosts-file conventions). Pi-hole’s gravity processing strips leading IPs/whitespace and keeps the domain portion.  ￼

Allowed / commonly seen details
	•	Leading IP may be 0.0.0.0, 127.0.0.1, etc. (Pi-hole strips it anyway).  ￼
	•	Blank lines are fine.
	•	Comment styles are commonly tolerated (see “Comments & noise” below).

Good for
	•	Big general-purpose ad/malware lists (e.g. StevenBlack hosts).

Pitfalls
	•	Some hosts files include weird tokens or non-domain “names”; those may be ignored as “non-domain entries”.  ￼

⸻

Format 2 — “Domain-only” / “just domains” lists (one domain per line)

This is also very common: one domain per line, no IPs.

Spec

A plain text file like:

example.com
ads.example.net
tracking.somewhere.org

Whitespace around the domain is typically harmless because Pi-hole’s cleanup step trims leading whitespace/tokens.  ￼

Good for
	•	Curated “justdomains” feeds (malwaredomains “justdomains”, Disconnect “simple_*” lists, etc.). (These show up as common upstream list styles used in the ecosystem; Pi-hole expects to turn them into domains internally.)  ￼

Pitfalls
	•	If a list includes wildcards (*.example.com) or regex-looking lines, those are generally not valid “domains” and will be ignored (or treated as non-domain noise).  ￼

⸻

Format 3 — “Simple Adblock Plus (ABP) domain rules” (||domain^)

Some list providers publish in Adblock Plus rule syntax. Pi-hole does not implement the full ABP filtering language, but it can ingest a subset that represents domain anchors.

The supported-looking subset (what you’ll see)

Lines like:

||doubleclick.net^
||2znp09oa.com^

This exact form is called out repeatedly in Pi-hole issue discussions as the “simple ABP” case.  ￼

Semantics (what it means)

In ABP, ||example.com^ is intended to match example.com and its subdomains (effectively “block the whole domain tree”). Pi-hole issue discussion explicitly notes ABP-format being more effective than hosts-format for lists that intend subdomain blocking.  ￼

What Pi-hole does with ABP files

Pi-hole’s gravity processing has historically been hosts/domain focused, and there’s been active work and fixes around properly ingesting ABP ||domain^ style lists (including not accidentally forcing hosts parameters for specific sources).  ￼

What Pi-hole does not support (ABP “full language”)

ABP supports a lot more than ||domain^ (paths, resource types, exceptions, CSS selectors, etc.). Pi-hole is not a browser-content blocker, so those ABP rules are not meaningful at DNS level and are typically removed/ignored during ingestion.  ￼

⸻

Comments & “noise” handling (what gets stripped/ignored)

Real-world lists contain headers, comments, and ABP metadata. Pi-hole’s gravity cleanup has explicit handling for several common ABP/comment patterns (as described in issue discussion), including:
	•	Carriage returns cleanup (Windows line endings)
	•	Lines starting with ! (ABP comments)
	•	Lines starting with [ (ABP header-ish content)
	•	ABP extended selector patterns like ## / #@# / etc. (removed because they aren’t domains)
	•	# comments
	•	Leading whitespace / tokens (also incidentally strips leading IPs in hosts lines)
	•	Empty lines removed  ￼

So: don’t panic if upstream lists contain a bunch of ABP “stuff” — Pi-hole will try to discard what it can’t translate into domains, but you should still prefer lists that are actually domain-based.

⸻

Formats Pi-hole does not support as upstream Adlists

These come up a lot when people try to reuse dnsmasq / router / other adblock formats.

dnsmasq wildcard / config-line blocklists

Example “dnsmasq formatted” lists (often containing things like address=/example.com/0.0.0.0 or wildcard-ish patterns) are not supported as adlists and have been explicitly reported as “list type not supported.”  ￼

Regex lists as subscriptions

Pi-hole supports regex blocking, but regex rules are not meant to be delivered as upstream “adlists”. Regex rules are managed separately in Pi-hole (as regex entries), and they’re evaluated differently and are more expensive than exact-domain blocking.  ￼

⸻

Practical guidance: how to choose + validate a list

1) Prefer domain-based feeds

Best compatibility:
	•	Hosts format (IP + domain)
	•	Domain-per-line (“just domains”)
	•	Simple ABP domain rules (||domain^) when you specifically want subdomain-wide blocking  ￼

Avoid:
	•	dnsmasq config style
	•	ABP lists full of URL paths, element-hiding rules, exceptions, etc.  ￼

2) Validate ingestion after adding a list

After adding the list URL in Pi-hole:
	•	Run a gravity update (UI “Update Gravity” or CLI pihole -g)
	•	Check the output for how many domains were parsed (and whether there were lots of “ignored non-domain entries”).  ￼
	•	Test a known domain using pihole -q domain.tld (this is commonly used in troubleshooting ABP-vs-hosts parsing).  ￼

3) Know what “0 domains” usually means

Common causes:
	•	The URL points to an ABP-heavy list that doesn’t contain many bare domains (or Pi-hole can’t extract domain anchors).
	•	The server requires specific query parameters for the desired output format (hosts vs ABP vs something else), and the URL you used didn’t request the right one.  ￼

⸻

Quick reference: supported upstream blocklist formats (cheat sheet)
	1.	Hosts file style

	•	Example: 0.0.0.0 ads.example.com
	•	Pi-hole strips IPs, ingests domains.  ￼

	2.	Domain-per-line

	•	Example: ads.example.com
	•	Cleanest possible “gravity” input.

	3.	Simple ABP domain anchor rules

	•	Example: ||example.com^
	•	Intended to cover domain + subdomains; Pi-hole discussions treat this as a meaningful supported case, distinct from “full ABP.”  ￼

Not supported as Adlists:
	•	dnsmasq config-style blocklists (“list type not supported”).  ￼
	•	“Regex list subscriptions” (regex rules exist, but are managed separately).  ￼

