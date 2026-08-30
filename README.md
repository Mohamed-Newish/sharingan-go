# sharingan

A recon/scan orchestrator for authorized bug-bounty and pentest work,
built around a WAF/bot-detection stealth engine rather than raw speed:
an adaptive rate limiter, a circuit breaker, and WAF-vendor fingerprinting
that all tune themselves to how the target is actually reacting, instead
of hammering it at a fixed rate until it starts blocking.

**Status: early / actively developed.** The CLI, safety rails (scope
guard, dry-run, circuit breaker), and output layout are implemented and
tested. `probe`, `ports`, `crawl`, and `jsintel` are wired to real tools
and tested end-to-end; `screenshots`, `wordlist`, `fuzz`, `sqli`, `xss`
are still stubs — see `internal/active/active.go`.

## Four modes

```
sharingan psv     [flags]   passive recon — never opens a connection to the target
sharingan act     [flags]   active recon/scan — touches the target, stealth engine on
sharingan origin  [flags]   find the real origin IP behind a WAF/CDN (opt-in, own scope gate)
sharingan isolate [flags]   find which request component triggers a block
```

`psv` only ever talks to third parties: crt.sh, subfinder/amass in
passive mode, assetfinder, and — because they query a web archive, not
the target — waybackurls/gau. `act` is everything that sends the target
itself a packet: liveness probing, ports, screenshots, crawling,
fuzzing, SQLi/XSS scanning.

## Install

Requires Go 1.22+.

```bash
git clone https://github.com/Mohamed-Newish/sharingan-go.git
cd sharingan-go
go build -o sharingan .
sudo mv sharingan /usr/local/bin/       # optional: put it on your PATH
```

Every phase shells out to an existing best-of-breed tool rather than
reimplementing it — install whichever you plan to use; a missing one
just gets skipped with a clear message, nothing crashes:

| Tool | Used by | Status here |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder), [amass](https://github.com/owasp-amass/amass), [assetfinder](https://github.com/tomnomnom/assetfinder) | `psv` subdomain sources | ✅ tested |
| [waybackurls](https://github.com/tomnomnom/waybackurls), [gau](https://github.com/lc/gau) | `psv` archive sources | ✅ tested |
| [httprobe](https://github.com/tomnomnom/httprobe) | `probe` | ✅ tested |
| [naabu](https://github.com/projectdiscovery/naabu) | `ports`, `origin` | ✅ tested |
| [katana](https://github.com/projectdiscovery/katana) | `crawl` | ⚠️ written from documented flags, not yet tested here |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | `--waf-deep` | ✅ tested |
| [asnmap](https://github.com/projectdiscovery/asnmap) | `origin` | ⚠️ written from documented flags, not yet tested here |
| [jsluice](https://github.com/BishopFox/jsluice) | `jsintel` (endpoints + secrets) | ⚠️ written from documented flags, not yet tested here |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | `jsintel` (endpoints) | ⚠️ written from documented flags, not yet tested here |
| [KeyHack](https://github.com/streaak/keyhack) | `jsintel` (secret validation) | ⚠️ best-effort — exact CLI/output format unverified, fails closed on a mismatch |

`crt.sh` needs nothing extra — it's a plain HTTPS call baked into the
binary. Same for `origin`'s Shodan cross-reference and TLS-cert
verification, and `isolate` — no external tool needed.

## Quickstart

```bash
# 1. Passive recon — safe to run against anything, touches no target infra
sharingan psv -t example.com -o targets

# 2. Sanity-check an active run before it sends anything
sharingan act -t example.com -o targets --dry-run --profile ninja -v

# 3. Run it for real, once the dry-run output looks right
sharingan act -t example.com -o targets --profile ninja
```

Results land in `targets/example.com/` — plain text files, one per data
type, safe to `grep`/`diff`/pipe into anything else.

### Working from a scope file instead of one target

```bash
cat > scope.txt <<EOF
*.example.com
api.example.com
EOF

sharingan psv -l scope.txt -o targets
sharingan act -l scope.txt -o targets --scope scope.txt --profile normal
```

`-l` just lists which targets to run against; `act` additionally
requires `--scope` (often the same file) because it's the allow-list
checked before *every single request* — refusing outright, not just
warning, if a request would go outside it. Passing `-t` for a single
target skips the extra flag: that one target plus its subdomains
becomes the implicit scope.

### Picking how loud to be

```bash
sharingan act -t example.com --profile ninja     # slow, cautious — default choice for anything unfamiliar
sharingan act -t example.com --profile normal     # sane default: fast enough, still WAF-aware
sharingan act -t example.com --profile loud        # unthrottled — only if the program explicitly tolerates it
```

The rate isn't fixed even within a profile — any 401/403/406/429/503
response halves it (down to a floor), and it creeps back up after a run
of clean responses. Too many blocked responses in a row trips a circuit
breaker that halts the run entirely for a cooldown period, rather than
continuing to hammer a target that's already pushing back.

### Narrowing to specific phases

```bash
sharingan act -t example.com --only probe,ports          # just liveness + port scan
sharingan act -t example.com --skip sqli,xss              # everything except the scan stages
sharingan act -t example.com --resume                     # skip phases whose output file already has content
```

### Finding the origin IP behind a WAF

```bash
sharingan origin -t example.com --confirm-scope --dry-run   # see what it would do first
sharingan origin -t example.com --confirm-scope --shodan-key $SHODAN_KEY
```

`asnmap` resolves the target's ASN to CIDR ranges, `naabu` sweeps them
for web ports, Shodan (optional) adds cross-reference candidates by TLS
cert CN — and every candidate is then independently verified with a
direct TLS handshake (target as SNI) checking the returned cert's
CN/SANs, since neither a naabu hit nor a Shodan index entry means "this
is actually the target." Only verified IPs are worth trusting.

**Why `--confirm-scope` instead of `--scope`:** this sweeps the whole
CIDR, not just the target domain — if that ASN turns out to be shared
hosting/cloud infra rather than infra dedicated to the target, you'd be
touching other tenants' hosts. `--max-cidr-size` (default 12, i.e. up to
4096 hosts) caps how large a CIDR it'll touch at all.

### Isolating what triggers a block

```bash
sharingan isolate --url "https://example.com/search?id=1&debug=true" -H "Cookie: session=abc"
```

Sends a baseline request first — if it isn't actually blocked, isolate
stops there ("nothing to isolate"). If it is, it removes each query
parameter one at a time and tries a battery of common WAF-evasion
headers (`X-Forwarded-For`, `X-Originating-IP`, stripped `Referer`,
...), one change at a time, and reports which single change flips the
response back to clean:

```
MUTATION                                      STATUS  RESULT
baseline                                         403  still blocked
remove param "id"                                200  UNBLOCKED ←
remove param "debug"                             403  still blocked
header X-Forwarded-For: 127.0.0.1                403  still blocked
...
```

This deliberately raises its own circuit-breaker tolerance — sending
several blocked requests in a row is the whole point here, not abuse.

### IP rotation on a persistent block

The breaker's own cooldown only helps with short-lived rate-limiting;
a longer WAF/CDN-level IP ban won't clear on its own. Rotating egress
IPs is opt-in and gated for a reason: several programs' rules of
engagement require testing from a single, consistent, disclosed IP
specifically so their own anti-abuse protection isn't defeated — check
that before using this.

```bash
sharingan act -t example.com --proxy-pool proxies.txt --confirm-rotation-permitted
```

`proxies.txt` is one proxy URL per line (`http://` or `socks5://`). A
proxy that draws a blocked response is put in cooldown and skipped on
the next pick, round-robin across the rest.

## Flags

### Shared (both modes)

| Flag | Default | Meaning |
|---|---|---|
| `-t, --target <domain>` | — | single target |
| `-l, --list <file>` | — | scope file, one target per line, `*.example.com` wildcards |
| `-o, --out <dir>` | `targets` | output root; writes to `<out>/<target>/` |
| `-c, --config <file>` | — | API keys / custom profiles (`key: value` format) |
| `--only <phases>` | — | comma list: run just these phases |
| `--skip <phases>` | — | comma list: skip these phases |
| `--resume` | off | skip phases whose output file is already non-empty |
| `--dry-run` | off | print what would run/request, send nothing |
| `-v` | off | verbose |

### `psv`-only

| Flag | Default | Meaning |
|---|---|---|
| `--sources <list>` | `crtsh,subfinder,wayback,gau` | `crtsh,subfinder,amass-passive,assetfinder,securitytrails,censys,shodan,github,wayback,gau,otx` |

### `act`-only

| Flag | Default | Meaning |
|---|---|---|
| `--scope <file>` | — | allow-list; **every** request is checked against it before being sent. Required with `-l`. Optional with `-t` — implies that one target + its subdomains are in scope. |
| `--profile <name>` | `normal` | `ninja` \| `normal` \| `loud` |
| `--rate <n>` | profile default | override starting requests/sec |
| `--concurrency <n>` | profile default | override worker-pool size |
| `--ja3 <chrome\|firefox\|off>` | `chrome` | TLS/header identity to present |
| `--waf-probe` | on | fingerprint the WAF before scanning, auto-tighten throttle |
| `--waf-deep` | off | also run `wafw00f` for report-quality vendor ID (extra requests, opt-in) |
| `--proxy <url>` | — | upstream proxy |
| `--proxy-pool <file>` | — | file of proxy URLs to rotate egress across on a block — see below, mutually exclusive with `--proxy` |
| `--confirm-rotation-permitted` | off | required alongside `--proxy-pool` |
| `--ports <spec>` | `top-1000` | port range for the ports phase |
| `--wordlist <path>` | — | seed wordlist, merged with the auto-derived one |
| `--blind-xss <url>` | — | your collector — the `xss` phase refuses to run without one |
| `--screenshot-tool` | `aquatone` | `aquatone` \| `eyewitness` \| `gowitness` |

### `origin`-only

| Flag | Default | Meaning |
|---|---|---|
| `-t <domain>` | — | target domain (required) |
| `--confirm-scope` | off | required — see above |
| `--shodan-key <key>` | — | optional; naabu-only works without it |
| `--ports <spec>` | `80,443` | ports to check per candidate IP |
| `--profile <name>` | `ninja` | drives naabu's `-rate`/`-c` for the CIDR sweep |
| `--max-cidr-size <n>` | `12` | skip any CIDR bigger than 2^n hosts |

### `isolate`-only

| Flag | Default | Meaning |
|---|---|---|
| `--url <url>` | — | the currently-blocked URL to isolate (required) |
| `-H 'Name: Value'` | — | extra header sent with every request (repeatable) |
| `--profile <name>` | `ninja` | rate/jitter for the diagnostic requests (breaker tolerance is raised internally regardless) |

### Phase vocabulary (`--only`/`--skip`, `act` only)

```
probe → ports → screenshots → crawl → jsintel → wordlist → fuzz → sqli → xss
```

## Stealth profiles

| Profile | rate/s | concurrency | jitter | breaker trips after |
|---|---|---|---|---|
| `ninja` | 1.5 | 2 | ±60% | 3 blocked responses |
| `normal` (default) | 10 | 10 | ±30% | 5 |
| `loud` | unlimited | 50 | none | 20 |

`--waf-probe` sends one baseline request first, fingerprints the vendor
(Cloudflare/Akamai/Imperva/AWS/Sucuri via header + cookie signatures)
and tightens the throttle further for the vendors known to run mature
managed rulesets, regardless of the chosen profile.

## Output layout

Under `<out>/<target>/`:

| File / dir | Holds |
|---|---|
| `domains` | subdomains discovered (passive + active) |
| `hosts` | confirmed-live hosts |
| `ports` | open ports |
| `urls` | harvested URLs (archive + live crawl) |
| `auth_urls` | URLs touching auth/password/token flows — worth a manual look |
| `paths.txt` | derived path wordlist |
| `params.txt` | derived param-name wordlist |
| `sqli_candidates` | marker-based SQLi scan leads — verify by hand before calling it a finding |
| `xss_candidates` | marker-based XSS scan leads — same caveat |
| `screenshots/` | aquatone/eyewitness/gowitness output |
| `raw_responses/` | raw response bodies/headers fetched from each host's root path |
| `js/` | JS files fetched for local analysis (never re-fetched — `jsluice`/`LinkFinder` run against these, not the network) |
| `js_endpoints` | endpoints mined from JS (`jsluice urls` + LinkFinder) |
| `js_secrets_candidates` | secrets mined from JS (`jsluice secrets`) — unverified |
| `js_secrets_verified` | subset KeyHack confirmed actually live |
| `sourcemaps_found` | JS files whose `sourceMappingURL` `.map` was actually fetchable — source disclosure, flag prominently |
| `waf_fingerprint.json` | `wafw00f -a` output, `--waf-deep` only |
| `origin_ips` | candidate origin IPs from `sharingan origin`, TLS-cert-verified or not (tagged) |
| `findings.jsonl` | structured findings, for downstream tooling |
| `sharingan.log` | audit trail of every request sent in `-act` mode — useful as report evidence and proof of scope-compliance |

`sqli_candidates`/`xss_candidates` are deliberately not called
"findings" — they're marker-based scanner leads that still need manual
verification, same as any automated scan output. Every artifact is
append-only and deduped — re-running never loses or reorders prior
results.

## Repo layout

```
sharingan-go/
├── go.mod
├── main.go                     thin entrypoint
├── cmd/
│   ├── root.go                 global flags, mode dispatch, usage
│   ├── psv.go                  `sharingan psv`
│   ├── act.go                  `sharingan act`
│   ├── origin.go                `sharingan origin`
│   └── isolate.go              `sharingan isolate`
└── internal/
    ├── config/config.go        optional API-key / profile config (key: value)
    ├── scope/scope.go          allow-list: wildcard domain matching, enforced pre-request
    ├── store/store.go          dedupe-append artifact files
    ├── output/layout.go        <out>/<target>/ file layout
    ├── toolrun/toolrun.go       shared "shell out and collect output" helper
    ├── passive/passive.go      psv sources (crtsh native; rest shell out to existing tools)
    ├── active/                 act pipeline
    │   ├── active.go            orchestration, scope guard, phase dispatch
    │   ├── probe.go, ports.go, crawl.go   httprobe / naabu / katana wrappers
    │   ├── jsintel.go           JS fetch (via stealth.Client) + jsluice/LinkFinder/sourcemaps/KeyHack
    │   └── waf.go               wafw00f --waf-deep pass
    ├── origin/origin.go        asnmap → naabu → Shodan → TLS-cert-verified origin IP
    ├── isolate/isolate.go      request-component block-trigger isolation
    └── stealth/
        ├── profiles.go         ninja/normal/loud presets
        ├── ratelimit.go        adaptive token-paced limiter with jitter
        ├── breaker.go          circuit breaker
        ├── wafid.go            WAF vendor fingerprinting + per-vendor throttle
        ├── proxypool.go        opt-in egress-IP rotation
        └── client.go           shared http.Client (matched browser identity; utls JA3 TODO)
```

## Disclaimer

For **authorized security testing and educational use only**. Run it
exclusively against assets you own or are explicitly permitted (in
scope) to test.

## Roadmap

1. Wire `screenshots`, `wordlist`, `fuzz`, `sqli`, `xss` — the remaining
   stub phases.
2. Verify `katana`/`asnmap`/`jsluice`/`LinkFinder`/`KeyHack` invocations
   against the real tools once installed (written from documented CLI
   usage, not yet tested here — see the install table above).
3. Thread `internal/config`'s API keys into the
   `securitytrails`/`censys`/`shodan`/`github` passive sources.
4. Swap `stealth.Client`'s transport for a real `utls`-based one so
   `--ja3` actually spoofs a Chrome/Firefox TLS ClientHello.
5. Once a WAF vendor is identified pre-scan, actually rebuild the
   client's limiter/breaker from `stealth.ProfileFor` (currently
   detected and logged, not yet applied — see the TODO in `active.go`).
