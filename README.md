# sharingan

A recon/scan orchestrator for authorized bug-bounty and pentest work,
built around a WAF/bot-detection stealth engine rather than raw speed:
an adaptive rate limiter, a circuit breaker, and WAF-vendor fingerprinting
that all tune themselves to how the target is actually reacting, instead
of hammering it at a fixed rate until it starts blocking.

**Status: early / actively developed.** The CLI, safety rails (scope
guard, dry-run, circuit breaker), and output layout are implemented and
tested. Most pipeline *phases* (`probe`, `ports`, `screenshots`, `crawl`,
`wordlist`, `fuzz`, `sqli`, `xss`) are stubs today — see
`internal/active/active.go`. `crtsh` in passive mode is fully working as
a reference implementation of the pattern the other sources will follow.

Every run prints a Sharingan-eye banner (truecolor Unicode half-blocks —
disable with `NO_COLOR=1` or `SHARINGAN_NO_BANNER=1`; it never prints
when output isn't a terminal, e.g. piped or redirected).

## Two modes, one hard boundary

```
sharingan psv [flags]   passive recon — never opens a connection to the target
sharingan act [flags]   active recon/scan — touches the target, stealth engine on
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

`psv`/`act` shell out to a few external tools for the sources/phases
that already wrap them well — install whichever of these you plan to
use:

- [subfinder](https://github.com/projectdiscovery/subfinder), [amass](https://github.com/owasp-amass/amass), [assetfinder](https://github.com/tomnomnom/assetfinder) — subdomain enumeration
- [waybackurls](https://github.com/tomnomnom/waybackurls), [gau](https://github.com/lc/gau) — archive URL harvesting

`crt.sh` needs nothing extra — it's a plain HTTPS call baked into the
binary.

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
| `--proxy <url>` | — | upstream proxy |
| `--ports <spec>` | `top-1000` | port range for the ports phase |
| `--wordlist <path>` | — | seed wordlist, merged with the auto-derived one |
| `--blind-xss <url>` | — | your collector — the `xss` phase refuses to run without one |
| `--screenshot-tool` | `aquatone` | `aquatone` \| `eyewitness` \| `gowitness` |

### Phase vocabulary (`--only`/`--skip`)

```
probe → ports → screenshots → crawl → wordlist → fuzz → sqli → xss
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
│   ├── root.go                 global flags, psv/act dispatch, usage
│   ├── psv.go                  `sharingan psv`
│   └── act.go                  `sharingan act`
└── internal/
    ├── config/config.go        optional API-key / profile config (key: value)
    ├── scope/scope.go          allow-list: wildcard domain matching, enforced pre-request
    ├── store/store.go          dedupe-append artifact files
    ├── output/layout.go        <out>/<target>/ file layout
    ├── passive/passive.go      psv sources (crtsh native; rest shell out to existing tools)
    ├── active/active.go        act pipeline orchestration, scope guard, phase dispatch
    └── stealth/
        ├── profiles.go         ninja/normal/loud presets
        ├── ratelimit.go        adaptive token-paced limiter with jitter
        ├── breaker.go          circuit breaker
        ├── wafid.go            WAF vendor fingerprinting + per-vendor throttle
        └── client.go           shared http.Client (matched browser identity; utls JA3 TODO)
```

## Disclaimer

For **authorized security testing and educational use only**. Run it
exclusively against assets you own or are explicitly permitted (in
scope) to test.

## Roadmap

1. Wire real phase implementations in `internal/active` — starting with
   `probe` (liveness) and `ports`, since everything downstream depends
   on `hosts`.
2. Thread `internal/config`'s API keys into the
   `securitytrails`/`censys`/`shodan`/`github` passive sources.
3. Swap `stealth.Client`'s transport for a real `utls`-based one so
   `--ja3` actually spoofs a Chrome/Firefox TLS ClientHello.
