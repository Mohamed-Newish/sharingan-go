# sharingan (Go)

The Go rewrite of [`Sharingan`](https://github.com/Mohamed-Newish/Sharingan)'s
`recon.sh` + `scanners.sh` — same pipeline, plus a built-in stealth engine
aimed at surviving WAF/bot-detection instead of tripping it. See
`breaking-the-wall/chapters/ch05_how_wafs_work.html` and
`ch06_cloudflare_in_depth.html` for the reasoning behind the design choices
below.

**Status: scaffold.** The CLI, safety rails (scope guard, dry-run,
circuit breaker), and output layout are real and working. Most pipeline
*phases* (`probe`, `ports`, `screenshots`, `crawl`, `wordlist`, `fuzz`,
`sqli`, `xss`) are stubs — see the `TODO` in `internal/active/active.go`.
`crtsh` in `-psv` is fully implemented as a working example of the pattern.

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
| `--scope <file>` | — | allow-list; **every** request is checked against it before being sent. Required with `-l` (a target list isn't automatically an allow-list). Optional with `-t` — implies that one target + its subdomains are in scope. |
| `--profile <name>` | `normal` | `ninja` \| `normal` \| `loud` — see below |
| `--rate <n>` | profile default | override starting requests/sec |
| `--concurrency <n>` | profile default | override worker-pool size |
| `--ja3 <chrome\|firefox\|off>` | `chrome` | TLS/header identity to present |
| `--waf-probe` | on | fingerprint the WAF before scanning, auto-tighten throttle |
| `--proxy <url>` | — | upstream proxy |
| `--ports <spec>` | `top-1000` | port range for the ports phase |
| `--wordlist <path>` | — | seed wordlist, merged with the auto-derived one |
| `--blind-xss <url>` | — | your collector — the `xss` phase refuses to run without one (no hardcoded default, unlike the old `recon.sh`'s placeholder) |
| `--screenshot-tool` | `aquatone` | `aquatone` \| `eyewitness` \| `gowitness` |

### Phase vocabulary (`--only`/`--skip`)

```
probe → ports → screenshots → crawl → wordlist → fuzz → sqli → xss
```
Matches `recon.sh`/`scanners.sh`'s phase order, so it reads the same as
`HUNTING_WORKFLOW.md`.

## Stealth profiles (`internal/stealth/profiles.go`)

| Profile | rate/s | concurrency | jitter | breaker trips after |
|---|---|---|---|---|
| `ninja` | 1.5 | 2 | ±60% | 3 blocked responses |
| `normal` (default) | 10 | 10 | ±30% | 5 |
| `loud` | unlimited | 50 | none | 20 |

Rate **adapts live**: any 401/403/406/429/503 halves it (down to a
floor); 20 consecutive clean responses nudge it back up 10%. A tripped
circuit breaker halts the whole run for the profile's cooldown window
rather than continuing to hammer a target that's already blocking —
"that's the exact behaviour that gets an IP banned."

`--waf-probe` sends one baseline request first, fingerprints the vendor
(Cloudflare/Akamai/Imperva/AWS/Sucuri via header + cookie signatures —
`internal/stealth/wafid.go`), and tightens the throttle further for the
"mature managed rules" vendors regardless of the chosen profile.

## Output layout

Identical to `HUNTING_WORKFLOW.md`, under `<out>/<target>/`: `domains`,
`hosts`, `ports`, `urls`, `reset_password_test`, `path_wlist`,
`param_wlist`, `dsss_res`, `xss_res`, `screenshots/`, `out/` — plus two
new files: `findings.jsonl` (structured, for later tooling/LLM triage)
and `sharingan.log` (audit trail of every request sent in `-act` mode).
Every artifact is append-only and deduped (`internal/store`, the `anew`
equivalent) — re-running never loses or reorders prior results.

## How a run actually flows

1. Parse flags, resolve targets from `-t`/`-l`.
2. **`psv`**: for each target, fan out to the requested sources
   concurrently; dedupe-append subdomain sources to `domains`, archive
   sources to `urls`. Nothing here ever dials the target.
3. **`act`**: for each target —
   1. Refuse immediately if the target isn't covered by `--scope`
      (or the implicit single-target scope from `-t`).
   2. WAF-probe (unless `--no-waf-probe`... not yet a flag, see TODO):
      one baseline request, classify vendor, tighten throttle.
   3. Walk the phase pipeline in order, skipping per `--only`/`--skip`;
      every phase's requests go through the shared `stealth.Client`
      (limiter + breaker + matched browser identity), and every result
      is dedupe-appended to its artifact file.
4. `--dry-run` short-circuits every request-sending step and only prints
   what *would* happen — safe to run against anything to sanity-check a
   command before it touches a target.

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
    ├── store/store.go          anew-equivalent: dedupe-append artifact files
    ├── output/layout.go        <out>/<target>/ file layout matching HUNTING_WORKFLOW.md
    ├── passive/passive.go      psv sources (crtsh native; rest shell out to existing tools)
    ├── active/active.go        act pipeline orchestration, scope guard, phase dispatch
    └── stealth/
        ├── profiles.go         ninja/normal/loud presets
        ├── ratelimit.go        adaptive token-paced limiter with jitter
        ├── breaker.go          circuit breaker
        ├── wafid.go            WAF vendor fingerprinting + per-vendor throttle
        └── client.go           shared http.Client (matched browser identity; utls JA3 TODO)
```

## Build

```bash
go build -o sharingan .
./sharingan act -t example.com --dry-run --profile ninja -v
```

## Next up (in priority order — see the design discussion this came out of)

1. Wire real phase implementations in `internal/active` — start with
   `probe` (httprobe-equivalent) and `ports` (naabu wrapper), since
   everything downstream depends on `hosts`.
2. Thread `internal/config`'s API keys into `passive.Run`'s
   `securitytrails`/`censys`/`shodan`/`github` sources.
3. Swap `stealth.Client`'s transport for a real `utls`-based one so
   `--ja3` actually spoofs a Chrome/Firefox TLS ClientHello instead of
   just validating the flag value.
