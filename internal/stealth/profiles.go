// Package stealth is the WAF/bot-detection-evasion engine: profiles,
// adaptive rate limiting, a circuit breaker, WAF fingerprinting, and
// (eventually) a JA3-controlled HTTP client. Every request -act sends
// goes through this package — see internal/stealth/client.go.
package stealth

import "time"

// Profile is a named stealth posture: how fast, how concurrent, how
// much randomized timing jitter, and how quickly to back off when the
// target starts pushing back.
type Profile struct {
	Name          string
	RatePerSecond float64       // starting request-rate ceiling (0 = unlimited)
	Concurrency   int           // worker pool size
	Jitter        float64       // +/- fraction of inter-request delay to randomize (0.3 = +/-30%)
	BreakerLimit  int           // consecutive blocked responses before the circuit trips
	CooldownAfter time.Duration // how long the breaker stays open once tripped
}

// Profiles are the three built-in stealth postures, selected with
// --profile. Custom profiles can override any of these via -c/--config
// (TODO: wire internal/config's key:value format to a profile override).
var Profiles = map[string]Profile{
	// Slowest, most cautious — use against anything you don't want to
	// risk an IP ban on, or a program with a low rate-limit tolerance.
	"ninja": {
		Name: "ninja", RatePerSecond: 1.5, Concurrency: 2, Jitter: 0.6,
		BreakerLimit: 3, CooldownAfter: 2 * time.Minute,
	},
	// Sane default: fast enough to be useful, still WAF-aware.
	"normal": {
		Name: "normal", RatePerSecond: 10, Concurrency: 10, Jitter: 0.3,
		BreakerLimit: 5, CooldownAfter: time.Minute,
	},
	// No holding back — matches the old recon.sh defaults (naabu -rate
	// 10000, meg -d 1000). Only for programs/agreements that explicitly
	// tolerate it; you lose the WAF-survival benefit of this whole tool.
	"loud": {
		Name: "loud", RatePerSecond: 0, Concurrency: 50, Jitter: 0,
		BreakerLimit: 20, CooldownAfter: 10 * time.Second,
	},
}
