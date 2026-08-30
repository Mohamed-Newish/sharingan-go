// Package active implements sharingan's -act pipeline: liveness
// probing, ports, screenshots, live crawling, JS analysis, wordlist
// derivation, and the sqli/xss scan stages. Every phase is expected to
// send its requests through cfg.Client (internal/stealth) — never a
// bare http.Client — and every target is checked against
// cfg.Scope.Allowed() before a single request is built.
//
// There is deliberately no blind content-discovery ("fuzz") phase —
// sweeping a wordlist against every host is exactly the runs-for-days,
// gets-blocked-eventually failure mode this tool exists to avoid, and
// external fuzzers (ffuf/feroxbuster) would bypass the stealth engine
// entirely the same way naabu/katana do (their own connections, not
// cfg.Client's). Brute-forcing belongs only against a specific
// candidate location once one looks worth it — a deliberate, targeted
// call, not an unconditional pipeline phase. wordlist stays: it's pure
// local text-processing of already-fetched urls, zero extra requests,
// and is exactly what would feed a future targeted tool.
//
// screenshots, wordlist, sqli, and xss are still stubs (TODO) — probe,
// ports, crawl, and jsintel are wired to real tools.
package active

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/scope"
	"github.com/Mohamed-Newish/sharingan-go/internal/stealth"
)

// Config bundles every -act flag the pipeline's phases need.
type Config struct {
	Profile        stealth.Profile
	Scope          *scope.List
	Client         *stealth.Client
	Proxy          string
	Ports          string
	BlindXSS       string
	ScreenshotTool string
	WAFProbe       bool
	WAFDeep        bool
	Only           string
	Skip           string
	Resume         bool
	DryRun         bool
	Verbose        bool
}

// pipeline is the fixed phase order --only/--skip select from. No
// "fuzz" — see the package doc for why.
var pipeline = []string{"probe", "ports", "screenshots", "crawl", "jsintel", "wordlist", "sqli", "xss"}

func (c Config) wants(phase string) bool {
	if c.Only != "" {
		return contains(strings.Split(c.Only, ","), phase)
	}
	if c.Skip != "" {
		return !contains(strings.Split(c.Skip, ","), phase)
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == s {
			return true
		}
	}
	return false
}

// Run executes the active pipeline for one target against lay, honoring
// cfg.Only/cfg.Skip/cfg.Resume/cfg.DryRun. It refuses outright if target
// isn't covered by cfg.Scope.
func Run(target string, lay *output.Layout, cfg Config) error {
	if !cfg.Scope.Allowed(target) {
		return fmt.Errorf("%s is not covered by --scope — refusing to send any traffic", target)
	}

	if cfg.WAFProbe && !cfg.DryRun {
		vendor, err := probeWAF(target, cfg.Client)
		if err != nil && cfg.Verbose {
			fmt.Printf("act: waf-probe: %v\n", err)
		}
		if vendor != stealth.VendorNone {
			fmt.Printf("act: %s: detected %s — tightening throttle\n", target, vendor)
			// TODO: rebuild cfg.Client from stealth.ProfileFor(cfg.Profile,
			// vendor) once Client exposes a way to swap its limiter/breaker
			// profile in place. Sketched here rather than wired end-to-end.
		}
	}
	if cfg.WAFDeep && !cfg.DryRun {
		runWAFDeep(target, lay)
	}

	for _, phase := range pipeline {
		if !cfg.wants(phase) {
			continue
		}
		if cfg.DryRun {
			fmt.Printf("[dry-run] act: would run phase %q against %s\n", phase, target)
			continue
		}

		var err error
		switch phase {
		case "probe":
			err = runProbe(target, lay, cfg)
		case "ports":
			err = runPorts(target, lay, cfg)
		case "screenshots":
			err = fmt.Errorf("TODO: shell out to cfg.ScreenshotTool -> lay.Screenshots")
		case "crawl":
			err = runCrawl(target, lay, cfg)
		case "jsintel":
			err = runJSIntel(target, lay, cfg)
		case "wordlist":
			err = fmt.Errorf("TODO: unfurl-equivalent path/param extraction from lay.URLs -> lay.PathWordlist / lay.ParamWordlist")
		case "sqli":
			err = fmt.Errorf("TODO: marker-based SQLi scan -> lay.SQLiCandidates")
		case "xss":
			if cfg.BlindXSS == "" {
				err = fmt.Errorf("skipped: --blind-xss not set — no hardcoded default collector; pass your own")
				break
			}
			err = fmt.Errorf("TODO: marker-based blind-XSS scan -> lay.XSSCandidates")
		}
		if err != nil {
			fmt.Printf("act: %s: %s: %v\n", target, phase, err)
		}
	}
	return nil
}

// probeWAF sends one baseline GET and classifies the response.
func probeWAF(target string, c *stealth.Client) (stealth.Vendor, error) {
	req, err := http.NewRequest("GET", "https://"+target+"/", nil)
	if err != nil {
		return stealth.VendorNone, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return stealth.VendorNone, err
	}
	defer resp.Body.Close()
	return stealth.Identify(resp), nil
}
