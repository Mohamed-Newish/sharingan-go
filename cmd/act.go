// act.go implements `sharingan act`: active recon/scan. Every request
// this mode sends goes through the stealth engine (internal/stealth) —
// adaptive rate limiting, a circuit breaker, and per-WAF-vendor
// throttling — and is checked against the scope allow-list before it's
// ever built, let alone fired.
package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/Mohamed-Newish/sharingan-go/internal/active"
	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/scope"
	"github.com/Mohamed-Newish/sharingan-go/internal/stealth"
)

func runAct(args []string) int {
	fs := flag.NewFlagSet("act", flag.ExitOnError)
	g := &Global{}
	registerGlobal(fs, g)
	scopeFile := fs.String("scope", "", "in-scope allow-list file; every request is checked against it before it's sent (required with -l; optional with -t, which implies single-target scope)")
	profileName := fs.String("profile", "normal", "stealth profile: ninja | normal | loud")
	rate := fs.Float64("rate", 0, "override the profile's starting requests/sec (0 = use profile default)")
	concurrency := fs.Int("concurrency", 0, "override the profile's worker-pool size (0 = use profile default)")
	ja3 := fs.String("ja3", "chrome", "TLS fingerprint to present: chrome | firefox | off")
	wafProbe := fs.Bool("waf-probe", true, "fingerprint the WAF before scanning and auto-tune throttling")
	proxy := fs.String("proxy", "", "upstream proxy URL (http/socks5)")
	ports := fs.String("ports", "top-1000", "port range/list for the port-scan phase")
	wordlist := fs.String("wordlist", "", "seed wordlist for the fuzz phase, merged with the auto-derived path/param lists")
	blindXSS := fs.String("blind-xss", "", "your blind-XSS collector URL — the xss phase refuses to run without one")
	screenshotTool := fs.String("screenshot-tool", "aquatone", "aquatone | eyewitness | gowitness")
	fs.Parse(args)

	prof, ok := stealth.Profiles[*profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "sharingan act: unknown --profile %q (want ninja|normal|loud)\n", *profileName)
		return 2
	}
	if *rate > 0 {
		prof.RatePerSecond = *rate
	}
	if *concurrency > 0 {
		prof.Concurrency = *concurrency
	}

	targets, err := g.Targets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan act:", err)
		return 2
	}

	var sc *scope.List
	switch {
	case *scopeFile != "":
		sc, err = scope.Load(*scopeFile)
	case g.Target != "":
		sc = scope.Single(g.Target)
	default:
		fmt.Fprintln(os.Stderr, "sharingan act: --scope <file> is required when using -l "+
			"(the -l file just lists targets to run — it isn't an allow-list by itself; "+
			"pass the same file to --scope, or a stricter one)")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan act:", err)
		return 2
	}

	client, err := stealth.NewClient(prof, *ja3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan act:", err)
		return 2
	}

	cfg := active.Config{
		Profile:        prof,
		Scope:          sc,
		Client:         client,
		Proxy:          *proxy,
		Ports:          *ports,
		Wordlist:       *wordlist,
		BlindXSS:       *blindXSS,
		ScreenshotTool: *screenshotTool,
		WAFProbe:       *wafProbe,
		Only:           g.Only,
		Skip:           g.Skip,
		Resume:         g.Resume,
		DryRun:         g.DryRun,
		Verbose:        g.Verbose,
	}

	for _, t := range targets {
		lay, err := output.New(g.Out, t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sharingan act:", err)
			return 1
		}
		if err := active.Run(t, lay, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "sharingan act: %s: %v\n", t, err)
		}
	}
	return 0
}
