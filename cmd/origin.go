// origin.go implements `sharingan origin`: WAF-bypass-via-origin-IP
// discovery (asnmap → naabu → Shodan → TLS-cert verification). Kept as
// its own subcommand, not an `act` flag, because it operates on whole
// CIDR ranges rather than the single target domain scope.List checks
// — see internal/origin's package doc for why --confirm-scope exists
// instead of the usual --scope domain matching.
package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/Mohamed-Newish/sharingan-go/internal/origin"
	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/stealth"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
)

func runOrigin(args []string) int {
	fs := flag.NewFlagSet("origin", flag.ExitOnError)
	target := fs.String("t", "", "target domain")
	fs.StringVar(target, "target", "", "target domain")
	out := fs.String("o", "targets", "output root directory")
	fs.StringVar(out, "out", "targets", "output root directory")
	shodanKey := fs.String("shodan-key", "", "Shodan API key (optional — naabu-only works without it, Shodan just adds cross-reference candidates)")
	ports := fs.String("ports", "80,443", "ports to check per candidate IP")
	profileName := fs.String("profile", "ninja", "stealth profile driving naabu's -rate/-c (default ninja: this sweeps a whole CIDR, be conservative)")
	maxCIDRSize := fs.Int("max-cidr-size", 12, "skip any CIDR bigger than 2^n hosts (default 4096) — the safety cap against sweeping shared-hosting ranges")
	confirmScope := fs.Bool("confirm-scope", false, "required: confirms you've checked the target's ASN/CIDR range is dedicated infra in scope, not shared hosting")
	dryRun := fs.Bool("dry-run", false, "print what would run, send nothing")
	verbose := fs.Bool("v", false, "verbose")
	fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "sharingan origin: -t <target> is required")
		return 2
	}
	if !*confirmScope {
		fmt.Fprintln(os.Stderr, "sharingan origin: --confirm-scope is required — this scans the target's "+
			"entire ASN/CIDR range, not just the one domain. If that ASN is a shared hosting/cloud provider "+
			"rather than infra dedicated to the target, you'd be touching other tenants' hosts. Confirm the "+
			"range is genuinely the target's own dedicated infra before running this.")
		return 2
	}

	prof, ok := stealth.Profiles[*profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "sharingan origin: unknown --profile %q (want ninja|normal|loud)\n", *profileName)
		return 2
	}

	if *dryRun {
		fmt.Printf("[dry-run] origin: would run asnmap -d %s, sweep CIDRs <= 2^%d hosts with naabu (-p %s), "+
			"cross-reference Shodan (key set: %v), TLS-verify every candidate\n",
			*target, *maxCIDRSize, *ports, *shodanKey != "")
		return 0
	}

	candidates, err := origin.Run(origin.Options{
		Target:          *target,
		ShodanKey:       *shodanKey,
		Ports:           *ports,
		Rate:            prof.RatePerSecond,
		Concurrency:     prof.Concurrency,
		MaxCIDRHostBits: *maxCIDRSize,
		Verbose:         *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan origin:", err)
		return 1
	}

	lay, err := output.New(*out, *target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan origin:", err)
		return 1
	}
	results, err := store.Open(lay.OriginIPs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan origin:", err)
		return 1
	}

	verifiedCount := 0
	for _, c := range candidates {
		if c.Verified {
			verifiedCount++
			results.Add(fmt.Sprintf("%s\tverified\t%s", c.IP, c.Source))
			fmt.Printf("origin: %s: %s VERIFIED (via %s) — matches the target's TLS cert\n", *target, c.IP, c.Source)
		} else if *verbose {
			results.Add(fmt.Sprintf("%s\tunverified\t%s", c.IP, c.Source))
		}
	}
	fmt.Printf("origin: %s: %d candidate(s), %d verified, written to %s\n", *target, len(candidates), verifiedCount, lay.OriginIPs)
	return 0
}
