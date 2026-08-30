// isolate.go implements `sharingan isolate`: given a URL that's
// currently getting blocked, find which single request component is
// actually responsible (see internal/isolate's package doc).
package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Mohamed-Newish/sharingan-go/internal/isolate"
	"github.com/Mohamed-Newish/sharingan-go/internal/stealth"
)

// headerFlags collects repeated -H 'Name: Value' flags.
type headerFlags map[string]string

func (h headerFlags) String() string { return "" }
func (h headerFlags) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("expected 'Name: Value', got %q", v)
	}
	h[strings.TrimSpace(name)] = strings.TrimSpace(value)
	return nil
}

func runIsolate(args []string) int {
	fs := flag.NewFlagSet("isolate", flag.ExitOnError)
	url := fs.String("url", "", "the currently-blocked URL to isolate the trigger on (required)")
	headers := headerFlags{}
	fs.Var(headers, "H", "extra header 'Name: Value' sent with every request (repeatable)")
	profileName := fs.String("profile", "ninja", "stealth profile for the diagnostic requests")
	ja3 := fs.String("ja3", "chrome", "TLS fingerprint to present: chrome | firefox | off")
	dryRun := fs.Bool("dry-run", false, "print what would be tried, send nothing")
	fs.Parse(args)

	if *url == "" {
		fmt.Fprintln(os.Stderr, "sharingan isolate: --url is required")
		return 2
	}

	if *dryRun {
		fmt.Printf("[dry-run] isolate: would send a baseline request to %s, then — only if it's actually "+
			"blocked — try removing each query param and a battery of evasion headers, one at a time\n", *url)
		return 0
	}

	prof, ok := stealth.Profiles[*profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "sharingan isolate: unknown --profile %q (want ninja|normal|loud)\n", *profileName)
		return 2
	}
	// Isolation deliberately sends a bounded battery of requests that
	// are *expected* to keep coming back blocked — that's the signal,
	// not abuse. The breaker's job is protecting an unbounded bulk scan
	// from hammering a target that's pushing back; it doesn't apply to
	// this small, deliberate diagnostic run, so raise its tolerance far
	// above the profile's normal default. Rate/jitter/concurrency still
	// come from the chosen profile — isolate stays just as slow/quiet
	// per-request, it just won't cut itself off mid-battery.
	prof.BreakerLimit = 1000
	client, err := stealth.NewClient(prof, *ja3, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan isolate:", err)
		return 2
	}

	results, err := isolate.Run(*url, headers, client)
	if len(results) > 0 {
		fmt.Printf("%-45s %6s  %s\n", "MUTATION", "STATUS", "RESULT")
		for _, r := range results {
			switch {
			case r.Error != "":
				fmt.Printf("%-45s %6s  ERROR: %s\n", r.Mutation, "-", r.Error)
			case r.Unblocked:
				fmt.Printf("%-45s %6d  UNBLOCKED ←\n", r.Mutation, r.Status)
			default:
				fmt.Printf("%-45s %6d  still blocked\n", r.Mutation, r.Status)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan isolate:", err)
		return 1
	}
	return 0
}
