// ports.go: port scan via naabu. Reads lay.Hosts, writes to lay.Ports.
// Rate/concurrency come from the active stealth profile, same as every
// other phase — naabu's own -rate/-c flags are the enforcement point
// since naabu makes its own connections outside sharingan's HTTP client.
package active

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

func runPorts(target string, lay *output.Layout, cfg Config) error {
	hosts, err := store.ReadLines(lay.Hosts)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		hosts = []string{target}
	}

	tmp, err := writeTempList(bareHosts(hosts))
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	args := []string{"-list", tmp, "-silent"}
	if cfg.Profile.RatePerSecond > 0 {
		args = append(args, "-rate", strconv.Itoa(int(cfg.Profile.RatePerSecond)))
	}
	if cfg.Profile.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(cfg.Profile.Concurrency))
	}
	if cfg.Ports == "" || cfg.Ports == "top-1000" {
		args = append(args, "-top-ports", "1000")
	} else {
		args = append(args, "-port", cfg.Ports)
	}

	lines, err := toolrun.Lines("naabu", args, "")
	if err != nil {
		return err
	}

	ports, err := store.Open(lay.Ports)
	if err != nil {
		return err
	}
	added, err := ports.AddAll(lines)
	if err != nil {
		return err
	}
	fmt.Printf("act: %s: ports: +%d open\n", target, added)
	return nil
}

// bareHosts strips scheme and path from a "hosts"-style artifact
// (which stores full URLs like https://example.com, as httprobe writes
// them) down to just host[:port] — what naabu's -list actually wants.
// Deduplicates in case stripping collapses two entries (http+https for
// the same host) into one.
func bareHosts(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		host := u
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
		if host != "" && !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

// writeTempList writes lines to a temp file for tools that want -list
// <file> rather than stdin, and returns its path.
func writeTempList(lines []string) (string, error) {
	f, err := os.CreateTemp("", "sharingan-list-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return "", err
		}
	}
	return f.Name(), nil
}
