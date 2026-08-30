// probe.go: liveness check via httprobe. Reads lay.Domains, writes
// confirmed-live hosts to lay.Hosts.
package active

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

func runProbe(target string, lay *output.Layout, cfg Config) error {
	domains, err := store.ReadLines(lay.Domains)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		domains = []string{target} // nothing enumerated yet — at least probe the target itself
	}

	concurrency := cfg.Profile.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	args := []string{"-c", strconv.Itoa(concurrency), "-prefer-https"}
	lines, err := toolrun.Lines("httprobe", args, strings.Join(domains, "\n"))
	if err != nil {
		return err
	}

	hosts, err := store.Open(lay.Hosts)
	if err != nil {
		return err
	}
	added, err := hosts.AddAll(lines)
	if err != nil {
		return err
	}
	fmt.Printf("act: %s: probe: +%d live hosts\n", target, added)
	return nil
}
