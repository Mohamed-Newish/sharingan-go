// crawl.go: live URL harvest via katana. Reads lay.Hosts, appends to
// lay.URLs (same file wayback/gau feed in passive mode — a URL is a
// URL regardless of source).
//
// NOTE: katana wasn't available to test this against at write time —
// flags below are written from katana's documented usage (-list,
// -silent, -c concurrency, -rl rate-limit, -d depth) and should be
// double-checked against `katana -h` once it's installed.
package active

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

func runCrawl(target string, lay *output.Layout, cfg Config) error {
	hosts, err := store.ReadLines(lay.Hosts)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		hosts = []string{target}
	}

	tmp, err := writeTempList(hosts)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	args := []string{"-list", tmp, "-silent", "-d", "2"}
	if cfg.Profile.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(cfg.Profile.Concurrency))
	}
	if cfg.Profile.RatePerSecond > 0 {
		args = append(args, "-rl", strconv.Itoa(int(cfg.Profile.RatePerSecond)))
	}

	lines, err := toolrun.Lines("katana", args, "")
	if err != nil {
		return err
	}

	urls, err := store.Open(lay.URLs)
	if err != nil {
		return err
	}
	added, err := urls.AddAll(lines)
	if err != nil {
		return err
	}
	fmt.Printf("act: %s: crawl: +%d urls\n", target, added)
	return nil
}
