// Package passive implements sharingan's -psv sources: everything here
// queries a third party, never the target itself. crt.sh is implemented
// natively (a plain HTTPS GET against a public API). The rest shell out
// to an existing, well-established CLI tool for that source — no reason
// to reimplement subfinder/amass/waybackurls/gau when they already work
// well; this package's job is orchestration and dedupe, not replacing
// best-of-breed tools.
package passive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
)

// Run fans out to the requested sources for one target and dedupe-appends
// every result to lay.Domains (subdomain sources) or lay.URLs (archive
// sources — wayback/gau/otx query a third-party archive, not the
// target, so they belong in passive mode).
func Run(target string, lay *output.Layout, sources string, apiKeys map[string]string, dryRun, verbose bool) error {
	domains, err := store.Open(lay.Domains)
	if err != nil {
		return err
	}
	urls, err := store.Open(lay.URLs)
	if err != nil {
		return err
	}

	for _, src := range strings.Split(sources, ",") {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		if dryRun {
			fmt.Printf("[dry-run] psv: would query %s for %s\n", src, target)
			continue
		}

		var found []string
		var werr error
		switch src {
		case "crtsh":
			found, werr = crtsh(target)
		case "subfinder", "amass-passive", "assetfinder":
			found, werr = shellOutSubdomains(src, target)
		case "wayback":
			found, werr = shellOutLines("waybackurls", target)
		case "gau":
			found, werr = shellOutLines("gau", target)
		case "shodan":
			if key := apiKeys["shodan"]; key != "" {
				found, werr = shodanSubdomains(key, target)
			} else {
				werr = fmt.Errorf("source %q needs an API key — set `shodan: <key>` in your sharingan config "+
					"(~/.config/sharingan/config, or pass -c <file>)", src)
			}
		case "otx", "securitytrails", "censys", "github":
			werr = fmt.Errorf("source %q needs an API key and isn't wired yet — only `shodan` is implemented so far", src)
		default:
			werr = fmt.Errorf("unknown passive source %q", src)
		}
		if werr != nil {
			if verbose {
				fmt.Printf("psv: %s: %v\n", src, werr)
			}
			continue
		}

		dest := domains
		if src == "wayback" || src == "gau" || src == "otx" {
			dest = urls
		}
		added, err := dest.AddAll(found)
		if err != nil {
			return err
		}
		if verbose {
			fmt.Printf("psv: %s: +%d new\n", src, added)
		}
	}
	return nil
}

// crtsh queries crt.sh's public JSON API for certificate-transparency
// subdomains — a request to crt.sh, never to the target.
func crtsh(target string) ([]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sharingan-psv")
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*."))
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out, nil
}

// shodanSubdomains queries Shodan's DNS domain endpoint for a target's
// known subdomains — a request to Shodan's index, never to the target
// itself, so it's safe in passive mode. Costs one Shodan query credit
// per call. Returns fully-qualified hostnames (sub + "." + domain).
func shodanSubdomains(apiKey, domain string) ([]string, error) {
	u := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s",
		url.PathEscape(domain), url.QueryEscape(apiKey))
	c := &http.Client{Timeout: 25 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return nil, fmt.Errorf("shodan: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("shodan: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var r struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("shodan: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range r.Subdomains {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		host := s + "." + domain
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out, nil
}

// shellOutSubdomains wraps an existing passive-mode CLI tool (subfinder
// -silent, amass enum -passive, assetfinder --subs-only) that's already
// good at this.
func shellOutSubdomains(tool, target string) ([]string, error) {
	var cmd *exec.Cmd
	switch tool {
	case "subfinder":
		cmd = exec.Command("subfinder", "-silent", "-d", target)
	case "amass-passive":
		cmd = exec.Command("amass", "enum", "-passive", "-d", target)
	case "assetfinder":
		cmd = exec.Command("assetfinder", "--subs-only", target)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return strings.Fields(string(out)), nil
}

// shellOutLines wraps an archive tool that reads stdin (waybackurls, gau).
func shellOutLines(tool, target string) ([]string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s | %s", target, tool))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}
