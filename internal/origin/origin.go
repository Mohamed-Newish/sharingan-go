// Package origin finds the real origin server behind a WAF/CDN: asnmap
// resolves the target's ASN to CIDR ranges, naabu sweeps those ranges
// for web ports, Shodan is cross-referenced by TLS cert CN, and every
// candidate IP is then verified directly (a TLS handshake with the
// target's hostname as SNI, checking the returned cert's CN/SANs) —
// never trusted just because a naabu hit or a Shodan index entry
// pointed at it, since Shodan's index can be stale and naabu just
// means "something is listening," not "it's this target."
//
// This is deliberately NOT wired into the normal act pipeline: CIDR-
// wide scanning touches infrastructure beyond the one target domain
// scope.List checks, so it requires an explicit, separate opt-in (see
// cmd/origin.go) rather than folding into --scope's domain-based
// matching, which doesn't mean anything for raw IPs.
package origin

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

// Options configures one origin-discovery run.
type Options struct {
	Target          string
	ShodanKey       string
	Ports           string // passed to naabu -p, e.g. "80,443"
	Rate            float64
	Concurrency     int
	MaxCIDRHostBits int // skip any CIDR bigger than this (e.g. 12 = /20 or smaller, 4096 hosts)
	Verbose         bool
}

// Candidate is one IP considered, and whether its TLS cert actually
// matched the target.
type Candidate struct {
	IP       string
	Source   string // "naabu" or "shodan"
	Verified bool
}

// Run does the full asnmap → naabu (+ Shodan) → TLS-verify pipeline
// and returns every candidate found (verified or not — callers should
// filter to Verified before treating anything as confirmed).
func Run(o Options) ([]Candidate, error) {
	cidrs, err := toolrun.Lines("asnmap", []string{"-d", o.Target, "-silent"}, "")
	if err != nil {
		return nil, fmt.Errorf("asnmap: %w", err)
	}
	kept, skipped := filterCIDRsBySize(cidrs, o.MaxCIDRHostBits)
	if o.Verbose {
		for _, c := range skipped {
			fmt.Printf("origin: skipping %s — larger than the --max-cidr-size safety cap\n", c)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("asnmap found no CIDR small enough to scan (raise --max-cidr-size to override)")
	}

	seen := map[string]bool{}
	var candidates []Candidate

	for _, cidr := range kept {
		args := []string{"-host", cidr, "-silent"}
		if o.Ports != "" {
			args = append(args, "-p", o.Ports)
		} else {
			args = append(args, "-p", "80,443")
		}
		if o.Rate > 0 {
			args = append(args, "-rate", strconv.Itoa(int(o.Rate)))
		}
		if o.Concurrency > 0 {
			args = append(args, "-c", strconv.Itoa(o.Concurrency))
		}
		lines, err := toolrun.Lines("naabu", args, "")
		if err != nil {
			if o.Verbose {
				fmt.Printf("origin: naabu %s: %v\n", cidr, err)
			}
			continue
		}
		for _, l := range lines {
			ip := l
			if idx := strings.LastIndex(l, ":"); idx != -1 {
				ip = l[:idx]
			}
			if ip != "" && !seen[ip] {
				seen[ip] = true
				candidates = append(candidates, Candidate{IP: ip, Source: "naabu"})
			}
		}
	}

	if o.ShodanKey != "" {
		ips, err := shodanSearch(o.ShodanKey, o.Target)
		if err != nil {
			if o.Verbose {
				fmt.Printf("origin: shodan: %v\n", err)
			}
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				candidates = append(candidates, Candidate{IP: ip, Source: "shodan"})
			}
		}
	}

	for i := range candidates {
		ok, err := verifyOriginTLS(candidates[i].IP, o.Target, 6*time.Second)
		if err != nil && o.Verbose {
			fmt.Printf("origin: verify %s: %v\n", candidates[i].IP, err)
		}
		candidates[i].Verified = ok
	}
	return candidates, nil
}

// filterCIDRsBySize keeps only CIDRs with at most 2^maxHostBits hosts
// — the safety cap against accidentally sweeping a huge, likely
// shared-hosting range that isn't really "the target's own infra."
func filterCIDRsBySize(cidrs []string, maxHostBits int) (kept, skipped []string) {
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			skipped = append(skipped, c)
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits-ones > maxHostBits {
			skipped = append(skipped, c)
			continue
		}
		kept = append(kept, c)
	}
	return
}

// verifyOriginTLS dials ip:443 with the target as SNI (so a
// name-based-virtual-hosted origin serves the right cert) and checks
// whether the returned certificate's CN/SANs actually cover the
// target — the real confirmation step, not just "something answered."
func verifyOriginTLS(ip, target string, timeout time.Duration) (bool, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		InsecureSkipVerify: true, // we're verifying identity ourselves against `target`, not chain trust
		ServerName:         target,
	})
	if err != nil {
		return false, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false, nil
	}
	names := append([]string{certs[0].Subject.CommonName}, certs[0].DNSNames...)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == target {
			return true, nil
		}
		if strings.HasPrefix(n, "*.") && strings.HasSuffix(target, n[1:]) {
			return true, nil
		}
		if strings.HasSuffix(n, "."+target) {
			return true, nil
		}
	}
	return false, nil
}

// shodanSearch queries Shodan for hosts whose TLS cert CN matches the
// target — a candidate list to verify, not a trusted answer on its own.
func shodanSearch(apiKey, target string) ([]string, error) {
	q := fmt.Sprintf(`ssl.cert.subject.cn:"%s"`, target)
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s",
		url.QueryEscape(apiKey), url.QueryEscape(q))

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("shodan: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var ips []string
	for _, m := range result.Matches {
		ips = append(ips, m.IPStr)
	}
	return ips, nil
}
