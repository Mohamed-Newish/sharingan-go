// jsintel.go: JS analysis phase. Every JS URL is checked against
// cfg.Scope before anything is fetched — a crawled page can easily
// reference third-party JS (CDNs, analytics) that must never be
// treated as target traffic even though the crawl itself only started
// from in-scope hosts. Everything in-scope is then fetched through
// cfg.Client (the stealth engine — rate-limited, breaker-checked),
// saved locally, and analyzed entirely offline (jsluice, LinkFinder,
// sourceMappingURL grep) so the parsing work itself generates zero
// extra target traffic. The one exception is confirming a discovered
// .map file is actually fetchable, which does need one more request
// through cfg.Client.
//
// jsluice, LinkFinder, and KeyHack (via audibleblink/kh — see
// runKeyHack) are all verified against the real tools, including
// jsluice's actual secrets JSON schema.
package active

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/store"
	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

const (
	maxJSFiles   = 300             // safety cap: don't fetch an unbounded number of JS files
	maxJSBodyLen = 5 * 1024 * 1024 // 5MB cap per file
)

var (
	jsURLPattern      = regexp.MustCompile(`(?i)\.js(\?|$)`)
	sourceMapPattern  = regexp.MustCompile(`//[#@]\s*sourceMappingURL=(\S+)`)
	sanitizeFileChars = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
)

func runJSIntel(target string, lay *output.Layout, cfg Config) error {
	urls, err := store.ReadLines(lay.URLs)
	if err != nil {
		return err
	}

	var jsURLs []string
	skippedOutOfScope := 0
	for _, u := range urls {
		if !jsURLPattern.MatchString(u) {
			continue
		}
		// urls can carry third-party JS (CDNs, analytics, ...) picked up
		// while crawling a page — never fetch those as if they were
		// target traffic, even though the crawl itself only started from
		// in-scope hosts.
		parsed, err := url.Parse(u)
		if err != nil || !cfg.Scope.Allowed(parsed.Hostname()) {
			skippedOutOfScope++
			continue
		}
		jsURLs = append(jsURLs, u)
	}
	if skippedOutOfScope > 0 {
		fmt.Printf("act: %s: jsintel: skipped %d out-of-scope JS URL(s) (third-party CDN/analytics, likely)\n", target, skippedOutOfScope)
	}
	if len(jsURLs) == 0 {
		fmt.Printf("act: %s: jsintel: no in-scope .js URLs in urls yet (run crawl first)\n", target)
		return nil
	}
	if len(jsURLs) > maxJSFiles {
		fmt.Printf("act: %s: jsintel: %d JS URLs found, capping at %d\n", target, len(jsURLs), maxJSFiles)
		jsURLs = jsURLs[:maxJSFiles]
	}

	if err := os.MkdirAll(lay.JSDir, 0o755); err != nil {
		return err
	}

	var localFiles []string
	sourcemaps, err := store.Open(lay.Sourcemaps)
	if err != nil {
		return err
	}

	for i, u := range jsURLs {
		body, err := fetchThroughClient(cfg, u)
		if err != nil {
			continue // one bad JS URL shouldn't abort the whole phase
		}
		name := sanitizeFileChars.ReplaceAllString(filepath.Base(u), "_")
		if name == "" || name == "_" {
			name = fmt.Sprintf("file_%d.js", i)
		}
		path := filepath.Join(lay.JSDir, fmt.Sprintf("%d_%s", i, name))
		if !strings.HasSuffix(path, ".js") {
			path += ".js"
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			continue
		}
		localFiles = append(localFiles, path)

		if m := sourceMapPattern.FindSubmatch(body); m != nil {
			if mapURL := resolveURL(u, string(m[1])); mapURL != "" {
				if _, err := fetchThroughClient(cfg, mapURL); err == nil {
					sourcemaps.Add(mapURL) // fetchable — source disclosure risk, flag it
				}
			}
		}
	}

	if len(localFiles) == 0 {
		fmt.Printf("act: %s: jsintel: fetched 0 JS files\n", target)
		return nil
	}
	fmt.Printf("act: %s: jsintel: fetched %d JS files\n", target, len(localFiles))

	endpoints, err := store.Open(lay.JSEndpoints)
	if err != nil {
		return err
	}
	secrets, err := store.Open(lay.JSSecrets)
	if err != nil {
		return err
	}
	verified, err := store.Open(lay.JSSecretsVerified)
	if err != nil {
		return err
	}

	if lines, err := toolrun.Lines("jsluice", append([]string{"urls"}, localFiles...), ""); err == nil {
		endpoints.AddAll(lines)
	} else {
		fmt.Printf("act: %s: jsintel: jsluice urls: %v\n", target, err)
	}
	var secretLines []string
	if lines, err := toolrun.Lines("jsluice", append([]string{"secrets"}, localFiles...), ""); err == nil {
		secretLines = lines
		secrets.AddAll(lines)
	} else {
		fmt.Printf("act: %s: jsintel: jsluice secrets: %v\n", target, err)
	}
	linkfinderErrs := 0
	for _, f := range localFiles {
		if lines, err := toolrun.Lines("linkfinder", []string{"-i", f, "-o", "cli"}, ""); err == nil {
			endpoints.AddAll(lines)
		} else {
			linkfinderErrs++
		}
	}
	if linkfinderErrs == len(localFiles) && len(localFiles) > 0 {
		fmt.Printf("act: %s: jsintel: linkfinder: not installed or failed on every file\n", target)
	}

	for _, line := range secretLines {
		if value, ok := runKeyHack(line); ok {
			verified.Add(value)
		}
	}

	return nil
}

// fetchThroughClient GETs u via the stealth engine and returns the
// (size-capped) body. Every byte of target-directed traffic in this
// phase goes through here — never a bare http.Get.
func fetchThroughClient(cfg Config, u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxJSBodyLen))
}

// resolveURL resolves a possibly-relative sourceMappingURL reference
// against the JS file's own URL.
func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

// runKeyHack tries to validate one jsluice-secrets JSON line against
// its issuing provider, via audibleblink/kh (the executable
// implementation of the streaak/keyhacks validation cookbook — kh
// <service> <token> exits 0 and prints the token if valid, exits 1 and
// prints nothing otherwise). Verified against the real tool: jsluice's
// secrets schema is {"kind":"AWSAccessKey","data":{"key":"..."}} — the
// single string inside "data" is the credential, whatever its field
// name (it varies per kind: "key", "token", etc., so this reads
// whichever one is there rather than hardcoding a name). kh only
// covers 7 services today (github-token, github-oauth, slack-token,
// mailgun, twitter, twitter-bearer, discord); anything else is left an
// unverified candidate, not an error.
func runKeyHack(secretLine string) (value string, ok bool) {
	if !toolrun.Available("keyhack") {
		return "", false
	}
	var parsed struct {
		Kind string                 `json:"kind"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(secretLine), &parsed); err != nil {
		return "", false
	}
	service := keyHackService(parsed.Kind)
	if service == "" {
		return "", false
	}
	secretValue := firstStringValue(parsed.Data)
	if secretValue == "" {
		return "", false
	}

	lines, err := toolrun.Lines("keyhack", []string{service, secretValue}, "")
	if err != nil || len(lines) == 0 {
		return "", false // nonzero exit or no output = invalid, per kh's own contract
	}
	return secretLine, true
}

// keyHackService maps a jsluice secret "kind" (e.g. "AWSAccessKey",
// "SlackToken") to the matching kh service command name, by
// case-insensitive substring — kh's own vocabulary is much smaller
// than jsluice's detector set, so most kinds intentionally return "".
func keyHackService(kind string) string {
	k := strings.ToLower(kind)
	switch {
	case strings.Contains(k, "github") && strings.Contains(k, "oauth"):
		return "github-oauth"
	case strings.Contains(k, "github"):
		return "github-token"
	case strings.Contains(k, "slack"):
		return "slack-token"
	case strings.Contains(k, "mailgun"):
		return "mailgun"
	case strings.Contains(k, "twitter") && strings.Contains(k, "bearer"):
		return "twitter-bearer"
	case strings.Contains(k, "twitter"):
		return "twitter"
	case strings.Contains(k, "discord"):
		return "discord"
	}
	return ""
}

// firstStringValue returns the first string value found in a
// jsluice-secrets "data" object — a name-agnostic read since the field
// name varies per kind and jsluice's detectors typically emit exactly
// one credential string per match.
func firstStringValue(m map[string]interface{}) string {
	for _, v := range m {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
