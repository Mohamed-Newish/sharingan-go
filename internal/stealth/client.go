// client.go builds the *http.Client every -act request goes through. It
// currently uses Go's standard transport with a realistic, matched
// header set (a UA bundled with the Accept-* headers that actually go
// with it, not just a random UA string). Go's default transport also
// carries a distinctive TLS ClientHello (JA3/JA4 fingerprint) that's
// trivially detectable as "not a browser" — spoofing a real Chrome/
// Firefox fingerprint via utls is the next layer to add here; --ja3 is
// accepted and validated today but not yet wired to an actual utls
// transport — see the TODO in NewClient.
package stealth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// identity is a User-Agent bundled with the Accept-* headers a real
// browser sends alongside it, so the header set reads as one consistent
// client rather than a mismatched UA-plus-defaults giveaway.
type identity struct {
	UserAgent      string
	Accept         string
	AcceptLanguage string
}

var chromeIdentity = identity{
	UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	AcceptLanguage: "en-US,en;q=0.9",
}

// Client wraps http.Client with the shared limiter + breaker for one run.
type Client struct {
	http    *http.Client
	limiter *Limiter
	breaker *Breaker
	id      identity
	pool    *ProxyPool // nil unless --proxy-pool + --confirm-rotation-permitted were both set
}

// NewClient builds a Client for profile p, presenting the ja3 identity
// ("chrome" | "firefox" | "off"), optionally through a single upstream
// proxy (empty string = none). Only "chrome"'s header bundle is wired
// up today; "firefox" and the actual utls JA3/JA4 ClientHello spoofing
// for either are TODO.
func NewClient(p Profile, ja3 string, proxyURL string) (*Client, error) {
	switch ja3 {
	case "chrome", "firefox", "off", "":
		// accepted; "firefox" identity and real utls ClientHello spoofing: TODO
	default:
		return nil, fmt.Errorf("unknown --ja3 profile %q (want chrome|firefox|off)", ja3)
	}
	transport := &http.Transport{}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("--proxy %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &Client{
		http:    &http.Client{Timeout: 15 * time.Second, Transport: transport},
		limiter: NewLimiter(p),
		breaker: NewBreaker(p),
		id:      chromeIdentity,
	}, nil
}

// UseProxyPool switches the client onto rotating egress IPs. Opt-in
// only — see proxypool.go's package doc for why this must never
// activate implicitly.
func (c *Client) UseProxyPool(pool *ProxyPool) {
	c.pool = pool
}

// Do sends req through the breaker + limiter, tagging it with a matched
// browser identity first, and feeds the response back into both so the
// next request adapts. When a proxy pool is active, it also picks the
// egress proxy for this request and burns it on a blocked response.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.breaker.Check(); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.id.UserAgent)
	req.Header.Set("Accept", c.id.Accept)
	req.Header.Set("Accept-Language", c.id.AcceptLanguage)

	var proxyLabel string
	if c.pool != nil {
		var t *http.Transport
		t, proxyLabel = c.pool.Pick()
		c.http.Transport = t
	}

	c.limiter.Wait()
	resp, err := c.http.Do(req)
	if err != nil {
		return resp, err
	}
	if IsBlocked(resp.StatusCode) {
		c.limiter.ReportBlocked()
		c.breaker.RecordBlocked()
		if c.pool != nil {
			c.pool.MarkBurned(proxyLabel)
		}
	} else {
		c.limiter.ReportOK()
		c.breaker.RecordOK()
	}
	return resp, nil
}

// IsBlocked reports whether an HTTP status code looks like a
// rate-limit/WAF/auth block rather than a normal response. Exported so
// other diagnostic tools (e.g. the isolate subcommand) can use the same
// definition of "blocked" the adaptive engine uses.
func IsBlocked(code int) bool {
	switch code {
	case 401, 403, 406, 429, 503:
		return true
	}
	return false
}
