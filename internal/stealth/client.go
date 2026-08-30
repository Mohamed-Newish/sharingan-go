// client.go builds the *http.Client every -act request goes through. It
// currently uses Go's standard transport with a realistic, matched
// header set (a UA bundled with the Accept-* headers that actually go
// with it, not just a random UA string). TLS fingerprint spoofing
// (JA3/JA4 via utls, so the client doesn't carry Go's default
// tool-shaped ClientHello — "a default python-requests/Go-http-client
// User-Agent and a tool-shaped TLS JA3 score you as a bot",
// breaking-the-wall/ch06_cloudflare_in_depth.html) is the next layer to
// add here; --ja3 is accepted and validated today but not yet wired to
// an actual utls transport — see the TODO in NewClient.
package stealth

import (
	"fmt"
	"net/http"
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
}

// NewClient builds a Client for profile p, presenting the ja3 identity
// ("chrome" | "firefox" | "off"). Only "chrome"'s header bundle is wired
// up today; "firefox" and the actual utls JA3/JA4 ClientHello spoofing
// for either are TODO — tracked as step 3 of the build sequence (see the
// conversation this scaffold came out of: orchestrator+limiter+breaker
// first, WAF fingerprinter second, utls client third).
func NewClient(p Profile, ja3 string) (*Client, error) {
	switch ja3 {
	case "chrome", "firefox", "off", "":
		// accepted; "firefox" identity and real utls ClientHello spoofing: TODO
	default:
		return nil, fmt.Errorf("unknown --ja3 profile %q (want chrome|firefox|off)", ja3)
	}
	return &Client{
		http:    &http.Client{Timeout: 15 * time.Second},
		limiter: NewLimiter(p),
		breaker: NewBreaker(p),
		id:      chromeIdentity,
	}, nil
}

// Do sends req through the breaker + limiter, tagging it with a matched
// browser identity first, and feeds the response back into both so the
// next request adapts.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.breaker.Check(); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.id.UserAgent)
	req.Header.Set("Accept", c.id.Accept)
	req.Header.Set("Accept-Language", c.id.AcceptLanguage)

	c.limiter.Wait()
	resp, err := c.http.Do(req)
	if err != nil {
		return resp, err
	}
	if blocked(resp.StatusCode) {
		c.limiter.ReportBlocked()
		c.breaker.RecordBlocked()
	} else {
		c.limiter.ReportOK()
		c.breaker.RecordOK()
	}
	return resp, nil
}

func blocked(code int) bool {
	switch code {
	case 401, 403, 406, 429, 503:
		return true
	}
	return false
}
