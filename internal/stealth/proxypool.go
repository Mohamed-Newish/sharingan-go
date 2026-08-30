// proxypool.go: opt-in egress-IP rotation. This is deliberately NOT
// wired to activate on its own — many programs' rules of engagement
// require testing from a single, consistent, disclosed IP specifically
// so their own rate-limiting/anti-abuse isn't defeated. A pool is only
// ever built when the operator passes --proxy-pool AND
// --confirm-rotation-permitted (see cmd/act.go) — check the program's
// ROE before using it, not just whether it's technically possible.
package stealth

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProxyPool round-robins across a set of proxies, marking one "burned"
// (skipped for a cooldown) when it draws a blocked response, so a
// single flagged egress IP doesn't keep eating blocks.
type ProxyPool struct {
	mu        sync.Mutex
	transport []*http.Transport
	label     []string
	burnedAt  []time.Time
	next      int
	cooldown  time.Duration
}

// NewProxyPool builds a pool from proxy URLs (http:// or socks5://).
func NewProxyPool(proxyURLs []string, cooldown time.Duration) (*ProxyPool, error) {
	if len(proxyURLs) == 0 {
		return nil, fmt.Errorf("proxy pool: no proxies given")
	}
	p := &ProxyPool{cooldown: cooldown}
	for _, raw := range proxyURLs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy pool: %q: %w", raw, err)
		}
		p.transport = append(p.transport, &http.Transport{Proxy: http.ProxyURL(u)})
		p.label = append(p.label, raw)
		p.burnedAt = append(p.burnedAt, time.Time{})
	}
	return p, nil
}

// Pick returns the next healthy (not currently in cooldown) transport
// and its label, round-robin. If every proxy is burned, it returns the
// least-recently-burned one anyway rather than hanging.
func (p *ProxyPool) Pick() (*http.Transport, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.transport)
	best := -1
	for i := 0; i < n; i++ {
		idx := (p.next + i) % n
		if p.burnedAt[idx].IsZero() || time.Since(p.burnedAt[idx]) > p.cooldown {
			best = idx
			break
		}
	}
	if best == -1 {
		best = p.next % n // all burned — least-recently-picked wins, better than deadlock
	}
	p.next = (best + 1) % n
	return p.transport[best], p.label[best]
}

// MarkBurned puts a proxy (by label, as returned from Pick) into
// cooldown so the next Pick skips it.
func (p *ProxyPool) MarkBurned(label string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, l := range p.label {
		if l == label {
			p.burnedAt[i] = time.Now()
			return
		}
	}
}
