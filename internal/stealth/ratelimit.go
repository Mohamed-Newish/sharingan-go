// ratelimit.go implements the adaptive request-rate limiter: it starts
// at a profile's baseline, halves itself on any sign of blocking
// (403/406/429/503), and creeps back up after a clean run. A rate of 0
// means unlimited (the "loud" profile).
package stealth

import (
	"math/rand"
	"sync"
	"time"
)

// Limiter paces one Client's outbound requests.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // current requests/sec, 0 = unlimited
	floor   float64 // never adapt below this
	ceiling float64 // never adapt above the profile's starting rate
	jitter  float64
	clean   int // consecutive non-blocked responses since the last speed-up
}

// NewLimiter builds a Limiter starting at p's rate, allowed to throttle
// down to 1/8th of it but never below, and to climb back up to p's rate
// but no higher.
func NewLimiter(p Profile) *Limiter {
	return &Limiter{
		rate: p.RatePerSecond, floor: p.RatePerSecond / 8,
		ceiling: p.RatePerSecond, jitter: p.Jitter,
	}
}

// Wait blocks until the next request may fire, at the current
// (possibly throttled-down) rate, with randomized jitter so requests
// don't land on a suspiciously regular cadence — a fixed interval is
// itself a fingerprint.
func (l *Limiter) Wait() {
	l.mu.Lock()
	rate := l.rate
	l.mu.Unlock()
	if rate <= 0 {
		return // unlimited (loud profile)
	}
	base := time.Duration(float64(time.Second) / rate)
	delta := time.Duration(float64(base) * l.jitter * (rand.Float64()*2 - 1))
	time.Sleep(base + delta)
}

// ReportBlocked halves the current rate (down to floor) and resets the
// clean-response streak — call this on any 401/403/406/429/503.
func (l *Limiter) ReportBlocked() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = max(l.rate/2, l.floor)
	l.clean = 0
}

// ReportOK nudges the rate back up by 10% after enough consecutive clean
// responses, capped at the profile's ceiling.
func (l *Limiter) ReportOK() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clean++
	if l.clean >= 20 {
		l.rate = min(l.rate*1.1, l.ceiling)
		l.clean = 0
	}
}

// CurrentRate reports the limiter's current requests/sec (post-adaptation),
// mainly for --verbose logging.
func (l *Limiter) CurrentRate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}
