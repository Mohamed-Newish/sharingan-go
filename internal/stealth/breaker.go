// breaker.go: a circuit breaker that halts a run after too many
// consecutive blocked responses, rather than continuing to hammer a
// target that has started blocking — "that's the exact behaviour that
// gets an IP banned" (breaking-the-wall/ch05_how_wafs_work.html).
package stealth

import (
	"fmt"
	"sync"
	"time"
)

// Breaker trips after Profile.BreakerLimit consecutive blocked
// responses and stays open for Profile.CooldownAfter.
type Breaker struct {
	mu        sync.Mutex
	limit     int
	cooldown  time.Duration
	strikes   int
	openUntil time.Time
}

func NewBreaker(p Profile) *Breaker {
	return &Breaker{limit: p.BreakerLimit, cooldown: p.CooldownAfter}
}

// ErrOpen is returned by Check while the breaker is tripped.
type ErrOpen struct{ Until time.Time }

func (e ErrOpen) Error() string {
	return fmt.Sprintf("circuit breaker open until %s (too many blocked responses)", e.Until.Format(time.RFC3339))
}

// Check returns ErrOpen if the breaker is currently tripped; callers
// must not send a request when this returns non-nil.
func (b *Breaker) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.openUntil.IsZero() && time.Now().Before(b.openUntil) {
		return ErrOpen{Until: b.openUntil}
	}
	return nil
}

// RecordBlocked registers one blocked response; trips the breaker once
// strikes reach the profile's limit.
func (b *Breaker) RecordBlocked() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.strikes++
	if b.strikes >= b.limit {
		b.openUntil = time.Now().Add(b.cooldown)
	}
}

// RecordOK resets the strike counter on any clean response.
func (b *Breaker) RecordOK() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.strikes = 0
}
