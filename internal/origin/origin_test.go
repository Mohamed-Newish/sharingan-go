package origin

import (
	"testing"
	"time"
)

func TestFilterCIDRsBySize(t *testing.T) {
	// Real output from `asnmap -d example.com -silent` — example.com is
	// Cloudflare-proxied, so this is what a Cloudflare-shared-CDN ASN
	// actually looks like: mostly huge ranges that must be filtered out.
	cidrs := []string{
		"172.66.128.0/19", // 8192 hosts — too big
		"172.66.160.0/20", // 4096 hosts — right at the cap
		"172.66.176.0/23", // 512 hosts — well under
		"104.16.0.0/14",   // 262144 hosts — way too big
		"104.20.0.0/18",   // 16384 hosts — too big
	}
	kept, skipped := filterCIDRsBySize(cidrs, 12) // 2^12 = 4096

	wantKept := []string{"172.66.160.0/20", "172.66.176.0/23"}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want %v", kept, wantKept)
	}
	for i, c := range wantKept {
		if kept[i] != c {
			t.Errorf("kept[%d] = %q, want %q", i, kept[i], c)
		}
	}
	if len(skipped) != 3 {
		t.Errorf("skipped %d CIDRs, want 3 (got %v)", len(skipped), skipped)
	}
}

func TestVerifyOriginTLS(t *testing.T) {
	// 1.1.1.1 is Cloudflare's public resolver, explicitly meant for this
	// kind of connectivity testing — a single benign handshake, not a
	// scan. Its cert covers "one.one.one.one" (confirmed via openssl
	// s_client before writing this test).
	ok, err := verifyOriginTLS("1.1.1.1", "one.one.one.one", 8*time.Second)
	if err != nil {
		t.Fatalf("verifyOriginTLS(1.1.1.1, one.one.one.one) error: %v", err)
	}
	if !ok {
		t.Error("expected 1.1.1.1's cert to match one.one.one.one, got false")
	}

	ok2, err2 := verifyOriginTLS("1.1.1.1", "definitely-not-cloudflare.invalid", 8*time.Second)
	if err2 != nil {
		t.Fatalf("verifyOriginTLS(1.1.1.1, definitely-not-cloudflare.invalid) error: %v", err2)
	}
	if ok2 {
		t.Error("expected 1.1.1.1's cert NOT to match an unrelated hostname, got true")
	}
}
