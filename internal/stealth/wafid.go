// wafid.go: a lightweight, first-request WAF fingerprinter. Not
// exhaustive — a first pass so -act can pick a sane per-vendor throttle
// before running any real scan traffic. Cloudflare, Akamai, and Imperva
// in particular run mature managed rulesets and are quick to challenge
// or rate-limit, so they get extra throttling regardless of profile.
package stealth

import (
	"net/http"
	"strings"
)

// Vendor is a detected (or absent) WAF/CDN in front of the target.
type Vendor string

const (
	VendorNone       Vendor = "none"
	VendorCloudflare Vendor = "cloudflare"
	VendorAkamai     Vendor = "akamai"
	VendorImperva    Vendor = "imperva"
	VendorAWS        Vendor = "aws"
	VendorSucuri     Vendor = "sucuri"
	VendorUnknown    Vendor = "unknown" // blocked outright, but no recognized signature
)

// Identify inspects one baseline response's headers/cookies for known
// WAF signatures. Call it once per host before scanning.
func Identify(resp *http.Response) Vendor {
	h := resp.Header
	get := func(k string) string { return strings.ToLower(h.Get(k)) }
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), ";"))

	switch {
	case h.Get("cf-ray") != "" || strings.Contains(get("server"), "cloudflare"):
		return VendorCloudflare
	case h.Get("x-akamai-transformed") != "" || strings.Contains(get("server"), "akamaighost"):
		return VendorAkamai
	case strings.Contains(cookies, "incap_ses") || strings.Contains(cookies, "visid_incap"):
		return VendorImperva
	case h.Get("x-amzn-requestid") != "" || h.Get("x-amz-cf-id") != "":
		return VendorAWS
	case strings.Contains(get("server"), "sucuri"):
		return VendorSucuri
	}
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		return VendorUnknown
	}
	return VendorNone
}

// ProfileFor layers a per-vendor throttle override on top of the user's
// chosen base profile. Cloudflare/Akamai/Imperva are materially more
// sensitive than an unprotected origin, so scale down regardless of
// what --profile asked for.
func ProfileFor(base Profile, v Vendor) Profile {
	p := base
	switch v {
	case VendorCloudflare, VendorAkamai, VendorImperva:
		p.RatePerSecond *= 0.5
		p.Concurrency = max(1, p.Concurrency/2)
		p.BreakerLimit = max(2, p.BreakerLimit/2)
	}
	return p
}
