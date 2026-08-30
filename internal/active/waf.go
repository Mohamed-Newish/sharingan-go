// waf.go: the optional deep WAF fingerprint pass via wafw00f. The
// lightweight always-on check in internal/stealth/wafid.go reads the
// baseline request we're already sending — zero extra cost — and
// exists to drive live throttling. wafw00f sends several extra probe
// requests against a ~150-vendor signature database; it's for
// report-quality vendor identification, opt-in via --waf-deep, not
// part of the hot path.
package active

import (
	"fmt"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/toolrun"
)

// runWAFDeep shells out to `wafw00f -a -f json -o <file> <target>` and
// leaves the raw JSON at lay.WAFFingerprint for later reading/reporting.
func runWAFDeep(target string, lay *output.Layout) {
	if !toolrun.Available("wafw00f") {
		fmt.Printf("act: %s: waf-deep: wafw00f not installed, skipping\n", target)
		return
	}
	url := "https://" + target
	_, err := toolrun.Lines("wafw00f", []string{"-a", "-f", "json", "-o", lay.WAFFingerprint, url}, "")
	if err != nil {
		fmt.Printf("act: %s: waf-deep: %v\n", target, err)
		return
	}
	fmt.Printf("act: %s: waf-deep: wrote %s\n", target, lay.WAFFingerprint)
}
