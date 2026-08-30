// Package output defines the on-disk target folder layout, matching
// HUNTING_WORKFLOW.md's artifact conventions exactly so a sharingan run
// slots into the existing hand-driven workflow (Burp, manual review)
// with zero translation — the same file names your bash pipeline and
// this tool both read and append to.
package output

import (
	"os"
	"path/filepath"
)

// Layout is every file/dir path sharingan reads from or writes to for
// one target, rooted at <out>/<target>/.
type Layout struct {
	Root string

	Domains           string // subdomains discovered (passive + active)
	Hosts             string // confirmed-live hosts
	Ports             string // open ports
	URLs              string // harvested URLs (archive + live crawl)
	ResetPasswordTest string // URLs touching auth/password flows
	PathWordlist      string // derived path wordlist
	ParamWordlist     string // derived param-name wordlist
	DsssResults       string // SQLi scan hits
	XSSResults        string // XSS scan hits
	Screenshots       string // dir: aquatone/eyewitness/gowitness output
	Out               string // dir: meg-style raw response bodies/headers
	Findings          string // findings.jsonl — structured, for tooling/LLM triage
	AuditLog          string // sharingan.log — every request sent in -act mode
}

// New builds the Layout for target under root, creating root/target if
// needed. It does not create every artifact file up front — store.Open
// creates files lazily on first write, same as anew does today.
func New(root, target string) (*Layout, error) {
	base := filepath.Join(root, target)
	l := &Layout{
		Root:              base,
		Domains:           filepath.Join(base, "domains"),
		Hosts:             filepath.Join(base, "hosts"),
		Ports:             filepath.Join(base, "ports"),
		URLs:              filepath.Join(base, "urls"),
		ResetPasswordTest: filepath.Join(base, "reset_password_test"),
		PathWordlist:      filepath.Join(base, "path_wlist"),
		ParamWordlist:     filepath.Join(base, "param_wlist"),
		DsssResults:       filepath.Join(base, "dsss_res"),
		XSSResults:        filepath.Join(base, "xss_res"),
		Screenshots:       filepath.Join(base, "screenshots"),
		Out:               filepath.Join(base, "out"),
		Findings:          filepath.Join(base, "findings.jsonl"),
		AuditLog:          filepath.Join(base, "sharingan.log"),
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, err
	}
	return l, nil
}
