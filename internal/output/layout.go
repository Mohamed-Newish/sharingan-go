// Package output defines the on-disk target folder layout: one
// plain-text artifact file per data type (domains, hosts, ports, urls,
// ...), so results stay easy to grep, diff, and feed into other tools —
// or review by hand in Burp — without any translation step.
package output

import (
	"os"
	"path/filepath"
)

// Layout is every file/dir path sharingan reads from or writes to for
// one target, rooted at <out>/<target>/.
type Layout struct {
	Root string

	Domains        string // subdomains discovered (passive + active)
	Hosts          string // confirmed-live hosts
	Ports          string // open ports
	URLs           string // harvested URLs (archive + live crawl)
	AuthURLs       string // URLs touching auth/password/token flows — worth a manual look
	PathWordlist   string // derived path wordlist
	ParamWordlist  string // derived param-name wordlist
	SQLiCandidates string // marker-based SQLi scan leads — verify by hand before calling it a finding
	XSSCandidates  string // marker-based XSS scan leads — same caveat
	Screenshots    string // dir: aquatone/eyewitness/gowitness output
	RawResponses   string // dir: raw response bodies/headers fetched from each host's root path
	Findings       string // findings.jsonl — structured, for tooling/LLM triage
	AuditLog       string // sharingan.log — every request sent in -act mode
}

// New builds the Layout for target under root, creating root/target if
// needed. It does not create every artifact file up front — store.Open
// creates files lazily on first write, same as anew does today.
func New(root, target string) (*Layout, error) {
	base := filepath.Join(root, target)
	l := &Layout{
		Root:           base,
		Domains:        filepath.Join(base, "domains"),
		Hosts:          filepath.Join(base, "hosts"),
		Ports:          filepath.Join(base, "ports"),
		URLs:           filepath.Join(base, "urls"),
		AuthURLs:       filepath.Join(base, "auth_urls"),
		PathWordlist:   filepath.Join(base, "paths.txt"),
		ParamWordlist:  filepath.Join(base, "params.txt"),
		SQLiCandidates: filepath.Join(base, "sqli_candidates"),
		XSSCandidates:  filepath.Join(base, "xss_candidates"),
		Screenshots:    filepath.Join(base, "screenshots"),
		RawResponses:   filepath.Join(base, "raw_responses"),
		Findings:       filepath.Join(base, "findings.jsonl"),
		AuditLog:       filepath.Join(base, "sharingan.log"),
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, err
	}
	return l, nil
}
