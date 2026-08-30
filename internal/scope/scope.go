// Package scope implements the in-scope allow-list that every outbound
// request sharingan sends in active mode is checked against before it's
// ever built. This is the technical enforcement of CLAUDE.md's "confirm
// a host is in-scope before sending traffic" rule — not just discipline.
package scope

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// List is a parsed, ready-to-query scope allow-list.
type List struct {
	roots []string // bare root domains; "example.com" covers itself and any subdomain
}

// Load reads a scope file, one target per line. A leading "*." is
// stripped — a wildcard entry and its bare root are treated identically
// (the root plus every subdomain is in scope either way). Blank lines
// and "#" comments are ignored.
func Load(path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	defer f.Close()

	l := &List{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "*.")
		l.roots = append(l.roots, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if len(l.roots) == 0 {
		return nil, fmt.Errorf("scope: %s has no usable entries", path)
	}
	return l, nil
}

// Single builds a List covering exactly one explicit target and its
// subdomains — used when the user passes -t instead of --scope, so a
// quick single-target run doesn't need a throwaway scope file.
func Single(target string) *List {
	return &List{roots: []string{strings.ToLower(strings.TrimPrefix(target, "*."))}}
}

// Allowed reports whether host is covered by the list: an exact match on
// a root, or any subdomain of one.
func (l *List) Allowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, root := range l.roots {
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

// Roots returns the parsed scope's root domains (a copy — callers can't
// mutate the list's internal state through it).
func (l *List) Roots() []string {
	out := make([]string, len(l.roots))
	copy(out, l.roots)
	return out
}
