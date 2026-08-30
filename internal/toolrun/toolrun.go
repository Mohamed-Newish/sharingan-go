// Package toolrun is the shared "shell out to an external CLI tool and
// collect its output" helper used by every active phase that wraps a
// best-of-breed tool (httprobe, naabu, katana, wafw00f, asnmap, jsluice,
// LinkFinder, KeyHack) instead of reimplementing it.
package toolrun

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Available reports whether name is on PATH.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Lines runs name with args, optionally feeding stdin (ignored if
// empty), and returns stdout split into trimmed, non-empty lines.
// Combines stderr into the returned error's text on failure so a
// missing flag or bad invocation is diagnosable, not just "exit 1".
func Lines(name string, args []string, stdin string) ([]string, error) {
	if !Available(name) {
		return nil, fmt.Errorf("%s: not installed (not found on PATH)", name)
	}
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", name, msg)
	}
	var lines []string
	for _, l := range strings.Split(out.String(), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
