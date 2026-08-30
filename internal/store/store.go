// Package store implements "always append, never overwrite" as a
// library: dedupe-append lines to an artifact file (domains, hosts,
// urls, ports, ...) without ever truncating or reordering what's
// already there — the same discipline tools like anew enforce for
// shell pipelines.
package store

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

// File is an append-only, deduped line store backed by a plain text file.
type File struct {
	path string
	seen map[string]bool
}

// Open loads path's existing lines (if any) into a dedupe set and
// returns a File ready to accept new ones. It never truncates path —
// same guarantee as anew.
func Open(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f := &File{path: path, seen: map[string]bool{}}
	if fh, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			f.seen[sc.Text()] = true
		}
		fh.Close()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return f, nil
}

// Add appends line to the file iff it hasn't been seen before — in this
// file's history, not just this run. Returns true if it was new.
func (f *File) Add(line string) (bool, error) {
	if line == "" || f.seen[line] {
		return false, nil
	}
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer fh.Close()
	if _, err := fmt.Fprintln(fh, line); err != nil {
		return false, err
	}
	f.seen[line] = true
	return true, nil
}

// AddAll feeds a batch of lines through Add; returns how many were
// actually new.
func (f *File) AddAll(lines []string) (added int, err error) {
	for _, l := range lines {
		ok, err := f.Add(l)
		if err != nil {
			return added, err
		}
		if ok {
			added++
		}
	}
	return added, nil
}

// Len reports how many unique lines the file currently holds — used by
// --resume to decide whether a phase already has output.
func (f *File) Len() int { return len(f.seen) }

// Lines returns the file's current lines (already deduped, insertion
// order not preserved — seen is a set). Used by a phase to read a
// prior phase's output as its own input, e.g. probe reading domains.
func (f *File) Lines() []string {
	out := make([]string, 0, len(f.seen))
	for l := range f.seen {
		out = append(out, l)
	}
	return out
}

// ReadLines is a convenience wrapper for a phase that only needs to
// read an artifact file (not append to it): open, grab the lines.
func ReadLines(path string) ([]string, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	return f.Lines(), nil
}
