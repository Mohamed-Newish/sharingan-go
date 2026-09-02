// Package config loads sharingan's optional config file: API keys for
// passive sources that need them (SecurityTrails, Censys, Shodan,
// GitHub). Deliberately a tiny "key: value" format, not YAML/TOML — no
// third-party dependency needed for something this small, keeping the
// whole tool a single static binary with no external module graph.
//
// Threaded through cmd/: psv loads it and hands APIKeys to the passive
// sources, and origin falls back to APIKeys["shodan"] when --shodan-key
// isn't passed. With no -c/--config flag, DefaultPath() is used, so a
// key dropped once into ~/.config/sharingan/config is picked up by every
// run with no flags.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Config holds everything loaded from a --config file.
type Config struct {
	APIKeys map[string]string // e.g. "shodan" -> key, "securitytrails" -> key
}

// DefaultPath is where sharingan looks when no -c/--config is given:
// ~/.config/sharingan/config. Returns "" if the home dir can't be
// resolved (then Load just yields an empty Config).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sharingan", "config")
}

// Load reads path in "key: value" form, one per line ("#" comments and
// blank lines ignored). An empty path falls back to DefaultPath(). A
// missing file is not an error — it just yields an empty Config, since
// the config is optional.
func Load(path string) (*Config, error) {
	cfg := &Config{APIKeys: map[string]string{}}
	if path == "" {
		path = DefaultPath()
	}
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		cfg.APIKeys[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return cfg, sc.Err()
}
