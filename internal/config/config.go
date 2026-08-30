// Package config loads sharingan's optional config file: API keys for
// passive sources that need them (SecurityTrails, Censys, Shodan,
// GitHub). Deliberately a tiny "key: value" format, not YAML/TOML — no
// third-party dependency needed for something this small, keeping the
// whole tool a single static binary with no external module graph.
//
// Not yet threaded through cmd/ — psv's api-key sources (securitytrails,
// censys, shodan, github) currently error out with a TODO pointing here.
package config

import (
	"bufio"
	"os"
	"strings"
)

// Config holds everything loaded from a --config file.
type Config struct {
	APIKeys map[string]string // e.g. "shodan" -> key, "securitytrails" -> key
}

// Load reads path in "key: value" form, one per line ("#" comments and
// blank lines ignored). A missing path is not an error — it just yields
// an empty Config, since --config is optional.
func Load(path string) (*Config, error) {
	cfg := &Config{APIKeys: map[string]string{}}
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
