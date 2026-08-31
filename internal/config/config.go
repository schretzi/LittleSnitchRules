// Package config loads and validates the lsrules configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML configuration.
type Config struct {
	// RulesDir holds the .lsrules files that are served. Everything else in
	// that directory is ignored - a rule group repository also contains a
	// README, a backlog and a .git, and none of that belongs on an open port.
	RulesDir string `yaml:"rules_dir"`

	Listen ListenConfig `yaml:"listen"`
	TLS    TLSConfig    `yaml:"tls"`
	Log    LogConfig    `yaml:"log"`
}

// ListenConfig is where the server binds.
//
// Host defaults to loopback and there is no reason to change it: Little Snitch
// subscribes from the same machine, and a rule group describes what runs here.
// It is a field rather than a constant only so that a mistake stays visible in
// the config instead of being invisible in the code.
type ListenConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// TLSConfig points at the certificate and key.
//
// HTTPS is not a preference here. Little Snitch refuses to subscribe to a rule
// group over anything else - `file://` is rejected outright with "For security
// reasons, only HTTPS URLs are allowed" - so a certificate is a hard
// requirement for this tool to be useful at all.
//
// Cert must be the full chain (leaf + issuing intermediate). MacbookSetup's
// local_ca role issues it that way with `step --bundle`, which is what lets a
// client verify against the root it already trusts without anything extra
// being installed.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// LogConfig configures the server's own log file, separate from the
// launchd-captured stderr file which only receives crash output.
//
// No rotation knobs: rotation belongs to newsyslog, configured in MacbookSetup
// under etc/newsyslog.d/lsrules.conf. This process's only obligation is to
// notice when newsyslog has rotated the file out from under it, which
// internal/logfile handles.
type LogConfig struct {
	Path string `yaml:"path"`
}

// DefaultPath is the config location, as a portable literal. It is expanded
// only at use time, so the resolving machine's username never ends up baked
// into generated docs or --help output.
func DefaultPath() string { return "~/.config/lsrules/config.yaml" }

// ExpandPath resolves a leading ~ against the current user's home directory.
func ExpandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("empty path")
	}
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	if !strings.HasPrefix(path, "~/") {
		return "", fmt.Errorf("cannot expand %q: only ~/ is supported", path)
	}
	return filepath.Join(home, path[2:]), nil
}

// Default returns the configuration a fresh install starts from: the rule
// groups in the LittleSnitchConfig checkout, the certificate local_ca issues
// for this service, and loopback.
func Default() Config {
	return Config{
		RulesDir: "~/Workspace/Schretzi/LittleSnitchConfig/rules",
		Listen:   ListenConfig{Host: "127.0.0.1", Port: 8443},
		TLS: TLSConfig{
			Cert: "~/.local/share/localca/lsrules.crt",
			Key:  "~/.local/share/localca/lsrules.key",
		},
		Log: LogConfig{Path: "~/Library/Logs/lsrules.log"},
	}
}

// Load reads and validates the configuration at path.
func Load(path string) (Config, error) {
	expanded, err := ExpandPath(path)
	if err != nil {
		return Config{}, err
	}
	raw, err := os.ReadFile(expanded) // #nosec G304 -- path is the operator-provided --config value, not untrusted input
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", expanded, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports what would stop the server from starting, all of it at
// once. A server that refuses to start is a background crash-loop under
// launchd, so this is what `config validate` and `service install` check
// before anything is written.
func (c Config) Validate() error {
	var problems []string

	if strings.TrimSpace(c.RulesDir) == "" {
		problems = append(problems, "rules_dir is empty")
	} else if dir, err := ExpandPath(c.RulesDir); err != nil {
		problems = append(problems, fmt.Sprintf("rules_dir: %v", err))
	} else if info, err := os.Stat(dir); err != nil {
		problems = append(problems, fmt.Sprintf("rules_dir %s: %v", dir, err))
	} else if !info.IsDir() {
		problems = append(problems, fmt.Sprintf("rules_dir %s is not a directory", dir))
	}

	if net.ParseIP(strings.TrimSpace(c.Listen.Host)) == nil {
		problems = append(problems, fmt.Sprintf("listen.host %q is not an IP address", c.Listen.Host))
	}
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		problems = append(problems, fmt.Sprintf("listen.port %d is out of range", c.Listen.Port))
	}

	for _, f := range []struct{ label, path string }{
		{"tls.cert", c.TLS.Cert},
		{"tls.key", c.TLS.Key},
	} {
		if strings.TrimSpace(f.path) == "" {
			problems = append(problems, f.label+" is empty")
			continue
		}
		p, err := ExpandPath(f.path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", f.label, err))
			continue
		}
		if _, err := os.Stat(p); err != nil {
			problems = append(problems, fmt.Sprintf("%s %s: %v (issued by MacbookSetup's local_ca role)", f.label, p, err))
		}
	}

	if strings.TrimSpace(c.Log.Path) == "" {
		problems = append(problems, "log.path is empty")
	}

	if len(problems) > 0 {
		return errors.New("invalid configuration:\n  - " + strings.Join(problems, "\n  - "))
	}
	return nil
}

// Address is the host:port the server binds and the URL it is reached at.
func (c Config) Address() string {
	return net.JoinHostPort(c.Listen.Host, strconv.Itoa(c.Listen.Port))
}

// BaseURL is where a subscription points. Always https, because there is no
// other option Little Snitch accepts.
func (c Config) BaseURL() string {
	host := c.Listen.Host
	// A certificate for a loopback service names localhost; the address is
	// the same machine either way, and the URL has to match the certificate.
	if host == "127.0.0.1" || host == "::1" {
		host = "localhost"
	}
	return fmt.Sprintf("https://%s/", net.JoinHostPort(host, strconv.Itoa(c.Listen.Port)))
}

// Save writes cfg to path, creating the directory. Used by `config init`.
func Save(path string, cfg Config) error {
	expanded, err := ExpandPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		return err
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(expanded, body, 0o600)
}
