package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writable(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.Mkdir(rules, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	cfg := Default()
	cfg.RulesDir = rules
	cfg.TLS = TLSConfig{Cert: cert, Key: key}
	return cfg
}

func TestValidateAcceptsAWorkingConfig(t *testing.T) {
	t.Parallel()
	if err := writable(t).Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// Every problem at once: a server that will not start is a launchd
// crash-loop, so the point of validation is to find all of it before the
// plist is written, not one thing per run.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()
	cfg := Config{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	for _, want := range []string{"rules_dir", "listen.host", "listen.port", "tls.cert", "tls.key", "log.path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

// The certificate is issued by MacbookSetup's local_ca role, and its absence
// is the most likely first-run failure - so the message names where it comes
// from rather than just saying the file is missing.
func TestValidatePointsAtWhoIssuesTheCertificate(t *testing.T) {
	t.Parallel()
	cfg := writable(t)
	cfg.TLS.Cert = filepath.Join(t.TempDir(), "missing.crt")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "local_ca") {
		t.Fatalf("error should point at local_ca, got: %v", err)
	}
}

// The URL has to match the certificate, which names localhost - a
// subscription to https://127.0.0.1:8443/ would fail hostname verification.
func TestBaseURLUsesLocalhostForLoopback(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if got := cfg.BaseURL(); got != "https://localhost:8443/" {
		t.Errorf("BaseURL() = %q", got)
	}
	if got := cfg.Address(); got != "127.0.0.1:8443" {
		t.Errorf("Address() = %q", got)
	}
}

// The default path stays a literal so the resolving machine's username never
// ends up in generated docs or --help output.
func TestDefaultPathIsPortable(t *testing.T) {
	t.Parallel()
	if got := DefaultPath(); !strings.HasPrefix(got, "~/") {
		t.Errorf("DefaultPath() = %q, want a ~/ literal", got)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := writable(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save(): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %v, want 0600", perm)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if loaded.RulesDir != cfg.RulesDir || loaded.Listen.Port != cfg.Listen.Port {
		t.Errorf("round trip lost values: %+v", loaded)
	}
}
