package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schretzi/littlesnitchrules/internal/config"
)

// testConfig writes a rules directory and a self-signed certificate, and
// returns a config pointing at them. The certificate is generated per test
// run rather than committed: a key in a repository is a key in a repository,
// even a throwaway one.
func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.Mkdir(rules, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rules, "test.lsrules"),
		[]byte(`{"name":"test","description":"d","rules":[]}`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rules, "README.md"), []byte("not served"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "1",
		"-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl not usable here: %v\n%s", err, out)
	}

	return config.Config{
		RulesDir: rules,
		Listen:   config.ListenConfig{Host: "127.0.0.1", Port: freePort(t)},
		TLS:      config.TLSConfig{Cert: certPath, Key: keyPath},
		Log:      config.LogConfig{Path: filepath.Join(dir, "log")},
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, not *net.TCPAddr", l.Addr())
	}
	return addr.Port
}

// startServer runs the server until the test ends and returns a client that
// trusts its certificate.
func startServer(t *testing.T, cfg config.Config) (*http.Client, string) {
	t.Helper()
	srv, err := New(cfg, io.Discard)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve() did not shut down within 10s")
		}
	})

	pem, err := os.ReadFile(cfg.TLS.Cert)
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("certificate not accepted into pool")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	base := fmt.Sprintf("https://localhost:%d/", cfg.Listen.Port)
	waitReady(t, client, base+"test.lsrules")
	return client, base
}

func waitReady(t *testing.T, c *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := c.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not become ready")
}

func TestServesRuleGroupOverTLS(t *testing.T) {
	cfg := testConfig(t)
	client, base := startServer(t, cfg)

	resp, err := client.Get(base + "test.lsrules")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"name":"test"`) {
		t.Errorf("body = %q", body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// The directory is a git checkout with a README, a backlog and a .git next to
// the rule groups. None of that belongs on a listening socket.
func TestServesNothingButRuleGroups(t *testing.T) {
	cfg := testConfig(t)
	client, base := startServer(t, cfg)

	for _, path := range []string{
		"README.md",
		"../../../etc/passwd",
		"../rules/test.lsrules",
		"",
	} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %q: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %q = %d, want 404", path, resp.StatusCode)
		}
	}
}

// A Little Snitch subscription fetches once and then asks again with a
// conditional request. The 304 is what says the subscription is alive rather
// than merely installed, so it is worth a test of its own.
func TestConditionalRequestGets304(t *testing.T) {
	cfg := testConfig(t)
	client, base := startServer(t, cfg)

	first, err := client.Get(base + "test.lsrules")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = first.Body.Close()
	modified := first.Header.Get("Last-Modified")
	if modified == "" {
		t.Fatal("no Last-Modified header, a conditional refresh cannot work")
	}

	req, err := http.NewRequest(http.MethodHead, base+"test.lsrules", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("If-Modified-Since", modified)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("conditional HEAD = %d, want 304", resp.StatusCode)
	}
}

func TestRuleFilesIgnoresEverythingElse(t *testing.T) {
	cfg := testConfig(t)
	files, err := RuleFiles(cfg.RulesDir)
	if err != nil {
		t.Fatalf("RuleFiles(): %v", err)
	}
	if len(files) != 1 || files[0] != "test.lsrules" {
		t.Errorf("RuleFiles() = %v, want [test.lsrules]", files)
	}
}

func TestInspectCertificateReportsExpiry(t *testing.T) {
	cfg := testConfig(t)
	info, err := InspectCertificate(cfg)
	if err != nil {
		t.Fatalf("InspectCertificate(): %v", err)
	}
	if info.Subject != "localhost" {
		t.Errorf("Subject = %q, want localhost", info.Subject)
	}
	if info.ExpiresIn <= 0 || info.ExpiresIn > 48*time.Hour {
		t.Errorf("ExpiresIn = %v, want within the certificate's one day", info.ExpiresIn)
	}
}
