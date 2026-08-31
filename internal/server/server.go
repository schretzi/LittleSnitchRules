// Package server serves .lsrules rule groups to Little Snitch over HTTPS.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/schretzi/littlesnitchrules/internal/config"
)

// Extension is the only thing this server will hand out.
const Extension = ".lsrules"

// shutdownGrace is how long in-flight requests get after SIGTERM before the
// listener is closed out from under them.
const shutdownGrace = 2 * time.Second

// readHeaderTimeout bounds how long a client may take to send its request
// headers. Little Snitch is on loopback and takes microseconds; the timeout is
// here so a stuck connection cannot pin a handler indefinitely.
const readHeaderTimeout = 10 * time.Second

// Server is the HTTPS server. Zero value is not usable - use New.
type Server struct {
	cfg  config.Config
	log  io.Writer
	http *http.Server
	dir  string
}

// New resolves the configuration into a ready server. It fails rather than
// starting degraded: under launchd a server that starts and cannot serve is a
// crash-loop with a healthy-looking label.
func New(cfg config.Config, logWriter io.Writer) (*Server, error) {
	dir, err := config.ExpandPath(cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	certPath, err := config.ExpandPath(cfg.TLS.Cert)
	if err != nil {
		return nil, err
	}
	keyPath, err := config.ExpandPath(cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	s := &Server{cfg: cfg, log: logWriter, dir: dir}
	s.http = &http.Server{
		Addr:              cfg.Address(),
		Handler:           s.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	return s, nil
}

// handler serves exactly the .lsrules files in one directory.
//
// Deliberately not http.FileServer over the directory: a rule group lives in a
// git checkout next to a README, a backlog and a .git, and none of that
// belongs on a listening socket. The extension check is the whole allowlist.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status, size := s.serveRule(w, r)
		s.logRequest(r, status, size, time.Since(start))
	})
	return mux
}

func (s *Server) serveRule(w http.ResponseWriter, r *http.Request) (status int, size int64) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, 0
	}

	name := strings.TrimPrefix(r.URL.Path, "/")
	// path.Base after the extension check, so "../../etc/passwd.lsrules"
	// cannot walk out of the directory even if someone names a file that way.
	if !strings.HasSuffix(name, Extension) || name != filepath.Base(name) {
		http.Error(w, "only "+Extension+" files are served here", http.StatusNotFound)
		return http.StatusNotFound, 0
	}

	// os.OpenInRoot rather than Open on a joined path: it refuses to resolve
	// outside s.dir at the syscall level, including through a symlink someone
	// dropped in the rules directory. The extension and base-name checks above
	// still stand - this is the floor under them, not a replacement.
	f, err := os.OpenInRoot(s.dir, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return http.StatusNotFound, 0
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return http.StatusNotFound, 0
	}

	w.Header().Set("Content-Type", "application/json")
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	// ServeContent handles If-Modified-Since, which is what a Little Snitch
	// subscription refresh actually sends: it fetches once and then asks
	// again with a conditional request, so the 304 in the log is the signal
	// that the subscription is alive rather than merely installed.
	http.ServeContent(rec, r, name, info.ModTime(), f)
	return rec.status, rec.written
}

// statusRecorder captures what ServeContent decided, so the log line reports
// 200 or 304 rather than guessing.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

func (s *Server) logRequest(r *http.Request, status int, size int64, took time.Duration) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	fmt.Fprintf(s.log, "%s %s %q %d %d %s\n",
		time.Now().Format(time.RFC3339), host,
		r.Method+" "+r.URL.Path, status, size, took.Round(time.Microsecond))
}

// Files lists the rule groups currently on offer, for `status`.
func (s *Server) Files() ([]string, error) { return RuleFiles(s.dir) }

// RuleFiles lists the .lsrules files in dir, sorted.
func RuleFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), Extension) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Serve runs until ctx is cancelled, then shuts down gracefully. launchd sends
// SIGTERM on stop and on a rotation-triggered restart; finishing the request
// in flight costs milliseconds and avoids a subscription refresh seeing a
// truncated response.
func (s *Server) Serve(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Address())
	if err != nil {
		return err
	}

	files, err := s.Files()
	if err != nil {
		return err
	}
	fmt.Fprintf(s.log, "%s serving %s on %s\n", time.Now().Format(time.RFC3339), s.dir, s.cfg.BaseURL())
	for _, f := range files {
		fmt.Fprintf(s.log, "%s   %s%s\n", time.Now().Format(time.RFC3339), s.cfg.BaseURL(), f)
	}
	if len(files) == 0 {
		fmt.Fprintf(s.log, "%s   (no %s files in %s yet)\n", time.Now().Format(time.RFC3339), Extension, s.dir)
	}

	errCh := make(chan error, 1)
	go func() {
		err := s.http.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		// Graceful first, but briefly. launchd SIGKILLs a job that does not
		// exit, and the only thing in flight here is a file smaller than a
		// packet - so a long grace period buys nothing and risks the job
		// being killed mid-shutdown instead of exiting cleanly.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		err := s.http.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			// A client holding a connection open past the grace period does
			// not get to keep the process alive.
			return s.http.Close()
		}
		return err
	}
}

// CertificateInfo describes the loaded certificate, for `status`.
type CertificateInfo struct {
	Subject   string
	Issuer    string
	NotAfter  time.Time
	DNSNames  []string
	ChainLen  int
	ExpiresIn time.Duration
}

// InspectCertificate reads the configured certificate without starting
// anything. `status` reports the expiry because this certificate is issued for
// a year by local_ca and nothing renews it automatically - the failure is
// silent until a subscription refresh fails.
func InspectCertificate(cfg config.Config) (CertificateInfo, error) {
	path, err := config.ExpandPath(cfg.TLS.Cert)
	if err != nil {
		return CertificateInfo{}, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from the operator's own config
	if err != nil {
		return CertificateInfo{}, err
	}
	var leaf *x509.Certificate
	chain := 0
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CertificateInfo{}, err
		}
		chain++
		if leaf == nil {
			leaf = c
		}
	}
	if leaf == nil {
		return CertificateInfo{}, errors.New("no certificate found in " + path)
	}
	return CertificateInfo{
		Subject:   leaf.Subject.CommonName,
		Issuer:    leaf.Issuer.CommonName,
		NotAfter:  leaf.NotAfter,
		DNSNames:  leaf.DNSNames,
		ChainLen:  chain,
		ExpiresIn: time.Until(leaf.NotAfter),
	}, nil
}
