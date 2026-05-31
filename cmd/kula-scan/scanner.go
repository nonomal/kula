package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Severity ranks how serious a failed safeguard is. The zero value is SevInfo.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// parseSeverity maps a CLI string to a Severity. Reports ok=false on an
// unknown name so the caller can surface a usage error.
func parseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SevInfo, true
	case "low":
		return SevLow, true
	case "medium", "med":
		return SevMedium, true
	case "high":
		return SevHigh, true
	case "critical", "crit":
		return SevCritical, true
	default:
		return SevInfo, false
	}
}

// Status is the outcome of a single check.
//
//   - StatusPass — the safeguard is present and behaves as expected.
//   - StatusFail — the safeguard is missing or bypassable (a finding).
//   - StatusWarn — not strictly a vulnerability, but a weak / risky posture.
//   - StatusSkip — the check did not apply (e.g. needs creds, feature disabled).
//   - StatusError — the probe itself could not complete (network/parse error).
type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusWarn
	StatusSkip
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusWarn:
		return "WARN"
	case StatusSkip:
		return "SKIP"
	default:
		return "ERROR"
	}
}

// Finding is the result of one safeguard probe.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Status      Status   `json:"-"`
	StatusStr   string   `json:"status"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// finding is a small constructor that keeps the string mirrors of the enum
// fields (used for JSON output) in sync with the typed values.
func finding(id, category, title string, sev Severity, st Status, detail string) Finding {
	return Finding{
		ID:          id,
		Category:    category,
		Title:       title,
		Severity:    sev,
		SeverityStr: sev.String(),
		Status:      st,
		StatusStr:   st.String(),
		Detail:      detail,
	}
}

// withEvidence and withRemediation are fluent helpers for building findings.
func (f Finding) withEvidence(format string, a ...any) Finding {
	f.Evidence = fmt.Sprintf(format, a...)
	return f
}

func (f Finding) withRemediation(s string) Finding {
	f.Remediation = s
	return f
}

// check is one named, categorised probe. aggressive checks have side effects
// on the target (rate-limit lockout, connection floods) and only run when the
// user passes -aggressive.
type check struct {
	id         string
	category   string
	aggressive bool
	run        func(s *Scanner) []Finding
}

// Scanner holds connection state and shared HTTP/WS/raw helpers used by every
// check. It is created once per target and reused across all probes.
type Scanner struct {
	base       *url.URL // scheme + host + base path; no trailing slash beyond base
	rawBase    string   // original -target string, for messages
	client     *http.Client
	insecure   bool
	timeout    time.Duration
	aggressive bool
	verbose    bool

	username string
	password string

	// Discovered during the discovery phase.
	reachable   bool
	https       bool
	authEnabled bool
	ollama      bool

	// Populated by ensureSession() when credentials are supplied and valid.
	session     string       // kula_session cookie value
	csrf        string       // csrf_token returned by login
	loginCookie *http.Cookie // the Set-Cookie issued at login, for attribute inspection
	loggedIn    bool
	loginTried  bool
}

// NewScanner builds a Scanner for target. basePath, when non-empty, is appended
// to every request path (kula's web.base_path feature).
func NewScanner(target, basePath, username, password string, timeout time.Duration, insecure, aggressive, verbose bool) (*Scanner, error) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target URL %q has no host", target)
	}

	// Fold a path component in the URL into basePath unless one was given
	// explicitly. This lets `kula-scan http://host:1234/kula` work.
	bp := strings.TrimRight(basePath, "/")
	if bp == "" && u.Path != "" && u.Path != "/" {
		bp = strings.TrimRight(u.Path, "/")
	}
	u.Path = bp
	u.RawQuery = ""
	u.Fragment = ""

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // -insecure is an explicit opt-in for self-signed test instances
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Observe redirects (301/302) directly rather than following them, so
		// base-path redirects and auth bounces are visible to the checks.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Scanner{
		base:       u,
		rawBase:    target,
		client:     client,
		insecure:   insecure,
		timeout:    timeout,
		aggressive: aggressive,
		verbose:    verbose,
		username:   username,
		password:   password,
		https:      u.Scheme == "https",
	}, nil
}

// urlFor joins the configured base (scheme+host+base path) with a root-relative
// request path like "/api/login".
func (s *Scanner) urlFor(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return s.base.Scheme + "://" + s.base.Host + s.base.Path + path
}

// httpResult bundles the parts of a response the checks care about.
type httpResult struct {
	status int
	header http.Header
	body   string
	err    error
}

// do issues an HTTP request to path with optional headers and body, returning a
// compact result. Cookies are never persisted between calls (the client has no
// jar); callers set Cookie/Authorization headers explicitly.
func (s *Scanner) do(method, path string, headers map[string]string, body string) httpResult {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.urlFor(path), rdr)
	if err != nil {
		return httpResult{err: err}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return httpResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if s.verbose {
		fmt.Printf("    %s %s -> %d (%d bytes)\n", method, path, resp.StatusCode, len(raw))
	}
	return httpResult{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// authedHeaders returns request headers carrying the active session cookie (and
// matching CSRF token when csrf is true), or nil when no session is available.
func (s *Scanner) authedHeaders(csrf bool) map[string]string {
	if s.session == "" {
		return nil
	}
	h := map[string]string{"Cookie": "kula_session=" + s.session}
	if csrf && s.csrf != "" {
		h["X-CSRF-Token"] = s.csrf
	}
	return h
}

// rawTCP opens a raw connection (TLS when the target is https) and writes a
// literal HTTP/1.1 request line, so the path is sent verbatim without any
// client-side URL normalisation. This is how traversal payloads are delivered.
// It returns the status code and body; a status of 0 means the server rejected
// the request at the protocol layer (an acceptable, safe outcome).
func (s *Scanner) rawTCP(requestLine string) (int, string) {
	host := s.base.Host
	if !strings.Contains(host, ":") {
		if s.https {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: s.timeout}
	if s.https {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: s.insecure}) //nolint:gosec // explicit opt-in
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return 0, ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	if _, err := fmt.Fprintf(conn, "%s\r\nHost: %s\r\nConnection: close\r\n\r\n", requestLine, s.base.Host); err != nil {
		return 0, ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body)
}

// wsDial attempts a WebSocket upgrade to path with the given extra headers,
// returning the HTTP response (for status inspection) and the connection (nil
// on failure). The caller is responsible for closing a non-nil connection.
func (s *Scanner) wsDial(path string, headers http.Header) (*websocket.Conn, *http.Response, error) {
	scheme := "ws"
	if s.https {
		scheme = "wss"
	}
	wsURL := scheme + "://" + s.base.Host + s.base.Path + path

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = s.timeout
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: s.insecure} //nolint:gosec // explicit opt-in
	return dialer.Dial(wsURL, headers)
}

// ---- discovery ---------------------------------------------------------------

// discover probes the target to learn whether it is reachable, whether auth is
// enabled, and which optional features (Ollama) are active. The findings it
// returns describe the target rather than judging it.
func (s *Scanner) discover() []Finding {
	var out []Finding

	// Confirm reachability via the unauthenticated liveness endpoint.
	if r := s.do(http.MethodGet, "/health", nil, ""); r.err == nil {
		s.reachable = true
	}

	// auth/status is always unauthenticated and reveals the auth posture.
	r := s.do(http.MethodGet, "/api/auth/status", nil, "")
	if r.err != nil {
		out = append(out, finding("DISC-001", "discovery", "Target reachable", SevInfo, StatusError,
			fmt.Sprintf("could not reach %s: %v", s.rawBase, r.err)).
			withRemediation("Check the target URL, port, and that kula's web server is enabled."))
		return out
	}
	s.reachable = true

	var status struct {
		AuthRequired bool `json:"auth_required"`
	}
	_ = json.Unmarshal([]byte(r.body), &status)
	s.authEnabled = status.AuthRequired

	// /api/config (open when auth is off; gated when on) reveals ollama state.
	cfg := s.do(http.MethodGet, "/api/config", s.authedHeaders(false), "")
	if cfg.status == http.StatusOK {
		var c struct {
			OllamaEnabled bool `json:"ollama_enabled"`
		}
		_ = json.Unmarshal([]byte(cfg.body), &c)
		s.ollama = c.OllamaEnabled
	}

	authState := "disabled"
	if s.authEnabled {
		authState = "enabled"
	}
	out = append(out, finding("DISC-001", "discovery", "Target fingerprint", SevInfo, StatusPass,
		fmt.Sprintf("reachable at %s (%s); authentication %s; ollama %v",
			s.urlFor(""), s.base.Scheme, authState, s.ollama)))

	// Plaintext transport with auth enabled means credentials cross the wire in
	// the clear unless a TLS-terminating proxy sits in front.
	if s.authEnabled && !s.https {
		out = append(out, finding("DISC-002", "discovery", "Credentials over plaintext HTTP", SevMedium, StatusWarn,
			"authentication is enabled but the target was reached over plain HTTP; login credentials and session cookies are exposed unless a TLS-terminating reverse proxy sits in front.").
			withRemediation("Serve kula behind HTTPS (reverse proxy + trust_proxy, or terminate TLS) so the Secure cookie flag and HSTS apply."))
	}

	return out
}

// ensureSession logs in once (lazily) using the supplied credentials and caches
// the resulting session cookie + CSRF token. It is a no-op without credentials
// or when auth is disabled. Returns true when an authenticated session exists.
func (s *Scanner) ensureSession() bool {
	if s.loggedIn {
		return true
	}
	if s.loginTried {
		return false
	}
	s.loginTried = true
	if s.username == "" || s.password == "" {
		return false
	}

	payload, _ := json.Marshal(map[string]string{"username": s.username, "password": s.password})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       s.base.Scheme + "://" + s.base.Host,
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.urlFor("/api/login"), strings.NewReader(string(payload)))
	if err != nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return false
	}
	for _, c := range resp.Cookies() {
		if c.Name == "kula_session" {
			s.session = c.Value
			s.loginCookie = c
		}
	}
	var parsed struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(raw, &parsed)
	s.csrf = parsed.CSRFToken
	s.loggedIn = s.session != ""
	return s.loggedIn
}

// allChecks returns the full registry in execution order. Categories run
// grouped; aggressive checks are tagged and filtered by the runner.
func allChecks() []check {
	var checks []check
	checks = append(checks, headerChecks()...)
	checks = append(checks, authChecks()...)
	checks = append(checks, csrfChecks()...)
	checks = append(checks, corsChecks()...)
	checks = append(checks, traversalChecks()...)
	checks = append(checks, metricsChecks()...)
	checks = append(checks, wsChecks()...)
	checks = append(checks, inputChecks()...)
	checks = append(checks, aggressiveChecks()...)
	return checks
}

// Run executes discovery and every selected check, returning all findings. only
// (when non-empty) restricts execution to the named categories.
func (s *Scanner) Run(only map[string]bool) []Finding {
	findings := s.discover()

	// If discovery could not reach the target, there is nothing more to probe.
	if !s.reachable {
		return findings
	}

	for _, c := range allChecks() {
		if len(only) > 0 && !only[c.category] {
			continue
		}
		if c.aggressive && !s.aggressive {
			findings = append(findings, finding(c.id, c.category, "Skipped (aggressive)", SevInfo, StatusSkip,
				"disruptive check not run; pass -aggressive to enable (it has side effects on the live target)."))
			continue
		}
		findings = append(findings, c.run(s)...)
	}
	return findings
}
