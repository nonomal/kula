package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// These tests validate the scanner's classification logic against two faithful
// mock servers: a "secure" one that emulates kula's safeguards (every probe must
// PASS) and an "insecure" one that omits them (the matching probes must FAIL or
// WARN). They exercise the check functions over a real loopback socket, so the
// HTTP, raw-TCP, and WebSocket helpers are all covered end to end without
// needing the full kula binary.

const (
	mockUser  = "admin"
	mockPass  = "secret"
	mockToken = "goodtoken"
)

// ---- secure mock -------------------------------------------------------------

func secureMock() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("kula is healthy"))
	})
	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, map[string]any{"auth_required": true, "authenticated": false})
	})

	// Protected routes require the valid session cookie.
	protected := func(body any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !hasValidSession(r) {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			writeJSONResp(w, body)
		}
	}
	mux.HandleFunc("/api/current", protected(map[string]any{"cpu": 1}))
	mux.HandleFunc("/api/config", protected(map[string]any{"auth_enabled": true, "ollama_enabled": false}))
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		if !hasValidSession(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		from, to := q.Get("from"), q.Get("to")
		if from != "" {
			if _, err := time.Parse(time.RFC3339, from); err != nil {
				http.Error(w, `{"error":"bad from"}`, http.StatusBadRequest)
				return
			}
		}
		if to != "" {
			if _, err := time.Parse(time.RFC3339, to); err != nil {
				http.Error(w, `{"error":"bad to"}`, http.StatusBadRequest)
				return
			}
		}
		if from != "" && to != "" {
			f, _ := time.Parse(time.RFC3339, from)
			t, _ := time.Parse(time.RFC3339, to)
			if t.Before(f) || t.Sub(f) > 31*24*time.Hour {
				http.Error(w, `{"error":"bad range"}`, http.StatusBadRequest)
				return
			}
		}
		writeJSONResp(w, map[string]any{"samples": []any{}})
	})
	mux.HandleFunc("/api/i18n", func(w http.ResponseWriter, r *http.Request) {
		if !hasValidSession(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		lang := r.URL.Query().Get("lang")
		if lang != "en" && lang != "de" {
			http.Error(w, `{"error":"invalid language"}`, http.StatusBadRequest)
			return
		}
		writeJSONResp(w, map[string]any{"hello": "hi"})
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !sameOriginPost(r) {
			http.Error(w, `{"error":"invalid origin"}`, http.StatusForbidden)
			return
		}
		var creds struct{ Username, Password string }
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&creds)
		if creds.Username != mockUser || creds.Password != mockPass {
			// Constant response regardless of which field is wrong (no enumeration).
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "kula_session", Value: mockToken, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		writeJSONResp(w, map[string]any{"status": "logged in", "csrf_token": "csrftok"})
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginPost(r) {
			http.Error(w, `{"error":"invalid origin"}`, http.StatusForbidden)
			return
		}
		if r.Header.Get("X-CSRF-Token") != "csrftok" {
			http.Error(w, `{"error":"invalid csrf token"}`, http.StatusForbidden)
			return
		}
		writeJSONResp(w, map[string]any{"status": "logged out"})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
			strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != "metricssecret" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kula-metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("kula_cpu_usage_percent 1\n"))
	})

	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte("body{color:#000}"))
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !hasValidSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			o := r.Header.Get("Origin")
			if o == "" {
				return true
			}
			u, err := url.Parse(o)
			return err == nil && u.Host == r.Host
		}}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	})

	// Everything else (including the index) returns 200 so header checks have a page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>kula</body></html>"))
	})

	return secureHeaders(mux)
}

// secureHeaders wraps h with kula's security headers (fresh nonce per request).
func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		nonce := base64.StdEncoding.EncodeToString(b)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';", nonce))
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.ServeHTTP(w, r)
	})
}

func hasValidSession(r *http.Request) bool {
	c, err := r.Cookie("kula_session")
	if err == nil && c.Value == mockToken {
		return true
	}
	authz := r.Header.Get("Authorization")
	return strings.HasPrefix(authz, "Bearer ") && strings.TrimPrefix(authz, "Bearer ") == mockToken
}

func sameOriginPost(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		o = r.Header.Get("Referer")
	}
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- insecure mock -----------------------------------------------------------

// insecureMock is a single handler (no ServeMux, so dot-dot paths are NOT
// cleaned/redirected) wrapped in a credential-reflecting CORS middleware. It
// omits security headers, leaves the API open, and serves file content for
// traversal paths — every safeguard is deliberately broken.
func insecureMock() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/health":
			_, _ = w.Write([]byte("kula is healthy"))
		case p == "/api/auth/status":
			writeJSONResp(w, map[string]any{"auth_required": true}) // claims auth, enforces none
		case p == "/api/config":
			writeJSONResp(w, map[string]any{"auth_enabled": true, "ollama_enabled": false})
		case p == "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "kula_session", Value: "anything", Path: "/"})
			writeJSONResp(w, map[string]any{"status": "logged in"}) // no origin check
		case p == "/metrics":
			_, _ = w.Write([]byte("kula_cpu_usage_percent 1\n")) // no token
		case p == "/style.css":
			_, _ = w.Write([]byte("body{}"))
		case strings.Contains(p, "etc/passwd"):
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash")) // traversal leak
		case strings.Contains(p, "go.mod"):
			_, _ = w.Write([]byte("module kula"))
		case strings.HasPrefix(p, "/api/"):
			writeJSONResp(w, map[string]any{"data": 1}) // open API, incl. /api/current,/history,/i18n
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>kula</html>"))
		}
	})
	// Reflect any Origin with credentials — a textbook CORS misconfiguration.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		h.ServeHTTP(w, r)
	})
}

// ---- harness -----------------------------------------------------------------

func scannerFor(t *testing.T, ts *httptest.Server, user, pass string) *Scanner {
	t.Helper()
	s, err := NewScanner(ts.URL, "", user, pass, 5*time.Second, false, false, false)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.discover()
	return s
}

func byID(findings []Finding, id string) (Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func wantStatus(t *testing.T, findings []Finding, id string, want Status) {
	t.Helper()
	f, ok := byID(findings, id)
	if !ok {
		t.Errorf("%s: finding not produced", id)
		return
	}
	if f.Status != want {
		t.Errorf("%s (%s): status = %s, want %s — detail: %s | evidence: %s",
			id, f.Title, f.Status, want, f.Detail, f.Evidence)
	}
}

// ---- secure-target tests: everything must PASS -------------------------------

func TestSecureTargetPasses(t *testing.T) {
	ts := httptest.NewServer(secureMock())
	defer ts.Close()
	s := scannerFor(t, ts, mockUser, mockPass)

	hdr := runHeaderChecks(s)
	wantStatus(t, hdr, "HDR-001", StatusPass)
	wantStatus(t, hdr, "HDR-002", StatusPass)
	wantStatus(t, hdr, "HDR-003", StatusPass)
	wantStatus(t, hdr, "HDR-004", StatusPass) // nonce freshness
	wantStatus(t, hdr, "HDR-007", StatusPass) // frame-ancestors

	auth := runAuthChecks(s)
	wantStatus(t, auth, "AUTH-001", StatusPass)
	wantStatus(t, auth, "AUTH-002", StatusPass)
	wantStatus(t, auth, "AUTH-003", StatusPass)
	wantStatus(t, auth, "AUTH-005", StatusPass)
	wantStatus(t, auth, "AUTH-006", StatusPass) // enumeration resistance
	wantStatus(t, auth, "AUTH-007", StatusPass) // HttpOnly

	csrf := runCSRFChecks(s)
	wantStatus(t, csrf, "CSRF-001", StatusPass)
	wantStatus(t, csrf, "CSRF-002", StatusPass)
	wantStatus(t, csrf, "CSRF-003", StatusPass)

	cors := runCORSChecks(s)
	wantStatus(t, cors, "CORS-001", StatusPass)

	trav := runTraversalChecks(s)
	wantStatus(t, trav, "TRAV-001", StatusPass)
	wantStatus(t, trav, "TRAV-002", StatusPass)

	// Secure mock requires the token "metricssecret".
	prom := runMetricsChecks(s)
	wantStatus(t, prom, "PROM-001", StatusPass)
	wantStatus(t, prom, "PROM-002", StatusPass)

	ws := runWSChecks(s)
	wantStatus(t, ws, "WS-001", StatusPass)
	wantStatus(t, ws, "WS-002", StatusPass)

	input := runInputChecks(s)
	wantStatus(t, input, "INPUT-001", StatusPass)
	wantStatus(t, input, "INPUT-003", StatusPass)
}

// ---- insecure-target tests: the matching probes must FAIL/WARN ---------------

func TestInsecureTargetFails(t *testing.T) {
	ts := httptest.NewServer(insecureMock())
	defer ts.Close()
	s := scannerFor(t, ts, "", "")

	hdr := runHeaderChecks(s)
	wantStatus(t, hdr, "HDR-001", StatusFail)
	wantStatus(t, hdr, "HDR-002", StatusFail)
	wantStatus(t, hdr, "HDR-003", StatusFail)

	auth := runAuthChecks(s)
	wantStatus(t, auth, "AUTH-001", StatusFail) // open API despite auth_required
	wantStatus(t, auth, "AUTH-002", StatusFail) // forged cookie accepted

	csrf := runCSRFChecks(s)
	wantStatus(t, csrf, "CSRF-001", StatusWarn) // no origin enforcement
	wantStatus(t, csrf, "CSRF-002", StatusWarn)

	cors := runCORSChecks(s)
	if f, ok := byID(cors, "CORS-001"); !ok || f.Status != StatusFail || f.Severity != SevCritical {
		t.Errorf("CORS-001: want FAIL/CRITICAL, got %v", f)
	}

	trav := runTraversalChecks(s)
	wantStatus(t, trav, "TRAV-001", StatusFail)

	prom := runMetricsChecks(s)
	wantStatus(t, prom, "PROM-001", StatusWarn) // exposed without token
}

// ---- report logic ------------------------------------------------------------

func TestExitCodeThreshold(t *testing.T) {
	findings := []Finding{
		finding("A", "x", "medium fail", SevMedium, StatusFail, ""),
		finding("B", "x", "pass", SevInfo, StatusPass, ""),
	}
	r := newReport("t", findings)
	if r.Summary.Fail != 1 || r.Summary.Pass != 1 {
		t.Fatalf("summary = %+v", r.Summary)
	}
	if code := r.exitCode(SevHigh); code != 0 {
		t.Errorf("exit with fail-on=high and only a medium fail = %d, want 0", code)
	}
	if code := r.exitCode(SevMedium); code != 1 {
		t.Errorf("exit with fail-on=medium and a medium fail = %d, want 1", code)
	}
	if code := r.exitCode(SevLow); code != 1 {
		t.Errorf("exit with fail-on=low = %d, want 1", code)
	}
}

func TestParseSeverityAndOnly(t *testing.T) {
	if _, ok := parseSeverity("bogus"); ok {
		t.Error("parseSeverity accepted a bogus value")
	}
	if sev, ok := parseSeverity("CRITICAL"); !ok || sev != SevCritical {
		t.Errorf("parseSeverity(CRITICAL) = %v,%v", sev, ok)
	}
	set := parseOnly("auth, CORS ,headers")
	for _, want := range []string{"auth", "cors", "headers"} {
		if !set[want] {
			t.Errorf("parseOnly missing %q in %v", want, set)
		}
	}
	if parseOnly("") != nil {
		t.Error("parseOnly(\"\") should be nil (means all)")
	}
}

func TestJSONStringEscaping(t *testing.T) {
	got := jsonString(`a"b\c` + "\n")
	if !strings.HasPrefix(got, `"`) || strings.Contains(got, "\n") {
		t.Errorf("jsonString did not escape control/quote chars: %s", got)
	}
}
