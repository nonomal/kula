# Kula — Security & Code Quality Review

**Project:** [github.com/c0m4r/kula](https://github.com/c0m4r/kula)  
**Version reviewed:** development HEAD (post-0.15.2-dev)  
**Language:** Go 1.26.3 (backend), JavaScript (frontend), Python/Bash (addons)  
**Reviewer date:** 2026-05-31  

---

## Executive Summary

Kula is a lightweight Linux server monitor with a Go backend, a browser-based dashboard served over HTTP/WebSocket, and optional integrations for PostgreSQL, MySQL, Nginx, Apache2, Docker/Podman containers, and an Ollama AI chat proxy. The codebase demonstrates a security-conscious design philosophy — Argon2id password hashing, CSRF tokens, CSP nonces, Landlock sandboxing, Origin validation, and rate limiting are all present. However, several findings range from medium-severity issues (credential exposure in DSN strings, SSRF surface in Ollama proxy, weak WebSocket read deadlines) to low-severity hardening opportunities. The code quality is generally strong, with clean architecture, comprehensive tests, and detailed inline documentation, though some areas show room for improvement around error-handling consistency, magic number elimination, and DRY refactoring.

**Overall Security Score: 7.5 / 10**  
**Overall Code Quality Score: 8.0 / 10**  
**Combined Score: 7.75 / 10**

---

> ## 🔎 Re-Review Note (Claude Opus 4.8 — 2026-05-31)
>
> Each finding below has an inline **Verdict** block validating it against the actual `0.17.3` source. Verdict legend: ✅ valid · ⚠️ partly valid / overstated · ❌ invalid or misguided. Summary:
>
> - **Metadata error:** this is `0.17.3`, not the "post-0.15.2-dev" stated in the header.
> - **Sound but severity-inflated:** H-01, H-02, M-05, M-06 — these treat an *admin-controlled* config file as an external attack surface, which deflates the SSRF/credential framing.
> - **Reject:** **M-02** (a rainbow table over a 256-bit random token is impossible — the crypto reasoning is invalid) and **L-05** (rightmost-XFF is the intentional *secure* choice; the suggested change regresses security).
> - **Largely invalid:** **M-01** (standard keepalive, already bounded by global + per-IP connection limits).
> - **Don't implement as written:** M-04 `0600` default, L-03 auto-token / forced-auth, and **L-06 `sslmode=prefer`** (unsupported by `lib/pq`).
> - **Genuinely actionable:** H-01 escaping (via `mysql.Config.FormatDSN`), M-03 trusted-proxy CIDRs, M-06 SSE sanitization (+ the newline-injection angle the review missed), L-01, L-06's warning half, L-03's doc note.
> - **Positives (§4) all verified accurate.**

---

## Table of Contents

1. [Scoring Methodology](#1-scoring-methodology)  
2. [Security Findings](#2-security-findings)  
   - [Critical](#21-critical)  
   - [High](#22-high)  
   - [Medium](#23-medium)  
   - [Low](#24-low)  
   - [Informational](#25-informational)  
3. [Code Quality Findings](#3-code-quality-findings)  
4. [Positive Security Observations](#4-positive-security-observations)  
5. [Recommendations Summary](#5-recommendations-summary)  
6. [Appendix: File Inventory](#6-appendix-file-inventory)

---

## 1. Scoring Methodology

Each finding is scored on a 0–10 severity scale reflecting exploitability, impact, and blast radius in the context of a self-hosted server monitoring tool. The overall scores are weighted averages:

| Category | Weight |
|---|---|
| Authentication & Session Management | 20% |
| Input Validation & Injection | 15% |
| Network & Transport Security | 15% |
| Access Control & Authorization | 15% |
| Sandbox & Process Isolation | 10% |
| Cryptographic Practices | 10% |
| Error Handling & Information Disclosure | 10% |
| Code Quality & Maintainability | 5% |

Scores per category and the composite are derived from the findings below.

---

## 2. Security Findings

### 2.1 Critical

No critical-severity findings were identified.

### 2.2 High

#### H-01: MySQL DSN Contains Plaintext Password in String

**File:** `internal/collector/mysql.go:41`  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)  
**Score:** 7.0 / 10

The MySQL DSN is assembled by directly interpolating the password into the connection string:

```go
dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", user, password, host, port, dbname)
```

If the `mysqlCollector` struct is ever logged, serialized, or exposed via a panic/stack trace, the plaintext password becomes visible. The DSN is stored as a field on the `mysqlCollector` struct for the process lifetime:

```go
type mysqlCollector struct {
    dsn string  // contains plaintext password
    // ...
}
```

While the Go MySQL driver requires the password in the DSN, the struct field should not retain it after connection establishment. Additionally, the `fmt.Sprintf` approach does not escape special characters in the password (e.g., `@`, `:`, `/`), which could cause connection failures or, worse, DSN parsing ambiguities leading to unintended authentication bypass.

**Contrast with PostgreSQL:** The PostgreSQL collector (`internal/collector/postgres.go:50-63`) properly escapes the password with backslash and single-quote escaping before embedding it in the libpq key=value DSN format — a significantly safer approach.

**Recommendation:**  
1. Clear the `dsn` field after `sql.Open` succeeds, or store only the `*sql.DB` handle.  
2. Apply URL-encoding or the same escaping logic used for PostgreSQL to handle special characters.  
3. Never log the DSN or include it in error messages.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Partly valid — severity overstated (real issue is Low, not High 7.0).**
> The genuine bug is the missing escaping: a password containing `@`, `:`, or `/` breaks the DSN — and the correct fix is `mysql.Config{}.FormatDSN()`, not manual escaping. However: (1) "authentication bypass" is wrong — a malformed DSN causes a *connection failure*, not a bypass; (2) the DSN is **never logged** in production (only in `app_test.go`), so the credential-exposure premise has no real code path; (3) recommendation #1 is flawed — `connect()` re-opens with `mc.dsn` on every reconnect ([mysql.go:81](../../internal/collector/mysql.go#L81)), so clearing the field would break automatic reconnection. Keep only the escaping fix.

---

#### H-02: Ollama Proxy SSRF Surface Beyond Loopback Validation

**File:** `internal/config/config.go:463-476`  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Score:** 6.5 / 10

The Ollama URL validation only allows `localhost`, `127.0.0.1`, and `::1`:

```go
func validateOllamaURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    host := u.Hostname()
    if host != "localhost" && host != "127.0.0.1" && host != "::1" {
        return fmt.Errorf("ollama.url: host %q is not a loopback address", host)
    }
    return nil
}
```

This validation has two bypass vectors:

1. **DNS rebinding:** `localhost` can resolve to a non-loopback address on systems with a modified `/etc/hosts` or in containerized environments where DNS is user-controlled. A malicious config pointing to `localhost` but with DNS rebinding can route traffic to internal services.

2. **Missing scheme validation:** The check does not verify that the scheme is `http://`. A `file://localhost/etc/passwd` or `gopher://localhost:6379/` URL would pass the hostname check. While Go's `http.Client` only supports HTTP(S), defense-in-depth mandates explicit scheme validation.

**Recommendation:**  
1. Add explicit scheme validation: reject anything other than `http://`.  
2. Consider resolving `localhost` to its IP address and validating the resolved IP is in the loopback range, or simply disallow `localhost` and require `127.0.0.1` or `::1`.  
3. Validate that the port is in a reasonable range for Ollama (e.g., 11434 or user-configured).

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Weak hardening — overstated as High.**
> Go's `http.Client` rejects non-HTTP(S) schemes at request time, so `file://` / `gopher://` URLs fail in practice — the scheme check is pure defense-in-depth. DNS-rebinding via `localhost` requires control of the (admin-owned) config file, so it isn't a realistic external threat. The allow-list already defeats userinfo tricks (`http://127.0.0.1@evil/` parses to host `evil`) and decimal-IP forms. A scheme check is cheap to add, but this is Low, not 6.5/High.

---

### 2.3 Medium

#### M-01: WebSocket Read Deadline Too Generous (60s Idle)

**File:** `internal/web/websocket.go:151`  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**Score:** 5.5 / 10

The WebSocket read deadline is set to 60 seconds:

```go
_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
```

Combined with the 50-second ping interval, a malicious client can hold a connection open indefinitely by responding to pings without sending any data. With the default `MaxWebsocketConns` of 100, an attacker can exhaust the global WebSocket connection quota from a single IP (after reaching the per-IP limit of 5) by distributing across multiple IPs, forcing legitimate users off.

**Recommendation:** Reduce the read deadline to 30 seconds with a 25-second ping interval. Add an absolute maximum connection lifetime (e.g., 4 hours) after which the server closes the connection and the client must reconnect.

> **🔎 Verdict (Opus 4.8 re-review): ❌ Largely invalid.**
> This is the standard gorilla/websocket keepalive pattern — the read deadline is reset on every pong ([websocket.go:151-155](../../internal/web/websocket.go#L151)), so "holding the connection open" by answering pings is *normal, intended* behavior, not an attack. Resource consumption is already bounded by the global (100) and per-IP (5) connection limits ([websocket.go:72-83](../../internal/web/websocket.go#L72)). An absolute max-lifetime cap is optional polish, not a Medium-severity DoS.

---

#### M-02: Session Tokens Stored as SHA-256 Hashes Without Per-Token Salt

**File:** `internal/web/auth.go:154-157`  
**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)  
**Score:** 5.0 / 10

Session tokens are hashed with a single round of SHA-256 for storage:

```go
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
}
```

While session tokens have high entropy (32 bytes from `crypto/rand`), a single unsalted SHA-256 hash enables rainbow-table-style attacks if the `sessions.json` file is leaked. For passwords, the project correctly uses Argon2id; for session tokens, the threat model is lower but not zero — stolen session files could be brute-forced if tokens were ever generated with insufficient entropy.

**Recommendation:** Use HMAC-SHA256 with a server-side secret key instead of plain SHA-256. This prevents offline attacks on the sessions file without the server's HMAC key.

> **🔎 Verdict (Opus 4.8 re-review): ❌ Technically invalid.**
> Session tokens are 32 bytes (256 bits) from `crypto/rand` ([generateToken](../../internal/web/auth.go#L395)). A rainbow table over a 2²⁵⁶ keyspace is computationally impossible — the finding even acknowledges the high entropy, which refutes its own premise. Single-round SHA-256 over a high-entropy *secret* (not a password) is the correct, standard construction. HMAC with a server pepper is a marginal defense-in-depth nicety, not a fix for a real weakness, and the "insufficient entropy" caveat is hypothetical (does not apply to a 32-byte random token).

---

#### M-03: `TrustProxy` Allows X-Forwarded-For Spoofing When Not Behind a Proxy

**File:** `internal/web/server.go:1009-1024`  
**CWE:** CWE-346 (Origin Validation Error)  
**Score:** 5.0 / 10

When `trust_proxy: true` is set, the code takes the **rightmost** IP from `X-Forwarded-For`:

```go
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
    parts := strings.Split(xff, ",")
    return strings.TrimSpace(parts[len(parts)-1])
}
```

The comment states "the rightmost IP is the one appended by our trusted proxy," but this is only correct if there is exactly one trusted reverse proxy. If Kula is exposed directly to the internet with `trust_proxy: true` (a misconfiguration), any client can spoof `X-Forwarded-For` to bypass IP-based rate limiting and per-IP WebSocket connection limits.

The code does log a warning at startup when `TrustProxy` is enabled, which is good, but the rightmost-IP convention assumes a specific proxy chain topology that may not always hold.

**Recommendation:**  
1. Add a configurable `trusted_proxy_cidrs` list and validate that `r.RemoteAddr` belongs to a trusted proxy before parsing `X-Forwarded-For`.  
2. Document the assumed proxy topology clearly in the example config.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Valid hardening (severity fair, partly mitigated).**
> Legitimate improvement — validating `RemoteAddr` against a trusted-proxy CIDR list before parsing XFF is the correct robust fix. Two caveats: the rightmost-IP choice itself is *correct and intentional* (leftmost entries are client-spoofable — see L-05), and the code **already logs a startup warning** when `TrustProxy` is enabled, which meaningfully mitigates the misconfiguration risk this finding describes.

---

#### M-04: Custom Metrics Unix Socket Lacks Authentication

**File:** `internal/collector/custom.go:42-68`  
**CWE:** CWE-306 (Missing Authentication for Critical Function)  
**Score:** 4.5 / 10

The custom metrics Unix socket at `<storage_dir>/kula.sock` accepts JSON from any process that can connect:

```go
listener, err := net.Listen("unix", sockPath)
if err := os.Chmod(sockPath, 0660); err != nil {
    log.Printf("[custom] warning: chmod socket: %v", err)
}
```

Any user in the same group as the Kula process can inject arbitrary metric values into the dashboard. While this is by design (the socket is group-readable for flexibility), a compromised or misbehaving process in the same group could flood the metrics with misleading data, potentially masking real issues.

**Recommendation:**  
1. Document the trust model explicitly.  
2. Consider adding an optional shared-secret field to the custom metrics config and requiring it as a field in the JSON payload.  
3. Reduce the socket mode to `0600` by default (owner-only) and let users opt into `0660`.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Valid observation, recommendations conflict with the design.**
> The socket is group-writable by design ([custom.go:52](../../internal/collector/custom.go#L52)). A `0600` default (rec #3) would **break** the intended use case — helper exporters (e.g. the NVIDIA script) running as a *different* user in the kula group. A shared secret over a unix socket (rec #2) is over-engineering; filesystem permissions are the appropriate access control here. Impact is Low: it requires same-group local access and only allows injecting misleading chart data. Documenting the trust model (rec #1) is the worthwhile part.

---

#### M-05: Nginx/Apache2 Status URLs Not Validated for Loopback

**File:** `internal/config/config.go:207-219`  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Score:** 4.5 / 10

Unlike the Ollama URL, the Nginx `status_url` and Apache2 `status_url` are not validated to ensure they target only loopback or trusted hosts:

```go
type NginxConfig struct {
    Enabled   bool   `yaml:"enabled"`
    StatusURL string `yaml:"status_url"`
}
```

An administrator or anyone who can modify the config file could set `status_url` to an internal service URL (e.g., `http://169.254.169.254/latest/meta-data/` on cloud instances), causing Kula to make periodic HTTP GET requests to that URL and expose the response content in the monitoring data.

**Recommendation:** Apply the same loopback validation used for `ollama.url` to `nginx.status_url` and `apache2.status_url`. If external URLs must be supported (e.g., monitoring a remote Nginx), add an explicit `allow_external_urls: true` flag.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Partly valid — impact overstated.**
> The inconsistency with Ollama is real. But the claim that this "expose[s] the response content in the monitoring data" is **false**: the nginx/apache parsers extract only specific integer fields ([nginx.go:57-114](../../internal/collector/nginx.go#L57)) and never reflect the raw body anywhere user-visible — at most a *blind* GET is possible. It also requires admin-controlled config, and remote monitoring is a legitimate use case. The `allow_external_urls` flag is a reasonable defense-in-depth addition; severity is Low.

---

#### M-06: Ollama Streaming Response Size Bounded but Error Messages Could Leak Internal State

**File:** `internal/web/ollama.go:468-470`  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**Score:** 4.0 / 10

When the Ollama backend returns a non-200 status, the response body is read (up to 512 bytes) and included in the error:

```go
b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
```

This error string is then forwarded to the client via SSE:

```go
_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
```

If the Ollama backend includes internal details in its error response (stack traces, internal IPs, file paths), these would be leaked to the browser client.

**Recommendation:** Sanitize the error before forwarding to the client. Return a generic error message to the SSE stream and log the detailed error server-side.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Valid but low severity (one detail missed).**
> The error (including ≤512 B of backend body) is indeed forwarded to the client ([ollama.go:359](../../internal/web/ollama.go#L359)). But the Ollama backend is loopback-only and the chat endpoint is authenticated, so the user effectively controls both ends — limited leak value. The review **missed** the sharper issue: unescaped newlines in that body can inject spurious SSE frames into the stream. Sanitizing (strip newlines + generic message) is cheap and worth doing; not Medium.

---

### 2.4 Low

#### L-01: Gzip Middleware Does Not Verify Content-Type Before Compressing

**File:** `internal/web/server.go:174-191`  
**Score:** 3.0 / 10

The gzip middleware compresses all responses where `Accept-Encoding: gzip` is present, except for WebSocket upgrades and SSE streams. However, it does not check `Content-Type` before compressing. Compressing already-compressed content (e.g., images, video, pre-compressed assets) wastes CPU and can slightly increase payload size.

**Recommendation:** Add a Content-Type whitelist (e.g., `text/*`, `application/json`, `application/javascript`) or blacklist (e.g., skip `image/*`, `video/*`, `application/octet-stream`).

> **🔎 Verdict (Opus 4.8 re-review): ✅ Valid (minor).**
> Correct — [gzipMiddleware](../../internal/web/server.go#L174) doesn't check Content-Type, so images/fonts get pointlessly recompressed. Genuine, low-impact efficiency item.

---

#### L-02: `readPasswordWithAsterisks` Fallback Leaks Password in Terminal History

**File:** `cmd/kula/main.go:210-212`  
**Score:** 3.0 / 10

If the terminal is not available, the fallback uses `bufio.NewReader`:

```go
reader := bufio.NewReader(os.Stdin)
password, _ := reader.ReadString('\n')
return strings.TrimSpace(password)
```

This reads the password in cleartext mode, potentially echoing it to the terminal and storing it in shell history. While this is a fallback for non-interactive environments, it is reached more often than expected (e.g., piped input, CI environments).

**Recommendation:** If `term.MakeRaw` fails, warn the user that the password will be echoed and prompt for confirmation, or refuse to proceed.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Partly valid — the "shell history" claim is wrong.**
> The echo concern is real for an interactive cooked TTY ([main.go:210](../../cmd/kula/main.go#L210)), but program stdin is **not** recorded in shell history — that's a shell feature for command lines only. This fallback is reached mainly for piped/non-interactive input, where there's no echo anyway. A warning is fine; very minor.

---

#### L-03: Prometheus Metrics Endpoint Without Authentication by Default

**File:** `internal/web/server.go:400-408`  
**Score:** 3.0 / 10

The `/metrics` endpoint is served without authentication when `token` is empty:

```go
if s.cfg.PrometheusMetrics.Token != "" {
    log.Printf("Prometheus metrics enabled at %s with bearer token authentication", metricsPath)
} else {
    log.Printf("Prometheus metrics enabled at %s without authentication", metricsPath)
}
```

The default config has `token: ""`, meaning any network-reachable Kula instance with Prometheus metrics enabled exposes all system metrics (CPU, memory, disk, network, processes, database stats) to unauthenticated users.

**Recommendation:**  
1. Generate a random token by default when `prometheus_metrics.enabled: true` and `token: ""`.  
2. Add a startup warning when metrics are enabled without a token.  
3. Consider requiring the auth middleware even for `/metrics` when `web.auth.enabled: true`.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Valid (minor); recs #1 and #3 impractical.**
> Correct that `/metrics` is unauthenticated when `token == ""` — but it's **disabled by default**, and startup **already logs** "without authentication" ([server.go:406](../../internal/web/server.go#L406)). Rec #1 (auto-generate a token) and rec #3 (force the session-auth middleware) would **break Prometheus scrapers**, which use a bearer token, not session cookies. The right fix is a louder doc/startup warning, not changing the auth model.

---

#### L-04: Integer Overflow Potential in Binary Codec

**File:** `internal/storage/codec.go:254-321`  
**Score:** 2.5 / 10

The binary codec truncates various integer fields without overflow checks:

```go
run := s.LoadAvg.Running
if run < 0 { run = 0 } else if run > 65535 { run = 65535 }
binary.LittleEndian.PutUint16(b[46:], uint16(run))
```

While clamping is present for some fields, others use raw casts without bounds checking:

```go
binary.LittleEndian.PutUint32(b[0:], uint32(int32(n.ActiveConnections)))
```

If `ActiveConnections` exceeds `int32` range (unlikely but possible on a compromised or misconfigured Nginx reporting absurd values), the cast wraps silently.

**Recommendation:** Apply consistent bounds checking/clamping to all integer fields before encoding, especially those cast from `int` to smaller integer types.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Valid (informational only).**
> The inconsistency is real — some fields clamp, others use raw `uint32(int32(...))` casts ([codec.go:305-314](../../internal/storage/codec.go#L305)). In practice irrelevant: local process/socket counts never approach the int32 ceiling. A consistency nit, not a finding with real-world impact.

---

#### L-05: `getClientIP` Rightmost XFF Logic May Be Incorrect for Multi-Proxy Setups

**File:** `internal/web/server.go:1009-1024`  
**Score:** 2.5 / 10

The comment says "the rightmost IP is the one appended by our trusted proxy," but in a multi-proxy chain (e.g., CDN -> load balancer -> Kula), the rightmost IP is the load balancer's IP, not the client's. The actual client IP would be the leftmost untrusted entry.

**Recommendation:** Support configurable proxy depth or use `X-Real-IP` as a fallback when available.

> **🔎 Verdict (Opus 4.8 re-review): ❌ Misguided.**
> Taking the rightmost IP is the *intentional, secure* choice ([server.go:1013](../../internal/web/server.go#L1013)) — for rate-limiting you want the IP your trusted proxy vouches for, since leftmost / `X-Real-IP` values are client-spoofable. Switching to the leftmost "untrusted" entry would **regress security** and contradicts M-03's own (correct) reasoning. Configurable proxy *depth* is fine; trusting `X-Real-IP` is not.

---

#### L-06: PostgreSQL Default SSL Mode is `disable`

**File:** `internal/config/config.go:350`  
**Score:** 2.5 / 10

```go
Postgres: PostgresConfig{
    SSLMode: "disable",
}
```

The default SSL mode for PostgreSQL is `disable`, meaning credentials and data travel in cleartext over the network. While the default host is `localhost` (mitigating network exposure), users who change the host to a remote server without changing `sslmode` will transmit passwords in cleartext.

**Recommendation:** Change the default to `prefer` or at minimum add a warning log when `sslmode=disable` and `host` is not a loopback address.

> **🔎 Verdict (Opus 4.8 re-review): ⚠️ Valid observation — primary recommendation is broken.**
> The `disable` default is real ([config.go:350](../../internal/config/config.go#L350)). But `lib/pq` (the driver in use) **does not support `sslmode=prefer`** — it returns `pq: unsupported sslmode`, so that default would break connections outright. Only the fallback recommendation (warn on `disable` + non-loopback host) is valid.

---

#### L-07: Error Returned but Ignored in Multiple Locations

**Files:** Various  
**Score:** 2.0 / 10

Several locations ignore errors from `rand.Read`, `conn.WriteMessage`, and similar calls:

```go
_, _ = rand.Read(b)  // server.go:209
_ = conn.WriteMessage(websocket.TextMessage, data)  // websocket.go:144
_, _ = w.Write(b)    // server.go:199
```

While `crypto/rand.Read` on modern Go always returns `nil` error (it panics instead), the pattern of silently discarding errors is dangerous if the code is refactored or if the Go runtime behavior changes.

**Recommendation:** Handle errors explicitly, even if only to log them. For `rand.Read`, add a panic or fatal log on error.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Valid (stylistic).**
> Fair point, low impact. As the finding itself notes, `crypto/rand.Read` does not return an error in modern Go. Reasonable hygiene, not security-relevant.

---

### 2.5 Informational

#### I-01: Nginx/Apache2 HTTP Clients Do Not Verify TLS Certificates

**File:** `internal/collector/nginx.go:30`, `internal/collector/apache2.go` (similar)  
**Score:** N/A (informational)

The HTTP client used to fetch status pages inherits Go's default TLS verification. This is fine for `http://localhost` but could be an issue if users configure `https://` URLs to remote servers with self-signed certificates.

**Recommendation:** Document that TLS certificate verification is enforced by default, and provide a `tls_skip_verify` option for self-signed certs (with appropriate warnings).

> **🔎 Verdict (Opus 4.8 re-review): ✅ Reasonable (informational).** Accurate; sensible doc/option suggestion.

---

#### I-02: NVIDIA Exporter Shell Script Uses `umask 077` but Writes to Shared Directory

**File:** `scripts/nvidia-exporter.sh`  
**Score:** N/A (informational)

The script correctly sets `umask 077` and uses atomic file replacement (`mv`), but the storage directory itself may have broader permissions, allowing other users to read `nvidia.log` if the file is created before `umask` takes effect or if the directory permissions allow deletion/replacement.

**Recommendation:** Ensure the storage directory is owned by the Kula user with mode `0700`.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Reasonable (informational).** Valid hardening note for the storage directory.

---

#### I-03: `base_path` Normalization Is Thorough but Complex

**File:** `internal/config/config.go:483-523`  
**Score:** N/A (informational)

The `normalizeBasePath` function includes extensive validation against open redirect (CWE-601), path traversal, and control character injection. This is well-implemented defense-in-depth. No issues found, but the complexity makes it worth noting for future maintainers.

> **🔎 Verdict (Opus 4.8 re-review): ✅ Agree.** Confirmed — [normalizeBasePath](../../internal/config/config.go#L483) correctly rejects `//`, `/\`, control chars, and `.`/`..` segments before emitting into redirects and `<base href>`. Solid.

---

## 3. Code Quality Findings

### 3.1 Architecture & Design

**Score:** 8.5 / 10

The codebase follows a clean separation of concerns:

```
cmd/kula/         — CLI entry point
internal/collector/ — Metrics collection (CPU, memory, disk, network, apps)
internal/config/    — Configuration loading and validation
internal/storage/   — Tiered ring-buffer storage with binary codec
internal/web/       — HTTP/WebSocket server, auth, Ollama proxy
internal/sandbox/   — Landlock-based process sandboxing
internal/tui/       — Terminal UI (Bubble Tea)
internal/i18n/      — Internationalization
```

Package boundaries are well-defined, and there are no circular dependencies. The `collector` package is the only one that imports `config` types, while `web` depends on `collector`, `config`, `storage`, and `i18n` — a reasonable dependency graph.

### 3.2 Error Handling

**Score:** 6.5 / 10

Error handling is inconsistent:

- **Good:** Most HTTP handlers return proper JSON error responses via `jsonError()`. The `store` package propagates errors with `fmt.Errorf("writing tier 0: %w", err)`.
- **Bad:** Many `io.Write`, `conn.WriteMessage`, and `rand.Read` calls silently discard errors with `_ =`. The `gzipResponseWriter.Write` method silently promotes to `http.StatusOK` if `WriteHeader` was never called, which could mask bugs.

**Code snippet — silently discarded error:**
```go
// internal/web/websocket.go:144
if sample := s.collector.Latest(); sample != nil {
    data, err := json.Marshal(sample)
    if err == nil {
        _ = conn.WriteMessage(websocket.TextMessage, data)  // error ignored
    }
}
```

### 3.3 Test Coverage

**Score:** 7.5 / 10

Test files exist for the major packages:

- `internal/web/auth_test.go` — Auth and CSRF middleware
- `internal/web/server_test.go` — Server routes
- `internal/web/websocket_test.go` — WebSocket handler
- `internal/web/prometheus_test.go` — Metrics endpoint
- `internal/web/ollama_test.go` — Ollama proxy
- `internal/storage/codec_test.go` — Binary codec roundtrip
- `internal/storage/store_test.go` — Store operations
- `internal/storage/migration_test.go` — Storage migration
- `internal/config/config_test.go` — Config parsing
- `internal/collector/process_test.go`, `containers_test.go`, etc.

However, integration tests for the full HTTP stack (auth -> API -> WebSocket) and end-to-end tests for the Ollama proxy are absent. The binary codec tests cover forward compatibility but could benefit from property-based fuzzing.

### 3.4 Magic Numbers

**Score:** 6.0 / 10

Several numeric constants are hardcoded without named constants:

```go
// internal/web/websocket.go:151
_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

// internal/web/websocket.go:182
ticker := time.NewTicker(50 * time.Second)

// internal/web/auth.go:137
if len(recent) >= 5 {  // 5 login attempts

// internal/web/ollama.go:28-42
ollamaMaxPrompt = 2000
ollamaMaxBody = 32 * 1024
ollamaMaxResponse = 10 * 1024 * 1024
```

The Ollama constants are properly named, but the WebSocket and auth constants are not.

**Recommendation:** Define named constants for all numeric thresholds, especially those that affect security or resource limits.

### 3.5 Code Duplication

**Score:** 7.0 / 10

The `chatRateLimiter` and `RateLimiter` in `auth.go` have nearly identical logic (sliding window with purge). The `fetchModelsOllama` and `fetchModelsOpenAI` methods share significant boilerplate for HTTP client creation, request building, and response parsing.

The `mergeSample` function in `store.go` uses a functional approach but is deeply nested with per-field merging that must be kept in sync with the `Sample` struct definition — any new field must be added in three places (`minSample`, `maxSample`, `aggregateSamples`).

**Recommendation:** Extract a generic sliding-window rate limiter type. Consider code generation or reflection-based field merging for `mergeSample`.

### 3.6 Documentation

**Score:** 9.0 / 10

The codebase has excellent inline documentation:

- Every exported function has a GoDoc comment
- The binary codec (`codec.go`) has a detailed backward-compatibility rules section
- Config struct fields have YAML tag documentation
- The example config (`config.example.yaml`) is thorough and well-commented
- `SECURITY.md` and `AGENTS.md` exist for vulnerability reporting and AI context

### 3.7 Concurrency Safety

**Score:** 8.0 / 10

Synchronization is generally well-handled:

- `sync.RWMutex` is used correctly for read-heavy paths (`Collector.Latest()`, `Store.QueryRangeWithMeta`)
- WebSocket connection counting uses `sync.Mutex` with `sync.Once` for cleanup
- Rate limiters are mutex-protected with bounded key counts

One potential issue: the `wsHub.broadcast` method holds `RLock` while iterating clients and acquiring individual client mutexes:

```go
func (h *wsHub) broadcast(data []byte) {
    h.mu.RLock()
    defer h.mu.RUnlock()
    for client := range h.clients {
        client.mu.Lock()
        paused := client.paused
        client.mu.Unlock()
        // ...
    }
}
```

This is safe (no deadlock possible since lock ordering is hub -> client), but holding the hub's `RLock` while blocking on individual client mutexes could slow down other operations that need the hub lock.

### 3.8 Dependency Management

**Score:** 8.0 / 10

Dependencies are minimal and well-chosen:

| Dependency | Purpose | Assessment |
|---|---|---|
| `gorilla/websocket` | WebSocket support | Mature, well-maintained |
| `charmbracelet/bubbletea` | TUI framework | Popular, actively maintained |
| `go-landlock` | Process sandboxing | Security-critical, niche but appropriate |
| `golang.org/x/crypto` | Argon2id hashing | Standard crypto library |
| `lib/pq` | PostgreSQL driver | Stable, widely used |
| `go-sql-driver/mysql` | MySQL driver | Standard choice |
| `gopkg.in/yaml.v3` | YAML parsing | Standard |

No known-vulnerable dependencies. The `go.sum` file pins exact versions.

---

## 4. Positive Security Observations

The following security measures are correctly implemented and deserve recognition:

### 4.1 Argon2id Password Hashing

```go
// internal/web/auth.go:146-151
func HashPassword(password, salt string, params config.Argon2Config) string {
    keyLen := uint32(32)
    hash := argon2.IDKey([]byte(password), []byte(salt), params.Time, params.Memory, params.Threads, keyLen)
    return hex.EncodeToString(hash)
}
```

Default parameters (time=3, memory=32768 KB, threads=4) exceed OWASP minimum recommendations (time=1, memory=19456 KB). This is excellent.

### 4.2 Constant-Time Credential Comparison

```go
// internal/web/auth.go:174-177
if subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Username)) == 1 {
    hash := HashPassword(password, a.cfg.PasswordSalt, a.cfg.Argon2)
    return subtle.ConstantTimeCompare([]byte(hash), []byte(a.cfg.PasswordHash)) == 1
}
```

Both username and password hash comparisons use `subtle.ConstantTimeCompare`, preventing timing side-channel attacks.

### 4.3 CSRF Protection (Double-Submit Cookie Pattern)

```go
// internal/web/auth.go:411-439
func (a *AuthManager) CSRFMiddleware(next http.Handler) http.Handler {
    // Origin/Referer validation + synchronizer token check
    expectedToken := a.GetCSRFToken(cookie.Value)
    providedToken := r.Header.Get("X-CSRF-Token")
    if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(providedToken)) != 1 {
        http.Error(w, `{"error":"invalid csrf token"}`, http.StatusForbidden)
    }
}
```

The CSRF middleware combines origin validation (defense in depth) with a synchronizer token pattern, using constant-time comparison. This is a robust implementation.

### 4.4 CSP Nonces and Security Headers

```go
// internal/web/server.go:206-233
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
    nonce := base64.StdEncoding.EncodeToString(b)
    csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline';", nonce)
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
    w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}
```

Per-request CSP nonces, comprehensive security headers, and conditional HSTS (only when TLS or trusted proxy indicates HTTPS) — all implemented correctly.

### 4.5 Landlock Sandbox

```go
// internal/sandbox/sandbox.go:225
err = landlock.V5.BestEffort().Restrict(allRules...)
```

The Landlock sandbox restricts filesystem access to only `/proc` (RO), `/sys` (RO), config file (RO), storage directory (RW), and network to specific ports. This is a significant defense-in-depth measure that limits the blast radius of any future RCE vulnerability.

### 4.6 SRI Hashes for JavaScript

```go
// internal/web/server.go:982-1006
func (s *Server) calculateSRIs() {
    sum := sha512.Sum384(data)
    hash := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
    s.sriHashes[key] = hash
}
```

Sub-Resource Integrity hashes are computed at startup for all embedded JavaScript files, preventing tampering with static assets.

### 4.7 Rate Limiting with Bounded Memory

```go
// internal/web/auth.go:47
const maxRateLimiterKeys = 16384

func reserveRateLimiterKey(m map[string][]time.Time, key string, purge func()) bool {
    if len(m) >= maxRateLimiterKeys {
        purge()
        if len(m) >= maxRateLimiterKeys {
            return false  // fail-closed
        }
    }
    return true
}
```

Rate limiters have a bounded key count and fail-closed when saturated — preventing memory exhaustion attacks.

### 4.8 WebSocket Origin Validation

```go
// internal/web/websocket.go:30-64
CheckOrigin: func(r *http.Request) bool {
    u, err := url.ParseRequestURI(origin)
    if u.Host == r.Host { return true }
    // Also check AllowedOrigins...
}
```

Proper Origin header validation using `url.ParseRequestURI` (not string matching) prevents Cross-Site WebSocket Hijacking (CSWSH).

### 4.9 Input Sanitization on Ollama Chat

```go
// internal/web/ollama.go:240-247
func sanitisePrompt(s string) string {
    s = strings.ReplaceAll(s, "\x00", "")
    if utf8.RuneCountInString(s) > ollamaMaxPrompt {
        runes := []rune(s)
        s = string(runes[:ollamaMaxPrompt])
    }
    return strings.TrimSpace(s)
}
```

Null byte stripping, length clamping, and model name validation via regex prevent injection attacks through the AI chat interface.

---

## 5. Recommendations Summary

### Priority Matrix

| ID | Severity | Effort | Recommendation |
|---|---|---|---|
| H-01 | High | Low | Clear MySQL DSN after `sql.Open`; apply password escaping |
| H-02 | High | Low | Validate Ollama URL scheme is `http://`; consider DNS resolution check |
| M-01 | Medium | Low | Reduce WebSocket idle timeout; add max connection lifetime |
| M-02 | Medium | Low | Use HMAC-SHA256 with server key for session token hashing |
| M-03 | Medium | Medium | Add `trusted_proxy_cidrs` config; validate `RemoteAddr` before parsing XFF |
| M-04 | Medium | Low | Document custom socket trust model; consider `0600` default mode |
| M-05 | Medium | Low | Apply loopback validation to Nginx/Apache2 status URLs |
| M-06 | Medium | Low | Sanitize Ollama error messages before forwarding to SSE client |
| L-01 | Low | Low | Add Content-Type check in gzip middleware |
| L-02 | Low | Low | Warn user when password echo fallback is used |
| L-03 | Low | Medium | Generate default Prometheus token or refuse unauthenticated metrics |
| L-04 | Low | Low | Add consistent bounds checking to binary codec integer casts |
| L-05 | Low | Medium | Support configurable proxy depth for XFF parsing |
| L-06 | Low | Low | Change PostgreSQL default SSL mode to `prefer`; warn on `disable` + remote host |
| L-07 | Low | Low | Handle `rand.Read` and `WriteMessage` errors explicitly |

### Quick Wins (implementable in < 1 hour each)

1. Add `if u.Scheme != "http" { return error }` to `validateOllamaURL`
2. Change `os.Chmod(sockPath, 0660)` to `0600` in `custom.go`
3. Add `log.Printf("Warning: password may be echoed")` in fallback path
4. Define named constants for WebSocket timeouts and rate limits
5. Add `strings.TrimSpace` and length limits to Ollama error messages before SSE forwarding

### Strategic Improvements (1–4 hours each)

1. Implement `trusted_proxy_cidrs` for robust XFF handling
2. Refactor rate limiters into a generic type
3. Add integration tests for auth flow (login -> CSRF -> API -> logout)
4. Clear sensitive data from structs after use (MySQL DSN, password strings)

---

## 6. Appendix: File Inventory

### Core Backend (Go)

| File | Lines | Purpose |
|---|---|---|
| `cmd/kula/main.go` | 297 | CLI entry point, command dispatch |
| `internal/config/config.go` | 643 | Config loading, validation, defaults |
| `internal/web/server.go` | ~1100 | HTTP server, routing, middleware chain |
| `internal/web/auth.go` | 462 | Authentication, sessions, CSRF, rate limiting |
| `internal/web/websocket.go` | 207 | WebSocket handler with origin validation |
| `internal/web/ollama.go` | ~1000 | Ollama/OpenAI-compatible AI chat proxy |
| `internal/web/prometheus.go` | 688 | Prometheus metrics exposition |
| `internal/collector/collector.go` | 244 | Collector orchestrator |
| `internal/collector/custom.go` | 195 | Unix socket custom metrics |
| `internal/collector/mysql.go` | 337 | MySQL monitoring |
| `internal/collector/postgres.go` | 350 | PostgreSQL monitoring |
| `internal/collector/containers.go` | 577 | Docker/Podman container monitoring |
| `internal/collector/nginx.go` | 116 | Nginx stub_status monitoring |
| `internal/storage/store.go` | 934 | Tiered storage with aggregation |
| `internal/storage/codec.go` | ~1200 | Binary codec for efficient storage |
| `internal/sandbox/sandbox.go` | 268 | Landlock process sandboxing |

### Addons & Scripts

| File | Purpose |
|---|---|
| `scripts/nvidia-exporter.sh` | NVIDIA GPU metric exporter |
| `scripts/custom_example.py` | Custom metrics example |
| `addons/reverse_proxy.py` | Unix socket reverse proxy for testing |
| `addons/docker/` | Docker build and compose files |
| `addons/ansible/` | Ansible deployment playbook |
| `addons/init/` | Systemd, OpenRC, Runit init scripts |

---

## Scoring Breakdown

| Category | Score | Weight | Weighted |
|---|---|---|---|
| Authentication & Session Management | 8.0 | 20% | 1.60 |
| Input Validation & Injection | 7.0 | 15% | 1.05 |
| Network & Transport Security | 7.0 | 15% | 1.05 |
| Access Control & Authorization | 7.5 | 15% | 1.13 |
| Sandbox & Process Isolation | 9.0 | 10% | 0.90 |
| Cryptographic Practices | 7.5 | 10% | 0.75 |
| Error Handling & Information Disclosure | 6.5 | 10% | 0.65 |
| Code Quality & Maintainability | 8.0 | 5% | 0.40 |
| **Total** | | **100%** | **7.53** |

**Final Security Score: 7.5 / 10**  
**Final Code Quality Score: 8.0 / 10**  
**Combined: 7.75 / 10**

---

*This review was performed through static analysis of the source code at the specified commit. No dynamic testing, fuzzing, or runtime exploitation was performed. The findings represent the reviewer's best assessment at the time of review and should be validated by the project maintainers.*
