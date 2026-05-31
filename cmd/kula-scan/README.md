# kula-scan

**Active, black-box safeguard scanner for a running Kula instance.**

Where the unit tests, fuzz targets, and in-process runtime tests
([`internal/web/runtime_security_test.go`](../../internal/web/runtime_security_test.go))
verify Kula's defenses *in the lab*, `kula-scan` verifies them *in the field*: it
points at a live Kula URL and probes it over HTTP/WebSocket the way an attacker or a
browser would, then reports — per check — whether each safeguard actually holds in the
deployed configuration (behind your proxy, with your TLS, your base path, your config).

It imports nothing from Kula's `internal/` packages. Every assertion is made over the
wire, so it complements the in-tree tests rather than duplicating them.

```
go build -o kula-scan ./cmd/kula-scan
./kula-scan http://localhost:27960
```

`kula-scan` is a developer/operator tool. It is **not** built into the release binary or
Docker image (those build only `./cmd/kula/`), but it lives in the same module, so
`go vet ./...` and `go test ./...` cover it.

## Usage

```
kula-scan [flags] <target-url>
```

| Flag | Meaning |
|------|---------|
| `-username`, `-password` | Credentials to unlock authenticated checks (login, CSRF token, WebSocket auth). Optional. |
| `-base-path` | Base path if Kula is mounted under one (e.g. `/kula`). Auto-detected from a path in the target URL. |
| `-timeout` | Per-request timeout (default `10s`). |
| `-insecure` | Skip TLS certificate verification (self-signed test instances). |
| `-aggressive` | Enable disruptive checks (see below). |
| `-only` | Comma-separated categories to run: `auth,csrf,cors,headers,traversal,metrics,ws,input,rate`. |
| `-fail-on` | Minimum FAIL severity that forces a non-zero exit: `info\|low\|medium\|high\|critical` (default `high`). |
| `-json` | Emit findings as JSON. |
| `-no-color` | Disable ANSI colors (auto-disabled when stdout is not a TTY or `NO_COLOR` is set). |
| `-v` | Verbose: print each request/response. |

### Examples

```bash
# Quick non-destructive scan
kula-scan http://localhost:27960

# Full authenticated scan over TLS
kula-scan -username admin -password 'hunter2' https://mon.example.com

# Only header / traversal / CORS checks
kula-scan -only headers,traversal,cors http://10.0.0.5:27960

# Include disruptive checks (rate-limit + connection floods)
kula-scan -aggressive -username admin -password 'hunter2' http://localhost:27960

# Machine-readable output for CI
kula-scan -json https://mon.example.com > report.json
```

### Exit status

- `0` — no failing safeguard at or above `-fail-on`.
- `1` — one or more safeguards FAIL at or above `-fail-on` (the IDs are printed).
- `2` — usage error (bad flag, unreachable target).

This makes `kula-scan` usable as a release/CI gate: stand up the instance, scan it, fail
the build if a safeguard regressed.

## What each status means

- **PASS** — the safeguard is present and behaves as expected.
- **FAIL** — the safeguard is missing or bypassable (a real finding).
- **WARN** — a weak/risky posture that may be an intentional config choice (e.g. auth
  disabled, `origin_validation` off, `/metrics` without a token, plaintext HTTP).
- **SKIP** — the check did not apply (feature disabled, no credentials supplied, or an
  aggressive check without `-aggressive`).
- **ERROR** — the probe itself could not complete (network/parse error).

## Check categories

| Category | What it probes | Maps to |
|----------|----------------|---------|
| `headers` | `X-Content-Type-Options`, `X-Frame-Options`, CSP (`default-src 'self'`, nonce, `frame-ancestors`), **per-request nonce freshness**, `Referrer-Policy`, `Permissions-Policy`, HSTS over TLS, banner disclosure | `securityMiddleware` |
| `auth` | Protected routes return 401 anonymously; forged cookies & bearer tokens rejected; login is POST-only; session cookie `HttpOnly`/`SameSite`/`Secure`; **username-enumeration resistance** | `AuthMiddleware`, `ValidateCredentials` |
| `csrf` | Origin/Referer required on state change; cross-origin POST blocked; CSRF synchronizer token enforced on authenticated sessions | `CSRFMiddleware` |
| `cors` | An arbitrary Origin is **not** reflected; never `ACAO: *` + credentials; `Vary: Origin` present | `corsMiddleware` |
| `traversal` | Byte-level path-traversal payloads (encoded, dot-dot, backslash) over a raw socket leak no files; no directory listing | `handleStatic` |
| `metrics` | `/metrics` bearer token enforced (and wrong token rejected); warns if exposed without a token | `handleMetrics` |
| `ws` | Unauthenticated upgrade rejected; cross-origin upgrade rejected (CSWSH); same-origin upgrade allowed | `handleWebSocket`, `CheckOrigin` |
| `input` | `/api/history` bad/inverted/over-long ranges → 400, huge `points` capped; `/api/i18n` rejects junk/traversal language codes | `handleHistory`, `handleI18n` |
| `rate` *(aggressive)* | Login brute-force throttling; Ollama rate limiting | login `RateLimiter`, Ollama limiter |

## Safety / `-aggressive`

The default scan is **non-destructive and idempotent**: it reads headers, sends a handful
of single-shot probes, and logs in at most a few times when credentials are supplied.

`-aggressive` adds checks that have **real side effects on the live target** and only run
with the flag (a warning is printed first):

- **`RATE-LOGIN`** — a burst of failed logins to confirm throttling. This **locks out
  login from your IP for ~5 minutes**.
- **`WS-FLOOD`** — opens more than the per-IP WebSocket limit to confirm the cap fires.
- **`INPUT-AGG`** — an oversized login body to confirm the `MaxBytesReader` cap.

Run `-aggressive` against staging, or accept the temporary lockout on production.

## How it works

- A `Scanner` (see [`scanner.go`](scanner.go)) holds an `http.Client` with **no cookie jar**
  (cookies are set explicitly per probe) that does **not** follow redirects, so 301/401/403
  responses are observed directly.
- Path-traversal payloads are sent over a **raw TCP/TLS socket** with a verbatim request
  line, bypassing any client-side URL normalization (mirrors the `rawRequest` helper in the
  runtime tests).
- WebSocket probes use `github.com/gorilla/websocket` — the same library the server uses.
- Checks live in [`checks.go`](checks.go), [`checks_ws.go`](checks_ws.go), and
  [`checks_aggressive.go`](checks_aggressive.go); the report/exit logic is in
  [`report.go`](report.go). Classification is unit-tested against secure and insecure mock
  servers in [`checks_test.go`](checks_test.go).
