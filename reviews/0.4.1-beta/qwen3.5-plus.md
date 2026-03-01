# 🔮 Kula-Szpiegula Security & Code Quality Review

**Repository:** https://github.com/c0m4r/kula  
**Review Date:** March 02, 2026  
**Version Reviewed:** 0.4.1-beta (main branch)  
**Reviewer:** Security Expert & Professional Code Reviewer

---

## Executive Summary

Kula-Szpiegula is a well-architected, lightweight Linux server monitoring tool written primarily in Go with a JavaScript/HTML frontend. The project demonstrates **strong security awareness** with several excellent practices implemented, though there are areas requiring attention before production deployment.

| Category | Score | Status |
|----------|-------|--------|
| **Security** | 7.5/10 | ⚠️ Good with Concerns |
| **Code Quality** | 8.5/10 | ✅ Very Good |
| **Performance** | 8.0/10 | ✅ Good |
| **Maintainability** | 8.0/10 | ✅ Good |

---

## 1. Security Assessment

### 1.1 ✅ Positive Security Findings

#### Authentication & Session Management
- **Argon2id Password Hashing**: Uses industry-standard Argon2id with appropriate parameters (time=1, memory=64MB, threads=4, keyLen=32)
  ```go
  hash := argon2.IDKey([]byte(password), []byte(salt), timeParam, memory, threads, keyLen)
  ```
- **Constant-Time Comparison**: Uses `crypto/subtle.ConstantTimeCompare` for credential validation, preventing timing attacks
- **Secure Session Tokens**: 32-byte cryptographically random tokens via `crypto/rand`
- **HttpOnly & Secure Cookies**: Session cookies properly configured with security flags
  ```go
  http.SetCookie(w, &http.Cookie{
      Name:     "kula_session",
      HttpOnly: true,
      Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
      SameSite: http.SameSiteStrictMode,
  })
  ```
- **Session Expiration & Cleanup**: Automatic cleanup of expired sessions via background goroutine

#### HTTP Security Headers
```go
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; ...")
```

#### Input Validation
- **Time Range Limits**: API enforces maximum 31-day query window
- **WebSocket Payload Limits**: `conn.MaxPayloadBytes = 4096` prevents memory exhaustion
- **Config Size Parsing**: Validates storage tier sizes with unit checking

#### Linux Security Features
- **Landlock LSM Integration**: Implements filesystem and network sandboxing (graceful degradation on unsupported kernels)
  ```go
  if err := sandbox.Enforce(configPath, cfg.Storage.Directory, cfg.Web.Port); err != nil {
      log.Printf("Warning: Landlock sandbox not enforced: %v", err)
  }
  ```

#### File Permissions
- Storage tier files created with `0600` permissions (owner read/write only)
  ```go
  f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
  ```

---

### 1.2 ⚠️ Security Concerns & Recommendations

#### CRITICAL: External CDN Dependencies (XSS Risk)
**Issue:** Frontend loads Chart.js and other libraries from external CDNs
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
```

**Risk:** Supply chain attacks, MITM if CDN compromised, CSP bypass potential

**Recommendation:**
```diff
- <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
+ <script src="/static/vendor/chart.min.js" integrity="sha384-..."></script>
```
- Vendor all JavaScript dependencies into the embedded static FS
- Add Subresource Integrity (SRI) hashes
- Update CSP to remove `cdn.jsdelivr.net` from `script-src`

---

#### HIGH: Insufficient Input Sanitization in TUI
**Issue:** Hostname and user data from `/proc` displayed without sanitization in terminal UI

**Risk:** If an attacker can influence `/proc` data (container escape, procfs manipulation), could inject escape sequences

**Recommendation:**
```go
// Add sanitization for terminal output
func sanitizeForTerminal(s string) string {
    return strings.Map(func(r rune) rune {
        if r < 32 && r != '\t' && r != '\n' && r != '\r' {
            return -1 // Remove control characters
        }
        return r
    }, s)
}
```

---

#### HIGH: Password in Memory
**Issue:** Password hash and salt stored in config struct in plaintext memory

**Risk:** Memory dumps could expose credentials

**Recommendation:**
- Use `[]byte` with `runtime.KeepAlive` for sensitive data
- Consider using a secrets management integration for production
- Zero out password buffers after use

---

#### MEDIUM: Missing Rate Limiting
**Issue:** No rate limiting on `/api/login` endpoint

**Risk:** Brute force attacks against authentication

**Recommendation:**
```go
// Add simple rate limiting
type loginAttempt struct {
    count   int
    lastTry time.Time
}
var loginAttempts = make(map[string]*loginAttempt)

func rateLimitLogin(ip string) bool {
    // Implement exponential backoff after N failures
}
```

---

#### MEDIUM: Information Disclosure via Error Messages
**Issue:** Some error messages reveal internal state
```go
http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
```

**Recommendation:** Log detailed errors server-side, return generic messages to clients

---

#### MEDIUM: No HTTPS Enforcement
**Issue:** Application runs on HTTP by default; HTTPS only detected via `X-Forwarded-Proto`

**Recommendation:**
- Add configuration option to require HTTPS
- Consider built-in TLS support with ACME/Let's Encrypt
- Document reverse proxy TLS termination requirements

---

#### LOW: Missing Security Logging
**Issue:** Failed login attempts not logged with sufficient detail for security monitoring

**Recommendation:**
```go
log.Printf("[SECURITY] Failed login attempt for user=%s from IP=%s", username, clientIP)
```

---

#### LOW: No Audit Trail
**Issue:** No logging of configuration changes or administrative actions

**Recommendation:** Add audit logging for security-sensitive operations

---

### 1.3 Security Checklist

| Control | Status | Notes |
|---------|--------|-------|
| Authentication | ✅ | Argon2id, secure sessions |
| Authorization | ✅ | Middleware-based |
| Input Validation | ⚠️ | Good but needs CDN mitigation |
| Output Encoding | ⚠️ | TUI needs sanitization |
| Session Management | ✅ | Secure cookies, expiration |
| Error Handling | ⚠️ | Some info disclosure |
| Logging | ⚠️ | Needs security event logging |
| Dependencies | ⚠️ | External CDN risk |
| Cryptography | ✅ | Argon2id, crypto/rand |
| Network Security | ⚠️ | No rate limiting |

---

## 2. Code Quality Assessment

### 2.1 ✅ Strengths

#### Architecture & Design
- **Clean Separation of Concerns**: Well-organized package structure (`collector`, `storage`, `web`, `tui`, `config`)
- **Interface Design**: Good use of Go interfaces where appropriate
- **Dependency Injection**: Server components properly injected rather than global state

#### Code Style
- **Consistent Formatting**: Follows Go conventions
- **Meaningful Names**: Variables and functions well-named
- **Comments**: Adequate documentation for complex logic

#### Error Handling
```go
if err != nil {
    return nil, fmt.Errorf("opening tier %d: %w", i, err)
}
```
- Proper error wrapping with context
- Graceful degradation patterns

#### Testing
- Unit tests present for storage and config packages
- Test files follow Go conventions (`*_test.go`)

---

### 2.2 ⚠️ Areas for Improvement

#### Missing Input Validation
**Issue:** Config parsing could be more robust
```go
func parseSize(s string) (int64, error) {
    var val float64
    var unit string
    _, err := fmt.Sscanf(s, "%f%s", &val, &unit)
    // ...
}
```

**Recommendation:** Add bounds checking for configuration values (min/max storage sizes, port ranges)

---

#### Resource Leaks Potential
**Issue:** Some file handles could leak on error paths
```go
f, err := os.Open("/proc/stat")
if err != nil {
    return nil
}
defer func() { _ = f.Close() }()
```

**Status:** Actually well-handled with deferred closes, but consider using `context` for cancellation

---

#### Concurrency Patterns
**Issue:** WebSocket hub uses channel-based communication but could benefit from context cancellation
```go
func (h *wsHub) run() {
    for {
        select {
        case client := <-h.regCh:
            // ...
        }
    }
}
```

**Recommendation:** Add context.Context for graceful shutdown

---

#### Magic Numbers
**Issue:** Several unexplained constants
```go
const maxSamples = 3600
const recordSize = 384  // utmp record size
```

**Recommendation:** Add comments explaining the source/rationale

---

#### Code Duplication
**Issue:** Similar parsing patterns in collector package could be abstracted

**Recommendation:** Consider a generic `/proc` file parser helper

---

### 2.3 Code Quality Metrics

| Metric | Assessment |
|--------|------------|
| Cyclomatic Complexity | Low-Medium (well-structured) |
| Code Coverage | Unknown (tests exist but coverage not reported) |
| Documentation | Good (README, inline comments) |
| Consistency | High |
| Technical Debt | Low |

---

## 3. Performance Assessment

### 3.1 ✅ Strengths

#### Efficient Data Collection
- Direct `/proc` and `/sys` reads (no external dependencies)
- Delta calculations for rates (CPU, network, disk)
- Buffered I/O for storage reads
  ```go
  br := bufio.NewReaderSize(sr, 1024*1024)  // 1MB buffer
  ```

#### Storage Engine
- **Ring-buffer design**: Predictable, bounded disk usage
- **Tiered aggregation**: Reduces query load for historical data
- **Pre-allocation**: No dynamic growth overhead

#### WebSocket Optimization
- Non-blocking send with buffer drop for slow clients
  ```go
  select {
  case client.sendCh <- data:
  default:
      // Client too slow, skip
  }
  ```

#### Frontend Performance
- Chart.js animations disabled for performance
  ```javascript
  Chart.defaults.animation = false;
  ```
- Batch chart updates instead of per-sample
- Efficient data buffer management (max 3600 samples)

---

### 3.2 ⚠️ Optimization Opportunities

#### Memory Usage
**Issue:** All historical samples kept in memory buffer
```javascript
maxBufferSize: 3600, // 1 hour of 1s data
```

**Recommendation:** Consider streaming large history queries

---

#### JSON Serialization Overhead
**Issue:** Full JSON encode/decode for every sample
```go
func encodeSample(s *AggregatedSample) ([]byte, error) {
    return json.Marshal(s)
}
```

**Recommendation:** Consider binary encoding (msgpack, protobuf) for storage tier

---

#### Query Performance
**Issue:** Full scan of ring buffer for time range queries

**Recommendation:** Add timestamp index for faster range queries

---

### 3.3 Performance Checklist

| Aspect | Status | Notes |
|--------|--------|-------|
| CPU Efficiency | ✅ | Direct /proc reads |
| Memory Usage | ⚠️ | Buffer could grow |
| Disk I/O | ✅ | Buffered, ring-buffer |
| Network | ✅ | WebSocket streaming |
| Frontend | ✅ | Optimized rendering |

---

## 4. Detailed Findings by Component

### 4.1 Authentication Module (`internal/web/auth.go`)

| Finding | Severity | Status |
|---------|----------|--------|
| Argon2id implementation | ✅ | Excellent |
| Constant-time comparison | ✅ | Correct |
| Session management | ✅ | Secure |
| Missing rate limiting | 🔴 | HIGH |
| Password in memory | 🟡 | MEDIUM |

---

### 4.2 Storage Engine (`internal/storage/`)

| Finding | Severity | Status |
|---------|----------|--------|
| Ring-buffer design | ✅ | Excellent |
| File permissions (0600) | ✅ | Secure |
| Header validation | ✅ | Magic string check |
| JSON for binary storage | 🟡 | MEDIUM (performance) |
| No encryption at rest | 🟡 | MEDIUM (compliance) |

---

### 4.3 Web Server (`internal/web/server.go`)

| Finding | Severity | Status |
|---------|----------|--------|
| Security headers | ✅ | Good |
| Auth middleware | ✅ | Proper |
| CSP configuration | 🟡 | MEDIUM (CDN) |
| Error handling | 🟡 | MEDIUM (info disclosure) |
| No rate limiting | 🔴 | HIGH |

---

### 4.4 Collectors (`internal/collector/`)

| Finding | Severity | Status |
|---------|----------|--------|
| /proc parsing | ✅ | Efficient |
| Delta calculations | ✅ | Correct |
| Error handling | ✅ | Graceful |
| TUI sanitization | 🔴 | HIGH |
| No input bounds | 🟡 | LOW |

---

### 4.5 Frontend (`internal/web/static/`)

| Finding | Severity | Status |
|---------|----------|--------|
| CDN dependencies | 🔴 | CRITICAL |
| No SRI hashes | 🔴 | HIGH |
| CSP violations | 🟡 | MEDIUM |
| Input validation | ✅ | Good |
| XSS protection | ⚠️ | Partial |

---

## 5. Recommendations Summary

### Immediate (Before Production)

1. **🔴 CRITICAL**: Vendor all JavaScript dependencies, remove CDN links
2. **🔴 HIGH**: Add rate limiting to login endpoint
3. **🔴 HIGH**: Sanitize TUI output for control characters
4. **🟡 MEDIUM**: Add security event logging
5. **🟡 MEDIUM**: Generic error messages to clients

### Short-term (Next Release)

6. Add HTTPS enforcement option
7. Implement audit logging
8. Add configuration validation bounds
9. Consider binary storage encoding
10. Add context.Context for graceful shutdown

### Long-term

11. Consider secrets management integration
12. Add encryption at rest for stored metrics
13. Implement metrics export (Prometheus, etc.)
14. Add comprehensive security test suite
15. Consider formal security audit

---

## 6. Conclusion

Kula-Szpiegula demonstrates **strong security fundamentals** with proper authentication, secure session management, and thoughtful use of Linux security features (Landlock). The code quality is high with clean architecture and good Go practices.

**Primary concerns** center around external CDN dependencies (supply chain risk) and missing rate limiting. These should be addressed before any production deployment, especially if the dashboard will be exposed to untrusted networks.

**Overall Assessment:** This is a well-engineered monitoring tool that, with the recommended fixes, would be suitable for production use in security-conscious environments.

---

## Appendix A: Security Testing Recommendations

```bash
# 1. Dependency audit
go list -m all | grep -v "=>"

# 2. Static analysis
golangci-lint run --enable-all

# 3. Security scanning
gosec ./...

# 4. Fuzzing (for parsers)
go test -fuzz=FuzzParseProcStat ./internal/collector/

# 5. Penetration testing
# - Test authentication bypass
# - Test WebSocket injection
# - Test path traversal in static files
# - Test CSRF (if forms added)
```

---

## Appendix B: Secure Configuration Template

```yaml
# config.secure.yaml
web:
  listen: "127.0.0.1"  # Bind to localhost only
  port: 8080
  auth:
    enabled: true
    session_timeout: 1h  # Shorter sessions for sensitive environments
  
storage:
  directory: "/var/lib/kula/data"
  # Consider encryption at rest for sensitive environments

# Deploy behind reverse proxy with TLS termination
# Use fail2ban for rate limiting at network level
```

---

**Report Generated:** March 02, 2026  
**Review Scope:** Full codebase review (Go backend + JavaScript frontend)  
**Next Review Recommended:** After implementing critical fixes
