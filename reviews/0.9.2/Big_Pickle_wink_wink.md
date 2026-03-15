# Kula Security Code Review Report

## Project Overview
- **Project Name**: Kula - Lightweight Linux Server Monitor
- **Language**: Go (backend) + JavaScript (frontend)
- **Module**: `kula-szpiegula`
- **Dependencies**: 9 direct, minimal attack surface

---

## Executive Summary

| Category | Rating |
|----------|--------|
| **Overall Security** | **8.2/10** |
| Code Quality | 8.0/10 |
| Performance | 8.5/10 |
| Security Controls | 8.0/10 |

The project demonstrates **good security practices** overall with defense-in-depth measures including Landlock sandboxing, Argon2id password hashing, CSRF protection, and comprehensive security headers. However, several improvements can strengthen the security posture.

---

## Security Findings

### MEDIUM Severity

#### 2. Rate Limiter Map Growth
**Location**: `internal/web/auth.go:71-91`
```go
func (rl *RateLimiter) Allow(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    // ... no upper bound check on map size
    rl.attempts[ip] = append(recent, now)
}
```
**Issue**: Unbounded map growth during attack - entries are only cleaned in CleanupSessions every 5 minutes.
**Risk**: Memory exhaustion DoS via login endpoint.
**Recommendation**: Add max entries limit or cleanup more frequently.

#### 3. X-Forwarded-For Trust Model
**Location**: `internal/web/server.go:638-653`
```go
if trustProxy {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return strings.TrimSpace(parts[len(parts)-1])
    }
}
```
**Issue**: When `trust_proxy: true`, last IP in X-Forwarded-For chain is trusted. If not behind proper reverse proxy, client can spoof IPs.
**Risk**: IP-based rate limiting bypass, session hijacking.
**Recommendation**: Document requirement that Kula must be behind trusted reverse proxy.

#### 4. WebSocket Origin Check Bypass
**Location**: `internal/web/websocket.go:24-48`
```go
CheckOrigin: func(r *http.Request) bool {
    // ...
    if u.Host != r.Host {
        return false
    }
    return true
}
```
**Issue**: Only checks Host header - doesn't verify protocol (HTTP vs HTTPS).
**Risk**: Minor - limited to same-origin policies.

---

### LOW Severity

#### 5. Information Disclosure in Error Messages
**Location**: `internal/web/server.go:410`
```go
jsonError(w, err.Error(), http.StatusInternalServerError)
```
**Issue**: Internal error messages may leak implementation details.
**Recommendation**: Use generic error messages in production.

#### 6. No HTTPS Enforcement
**Location**: `internal/web/server.go:502-510`
**Issue**: Server doesn't enforce HTTPS; relies on reverse proxy or user configuration.
**Risk**: Session hijacking, credential theft on HTTP.
**Recommendation**: Add HTTP-to-HTTPS redirect when TLS detected.

#### 7. External API Call on Landing Page
**Location**: `landing/landing.js:75`
```javascript
const resp = await fetch('https://api.github.com/repos/c0m4r/kula');
```
**Issue**: Client makes external network request to GitHub API.
**Risk**: Privacy leak (IP exposed to GitHub), dependency on external service.
**Recommendation**: Move to server-side or remove star counter.

#### 8. Console Version Disclosure
**Location**: `internal/web/static/app.js:1894-1899`
```javascript
console.log('%c K U L A %c v' + cfg.version ...
```
**Issue**: Version exposed in browser console.
**Risk**: Reconnaissance for targeted exploits.

---

## Security Controls Assessment

### Authentication & Session Management ✅ GOOD
- Argon2id with configurable parameters
- Session tokens: 32-byte random, SHA-256 hashed
- Session binding: IP + UserAgent fingerprint
- Sliding expiration
- Secure cookies: `HttpOnly`, `Secure`, `SameSiteStrictMode`

### Authorization ✅ GOOD
- Auth middleware on protected routes
- CSRF validation via Origin/Referer check
- Per-route and global WebSocket limits

### Input Validation ✅ GOOD
- JSON body size limit: 4096 bytes
- Query parameter validation (time ranges, points)
- Max 31-day query window
- Points capped at 5000

### Security Headers ✅ EXCELLENT
- `X-Content-Type- Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` with nonces
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` (geolocation, mic, camera blocked)

### Sandboxing ✅ GOOD
- Landlock filesystem restrictions
- Read-only /proc, /sys
- Read-write storage directory only
- TCP bind restricted to web port

### WebSocket Security ✅ GOOD
- Origin validation against Host header
- Read limit: 4096 bytes
- Ping/Pong keepalive
- Per-IP connection limits

### Data Storage ⚠️ PARTIAL
- Binary format (safe from injection)
- File permissions: 0600
- Sessions stored as JSON

---

## Performance Observations

### Strengths
- Efficient tiered storage with in-memory caching
- WebSocket broadcast with channel buffering
- Compression support (gzip)
- Query downsampling for large ranges

### Concerns
- Default collection interval: 1 second (high CPU)
- Unbounded data structures: wsIPCounts map

---

## Code Quality Issues

### Potential Issues
1. **Panic recovery missing** in `handleWebSocket` read pump
2. **No graceful degradation** if Landlock unavailable (handled via BestEffort)
3. **No input sanitization** in config parsing - relies on YAML library safety

---

## Recommendations Summary

| Priority | Recommendation |
|----------|----------------|
| **P1** | Add rate limiter map size bounds |
| **P1** | Document trust_proxy requirements |
| **P2** | Add HTTPS enforcement redirect |
| **P2** | Remove GitHub API call from landing |
| **P2** | Sanitize error messages in API |
| **P3** | Remove console version disclosure |

---

## Conclusion

Kula demonstrates **solid security engineering** with defense-in-depth across authentication, session management, authorization, and sandboxing. The codebase is well-structured with proper error handling and input validation.

Overall, the security posture is **production-ready** with minor hardening recommended for high-security environments.
