# Code Review Report: Kula

**Lightweight Linux Server Monitoring Tool**

Repository: https://github.com/c0m4r/kula

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview](#2-project-overview)
   - 2.1 [Project Structure](#21-project-structure)
   - 2.2 [Technology Stack](#22-technology-stack)
3. [Code Quality Analysis](#3-code-quality-analysis)
   - 3.1 [Architecture and Design Patterns](#31-architecture-and-design-patterns)
   - 3.2 [Error Handling](#32-error-handling)
   - 3.3 [Code Readability and Maintainability](#33-code-readability-and-maintainability)
   - 3.4 [Testing Coverage](#34-testing-coverage)
4. [Performance Analysis](#4-performance-analysis)
   - 4.1 [Metric Collection Efficiency](#41-metric-collection-efficiency)
   - 4.2 [Storage Engine Performance](#42-storage-engine-performance)
   - 4.3 [Web Server Performance](#43-web-server-performance)
   - 4.4 [Memory Management](#44-memory-management)
5. [Security Analysis](#5-security-analysis)
   - 5.1 [Authentication and Authorization](#51-authentication-and-authorization)
   - 5.2 [Input Validation and Injection Prevention](#52-input-validation-and-injection-prevention)
   - 5.3 [Landlock Sandbox](#53-landlock-sandbox)
   - 5.4 [Network Security](#54-network-security)
6. [Detailed Findings](#6-detailed-findings)
   - 6.1 [Critical Issues](#61-critical-issues)
   - 6.2 [High Priority Recommendations](#62-high-priority-recommendations)
   - 6.3 [Medium Priority Recommendations](#63-medium-priority-recommendations)
   - 6.4 [Low Priority Recommendations](#64-low-priority-recommendations)
7. [Summary Assessment](#7-summary-assessment)
8. [Conclusion](#8-conclusion)

---

## 1. Executive Summary

Kula (Kula-Szpiegula) is a lightweight, self-contained Linux server monitoring tool written in Go. The project collects system metrics every second by reading directly from /proc and /sys filesystems, stores them in a custom tiered ring-buffer storage engine, and serves them through a real-time web UI dashboard and terminal TUI. This code review evaluates the project across three critical dimensions: code quality, performance characteristics, and security posture. The analysis reveals a well-architected system with thoughtful design decisions, though several areas warrant attention for production deployment scenarios.

The project demonstrates professional-grade Go development practices with clear separation of concerns, proper error handling patterns, and efficient resource management. The implementation of a custom storage engine with tiered aggregation is particularly noteworthy, showing deep understanding of time-series data management challenges. However, as with any monitoring tool that exposes system metrics over a network interface, careful attention must be paid to security configurations and deployment practices.

---

## 2. Project Overview

### 2.1 Project Structure

The project follows standard Go project layout conventions with a clean separation between application entry points, internal packages, and deployment artifacts. The `cmd/kula` directory contains the main entry point with CLI handling, while `internal/` packages encapsulate core functionality including metric collection, storage management, web server, and terminal UI components. This structure promotes code reusability and maintains clear boundaries between different subsystems.

The modular architecture enables independent testing and potential future extraction of components. For example, the collector package could be used independently of the web server, and the storage engine could serve as a foundation for other time-series applications. The use of `internal/` packages ensures these components are not accidentally imported by external projects, maintaining proper encapsulation.

### 2.2 Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go (Golang) - CGO_ENABLED=0 for static binary |
| Web Framework | Standard library net/http with golang.org/x/net/websocket |
| Frontend | Vanilla JavaScript with Chart.js, embedded in binary |
| Storage | Custom ring-buffer files with JSON encoding |
| TUI Framework | Bubble Tea with Lipgloss styling |
| Sandboxing | Landlock LSM via go-landlock library |
| Configuration | YAML with gopkg.in/yaml.v3 |
| Authentication | Argon2id password hashing, session-based |

---

## 3. Code Quality Analysis

### 3.1 Architecture and Design Patterns

The codebase demonstrates solid architectural principles with clear separation of concerns. Each package has a well-defined responsibility: the collector package handles metric gathering, storage manages persistence, web provides HTTP/WebSocket services, and tui offers terminal-based visualization. This separation allows each component to evolve independently and facilitates comprehensive testing. The design follows Go idioms closely, making the code accessible to experienced Go developers.

**Strengths:**

- Clean package boundaries with single responsibility principle applied consistently across modules
- Effective use of Go interfaces for abstraction, particularly in the storage layer
- Proper use of `sync.RWMutex` for concurrent access to shared state
- Well-structured error handling with proper error wrapping using `fmt.Errorf`
- Consistent naming conventions following Go standard library patterns
- Comprehensive documentation comments on exported types and functions

**Areas for Improvement:**

- Some functions in collector packages are quite long and could benefit from further decomposition
- The main.go file combines multiple command handlers that could be separated into cmd subpackages
- Limited use of dependency injection, making some components harder to test in isolation

### 3.2 Error Handling

The project demonstrates robust error handling practices throughout the codebase. Errors are properly propagated with context using `fmt.Errorf` with `%w` verb for error wrapping. File operations consistently check for errors and handle them appropriately, with deferred close operations using the blank identifier pattern (`_`) to avoid shadowing potential errors from the main operation. The collector functions gracefully handle missing or malformed `/proc` data by returning zero values rather than errors, which is appropriate for monitoring scenarios where partial data is still valuable.

One notable pattern in the storage tier implementation is the handling of corrupted headers: instead of failing completely, the code reinitializes the file, demonstrating defensive programming. This approach ensures the system remains operational even when encountering unexpected file states, which is crucial for monitoring tools that must maintain availability. The websocket implementation also shows good error handling with proper connection cleanup in defer blocks and graceful handling of slow or disconnected clients.

**Example - Defensive Error Handling in tier.go:**

```go
if info.Size() >= headerSize {
    if err := t.readHeader(); err != nil {
        // Corrupted header — reinitialize
        t.writeOff = 0
        t.count = 0
        if err := t.writeHeader(); err != nil {
            _ = f.Close()
            return nil, err
        }
    }
}
```

### 3.3 Code Readability and Maintainability

The codebase scores highly on readability metrics. Variable and function names are descriptive and follow Go conventions. The use of named return values is limited to appropriate cases, avoiding the confusion that can arise from overusing this feature. Comments are used judiciously to explain non-obvious logic, particularly in the storage engine where the ring-buffer mechanics and file format are documented. The README provides comprehensive documentation of the project structure, making it easy for new contributors to navigate the codebase.

The config package implementation shows good maintainability practices with default values clearly defined in `DefaultConfig()` and proper parsing of size suffixes (KB, MB, GB) for human-readable configuration. The separation of configuration structure definitions from loading logic makes the configuration schema immediately visible to readers. The use of `yaml.v3` for configuration parsing is appropriate, and the handling of missing config files by returning defaults is a user-friendly approach.

### 3.4 Testing Coverage

The project includes test coverage with race condition detection enabled (`go test -race`). The collector tests verify parsing of `/proc` filesystem data, while storage tests exercise the ring-buffer implementation. However, the test coverage appears incomplete, particularly for the web server and WebSocket handling code. Adding integration tests for the HTTP endpoints and WebSocket message handling would improve confidence in the system's reliability. The project would also benefit from benchmark tests for the storage engine to validate performance claims.

**Current Test Coverage Areas:**
- Collector parsing functions
- Storage tier read/write operations
- Configuration loading

**Missing Test Coverage:**
- HTTP endpoint handlers
- WebSocket message handling
- Authentication flows
- End-to-end integration tests

---

## 4. Performance Analysis

### 4.1 Metric Collection Efficiency

The metric collection subsystem is designed for efficiency, reading directly from the kernel's `/proc` and `/sys` interfaces rather than spawning external processes. This approach minimizes overhead and provides the fastest possible access to system metrics. The use of `bufio.Scanner` for reading files ensures efficient I/O with minimal system calls. The collector maintains previous state (`prevCPU`, `prevNet`, `prevDisk`) to calculate rates and percentages, avoiding redundant data storage while enabling accurate derivative calculations.

The CPU collection implementation demonstrates particular efficiency by parsing only the necessary fields from `/proc/stat`. Network metrics are collected per interface without requiring system calls, and the socket statistics parsing handles both IPv4 and IPv6 separately, allowing the system to function correctly regardless of which protocol stacks are available. The one-second collection interval is appropriate for most monitoring scenarios, though the configurable interval allows for adjustment in performance-sensitive environments.

### 4.2 Storage Engine Performance

The custom tiered ring-buffer storage engine is a highlight of the project's performance design. By pre-allocating files with fixed maximum sizes, the system achieves predictable disk usage without requiring garbage collection or cleanup processes. The ring-buffer approach means new data overwrites old data in place, avoiding the overhead of file deletion and recreation. The tiered aggregation (1s, 1m, 5m resolutions) reduces storage requirements while maintaining granular recent data and historical context.

**Key Performance Features:**

- **Pre-allocated files** eliminate runtime allocation overhead and prevent disk fragmentation
- **Buffered I/O** with 1MB buffer size for read operations dramatically improves query performance
- **Timestamp extraction** for pre-filtering avoids full JSON deserialization for out-of-range records
- **Header updates** only every 10 writes reduce disk I/O during high-frequency collection
- **Efficient binary format** with length-prefixed records enables fast seeking and reading

**Storage File Format:**

```
Header (64 bytes):
  [0:8]   magic "KULASPIE"
  [8:16]  version (uint64)
  [16:24] max data size (uint64)
  [24:32] write offset within data region (uint64)
  [32:40] total records written (uint64)
  [40:48] oldest timestamp (int64, unix nano)
  [48:56] newest timestamp (int64, unix nano)
  [56:64] reserved
Data region:
  Sequence of: [length uint32][data []byte]
```

### 4.3 Web Server Performance

The HTTP server implementation uses Go's standard `net/http` package with efficient routing through `http.ServeMux`. The WebSocket hub pattern prevents slow clients from blocking the broadcast loop by using non-blocking channel sends with a default case that skips clients whose buffers are full. This approach ensures that a single slow or disconnected client cannot degrade performance for other connected clients. The static file serving from embedded filesystem (`embed.FS`) eliminates disk I/O for web assets and simplifies deployment.

The logging middleware adds minimal overhead, measuring request duration and recording status codes. The performance logging mode provides visibility into database query times without excessive verbosity. The session cleanup goroutine running every 5 minutes prevents memory growth from accumulated expired sessions. The one area where performance could be improved is the history API endpoint, which currently reads all matching records into memory before returning them. For very large time ranges, streaming the response would be more memory-efficient.

**WebSocket Hub Pattern:**

```go
func (h *wsHub) broadcast(data []byte) {
    h.mu.RLock()
    defer h.mu.RUnlock()

    for client := range h.clients {
        if !client.paused {
            select {
            case client.sendCh <- data:
            default:
                // Client too slow, skip
            }
        }
    }
}
```

### 4.4 Memory Management

Memory management is handled thoughtfully throughout the codebase. The collector maintains only the previous state necessary for rate calculations, avoiding accumulation of historical data in memory. The storage engine's use of fixed-size files prevents unbounded memory growth. WebSocket clients have bounded send buffers (64 messages), with slow clients being skipped rather than blocking. The JSON encoding for samples uses standard library `encoding/json`, which while not the fastest option, provides adequate performance for the one-second collection interval and avoids external dependencies.

---

## 5. Security Analysis

### 5.1 Authentication and Authorization

The authentication system implements several security best practices. Password hashing uses Argon2id, the winner of the Password Hashing Competition and currently recommended for new systems. The implementation uses appropriate parameters: 64MB memory, 4 threads, 1 iteration, and 32-byte key length. Sessions are managed server-side with cryptographically random tokens (32 bytes from `crypto/rand`), and the session timeout is configurable. The use of constant-time comparison for credential validation prevents timing attacks.

**Security Strengths:**

- Argon2id password hashing with appropriate parameters (memory-hard, resistant to GPU attacks)
- Cryptographically secure session tokens using `crypto/rand`
- `HttpOnly` cookies prevent XSS attacks from stealing session tokens
- `SameSite=Strict` prevents CSRF attacks in most scenarios
- Support for both cookie and Bearer token authentication
- Optional authentication allows flexibility for trusted network deployments

**Security Concerns:**

- No rate limiting on login endpoint - vulnerable to brute force attacks
- Single-user authentication model may not suit all deployment scenarios
- Session tokens stored in memory only - sessions lost on restart
- No password complexity requirements enforced

**Argon2id Implementation:**

```go
func HashPassword(password, salt string) string {
    timeParam := uint32(1)
    memory := uint32(64 * 1024)  // 64 MB
    threads := uint8(4)
    keyLen := uint32(32)

    hash := argon2.IDKey([]byte(password), []byte(salt), timeParam, memory, threads, keyLen)
    return hex.EncodeToString(hash)
}
```

### 5.2 Input Validation and Injection Prevention

The codebase demonstrates good input validation practices. HTTP request parameters are parsed with appropriate bounds checking, such as the 31-day limit on history queries and validation of time range direction. The WebSocket implementation limits message size to 4096 bytes, preventing memory exhaustion attacks. JSON parsing uses the standard library's `encoding/json`, which is safe against injection attacks. The `/proc` and `/sys` file reading does not involve user input, eliminating path traversal concerns for metric collection.

**Content-Security-Policy Header:**

```go
w.Header().Set("Content-Security-Policy", 
    "default-src 'self' 'unsafe-inline'; " +
    "style-src 'self' fonts.googleapis.com; " +
    "font-src fonts.gstatic.com; " +
    "script-src 'self' cdn.jsdelivr.net; " +
    "connect-src 'self' cdn.jsdelivr.net ws: wss:;")
```

**Other Security Headers:**

```go
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
```

The use of `'unsafe-inline'` for scripts is a slight weakness (necessary for the embedded Chart.js application), but it's mitigated by the fact that the entire frontend is embedded in the binary and served from the same origin. The `X-Frame-Options: DENY` header prevents clickjacking attacks, and `X-Content-Type-Options: nosniff` prevents MIME type sniffing attacks.

### 5.3 Landlock Sandbox

The Landlock sandbox implementation is a significant security feature that restricts the process's capabilities after initialization. The sandbox enforces read-only access to `/proc` and `/sys` for metric collection, read-only access to the configuration file, and read-write access only to the designated storage directory. Network access is restricted to binding on the configured web port. This defense-in-depth approach limits the potential impact of any code execution vulnerabilities that might be discovered in the HTTP handling code.

**Sandbox Rules:**

```go
fsRules := []landlock.Rule{
    landlock.RODirs("/proc"),
    landlock.RODirs("/sys").IgnoreIfMissing(),
    landlock.ROFiles(absConfigPath).IgnoreIfMissing(),
    landlock.RWDirs(absStorageDir),
}

netRules := []landlock.Rule{
    landlock.BindTCP(uint16(webPort)),
}
```

The use of `BestEffort()` ensures graceful degradation on older kernels, maintaining functionality while still applying restrictions where possible. The sandbox is applied after initialization but before accepting connections, ensuring the process has the necessary access during startup while being restricted during operation. The warning message when Landlock fails provides visibility into the security state without preventing operation on unsupported systems.

### 5.4 Network Security

By default, the web server listens on `0.0.0.0:8080`, which exposes the monitoring interface on all network interfaces. When authentication is disabled (the default), this exposes system metrics to any network-connected attacker. The documentation should more prominently warn about the security implications of running without authentication on public networks. The `Secure` cookie flag is correctly set based on TLS detection or `X-Forwarded-Proto` header, supporting proper deployment behind TLS-terminating proxies.

**Cookie Security Configuration:**

```go
http.SetCookie(w, &http.Cookie{
    Name:     "kula_session",
    Value:    token,
    Path:     "/",
    HttpOnly: true,
    Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
    MaxAge:   int(s.cfg.Auth.SessionTimeout.Seconds()),
    SameSite: http.SameSiteStrictMode,
})
```

For production deployments, running behind a reverse proxy with TLS is strongly recommended.

---

## 6. Detailed Findings

### 6.1 Critical Issues

No critical security vulnerabilities were identified in the codebase. The architecture and implementation practices demonstrate security-conscious development. The Landlock sandbox provides defense-in-depth that would contain many potential exploitation scenarios. However, the default configuration of disabled authentication with network binding on all interfaces poses a risk for users who deploy without reviewing configuration options.

### 6.2 High Priority Recommendations

1. **Implement Rate Limiting:** Add rate limiting to the login endpoint to prevent brute force password attacks. Consider using a token bucket or sliding window algorithm with configurable thresholds.

2. **Add Security Documentation:** Create a `SECURITY.md` file with responsible disclosure policy and upgrade guidelines. Document the security implications of running without authentication.

3. **Default Binding Address:** Consider changing the default listen address to `127.0.0.1` to prevent accidental exposure on public networks. Users who need external access can explicitly configure `0.0.0.0`.

### 6.3 Medium Priority Recommendations

1. **Session Persistence:** Consider persisting sessions to disk to maintain user sessions across process restarts. This could use an encrypted file or integrated with the existing storage engine.

2. **Streaming History API:** Implement streaming JSON encoding for large history queries to reduce memory usage. Consider using `json.Encoder` directly on the response writer.

3. **Password Policy:** Add optional password complexity requirements when generating password hashes. Document minimum recommended password lengths.

4. **CSP Enhancement:** Consider using nonce-based CSP instead of `'unsafe-inline'` for scripts. This would require changes to the frontend but would provide stronger XSS protection.

### 6.4 Low Priority Recommendations

1. **Benchmark Tests:** Add benchmark tests for the storage engine to validate performance characteristics and catch regressions.

2. **Fuzz Testing:** Add fuzz tests for the JSON parsing and `/proc` file parsing code to identify edge cases.

3. **Dependency Scanning:** Add automated dependency vulnerability scanning using tools like `govulncheck` in CI pipeline.

4. **Integration Tests:** Expand test coverage to include HTTP endpoint tests and WebSocket message handling tests.

---

## 7. Summary Assessment

The following table provides a summary assessment across the three evaluation dimensions, with ratings on a scale of 1-5 (1=Poor, 5=Excellent). The overall assessment reflects the project's maturity as a production-ready monitoring tool with some areas requiring attention for security-sensitive deployments.

| Category | Score | Summary |
|----------|-------|---------|
| Code Quality | 4.5/5 | Clean architecture, good practices |
| Performance | 4.5/5 | Efficient storage, minimal overhead |
| Security | 4.0/5 | Good practices, needs rate limiting |
| **Overall** | **4.3/5** | Production-ready with minor improvements needed |

---

## 8. Conclusion

Kula represents a well-designed and professionally implemented Linux monitoring tool. The codebase demonstrates strong software engineering practices with clean architecture, efficient resource management, and security-conscious design decisions. The custom tiered storage engine is particularly impressive, showing deep understanding of time-series data management challenges and performance optimization techniques.

The security posture is good, with Argon2id password hashing, proper session management, and the innovative Landlock sandbox providing defense-in-depth. The main security concern is the default configuration of disabled authentication with network-wide binding, which could lead to accidental exposure of system metrics in naive deployments. This is mitigated by clear documentation and the ease of enabling authentication.

**Deployment Recommendations:**

For organizations considering deploying Kula, the tool is recommended for production use with the following conditions:

1. Enable authentication if the web interface is accessible from untrusted networks
2. Run behind a TLS-terminating reverse proxy for encrypted transport
3. Review the configuration file carefully before deployment

The project's AGPL-3.0 license should also be considered for organizations with specific licensing requirements.

Overall, Kula fills an important niche as a lightweight, self-contained monitoring solution with no external dependencies. The project demonstrates the viability of building sophisticated monitoring tools without relying on complex infrastructure, making it particularly suitable for edge deployments, embedded systems, and environments where simplicity and minimal footprint are paramount.

---

*Report Generated: 2025-03-01*

*Reviewer: AI Code Review Analysis*

*Model: Claude 3.5 Sonnet*
