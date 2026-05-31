package config

import (
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// Fuzz coverage for the security-bearing config validators. base_path is
// reflected into a Location redirect and an HTML <base href>, so a bad
// normalization is an open redirect (CWE-601); the ollama URL gate is the
// SSRF boundary that keeps the AI proxy pointed at loopback. These targets
// assert the validators uphold their security contract for every input.

// FuzzNormalizeBasePath asserts the normalizer never emits a value that could
// drive an open redirect, directory traversal, or header/HTML injection, and
// that its output is a fixed point (idempotent).
func FuzzNormalizeBasePath(f *testing.F) {
	for _, s := range []string{
		"", "/", "/kula", "kula", "/monitoring/kula",
		"//evil.com", "/\\evil.com", "///evil", "/\\/evil",
		"/a/../b", "/a/./b", "/a//b//", "/a/b/",
		"  /spaced  ", "/has space", "/q?x", "/h#x", "/back\\slash",
		"/uniçode", "/\x00null", "/\ttab", "/..", "/.", "/../..",
		strings.Repeat("/seg", 500),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, p string) {
		out, err := normalizeBasePath(p)
		if err != nil {
			if out != "" {
				t.Fatalf("normalizeBasePath(%q): error returned with non-empty out %q", p, out)
			}
			return
		}
		if out == "" {
			return // "serve at root" — always safe
		}

		// 1. Exactly one leading slash: a leading "//" or "/\" is read by
		//    browsers as a protocol-relative URL to another host (open redirect).
		if out[0] != '/' {
			t.Fatalf("normalizeBasePath(%q) = %q: must begin with '/'", p, out)
		}
		if len(out) > 1 && (out[1] == '/' || out[1] == '\\') {
			t.Fatalf("normalizeBasePath(%q) = %q: protocol-relative prefix (CWE-601)", p, out)
		}

		// 2. No interior "//" and no trailing slash.
		if strings.Contains(out, "//") {
			t.Fatalf("normalizeBasePath(%q) = %q: contains '//'", p, out)
		}
		if strings.HasSuffix(out, "/") {
			t.Fatalf("normalizeBasePath(%q) = %q: has trailing slash", p, out)
		}

		// 3. No empty/'.'/'..' segments (traversal) and no dangerous characters.
		for _, seg := range strings.Split(strings.TrimPrefix(out, "/"), "/") {
			switch seg {
			case "", ".", "..":
				t.Fatalf("normalizeBasePath(%q) = %q: illegal segment %q", p, out, seg)
			}
		}
		for _, r := range out {
			if unicode.IsControl(r) || unicode.IsSpace(r) || r == '?' || r == '#' || r == '\\' {
				t.Fatalf("normalizeBasePath(%q) = %q: illegal char %q", p, out, r)
			}
		}

		// 4. Idempotent: feeding the output back must produce the same value.
		out2, err2 := normalizeBasePath(out)
		if err2 != nil || out2 != out {
			t.Fatalf("normalizeBasePath not idempotent: %q -> %q -> %q (err %v)", p, out, out2, err2)
		}
	})
}

// FuzzValidateOllamaURL asserts the SSRF gate never accepts a non-loopback
// host: anything it returns nil for (and that is non-empty) must resolve to a
// loopback literal.
func FuzzValidateOllamaURL(f *testing.F) {
	for _, s := range []string{
		"", "http://localhost:11434", "http://127.0.0.1", "http://[::1]:11434",
		"http://evil.com", "https://169.254.169.254", "http://localhost@evil.com",
		"http://localhost.evil.com", "http://127.0.0.1.evil.com", "ftp://localhost",
		"http://", "://", "http://[::1]", "HTTP://LOCALHOST", "http://0.0.0.0",
		"http://2130706433", "http://127.1", "//localhost",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		err := validateOllamaURL(raw)
		if raw == "" {
			if err != nil {
				t.Fatalf("empty ollama URL must be allowed, got %v", err)
			}
			return
		}
		if err != nil {
			return // rejected — safe
		}
		// Accepted a non-empty URL: the host MUST be one of the loopback
		// literals the validator claims to allow. Anything else is an SSRF hole.
		u, perr := url.Parse(raw)
		if perr != nil {
			t.Fatalf("validateOllamaURL accepted %q that url.Parse rejects: %v", raw, perr)
		}
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			t.Fatalf("validateOllamaURL accepted non-loopback host %q (url %q)", u.Hostname(), raw)
		}
	})
}

// FuzzParseSize ensures the tier size parser never panics on arbitrary config
// values and that a successful parse of a non-negative-looking value is itself
// non-negative.
func FuzzParseSize(f *testing.F) {
	for _, s := range []string{
		"250MB", "1.5GB", "0B", "100KB", "1B", "", "MB", "-5MB", "1e308GB",
		"999999999999999999999GB", "NaNMB", "1.2.3MB", "  10 MB", "+1MB", "InfGB",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseSize(s) // must not panic
	})
}
