package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// randToken returns n random hex characters, used to build unique throwaway
// usernames/origins so probes don't collide with real data on the target.
func randToken(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "0000000000"[:n]
	}
	return hex.EncodeToString(b)[:n]
}

// jsonString JSON-encodes s into a quoted string literal, safely escaping any
// metacharacters so crafted usernames can't break out of the request body.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// containsFold reports whether any element of vals equals target (case-insensitively).
func containsFold(vals []string, target string) bool {
	for _, v := range vals {
		// Vary may pack multiple tokens into one header value ("Origin, Accept").
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), target) {
				return true
			}
		}
	}
	return false
}

// cloneHeader returns a shallow copy of h (or a fresh header when h is nil) so a
// probe can add an Origin without mutating a shared header map.
func cloneHeader(h http.Header) http.Header {
	out := http.Header{}
	for k, vs := range h {
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	return out
}

// statusOf renders a response status for evidence strings, tolerating nil.
func statusOf(resp *http.Response) string {
	if resp == nil {
		return "<no response>"
	}
	return resp.Status
}
