package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRuleSummary(t *testing.T) {
	summary := BuildRuleSummary("/etc/kula/config.yaml", "/var/lib/kula", 27960)

	// Should contain all expected components
	expected := []string{
		"/proc[ro]",
		"/sys[ro]",
		"/etc/kula/config.yaml[ro]",
		"/var/lib/kula[rw]",
		"bind TCP/27960",
	}
	for _, want := range expected {
		if !containsSubstring(summary, want) {
			t.Errorf("BuildRuleSummary() = %q, missing %q", summary, want)
		}
	}
}

func TestBuildRuleSummaryRelativePaths(t *testing.T) {
	// Relative paths should be resolved to absolute
	summary := BuildRuleSummary("config.yaml", "./data", 9090)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	absConfig := filepath.Join(cwd, "config.yaml")
	absData := filepath.Join(cwd, "data")

	if !containsSubstring(summary, absConfig+"[ro]") {
		t.Errorf("BuildRuleSummary() = %q, missing absolute config path %q", summary, absConfig)
	}
	if !containsSubstring(summary, absData+"[rw]") {
		t.Errorf("BuildRuleSummary() = %q, missing absolute storage path %q", summary, absData)
	}
}

func TestBuildRuleSummaryDifferentPorts(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{80, "bind TCP/80"},
		{443, "bind TCP/443"},
                {9090, "bind TCP/9090"},
		{27960, "bind TCP/27960"},
	}

	for _, tt := range tests {
		summary := BuildRuleSummary("/etc/kula/config.yaml", "/var/lib/kula", tt.port)
		if !containsSubstring(summary, tt.want) {
			t.Errorf("BuildRuleSummary(port=%d) = %q, missing %q", tt.port, summary, tt.want)
		}
	}
}

// NOTE: We don't test Enforce() directly here because Landlock enforcement
// is process-wide and irreversible — it would sandbox the test runner itself,
// preventing cleanup of temporary directories. The Enforce() function is
// tested implicitly by running `kula serve` and observing the log output.

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
