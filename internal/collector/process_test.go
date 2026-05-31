package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCollectProcessesEdgeCases exercises the readdir + raw-read path on a
// synthetic /proc: a normal PID, a numeric PID directory whose stat has
// vanished (the process exited between the readdir and the open — a real race
// on a live system), and non-numeric entries that must be ignored without a
// syscall. Total counts every numeric entry (matching the prior os.ReadFile
// behaviour where Total++ happened before the read could fail), while state and
// thread counts only reflect PIDs whose stat was readable.
func TestCollectProcessesEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// PID 100: running, 5 threads (num_threads is field 20 → token 17 after ')').
	mustWriteStat(t, dir, "100",
		"100 (worker) R 1 100 100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 5 0 0\n")
	// PID 200: directory exists but stat is gone (exited mid-scan).
	if err := os.MkdirAll(filepath.Join(dir, "200"), 0o755); err != nil {
		t.Fatal(err)
	}
	// PID 300: sleeping, comm containing spaces and a ')' to stress the
	// LastIndexByte split. 1 thread.
	mustWriteStat(t, dir, "300",
		"300 (od) ev) S 1 300 300 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 0\n")
	// Non-numeric entries must be skipped entirely.
	mustWriteStat(t, dir, "self", "999 (kula) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 9 0 0\n")
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal: 1 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procPath
	procPath = dir
	defer func() { procPath = orig }()

	ps := collectProcesses()

	if ps.Total != 3 { // 100, 200, 300 are numeric; self/meminfo are not
		t.Errorf("Total = %d, want 3", ps.Total)
	}
	if ps.Running != 1 {
		t.Errorf("Running = %d, want 1 (only PID 100)", ps.Running)
	}
	if ps.Sleeping != 1 {
		t.Errorf("Sleeping = %d, want 1 (only PID 300)", ps.Sleeping)
	}
	if ps.Threads != 6 { // 5 (PID 100) + 1 (PID 300); 200 unreadable, self ignored
		t.Errorf("Threads = %d, want 6", ps.Threads)
	}
}

func mustWriteStat(t *testing.T, root, pid, content string) {
	t.Helper()
	pdir := filepath.Join(root, pid)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "stat"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
