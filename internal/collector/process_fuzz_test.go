package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzCollectProcessesStat drives the per-PID /proc/<pid>/stat parser with
// arbitrary stat-file contents.
//
// The comm field (field 2) is attacker-influenced: any local user can exec a
// process whose name contains ')' , spaces, or — on some kernels — newlines,
// which is precisely why the parser keys off the *last* ')'. A malformed or
// hostile stat record must not panic, because the per-second Collect() loop
// runs with no recover(): a single panic here takes down the whole monitoring
// agent (local denial of service).
func FuzzCollectProcessesStat(f *testing.F) {
	f.Add([]byte("1 (systemd) S 0 1 1 0 -1 4194560 12345 0 0 0 100 200 0 0 20 0 1 0 5 170000000 2000 184\n"))
	f.Add([]byte("42 (a) b) c) R 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 9 0 0\n")) // comm with embedded ')'
	f.Add([]byte("7 (kworker/0:1) D 2 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 1 0 0"))
	f.Add([]byte("1 () S 0 0"))                                       // empty comm
	f.Add([]byte("1 (x)"))                                            // nothing after the comm
	f.Add([]byte("1 (x) "))                                           // only a space after the comm
	f.Add([]byte("1 (x) Z"))                                          // state present, nothing else
	f.Add([]byte("1 (x)\n\n"))                                        // newline-led remainder (empty first token)
	f.Add([]byte("1 (weird\n) S 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 2 0")) // newline inside comm
	f.Add([]byte(""))                                                 // empty file
	f.Add([]byte(")"))                                                // bare paren
	f.Add([]byte("123 no parens at all here"))

	// Point procPath at a temp tree with one numeric PID dir for the whole run;
	// each iteration just rewrites that PID's stat file. collectProcesses reads
	// it via a raw syscall, so a real on-disk file is required.
	dir := f.TempDir()
	pidDir := filepath.Join(dir, "1")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		f.Fatal(err)
	}
	statPath := filepath.Join(pidDir, "stat")

	orig := procPath
	procPath = dir
	f.Cleanup(func() { procPath = orig })

	f.Fuzz(func(t *testing.T, stat []byte) {
		if err := os.WriteFile(statPath, stat, 0o644); err != nil {
			t.Fatal(err)
		}
		_ = collectProcesses() // must not panic
	})
}
