package collector

import (
	"bytes"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// procReadBufSize is large enough to hold any /proc/<pid>/stat record in a
// single read: comm is capped at 16 bytes (TASK_COMM_LEN) and the line carries
// ~50 small space-separated integers, so the record never approaches this
// size. procfs returns the whole record in one read when the buffer fits.
const procReadBufSize = 2048

func collectProcesses() ProcessStats {
	ps := ProcessStats{}

	d, err := os.Open(procPath)
	if err != nil {
		return ps
	}
	// Readdirnames returns just the entry names — it skips both the per-entry
	// DirEntry allocation and the sort that os.ReadDir pays for, neither of
	// which is needed to merely count process states.
	names, err := d.Readdirnames(-1)
	_ = d.Close()
	if err != nil {
		return ps
	}

	// A single buffer, reused across every PID, replaces the fresh allocation
	// os.ReadFile makes per file. Reading with a raw syscall also skips the
	// size-probing Stat that os.ReadFile performs — pointless on /proc, which
	// always reports size 0 — and the *os.File that os.Open allocates per PID.
	var buf [procReadBufSize]byte

	for _, name := range names {
		// Only numeric directories are PIDs. Non-numeric entries (meminfo,
		// self, …) are skipped without a syscall.
		if _, err := strconv.ParseInt(name, 10, 64); err != nil {
			continue
		}

		ps.Total++

		// Read /proc/[pid]/stat once. It carries both the process state and the
		// thread count (num_threads, field 20), so the per-process os.ReadDir on
		// /proc/[pid]/task — a second syscall plus a DirEntry slice allocation for
		// every process — is not needed. On hosts running thousands of processes
		// this roughly halves the syscalls of the heaviest collector.
		n, ok := readProcStat(procPath+"/"+name+"/stat", buf[:])
		if !ok {
			continue
		}
		data := buf[:n]

		// The comm field (field 2) may contain spaces and parentheses, so the
		// fields we need follow the final ')': field 3 = state, field 20 =
		// num_threads, i.e. tokens 0 and 17 of the remainder.
		idx := bytes.LastIndexByte(data, ')')
		if idx < 0 || idx+2 >= len(data) {
			continue
		}
		rest := data[idx+2:]

		fieldIdx := 0
		pos := 0
		for pos < len(rest) {
			for pos < len(rest) && rest[pos] == ' ' {
				pos++
			}
			if pos >= len(rest) {
				break
			}
			start := pos
			for pos < len(rest) && rest[pos] != ' ' && rest[pos] != '\n' {
				pos++
			}
			field := rest[start:pos]
			if len(field) == 0 {
				// An empty token only occurs when the token scan stopped on a
				// '\n' with nothing after it — the end of the single-line stat
				// record. The state/thread-count fields, if present, are already
				// captured, so stop here rather than index field[0] out of range
				// on a truncated or malformed record (which would panic and, with
				// no recover() in the Collect loop, crash the agent).
				break
			}

			switch fieldIdx {
			case 0:
				switch field[0] {
				case 'R':
					ps.Running++
				case 'S':
					ps.Sleeping++
				case 'D':
					ps.Blocked++
				case 'Z':
					ps.Zombie++
				}
			case 17:
				ps.Threads += int(parseUintBytes(field))
			}
			if fieldIdx == 17 {
				break // state and thread count captured; skip the rest of the line
			}
			fieldIdx++
		}
	}

	return ps
}

// readProcStat reads the /proc stat file at path into buf with a single read
// syscall, returning the number of bytes read. ok is false if the file can't be
// opened (e.g. the process exited between the readdir and the open) or yields
// no data. Using the raw syscall avoids the *os.File allocation and the
// size-probing Stat that os.ReadFile would incur on every PID each second.
func readProcStat(path string, buf []byte) (n int, ok bool) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false
	}
	for {
		n, err = unix.Read(fd, buf)
		if err != unix.EINTR {
			break
		}
	}
	_ = unix.Close(fd)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}
