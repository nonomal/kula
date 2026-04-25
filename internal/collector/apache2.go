package collector

import (
	"io"
	"net/http"
	"strconv"
	"strings"
)

// apache2Raw holds the raw cumulative counters from mod_status ?auto.
type apache2Raw struct {
	totalAccesses uint64
	totalKBytes   uint64
}

// collectApache2 fetches the Apache2 mod_status ?auto page and parses it.
// Returns nil on any error (server down, bad format, etc.) — non-fatal.
//
// Expected ?auto format (key-value pairs):
//
//	Total Accesses: 1234
//	Total kBytes: 5678
//	CPULoad: .12345
//	Uptime: 12345
//	ReqPerSec: .1
//	BytesPerSec: 470.7
//	BytesPerReq: 4707.21
//	BusyWorkers: 3
//	IdleWorkers: 7
//	Scoreboard: _W___R___................................................
func (c *Collector) collectApache2(elapsed float64) *Apache2Stats {
	if c.apacheClient == nil {
		c.apacheClient = &http.Client{Timeout: c.collCfg.Interval}
	}

	resp, err := c.apacheClient.Get(c.appCfg.Apache2.StatusURL)
	if err != nil {
		c.appErrorf("[apache2] fetch error: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.appErrorf("[apache2] unexpected status: %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		c.debugf("[apache2] read error: %v", err)
		return nil
	}

	c.debugf("[apache2] status body: %s", string(body))
	return c.parseApache2Status(string(body), elapsed)
}

// parseApache2Status parses the Apache2 mod_status ?auto key-value format
// and computes per-second rates using the previous raw counters.
func (c *Collector) parseApache2Status(body string, elapsed float64) *Apache2Stats {
	stats := &Apache2Stats{}
	lines := strings.Split(body, "\n")

	var scoreboard string
	scoreboardActive := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			if scoreboardActive {
				scoreboard += line
			}
			continue
		}

		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])

		if key == "Scoreboard" {
			scoreboardActive = true
			scoreboard += val
			continue
		}

		scoreboardActive = false

		switch key {
		case "BusyWorkers":
			if v, err := strconv.Atoi(val); err == nil {
				stats.BusyWorkers = v
			}
		case "IdleWorkers":
			if v, err := strconv.Atoi(val); err == nil {
				stats.IdleWorkers = v
			}
		case "Total Accesses":
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				stats.TotalAccesses = v
			}
		case "Total kBytes":
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				stats.TotalKBytes = v
			}
		case "ReqPerSec":
			stats.ReqPerSec = parseFloatQuiet(val)
		case "BytesPerSec":
			stats.BytesPerSec = parseFloatQuiet(val)
		case "BytesPerReq":
			stats.BytesPerReq = parseFloatQuiet(val)
		case "CPULoad":
			stats.CPULoad = parseFloatQuiet(val)
		case "Uptime":
			if v, err := strconv.ParseInt(val, 10, 64); err == nil {
				stats.Uptime = v
			}
		}
	}

	// Compute per-second rates from cumulative deltas
	cur := apache2Raw{
		totalAccesses: stats.TotalAccesses,
		totalKBytes:   stats.TotalKBytes,
	}
	if c.prevApache.totalAccesses > 0 && elapsed > 0 {
		if cur.totalAccesses >= c.prevApache.totalAccesses {
			stats.AccessesPS = round2(float64(cur.totalAccesses-c.prevApache.totalAccesses) / elapsed)
		}
		if cur.totalKBytes >= c.prevApache.totalKBytes {
			stats.KBytesPS = round2(float64(cur.totalKBytes-c.prevApache.totalKBytes) / elapsed)
		}
	}
	c.prevApache = cur

	// Count Scoreboard worker states
	if scoreboard != "" {
		for _, ch := range scoreboard {
			switch ch {
			case '_':
				stats.Waiting++
			case 'R':
				stats.Reading++
			case 'W':
				stats.Sending++
			case 'K':
				stats.Keepalive++
			}
		}
	}

	c.debugf("[apache2] parsed: busy=%d idle=%d accesses=%d kbytes=%d rps=%.2f bps=%.2f waiting=%d reading=%d sending=%d keepalive=%d",
		stats.BusyWorkers, stats.IdleWorkers, stats.TotalAccesses, stats.TotalKBytes,
		stats.ReqPerSec, stats.BytesPerSec, stats.Waiting, stats.Reading, stats.Sending, stats.Keepalive)

	if stats.TotalAccesses == 0 && stats.BusyWorkers == 0 && stats.IdleWorkers == 0 {
		return nil
	}

	return stats
}

// parseFloatQuiet parses a float64 from a string, returning 0 on failure.
func parseFloatQuiet(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if vv, e2 := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64); e2 == nil {
			return vv
		}
		return 0
	}
	return v
}
