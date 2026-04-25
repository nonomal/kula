package collector

import (
	"context"
	"encoding/json"
	"kula/internal/config"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNginxCollector(t *testing.T) {
	// Mock Nginx stub_status output
	stubOutput := `Active connections: 291 
server accepts handled requests
 16630948 16630948 31070465 
Reading: 6 Writing: 179 Waiting: 106 
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stubOutput))
	}))
	defer server.Close()

	c := &Collector{
		nginxClient: &http.Client{},
		appCfg: config.ApplicationsConfig{
			Nginx: config.NginxConfig{
				Enabled:   true,
				StatusURL: server.URL,
			},
		},
	}

	stats := c.collectNginx(1.0)
	if stats == nil {
		t.Fatal("Expected stats, got nil")
	}

	if stats.ActiveConnections != 291 {
		t.Errorf("Expected ActiveConnections 291, got %d", stats.ActiveConnections)
	}
	if stats.Reading != 6 || stats.Writing != 179 || stats.Waiting != 106 {
		t.Errorf("Unexpected R/W/W: %d/%d/%d", stats.Reading, stats.Writing, stats.Waiting)
	}

	// Test malformed output
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not nginx output"))
	}))
	defer badServer.Close()

	c.appCfg.Nginx.StatusURL = badServer.URL
	stats = c.collectNginx(1.0)
	if stats != nil {
		t.Error("Expected nil stats for malformed output")
	}
}

func TestApache2Collector(t *testing.T) {
	stubOutput := `Total Accesses: 1234
Total kBytes: 5678
CPULoad: .12345
Uptime: 12345
ReqPerSec: .1
BytesPerSec: 470.7
BytesPerReq: 4707.21
BusyWorkers: 3
IdleWorkers: 7
Scoreboard: _W___R___K...............................................
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stubOutput))
	}))
	defer server.Close()

	c := &Collector{
		apacheClient: &http.Client{},
		appCfg: config.ApplicationsConfig{
			Apache2: config.Apache2Config{
				Enabled:   true,
				StatusURL: server.URL,
			},
		},
	}

	stats := c.collectApache2(1.0)
	if stats == nil {
		t.Fatal("Expected stats, got nil")
	}

	if stats.BusyWorkers != 3 {
		t.Errorf("Expected BusyWorkers 3, got %d", stats.BusyWorkers)
	}
	if stats.IdleWorkers != 7 {
		t.Errorf("Expected IdleWorkers 7, got %d", stats.IdleWorkers)
	}
	if stats.TotalAccesses != 1234 {
		t.Errorf("Expected TotalAccesses 1234, got %d", stats.TotalAccesses)
	}
	if stats.TotalKBytes != 5678 {
		t.Errorf("Expected TotalKBytes 5678, got %d", stats.TotalKBytes)
	}
	if stats.ReqPerSec != 0.1 {
		t.Errorf("Expected ReqPerSec 0.1, got %f", stats.ReqPerSec)
	}
	if stats.BytesPerSec != 470.7 {
		t.Errorf("Expected BytesPerSec 470.7, got %f", stats.BytesPerSec)
	}
	if stats.Uptime != 12345 {
		t.Errorf("Expected Uptime 12345, got %d", stats.Uptime)
	}
	// Scoreboard: _ (waiting), W (sending), R (reading), K (keepalive), . (open slot, ignored)
	if stats.Waiting < 1 || stats.Reading < 1 || stats.Sending < 1 || stats.Keepalive < 1 {
		t.Errorf("Expected non-zero scoreboard states: W=%d R=%d S=%d K=%d",
			stats.Waiting, stats.Reading, stats.Sending, stats.Keepalive)
	}

	// Test malformed output returns nil
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not apache output"))
	}))
	defer badServer.Close()

	c.appCfg.Apache2.StatusURL = badServer.URL
	stats = c.collectApache2(1.0)
	if stats != nil {
		t.Error("Expected nil stats for malformed output")
	}

	// Test empty scoreboard still produces valid stats
	noSB := `BusyWorkers: 1
IdleWorkers: 5
`
	noSBServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(noSB))
	}))
	defer noSBServer.Close()

	c.appCfg.Apache2.StatusURL = noSBServer.URL
	c.prevApache = apache2Raw{} // reset
	stats = c.collectApache2(1.0)
	if stats == nil {
		t.Fatal("Expected stats without scoreboard, got nil")
	}
	if stats.BusyWorkers != 1 || stats.IdleWorkers != 5 {
		t.Errorf("Expected 1 busy, 5 idle; got %d, %d", stats.BusyWorkers, stats.IdleWorkers)
	}

	// Test multi-line scoreboard (e.g. large MPM event config)
	multiSB := `BusyWorkers: 2
IdleWorkers: 10
Scoreboard: _W__R__K__...............................................
_________W_______R___________________K__________________.............
`
	multiSBServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(multiSB))
	}))
	defer multiSBServer.Close()

	c.appCfg.Apache2.StatusURL = multiSBServer.URL
	c.prevApache = apache2Raw{} // reset
	stats = c.collectApache2(1.0)
	if stats == nil {
		t.Fatal("Expected stats with multi-line scoreboard, got nil")
	}
	// Should count workers across BOTH scoreboard lines
	if stats.Waiting < 2 || stats.Reading < 2 || stats.Sending < 2 || stats.Keepalive < 2 {
		t.Errorf("Multi-line scoreboard undercounted: W=%d R=%d S=%d K=%d (all should be >= 2)",
			stats.Waiting, stats.Reading, stats.Sending, stats.Keepalive)
	}

	// Test counter reset (service restart): previous counters are high,
	// current counters reset to 0 — should NOT produce insane rates.
	c.appCfg.Apache2.StatusURL = server.URL
	c.prevApache = apache2Raw{totalAccesses: 50000000, totalKBytes: 100000000}
	resetOutput := `Total Accesses: 100
Total kBytes: 200
`
	resetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resetOutput))
	}))
	defer resetServer.Close()
	c.appCfg.Apache2.StatusURL = resetServer.URL
	stats = c.collectApache2(1.0)
	if stats == nil {
		t.Fatal("Expected stats after counter reset, got nil")
	}
	if stats.AccessesPS != 0 || stats.KBytesPS != 0 {
		t.Errorf("Expected 0 PS after counter reset, got AccessesPS=%g KBytesPS=%g",
			stats.AccessesPS, stats.KBytesPS)
	}
}

func TestNginxCollectorCounterReset(t *testing.T) {
	stubOutput := `Active connections: 1 
server accepts handled requests
 100 100 200 
Reading: 0 Writing: 1 Waiting: 0 
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stubOutput))
	}))
	defer server.Close()

	c := &Collector{
		nginxClient: &http.Client{},
		appCfg: config.ApplicationsConfig{
			Nginx: config.NginxConfig{
				Enabled:   true,
				StatusURL: server.URL,
			},
		},
		prevNginx: nginxRaw{accepts: 50000000, handled: 50000000, requests: 100000000},
	}

	stats := c.collectNginx(1.0)
	if stats == nil {
		t.Fatal("Expected stats after nginx counter reset, got nil")
	}
	if stats.AcceptsPS != 0 || stats.HandledPS != 0 || stats.RequestsPS != 0 {
		t.Errorf("Expected 0 PS after nginx counter reset, got A=%g H=%g R=%g",
			stats.AcceptsPS, stats.HandledPS, stats.RequestsPS)
	}
}

func TestPostgresCollectorMath(t *testing.T) {
	pc := &postgresCollector{
		prev: pgRaw{
			xactCommit: 100,
			blksRead:   50,
			blksHit:    50,
		},
	}

	cur := pgRaw{
		xactCommit: 150,
		blksRead:   60,
		blksHit:    140,
	}

	stats := &PostgresStats{}
	pc.calculateStats(stats, cur, 10.0) // 10 seconds elapsed

	if stats.TxCommitPS != 5.0 { // (150-100)/10
		t.Errorf("Expected 5.0 TPS, got %.2f", stats.TxCommitPS)
	}
	if stats.BlksHitPct != 70.0 { // 140 / (60+140) * 100
		t.Errorf("Expected 70%% hit ratio, got %.2f", stats.BlksHitPct)
	}
}

func TestPostgresDSN(t *testing.T) {
	// TCP
	pc1 := newPostgresCollector("localhost", 5432, "user", "pass", "db", "disable", false, time.Second)
	if !strings.Contains(pc1.dsn, "host=localhost") || !strings.Contains(pc1.dsn, "port=5432") {
		t.Errorf("Unexpected TCP DSN: %s", pc1.dsn)
	}

	// Unix socket
	pc2 := newPostgresCollector("/var/run/postgresql", 0, "user", "", "db", "disable", false, time.Second)
	if !strings.Contains(pc2.dsn, "host=/var/run/postgresql") || strings.Contains(pc2.dsn, "port=") {
		t.Errorf("Unexpected Unix DSN: %s", pc2.dsn)
	}
}

func TestCustomCollector(t *testing.T) {
	sockPath := "/tmp/kula_test.sock"
	defer func() { _ = os.Remove(sockPath) }()

	cfg := map[string][]config.CustomMetricConfig{
		"fans": {
			{Name: "fan1", Unit: "RPM", Max: 5000},
		},
	}

	cc, err := newCustomCollector(context.Background(), sockPath, cfg, false)
	if err != nil {
		t.Fatalf("Failed to create custom collector: %v", err)
	}
	defer cc.Close()

	// Send valid metric
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	
	msg := map[string]any{
		"custom": map[string]any{
			"fans": []map[string]any{
				{"fan1": 1234},
			},
		},
	}
	_ = json.NewEncoder(conn).Encode(msg)
	_ = conn.Close()

	// Busy wait for processing (since acceptLoop is async)
	var latest map[string][]CustomMetricValue
	for i := 0; i < 20; i++ {
		latest = cc.Latest()
		if len(latest) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(latest["fans"]) == 0 {
		t.Fatal("No metrics received")
	}
	if latest["fans"][0].Value != 1234 {
		t.Errorf("Expected 1234, got %.2f", latest["fans"][0].Value)
	}
}
