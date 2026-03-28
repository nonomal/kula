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
