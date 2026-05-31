// Command kula-scan is an active, black-box safeguard scanner for a running
// kula instance. It probes a live target over HTTP/WebSocket the way an
// attacker or browser would and reports, per check, whether each security
// safeguard actually holds: authentication gating, CSRF/origin validation,
// CORS, security headers, path-traversal defenses, the Prometheus token,
// WebSocket origin/auth/connection gates, and input/DoS caps.
//
// It imports nothing from kula's internal packages — every assertion is made
// over the wire against a deployed configuration, so it complements (rather
// than duplicates) the in-process runtime tests.
//
// Usage:
//
//	kula-scan [flags] <target-url>
//
// Exit status is non-zero when any safeguard FAILs at or above -fail-on
// severity (default high), so it can gate CI / releases.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("kula-scan", flag.ContinueOnError)
	fs.Usage = func() { printUsage(fs.Output()) }

	var (
		target     = fs.String("target", "", "target base URL, e.g. http://localhost:27960 (or pass as positional arg)")
		username   = fs.String("username", "", "username for authenticated checks (optional)")
		password   = fs.String("password", "", "password for authenticated checks (optional)")
		basePath   = fs.String("base-path", "", "base path if kula is mounted under one, e.g. /kula")
		timeout    = fs.Duration("timeout", 10*time.Second, "per-request timeout")
		insecure   = fs.Bool("insecure", false, "skip TLS certificate verification")
		aggressive = fs.Bool("aggressive", false, "enable disruptive checks (login lockout, WS/connection floods)")
		only       = fs.String("only", "", "comma-separated categories to run (auth,csrf,cors,headers,traversal,metrics,ws,input,rate)")
		failOn     = fs.String("fail-on", "high", "min FAIL severity for non-zero exit: info|low|medium|high|critical")
		asJSON     = fs.Bool("json", false, "emit findings as JSON")
		noColor    = fs.Bool("no-color", false, "disable ANSI colors")
		verbose    = fs.Bool("v", false, "verbose: print each request/response")
	)

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	tgt := *target
	if tgt == "" && fs.NArg() > 0 {
		tgt = fs.Arg(0)
	}
	if tgt == "" {
		fmt.Fprintln(os.Stderr, "error: no target URL given")
		printUsage(os.Stderr)
		return 2
	}

	failSev, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: invalid -fail-on %q (want info|low|medium|high|critical)\n", *failOn)
		return 2
	}

	onlySet := parseOnly(*only)

	scanner, err := NewScanner(tgt, *basePath, *username, *password, *timeout, *insecure, *aggressive, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	useColor := !*noColor && !*asJSON && colorEnabled()

	if *aggressive && !*asJSON {
		fmt.Fprintln(os.Stderr, banner(useColor,
			"AGGRESSIVE MODE: this will lock out login from your IP for ~5 min and open many WebSocket connections on the target."))
	}

	findings := scanner.Run(onlySet)
	report := newReport(scanner.urlFor(""), findings)

	if *asJSON {
		if err := report.writeJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
			return 2
		}
	} else {
		report.writeText(os.Stdout, !useColor)
		if ids := report.failingIDs(failSev); len(ids) > 0 {
			fmt.Printf("\nFAILING safeguards at/above %s: %s\n", failSev, strings.Join(ids, ", "))
		}
	}

	return report.exitCode(failSev)
}

// parseOnly turns a comma list into a set; empty input means "all categories".
func parseOnly(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	set := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			set[p] = true
		}
	}
	return set
}

// colorEnabled reports whether ANSI colors should be used: honors NO_COLOR and
// only colorizes when stdout is a character device (a terminal).
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func banner(color bool, msg string) string {
	if color {
		return cYellow + cBold + "⚠ " + msg + cReset
	}
	return "WARNING: " + msg
}

func printUsage(w interface{ Write([]byte) (int, error) }) {
	fmt.Fprint(w, `kula-scan — active safeguard scanner for a running kula instance

Usage:
  kula-scan [flags] <target-url>

Examples:
  kula-scan http://localhost:27960
  kula-scan -username admin -password secret https://mon.example.com
  kula-scan -only headers,traversal,cors http://10.0.0.5:27960
  kula-scan -aggressive -username admin -password secret http://localhost:27960
  kula-scan -json http://localhost:27960 > report.json

Flags:
  -target string      target base URL (or pass as positional arg)
  -username string    username for authenticated checks
  -password string    password for authenticated checks
  -base-path string   base path if kula is mounted under one (e.g. /kula)
  -timeout duration   per-request timeout (default 10s)
  -insecure           skip TLS certificate verification
  -aggressive         enable disruptive checks (login lockout, WS/connection floods)
  -only string        comma-separated categories: auth,csrf,cors,headers,traversal,metrics,ws,input,rate
  -fail-on string     min FAIL severity for non-zero exit: info|low|medium|high|critical (default high)
  -json               emit findings as JSON
  -no-color           disable ANSI colors
  -v                  verbose request/response logging

Exit status: 0 = no failing safeguard at/above -fail-on; 1 = one or more failures; 2 = usage error.
`)
}
