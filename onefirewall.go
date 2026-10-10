package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ctiAPIKey is OneFirewall's authorization key. Reporting is a pure
// no-op everywhere below unless this is set - nothing here ever calls
// out to a third party by default.
var ctiAPIKey = os.Getenv("CTI_API_KEY")

// oneFirewallOutput returns a writer that watches every log line this
// app produces for the "[T1234 Name | Category]" bracket this
// codebase's MITRE tagging consistently emits (mitre.go's web-request
// classifier, and every fake-service handler's own log lines), and
// reports the source IP to OneFirewall's threat-intel API when it finds
// one. Returns (nil, "") if CTI_API_KEY isn't set.
func oneFirewallOutput() (io.Writer, string) {
	if ctiAPIKey == "" {
		return nil, ""
	}
	return &oneFirewallWriter{}, "onefirewall-cti"
}

var mitreTagPattern = regexp.MustCompile(`\[(T\d+(?:\.\d+)?)\s+[^|]+\|\s*([^\]]+)\]`)

type oneFirewallWriter struct{}

// Write is called once per log.Printf/Print/Println, same as
// syslogWriter - it never blocks on the actual HTTP call (that happens
// in a background goroutine via reportToOneFirewall), so this can't add
// latency to the request/connection path that triggered the log line.
func (w *oneFirewallWriter) Write(p []byte) (int, error) {
	line := string(p)
	m := mitreTagPattern.FindStringSubmatch(line)
	if m != nil {
		code := strings.TrimSpace(m[1])
		category := strings.TrimSpace(m[2])
		if ip := leadingIP(line); ip != "" {
			reportToOneFirewall(ip, code, category, strings.TrimSpace(line))
		}
	}
	return len(p), nil
}

// leadingIP pulls the first host:port (or bare IP) token out of a log
// line - every log.Printf call site in this codebase starts with
// r.RemoteAddr or conn.RemoteAddr(), both "ip:port" - and returns just
// the host part. Returns "" if nothing in the line parses as an IP
// (startup/status lines, for instance), so those are never reported.
func leadingIP(line string) string {
	for _, field := range strings.Fields(line) {
		host, _, err := net.SplitHostPort(field)
		if err != nil {
			host = field
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// mitreConfidence maps a MITRE technique to how confident we are that
// touching it reflects deliberate malicious intent rather than
// incidental traffic. An actual exploitation payload (SQLi, Log4Shell,
// command injection, ...) scores highest; merely connecting to a fake
// service nothing legitimate should ever reach (T1133) scores lower -
// suspicious on its own, but not proof of intent the way a live payload
// is. Anything not listed falls back to a middling 0.5.
var mitreConfidence = map[string]float64{
	"T1552.005": 0.95, // cloud instance metadata API
	"T1552.001": 0.9,  // credentials in files
	"T1098":     0.85, // account manipulation
	"T1499":     0.85, // endpoint DoS (ReDoS probe)
	"T1059.007": 0.9,  // XSS
	"T1059":     0.9,  // command injection / Shellshock
	"T1190":     0.95, // SQLi / SSTI / Log4Shell / Spring4Shell / XXE / NoSQLi
	"T1005":     0.85, // path traversal / data from local system
	"T1110":     0.7,  // brute force
	"T1213":     0.7,  // data from information repositories
	"T1595.002": 0.6,  // active scanning
	"T1133":     0.5,  // connected to an exposed service, nothing more
	"T1087":     0.75, // account discovery (VRFY, ISAPI user enum)
	"T1078.001": 0.8,  // default/weak credentials accepted
	"T1040":     0.6,  // plaintext credential interception risk
	"T1018":     0.85, // remote system discovery (DNS AXFR)
	"T1498.002": 0.9,  // reflection amplification probe
	"T1496":     0.9,  // resource hijacking (LLMjacking)
	"T1565.001": 0.6,  // unauthenticated printer access
}

func confidenceForCode(code string) float64 {
	if v, ok := mitreConfidence[code]; ok {
		return v
	}
	return 0.5
}

// reportCooldown bounds how often the same IP gets reported, so one
// scan burst (which can generate hundreds of tagged log lines in
// seconds) doesn't hammer OneFirewall's API or spin up hundreds of
// outbound goroutines.
const reportCooldown = 5 * time.Minute

var (
	reportedMu sync.Mutex
	reportedAt = map[string]time.Time{}
)

func init() {
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			cutoff := time.Now().Add(-2 * reportCooldown)
			reportedMu.Lock()
			for ip, t := range reportedAt {
				if t.Before(cutoff) {
					delete(reportedAt, ip)
				}
			}
			reportedMu.Unlock()
		}
	}()
}

func shouldReport(ip string) bool {
	reportedMu.Lock()
	defer reportedMu.Unlock()
	if last, ok := reportedAt[ip]; ok && time.Since(last) < reportCooldown {
		return false
	}
	reportedAt[ip] = time.Now()
	return true
}

// reportToOneFirewall sends one detected-attack sighting to
// OneFirewall's threat-intel API. Never reports private/loopback/
// link-local addresses - that's almost always our own local testing
// traffic, and reporting it would just pollute a real threat-intel feed
// with noise, not a real attacker.
func reportToOneFirewall(ip, code, category, notes string) {
	if ctiAPIKey == "" || ip == "" || code == "" {
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
		return
	}
	if !shouldReport(ip) {
		return
	}

	body := map[string]any{
		"ip":         ip,
		"confidence": confidenceForCode(code),
		"source":     "velocitylab",
		"notes":      notes,
		"tags": []string{
			code,
			"details#" + category,
			"velocitylab",
			"honeynet",
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return
	}

	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest(http.MethodPost, "https://app.onefirewall.com/api/v1/ips", bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", ctiAPIKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("OneFirewall report for %s failed: %v", ip, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			log.Printf("OneFirewall report for %s: unexpected status %s: %s", ip, resp.Status, respBody)
		}
	}()
}
