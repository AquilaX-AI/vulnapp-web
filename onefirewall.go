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

// mitreTagPattern matches every "[T1234 Official Technique Name |
// Plain-English Category]" bracket this codebase emits (mitre.go's
// classifyRequest builds it as "%s %s | %s" from Code, Name, Category).
// Group 1 is the code, group 2 the official name, group 3 the category -
// shared by every log sink below that needs to parse it (OneFirewall
// reporting, the CSV attack log).
var mitreTagPattern = regexp.MustCompile(`\[(T\d+(?:\.\d+)?)\s+([^|]+)\|\s*([^\]]+)\]`)

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
		category := strings.TrimSpace(m[3])
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

var (
	cveIDPattern     = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	mitreBasePattern = regexp.MustCompile(`mitre_base=(T\d+(?:\.\d+)?)`)
	tacticPattern    = regexp.MustCompile(`tactic="([^"]+)"`)
	classPattern     = regexp.MustCompile(`attack_class="([^"]+)"`)
	// exploitPayloadPattern spots content that is only ever sent by
	// someone trying to execute something: downloaders, shells, and the
	// classic "does it run" probes. Distinct from merely touching an
	// exploit-shaped path.
	exploitPayloadPattern = regexp.MustCompile("(?i)(wget\\s|curl\\s|/bin/(ba)?sh|bash\\s+-[ci]|nc\\s+-e|powershell|certutil|\\|\\s*sh\\b|(?:[;|&`$(>]|%3b|%7c)\\s*(id|whoami|uname)(?:\\s|$|[;|&)`\"']|%0a|%20|%26|%3b)|^AB;|SITE\\s+CPTO|JDWP-Handshake)")
	webVuln2Set           = func() map[string]bool {
		m := map[string]bool{}
		for _, c := range webVuln2Categories {
			m[c] = true
		}
		return m
	}()
)

// confidenceForEvent scores one log line by how strongly it proves
// hostile intent, rather than by MITRE technique alone - the same T1190
// tag covers everything from "ran a SQLi payload" to "fetched a path an
// exploit happens to use", and those are not equally damning:
//
//	0.98  a command/downloader payload was actually delivered
//	0.95  exploit-shaped request to a CVE-specific trap (or a live
//	      SQLi/XSS/Log4Shell/... payload, per mitreConfidence)
//	0.85  data sent to a vulnerable-service decoy, or a trap for a
//	      misconfiguration with no CVE
//	0.80  hit a deliberately-vulnerable web endpoint (no payload seen)
//	0.70  requested a commonly-scanned sensitive file / debug path
//	0.60  scanning (UDP probes, scanner User-Agents, request bursts)
//	0.50  merely connected / loaded a landing page
func confidenceForEvent(code, category, line string) float64 {
	// Scoring reasons about the evidence tier of the *original* coarse
	// tag; refinement (mitrerefine.go) records it as mitre_base=.
	if m := mitreBasePattern.FindStringSubmatch(line); m != nil {
		code = m[1]
	}
	if strings.Contains(line, "rce_payload=true") || exploitPayloadPattern.MatchString(line) {
		return 0.98
	}
	base := confidenceForCode(code)
	switch {
	case strings.Contains(line, " connected to "):
		return 0.5
	case webVuln2Set[category]:
		if strings.HasPrefix(category, "Sensitive File") {
			return 0.7
		}
		return 0.8
	case code == "T1190" && strings.Contains(line, " sent ") && strings.Contains(line, "proto=tcp"):
		return 0.85 // raw TCP decoy: bytes sent, no exploit-specific marker
	case code == "T1190" && strings.Contains(category, "(CVE-"):
		return 0.95
	case code == "T1190" && strings.Contains(category, "Exploitation Attempt ("):
		return 0.85 // trap for a CVE-less misconfiguration
	}
	return base
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
	// reportedConf is the highest confidence reported for an IP within its
	// current cooldown window.
	reportedConf = map[string]float64{}
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
					delete(reportedConf, ip)
				}
			}
			reportedMu.Unlock()
		}
	}()
}

// shouldReport applies the per-IP cooldown, but lets a *stronger*
// signal through: a scanner that first just connects (0.5) and then
// delivers an exploit (0.95+) must not have the exploit swallowed by the
// cooldown the connect started.
func shouldReport(ip string, conf float64) bool {
	reportedMu.Lock()
	defer reportedMu.Unlock()
	last, seen := reportedAt[ip]
	fresh := !seen || time.Since(last) >= reportCooldown
	if !fresh && conf < reportedConf[ip]+0.1 {
		return false
	}
	reportedAt[ip] = time.Now()
	if fresh || conf > reportedConf[ip] {
		reportedConf[ip] = conf
	}
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
	conf := confidenceForEvent(code, category, notes)
	if !shouldReport(ip, conf) {
		return
	}

	body := map[string]any{
		"ip":         ip,
		"confidence": conf,
		"source":     "velocitylabs",
		"notes":      notes,
		"tags": append([]string{
			code,
			"details#" + category,
			"velocitylab",
			"honeynet",
		}, cveTags(notes)...),
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return
	}

	// Everything from here on MUST run inside the goroutine, never
	// synchronously in this function: reportToOneFirewall is reached via
	// oneFirewallWriter.Write(), which Go's standard log package invokes
	// while holding its own internal mutex (it serializes all log
	// output). Calling log.Printf synchronously from here - even just to
	// log that a report is starting - re-enters that same non-reentrant
	// mutex on the same goroutine and deadlocks permanently. That
	// deadlock doesn't just break this one call either: every other
	// goroutine's log.Printf (for any request, on any endpoint) then
	// blocks forever on the same lock, freezing the entire process.
	// Caught this exactly that way - one attack request froze the whole
	// server, confirmed by a second curl to an unrelated endpoint also
	// hanging - before moving this log line below, into the goroutine,
	// which runs later, on a different goroutine, after the outer
	// log.Printf call has already returned and released its lock.
	go func() {
		log.Printf("OneFirewall: reporting %s (%s, confidence %.2f)", ip, code, conf)
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest(http.MethodPost, "https://app.onefirewall.com/api/v1/ips", bytes.NewReader(payload))
		if err != nil {
			log.Printf("OneFirewall report for %s: failed to build request: %v", ip, err)
			return
		}
		req.Header.Set("Authorization", ctiAPIKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("OneFirewall report for %s FAILED (network error): %v", ip, err)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode >= 300 {
			log.Printf("OneFirewall report for %s FAILED: HTTP %s: %s", ip, resp.Status, respBody)
			return
		}
		log.Printf("OneFirewall report for %s accepted: HTTP %s", ip, resp.Status)
	}()
}

// cveTags returns up to five "cve#CVE-YYYY-N" tags for the CVE IDs a log
// line names, so the feed says exactly which vulnerability was targeted.
func cveTags(line string) []string {
	return append(cveIDTags(line), mitreContextTags(line)...)
}

// mitreContextTags carries the refined tactic and attack class (added by
// mitrerefine.go) into the feed as tags.
func mitreContextTags(line string) []string {
	var out []string
	if m := tacticPattern.FindStringSubmatch(line); m != nil {
		out = append(out, "tactic#"+m[1])
	}
	if m := classPattern.FindStringSubmatch(line); m != nil {
		out = append(out, "class#"+m[1])
	}
	return out
}

func cveIDTags(line string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range cveIDPattern.FindAllString(line, -1) {
		if !seen[id] && len(out) < 5 {
			seen[id] = true
			out = append(out, "cve#"+id)
		}
	}
	return out
}
