package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// classifyRequest inspects a request's path, query string, form body, and
// User-Agent against a prioritized set of signatures and returns the
// best-fit MITRE ATT&CK technique, the way a WAF/SIEM rule set tags
// traffic. It's advisory, not authoritative: real classification needs
// more context (request history, response codes, actual exploit success)
// than a single request in isolation - same limitation any signature-
// based detector has. An empty string means nothing matched.
func classifyRequest(r *http.Request) string {
	bodyValues := peekFormValues(r)
	values := allValues(r, bodyValues)

	for _, rule := range mitreRules {
		if rule.Match(r, values) {
			return fmt.Sprintf("%s %s", rule.Code, rule.Name)
		}
	}
	return ""
}

type mitreRule struct {
	Code  string
	Name  string
	Match func(r *http.Request, values []string) bool
}

var (
	sqliPattern       = regexp.MustCompile(`(?i)(\bunion\b[^;]{0,30}\bselect\b|'\s*or\s*'?\w+'?\s*=\s*'?\w+'?|--\s|;\s*drop\b|\bsleep\s*\()`)
	xssPattern        = regexp.MustCompile(`(?i)(<script|onerror\s*=|onload\s*=|javascript:)`)
	traversalPattern  = regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f)`)
	cmdInjectPattern  = regexp.MustCompile(`(?i)(;\s*(sleep|cat|ls|whoami|id)\b|\|\|?\s*\w|&&\s*\w|\$\()`)
	sstiPattern       = regexp.MustCompile(`\{\{.*\}\}`)
	scannerUAPattern  = regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|nessus|acunetix|nuclei|gobuster|dirbuster|wpscan|masscan|zgrab|burp|zap)`)
)

// mitreRules is ordered most-specific/highest-signal first, since
// classifyRequest returns on the first match.
var mitreRules = []mitreRule{
	{"T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", func(r *http.Request, _ []string) bool {
		p := r.URL.Path
		return p == "/internal/metadata" || strings.HasPrefix(p, "/computeMetadata/") || p == "/metadata/instance"
	}},
	{"T1552.001", "Unsecured Credentials: Credentials In Files", func(r *http.Request, _ []string) bool {
		switch r.URL.Path {
		case "/.env", "/.git/config", "/.git/HEAD", "/.git/logs/HEAD", "/config.php.bak":
			return true
		}
		return strings.HasPrefix(r.URL.Path, "/uploads/") &&
			(strings.Contains(r.URL.Path, "backup.sql") || strings.Contains(r.URL.Path, "config.old"))
	}},
	{"T1098", "Account Manipulation", func(r *http.Request, _ []string) bool {
		return r.URL.Path == "/api/profile" && (r.Method == http.MethodPut || r.Method == http.MethodPatch)
	}},
	{"T1499", "Endpoint Denial of Service", func(r *http.Request, _ []string) bool {
		return r.URL.Path == "/api/validate-coupon" && len(r.URL.Query().Get("code")) > 15
	}},
	{"T1059.007", "Command and Scripting Interpreter: JavaScript", func(_ *http.Request, values []string) bool {
		return anyMatch(values, xssPattern)
	}},
	{"T1059", "Command and Scripting Interpreter", func(_ *http.Request, values []string) bool {
		return anyMatch(values, cmdInjectPattern)
	}},
	{"T1190", "Exploit Public-Facing Application (SQL injection)", func(_ *http.Request, values []string) bool {
		return anyMatch(values, sqliPattern)
	}},
	{"T1190", "Exploit Public-Facing Application (template injection)", func(_ *http.Request, values []string) bool {
		return anyMatch(values, sstiPattern)
	}},
	{"T1005", "Data from Local System", func(_ *http.Request, values []string) bool {
		return anyMatch(values, traversalPattern)
	}},
	{"T1110", "Brute Force", func(r *http.Request, _ []string) bool {
		return r.Method == http.MethodPost && (r.URL.Path == "/login" || r.URL.Path == "/reset-password")
	}},
	{"T1213", "Data from Information Repositories", func(r *http.Request, _ []string) bool {
		return r.URL.Path == "/api/config" || r.URL.Path == "/api/data"
	}},
	{"T1595.002", "Active Scanning: Vulnerability Scanning", func(r *http.Request, _ []string) bool {
		if scannerUAPattern.MatchString(r.Header.Get("User-Agent")) {
			return true
		}
		if r.Method == http.MethodTrace || r.Method == http.MethodOptions {
			return true
		}
		switch r.URL.Path {
		case "/phpinfo.php", "/swagger.json", "/robots.txt":
			return true
		}
		return strings.HasPrefix(r.URL.Path, "/debug/pprof/")
	}},
}

func anyMatch(values []string, re *regexp.Regexp) bool {
	for _, v := range values {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func allValues(r *http.Request, bodyValues url.Values) []string {
	var out []string
	for _, v := range r.URL.Query() {
		out = append(out, v...)
	}
	for _, v := range bodyValues {
		out = append(out, v...)
	}
	return out
}

// peekFormValues reads a form-urlencoded body for classification and
// restores it so the real handler downstream can still read it normally.
// Multipart bodies (file uploads) are left alone rather than buffered
// here.
func peekFormValues(r *http.Request) url.Values {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return nil
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return nil
	}
	if r.Body == nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	values, _ := url.ParseQuery(string(bodyBytes))
	return values
}
