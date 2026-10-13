package main

import (
	"io"
	"regexp"
	"strings"
)

// Granular MITRE ATT&CK refinement.
//
// Call sites across the codebase tag events with a handful of coarse
// techniques (T1190, T1133, T1595.002, ...) plus a plain-English
// category. refiningWriter sits in front of every log sink and, per line:
//
//  1. swaps the coarse technique for the most specific one that fits the
//     category (e.g. a Kerberos probe becomes T1558, an exposed Key Vault
//     becomes T1555.006, an IMDS token theft becomes T1528);
//  2. appends tactic="..." (the ATT&CK tactic the technique belongs to)
//     and attack_class="..." (a coarse, human-readable bucket) fields;
//  3. appends mitre_base=<coarse code> whenever it changed the technique,
//     so downstream scoring (onefirewall.go) can still see the original.
//
// Everything is derived from the category string alone - never from
// attacker-controlled request content - so a payload can't forge its own
// classification. "connected to" lines (a bare connection, no data) keep
// their T1133 technique: connecting to an exposed remote service *is*
// External Remote Services; only lines carrying real content are refined.

type techRule struct {
	re   *regexp.Regexp
	code string
	name string
}

func tr(pattern, code, name string) techRule {
	return techRule{regexp.MustCompile("(?i)" + pattern), code, name}
}

// techRules is ordered most-specific first; the first match wins.
var techRules = []techRule{
	tr(`brute-?force`, "T1110.001", "Brute Force: Password Guessing"),
	tr(`kerberos`, "T1558", "Steal or Forge Kerberos Tickets"),
	tr(`managed-identity|\bIMDS\b|Instance Metadata|\(MSI\)`, "T1528", "Steal Application Access Token"),
	tr(`Key Vault|Secrets Management`, "T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores"),
	tr(`Azure (Blob|Queue|Table)|Cosmos DB`, "T1530", "Data from Cloud Storage"),
	tr(`Cluster Secrets`, "T1552.007", "Unsecured Credentials: Container API"),
	tr(`Docker Engine|Container Escape|Container Management|Deploy Container`, "T1610", "Deploy Container"),
	tr(`Kubernetes|Kubelet|Container Orchestration|Swarm|Dapr`, "T1609", "Container Administration Command"),
	tr(`Container Registry|Docker Registry|Container Image|Cluster Information`, "T1613", "Container and Resource Discovery"),
	tr(`Remote Desktop`, "T1021.001", "Remote Services: Remote Desktop Protocol"),
	tr(`File Share|\bSMB\b`, "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
	tr(`\bVNC\b`, "T1021.005", "Remote Services: VNC"),
	tr(`Remote Management|\bWinRM\b`, "T1021.006", "Remote Services: Windows Remote Management"),
	tr(`SSH|Java RMI|Remote Debugger|\bAJP\b|IRC Daemon|FTP Backdoor|FTP Arbitrary|Mail Server RCE|Distributed Compiler|Config Theft / RCE|Network Management Authentication Bypass|Erlang Node|Legacy Remote|Game Server`, "T1210", "Exploitation of Remote Services"),
	tr(`RPC Service Enumeration`, "T1046", "Network Service Discovery"),
	tr(`Zone Transfer`, "T1590.002", "Gather Victim Network Information: DNS"),
	tr(`Source Disclosure|Artifact Repository`, "T1213.003", "Data from Information Repositories: Code Repositories"),
	tr(`TFTP|Unauthenticated File Sync|Network File Share|Unauthorized File Access`, "T1039", "Data from Network Shared Drive"),
	tr(`Open Proxy`, "T1090", "Proxy"),
	tr(`Algorithm-None|JWT`, "T1606", "Forge Web Credentials"),
	tr(`2FA Bypass`, "T1111", "Multi-Factor Authentication Interception"),
	tr(`Unrestricted File Upload`, "T1505.003", "Server Software Component: Web Shell"),
	tr(`Server-Side Request Forgery|SSRF Attempt`, "T1190", "Exploit Public-Facing Application"),
	tr(`Open Redirect`, "T1566.002", "Phishing: Spearphishing Link"),
	tr(`Financial|Race Condition`, "T1657", "Financial Theft"),
	tr(`Denial of Service Attempt`, "T1499.004", "Endpoint Denial of Service: Application or System Exploitation"),
	tr(`Command Injection|Shellshock|Gadget Command`, "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
	tr(`Sensitive File / Debug`, "T1595.003", "Active Scanning: Wordlist Scanning"),
	tr(`Information Disclosure`, "T1082", "System Information Discovery"),
}

type classRule struct {
	re    *regexp.Regexp
	class string
}

func cr(pattern, class string) classRule {
	return classRule{regexp.MustCompile("(?i)" + pattern), class}
}

var classRules = []classRule{
	cr(`ICS|SCADA|OPC UA|Modbus|DNP3|IEC-?104|S7|Building Automation`, "ICS/OT Access"),
	cr(`Amplification|Denial of Service|DoS`, "Denial of Service"),
	cr(`Brute-?Force|Spray|Default Credential|Enumeration`, "Credential Attack"),
	cr(`Metadata|Token Theft|Managed|Secrets|Credential/Secrets|Cloud Credential|Key Vault`, "Cloud / Credential Theft"),
	cr(`Traversal|File Read|Zip Slip|File Disclosure`, "Path Traversal / File Read"),
	cr(`Authentication Bypass|403 Bypass|Access Control|2FA|Algorithm-None|Account Takeover|Privilege|BOLA|Object Level`, "Auth / Access-Control Bypass"),
	cr(`Injection|XXE|XSS|Cross-Site|Format String|Prototype Pollution|Deserialization|Template`, "Injection / Deserialization"),
	cr(`Scanning|Reconnaissance|Fingerprint|Probe|Discovery`, "Reconnaissance"),
	cr(`Proxy|Relay|Hijack|LLM|Resource`, "Resource / Service Abuse"),
	cr(`Remote Desktop|Remote Shell|Remote Management|Remote Login|File Share|Lateral`, "Remote Access / Lateral Movement"),
	cr(`Disclosure|Exposure|Config Theft|Source`, "Information Disclosure"),
	cr(`Exploitation Attempt \(|RCE|Remote Code|Backdoor|Command|Shell`, "Known-CVE / Remote Code Execution"),
}

func attackClassFor(category string) string {
	for _, r := range classRules {
		if r.re.MatchString(category) {
			return r.class
		}
	}
	return "Exposed Service Access"
}

// tacticByTechnique maps a technique (or, failing that, its parent) to
// the ATT&CK tactic it is filed under.
var tacticByTechnique = map[string]string{
	"T1190": "Initial Access", "T1133": "Initial Access", "T1566.002": "Initial Access", "T1078.001": "Initial Access",
	"T1595.002": "Reconnaissance", "T1595.003": "Reconnaissance", "T1590.002": "Reconnaissance",
	"T1059": "Execution", "T1059.004": "Execution", "T1059.007": "Execution", "T1609": "Execution", "T1610": "Execution",
	"T1505.003": "Persistence", "T1098": "Persistence",
	"T1110": "Credential Access", "T1110.001": "Credential Access", "T1110.003": "Credential Access",
	"T1552.001": "Credential Access", "T1552.005": "Credential Access", "T1552.007": "Credential Access",
	"T1555.006": "Credential Access", "T1528": "Credential Access", "T1558": "Credential Access",
	"T1040": "Credential Access", "T1111": "Credential Access", "T1606": "Credential Access",
	"T1087": "Discovery", "T1046": "Discovery", "T1018": "Discovery", "T1082": "Discovery", "T1613": "Discovery",
	"T1021.001": "Lateral Movement", "T1021.002": "Lateral Movement", "T1021.005": "Lateral Movement",
	"T1021.006": "Lateral Movement", "T1210": "Lateral Movement",
	"T1005": "Collection", "T1213": "Collection", "T1213.003": "Collection", "T1039": "Collection", "T1530": "Collection",
	"T1090": "Command and Control",
	"T1496": "Impact", "T1498.002": "Impact", "T1499": "Impact", "T1499.004": "Impact", "T1565.001": "Impact", "T1657": "Impact",
}

func tacticFor(code string) string {
	if t, ok := tacticByTechnique[code]; ok {
		return t
	}
	if i := strings.IndexByte(code, '.'); i > 0 {
		if t, ok := tacticByTechnique[code[:i]]; ok {
			return t
		}
	}
	return "Unknown"
}

// refineTag returns the (possibly more specific) technique for an event.
// connectOnly lines keep their coarse technique.
func refineTag(code, name, category string, connectOnly bool) (string, string) {
	if connectOnly {
		return code, name
	}
	for _, r := range techRules {
		if r.re.MatchString(category) {
			return r.code, r.name
		}
	}
	return code, name
}

// refineLine rewrites one log line's MITRE bracket and appends the
// tactic/class fields. Lines with no bracket pass through untouched.
func refineLine(line string) string {
	idx := mitreTagPattern.FindStringSubmatchIndex(line)
	if idx == nil {
		return line
	}
	code := strings.TrimSpace(line[idx[2]:idx[3]])
	name := strings.TrimSpace(line[idx[4]:idx[5]])
	category := strings.TrimSpace(line[idx[6]:idx[7]])

	newCode, newName := refineTag(code, name, category, strings.Contains(line, " connected to "))
	tag := "[" + newCode + " " + newName + " | " + category + "]"

	trailer := ""
	if strings.HasSuffix(line, "\n") {
		line, trailer = line[:len(line)-1], "\n"
	}
	// idx offsets are into the original line; the trailing newline sits
	// after the tag, so they remain valid after trimming it.
	out := line[:idx[0]] + tag + line[idx[1]:]
	out += ` tactic="` + tacticFor(newCode) + `" attack_class="` + attackClassFor(category) + `"`
	if newCode != code {
		out += " mitre_base=" + code
	}
	return out + trailer
}

// refiningWriter wraps the fan-out writer so every sink (stderr, CSV,
// syslog, OneFirewall) sees the same refined line.
type refiningWriter struct{ next io.Writer }

func (w refiningWriter) Write(p []byte) (int, error) {
	if _, err := w.next.Write([]byte(refineLine(string(p)))); err != nil {
		return 0, err
	}
	return len(p), nil
}
