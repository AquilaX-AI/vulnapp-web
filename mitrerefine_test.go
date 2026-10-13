package main

import (
	"strings"
	"testing"
)

func TestRefineLine(t *testing.T) {
	cases := []struct {
		name, line, wantCode, wantTactic, wantClass string
		wantBase                                    bool
	}{
		{"kerberos", `1.2.3.4:5 sent "x" to Kerberos KDC [T1190 Exploit Public-Facing Application | Kerberos Attack Attempt (AS-REP roasting)] proto=tcp`, "T1558", "Credential Access", "", true},
		{"imds token theft", `1.2.3.4:5 GET /metadata/identity/oauth2/token [T1190 Exploit Public-Facing Application | Azure Instance Metadata Service (IMDS) Exploitation Attempt (SSRF -> VM metadata & managed-identity token theft)] proto=http`, "T1528", "Credential Access", "Cloud / Credential Theft", true},
		{"key vault", `1.2.3.4:5 GET /secrets [T1190 Exploit Public-Facing Application | Azure Key Vault (public network access) Exploitation Attempt (x)] proto=http`, "T1555.006", "Credential Access", "", true},
		{"blob", `1.2.3.4:5 GET /?comp=list [T1190 Exploit Public-Facing Application | Azure Blob Storage (public container) Exploitation Attempt (x)] proto=http`, "T1530", "Collection", "", true},
		{"rmi", `1.2.3.4:5 sent 7 bytes [T1190 Exploit Public-Facing Application | Java RMI Deserialization Attempt (CVE-2011-3556)] proto=tcp`, "T1210", "Lateral Movement", "", true},
		{"connect-only keeps T1133", `1.2.3.4:5 connected to [::]:636 [T1133 External Remote Services | Directory Service Brute-Force / Enumeration Attempt (x)] proto=tcp`, "T1133", "Initial Access", "Credential Attack", false},
		{"coarse cve trap stays T1190", `1.2.3.4:5 POST /mgmt/tm/util/bash [T1190 Exploit Public-Facing Application | F5 BIG-IP Exploitation Attempt (CVE-2022-1388)] proto=http`, "T1190", "Initial Access", "Known-CVE / Remote Code Execution", false},
		{"sql injection untouched", `1.2.3.4:5 GET /products [T1190 Exploit Public-Facing Application | SQL Injection Attempt] proto=http`, "T1190", "Initial Access", "Injection / Deserialization", false},
		{"sensitive file probe", `1.2.3.4:5 GET /.aws/credentials [T1190 Exploit Public-Facing Application | Sensitive File / Debug Endpoint Exposure Attempt] proto=http`, "T1595.003", "Reconnaissance", "", true},
		{"no tag passes through", "plain log line\n", "", "", "", false},
	}
	for _, c := range cases {
		out := refineLine(c.line)
		if c.wantCode == "" {
			if out != c.line {
				t.Errorf("%s: untagged line modified: %q", c.name, out)
			}
			continue
		}
		if !strings.Contains(out, "["+c.wantCode+" ") {
			t.Errorf("%s: want code %s in %q", c.name, c.wantCode, out)
		}
		if !strings.Contains(out, `tactic="`+c.wantTactic+`"`) {
			t.Errorf("%s: want tactic %q in %q", c.name, c.wantTactic, out)
		}
		if c.wantClass != "" && !strings.Contains(out, `attack_class="`+c.wantClass+`"`) {
			t.Errorf("%s: want class %q in %q", c.name, c.wantClass, out)
		}
		if c.wantBase != strings.Contains(out, "mitre_base=") {
			t.Errorf("%s: mitre_base presence = %v, want %v (%q)", c.name, !c.wantBase, c.wantBase, out)
		}
		if !mitreTagPattern.MatchString(out) {
			t.Errorf("%s: refined line no longer parses: %q", c.name, out)
		}
	}
}

// Scoring must reason about the original coarse tag, not the refined one.
func TestConfidenceSurvivesRefinement(t *testing.T) {
	line := refineLine(`1.2.3.4:5 GET /metadata/identity/oauth2/token [T1190 Exploit Public-Facing Application | Azure Instance Metadata Service (IMDS) Exploitation Attempt (CVE-2099-1)] dest=:8312 proto=http` + "\n")
	m := mitreTagPattern.FindStringSubmatch(line)
	if got := confidenceForEvent(strings.TrimSpace(m[1]), strings.TrimSpace(m[3]), line); got != 0.95 {
		t.Errorf("refined T1528 line scored %.2f, want 0.95 (line %q)", got, line)
	}
}
