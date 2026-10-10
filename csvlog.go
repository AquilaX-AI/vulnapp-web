package main

import (
	"encoding/csv"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// csvLogPath is where every attack-tagged event gets appended as one CSV
// row - a local, dependency-free record (no syslog/CTI setup required)
// an analyst can open directly. Unlike syslogOutput/oneFirewallOutput,
// this sink is on by default; CSV_LOG_PATH only overrides where it writes.
var csvLogPath = getenvDefault("CSV_LOG_PATH", "logs.csv")

var csvHeader = []string{
	"timestamp", "ip", "source_port", "destination_port", "protocol",
	"service", "user_agent", "mitre_code", "mitre_name", "attempt",
	"details", "notes",
}

// csvOutput opens (or creates) csvLogPath for append and returns a writer
// that turns every attack-tagged log line into one CSV row. Returns
// (nil, "") only if the file genuinely can't be opened (e.g. unwritable
// directory) - logging itself never stops working either way, since this
// is one sink among several in initLogging's io.MultiWriter.
func csvOutput() (io.Writer, string) {
	f, err := os.OpenFile(csvLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("CSV attack log %s not started: %v", csvLogPath, err)
		return nil, ""
	}
	if info, statErr := f.Stat(); statErr == nil && info.Size() == 0 {
		w := csv.NewWriter(f)
		_ = w.Write(csvHeader)
		w.Flush()
	}
	return &csvLogWriter{f: f}, "csv(" + csvLogPath + ")"
}

type csvLogWriter struct {
	f *os.File
}

var (
	uaFieldPattern    = regexp.MustCompile(`ua="([^"]*)"`)
	protoFieldPattern = regexp.MustCompile(`proto=(\S+)`)
	destFieldPattern  = regexp.MustCompile(`dest=(\S+)`)
)

// Write is called once per log.Printf/Print/Println, same as every other
// sink in this file's package - Go's log package serializes all of
// these under its own internal mutex, so no locking is needed here
// either (see onefirewall.go's reportToOneFirewall comment for the
// deadlock this same guarantee is load-bearing for elsewhere).
func (w *csvLogWriter) Write(p []byte) (int, error) {
	raw := strings.TrimRight(string(p), "\n")
	m := mitreTagPattern.FindStringSubmatch(raw)
	if m == nil {
		return len(p), nil // only attack-tagged lines are attacker records
	}
	code := strings.TrimSpace(m[1])
	name := strings.TrimSpace(m[2])
	category := strings.TrimSpace(m[3])

	srcField, srcIP, srcPort := leadingAddrField(raw)
	if srcIP == "" {
		return len(p), nil
	}

	dest, proto, ua := "", "", ""
	if dm := destFieldPattern.FindStringSubmatch(raw); dm != nil {
		dest = dm[1]
	}
	if pm := protoFieldPattern.FindStringSubmatch(raw); pm != nil {
		proto = pm[1]
	}
	if um := uaFieldPattern.FindStringSubmatch(raw); um != nil {
		ua = um[1]
	}
	if dest == "" || proto == "" || ua == "" {
		if cached := lookupConnMeta(srcField); cached.dest != "" {
			if dest == "" {
				dest = cached.dest
			}
			if proto == "" {
				proto = cached.proto
			}
			if ua == "" {
				ua = cached.ua
			}
		}
	}

	_, dstPort := splitHostPortSafe(dest)
	service := servicePortName[":"+dstPort]

	details := mitreTagPattern.ReplaceAllString(raw, "")
	details = strings.TrimSpace(strings.Replace(details, srcField, "", 1))

	row := []string{
		time.Now().UTC().Format(time.RFC3339),
		srcIP, srcPort, dstPort, proto, service, ua, code, name, category,
		details, raw,
	}
	for i, v := range row {
		row[i] = neutralizeFormula(v)
	}

	cw := csv.NewWriter(w.f)
	if err := cw.Write(row); err != nil {
		return len(p), nil // never let a CSV write error take down other sinks
	}
	cw.Flush()
	return len(p), nil
}

// leadingAddrField finds the first space-separated field in line that
// parses as "host:port" with a valid IP host - every log.Printf call
// site in this codebase starts with r.RemoteAddr or conn.RemoteAddr(),
// both in that exact form. Returns the raw field (so it can be stripped
// back out of the line for the "details" column) plus the IP and port
// split apart, or ("", "", "") if nothing matches.
func leadingAddrField(line string) (field, ip, port string) {
	for _, f := range strings.Fields(line) {
		host, p, err := net.SplitHostPort(f)
		if err != nil {
			continue
		}
		if parsed := net.ParseIP(host); parsed != nil {
			return f, parsed.String(), p
		}
	}
	return "", "", ""
}

// splitHostPortSafe is net.SplitHostPort without the error-handling
// ceremony at every call site - an empty or malformed addr just yields
// "" for both parts, which is exactly "unknown" for this CSV log's
// purposes rather than something worth failing a write over.
func splitHostPortSafe(addr string) (host, port string) {
	host, port, _ = net.SplitHostPort(addr)
	return host, port
}

// neutralizeFormula defuses spreadsheet formula injection: every field
// in this CSV can contain raw, attacker-controlled input (User-Agent,
// submitted body snippets, ...), and an analyst is expected to open this
// file directly in Excel/Sheets. A field opening with =, +, -, @, or a
// tab would otherwise be interpreted as a formula there - prefixing it
// with a single quote forces it back to plain text without changing the
// data itself.
func neutralizeFormula(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t':
		return "'" + s
	}
	return s
}

// servicePortName names the product/protocol behind each fake service's
// port, for the CSV log's "service" column - distinct from
// portAttackCategory's "what kind of attempt is this" text.
var servicePortName = map[string]string{
	":21":    "FTP",
	":23":    "Telnet",
	":25":    "SMTP",
	":587":   "SMTP (submission)",
	":465":   "SMTPS",
	":143":   "IMAP",
	":993":   "IMAPS",
	":110":   "POP3",
	":995":   "POP3S",
	":53":    "DNS",
	":161":   "SNMP",
	":123":   "NTP",
	":1900":  "SSDP/UPnP",
	":19":    "chargen",
	":1883":  "MQTT",
	":502":   "Modbus",
	":554":   "RTSP",
	":104":   "DICOM",
	":11112": "DICOM",
	":102":   "S7comm",
	":4840":  "OPC UA",
	":6379":  "Redis",
	":11211": "Memcached",
	":2181":  "ZooKeeper",
	":3306":  "MySQL",
	":5900":  "VNC",
	":9200":  "Elasticsearch",
	":2375":  "Docker API",
	":5984":  "CouchDB",
	":8500":  "Consul",
	":3000":  "Grafana",
	":5601":  "Kibana",
	":9090":  "Prometheus",
	":15672": "RabbitMQ Management",
	":8086":  "InfluxDB",
	":8200":  "Vault",
	":8888":  "Jupyter",
	":10000": "Webmin",
	":8761":  "Eureka",
	":8080":  "Jenkins",
	":9000":  "Portainer",
	":19999": "Netdata",
	":5000":  "Docker Registry",
	":8161":  "ActiveMQ",
	":8081":  "Nexus",
	":50070": "Hadoop NameNode",
	":2379":  "etcd",
	":6443":  "Kubernetes API",
	":10250": "Kubelet",
	":5985":  "WinRM",
	":30000": "Kubernetes Dashboard",
	":3001":  "Open WebUI",
	":4433":  "GlobalProtect VPN",
	":4434":  "FortiGate",
	":4435":  "Ivanti Connect Secure",
	":4436":  "SonicWall",
	":8291":  "MikroTik WinBox",
	":8728":  "MikroTik RouterOS API",
	":8070":  "Hikvision ISAPI",
	":8090":  "Dahua NetSurveillance",
	":37777": "Dahua DHIP",
	":9100":  "JetDirect Printer",
	":11434": "Ollama",
	":6277":  "MCP Server",
	":8000":  "ChromaDB",
	":9091":  "Milvus",
	":80":    "Acme Supplies Web App (HTTP)",
	":443":   "Acme Supplies Web App (HTTPS)",
}
