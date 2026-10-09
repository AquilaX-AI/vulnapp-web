package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// startFakeServices binds a set of commonly internet-facing-but-shouldn't
// be ports - the same "exposed management/database interface" category a
// network/recon scanner (nmap, masscan, Shodan-style tooling) checks for -
// each giving back just enough of a real banner or response to be
// fingerprinted. None of these implement the real protocol beyond that:
// there's no auth to bypass and no backing data store, just a TCP or
// HTTP listener that answers the way the real thing would on first
// contact. Binding is best-effort - if a port is already taken (e.g. a
// real service on that port on this host), it's logged and skipped
// rather than treated as fatal, since none of these are essential to the
// app's main purpose.
func startFakeServices() {
	// Plaintext/line-based protocols: old, vulnerable-sounding version
	// strings on purpose, matching the rest of the app's "ancient stack"
	// theme.
	// SSH sends its identification string immediately on connect, before
	// any key exchange - a real, old, vulnerable-history OpenSSH version
	// fingerprints just as easily as any plaintext banner.
	startBannerService(":22", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n", nil)
	startFTPService(":21")
	startTelnetService(":23")
	startBannerService(":6379", "", redisReply)
	startBannerService(":11211", "", memcachedReply)
	startBannerService(":2181", "", zookeeperReply) // ZooKeeper's "four-letter commands"
	startMySQLService(":3306")                      // binary greeting, not a plain-text banner

	// Mail stack: stateful SMTP/IMAP/POP3 fakes - see mailservices.go.
	startMailServices()

	// DNS zone transfer (AXFR) - see dns.go.
	startDNSAXFRService(":53")

	// Protocols where the client speaks first (PostgreSQL, MSSQL, RDP,
	// VNC, MongoDB, Oracle, Cassandra, Kafka, RabbitMQ/AMQP, ActiveMQ,
	// SMB): accepting the connection and staying silent is actually
	// protocol-accurate, and still enough for a port scanner to mark the
	// port "open".
	for _, addr := range []string{
		":5432", ":1433", ":3389", ":5900", ":27017",
		":1521", ":9042", ":9092", ":5672", ":61616", ":445",
	} {
		startSilentService(addr)
	}

	// HTTP-based fake services: these products genuinely just speak
	// plain HTTP, so a tiny handler is a faithful (if minimal) fake -
	// each with an old-ish, real version number with its own history of
	// CVEs, same as the rest of the app.
	startFakeHTTPService(":9200", handleFakeElasticsearch)
	startFakeHTTPService(":2375", handleFakeDockerAPI)
	startFakeHTTPService(":5984", handleFakeCouchDB)
	startFakeHTTPService(":8500", handleFakeConsul)

	// The "ops tooling someone spun up and forgot about" category - the
	// single most common way this stuff actually ends up exposed in the
	// real world, so it gets the biggest slice of ports.
	startFakeHTTPService(":3000", handleFakeGrafana)
	startFakeHTTPService(":5601", handleFakeKibana)
	startFakeHTTPService(":9090", handleFakePrometheus)
	startFakeHTTPService(":15672", handleFakeRabbitMQ)
	startFakeHTTPService(":8086", handleFakeInfluxDB)
	startFakeHTTPService(":8200", handleFakeVault)
	startFakeHTTPService(":8888", handleFakeJupyter)
	startFakeHTTPService(":10000", handleFakeWebmin)
	startFakeHTTPService(":8761", handleFakeEureka)
	startFakeHTTPService(":8080", handleFakeJenkins)
	startFakeHTTPService(":9000", handleFakePortainer)
	startFakeHTTPService(":19999", handleFakeNetdata)

	// Infrastructure/orchestration APIs - the category behind some of
	// the bigger real-world breaches (exposed etcd/kubelet leaking
	// cluster secrets, open Docker registries leaking proprietary
	// images, ...).
	startFakeHTTPService(":5000", handleFakeDockerRegistry)
	startFakeHTTPService(":8161", handleFakeActiveMQ)
	startFakeHTTPService(":8081", handleFakeNexus)
	startFakeHTTPService(":50070", handleFakeHadoopNameNode)
	startFakeHTTPService(":2379", handleFakeEtcd)
	startFakeHTTPService(":6443", handleFakeKubernetesAPI)
	startFakeHTTPService(":10250", handleFakeKubelet)
	startFakeHTTPService(":5985", handleFakeWinRM)
}

func startBannerService(addr, banner string, reply func(string) string) {
	if banner == "" && reply == nil {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if banner != "" {
			conn.Write([]byte(banner))
		}
		if reply == nil {
			return
		}
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			if resp := reply(scanner.Text()); resp != "" {
				conn.Write([]byte(resp))
			}
		}
	})
}

func startSilentService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 1024)
		conn.Read(buf) // nolint - discard whatever the client sends, never reply
	})
}

func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		log.Printf("%s connected to %s [T1133 External Remote Services]", conn.RemoteAddr(), ln.Addr())
		go handle(conn)
	}
}

// startFTPService models the actual vulnerability behind an exposed
// vsFTPd 2.3.4, not just the open port: anonymous login is accepted, and
// once "in", LIST reveals the same sensitive-looking files as the real
// backup exposure on /uploads/ - the realistic way this class of bug
// chains together (FTP misconfig -> file/credential disclosure).
func startFTPService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleFTPConn)
}

func handleFTPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprint(conn, "220 (vsFTPd 2.3.4)\r\n")

	loggedIn := false
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER"):
			fmt.Fprint(conn, "331 Please specify the password.\r\n")
		case strings.HasPrefix(upper, "PASS"):
			// The actual bug: any username/password (including the
			// anonymous/anonymous or anonymous/blank convention) is
			// accepted - there's no real auth check at all.
			loggedIn = true
			log.Printf("%s FTP login accepted [T1078.001 Valid Accounts: Default Accounts]", conn.RemoteAddr())
			fmt.Fprint(conn, "230 Login successful.\r\n")
		case strings.HasPrefix(upper, "SYST"):
			fmt.Fprint(conn, "215 UNIX Type: L8\r\n")
		case strings.HasPrefix(upper, "PWD"):
			fmt.Fprint(conn, `257 "/" is the current directory`+"\r\n")
		case strings.HasPrefix(upper, "LIST") || strings.HasPrefix(upper, "NLST"):
			if !loggedIn {
				fmt.Fprint(conn, "530 Please login with USER and PASS.\r\n")
				continue
			}
			log.Printf("%s FTP directory listing requested [T1005 Data from Local System]", conn.RemoteAddr())
			fmt.Fprint(conn, "150 Here comes the directory listing.\r\n")
			fmt.Fprint(conn, "-rw-r--r--    1 ftp      ftp          4823 Jan 03  2024 backup.sql\r\n")
			fmt.Fprint(conn, "-rw-r--r--    1 ftp      ftp           512 Jan 03  2024 config.old\r\n")
			fmt.Fprint(conn, "226 Directory send OK.\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "221 Goodbye.\r\n")
			return
		default:
			fmt.Fprint(conn, "502 Command not implemented.\r\n")
		}
	}
}

// startTelnetService is a light, Cowrie-style interactive honeypot: any
// credentials are accepted, and every command typed afterward gets
// logged (tagged as actual command-and-scripting-interpreter activity)
// and answered with a plausible-looking canned response - enough to
// "capture" what an attacker tries without ever running anything real.
func startTelnetService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleTelnetConn)
}

func handleTelnetConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))

	fmt.Fprint(conn, "Ubuntu 16.04.6 LTS\r\nacme-web01 login: ")
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	fmt.Fprint(conn, "Password: ")
	if !scanner.Scan() {
		return
	}
	log.Printf("%s telnet login accepted with arbitrary credentials [T1078.001 Valid Accounts: Default Accounts]", conn.RemoteAddr())

	fmt.Fprint(conn, "\r\nWelcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-104-generic x86_64)\r\n\r\n")
	fmt.Fprint(conn, "acme-web01:~$ ")
	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			fmt.Fprint(conn, "acme-web01:~$ ")
			continue
		}
		log.Printf("%s telnet command: %q [T1059 Command and Scripting Interpreter]", conn.RemoteAddr(), cmd)
		if out := fakeShellOutput(cmd); out != "" {
			fmt.Fprint(conn, out)
		}
		if first, _, _ := strings.Cut(cmd, " "); first == "exit" || first == "logout" {
			fmt.Fprint(conn, "logout\r\n")
			return
		}
		fmt.Fprint(conn, "acme-web01:~$ ")
	}
}

func fakeShellOutput(cmd string) string {
	first, _, _ := strings.Cut(cmd, " ")
	switch first {
	case "whoami":
		return "www-data\r\n"
	case "id":
		return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\r\n"
	case "uname":
		return "Linux acme-web01 4.4.0-104-generic x86_64 GNU/Linux\r\n"
	case "pwd":
		return "/home/www-data\r\n"
	case "ls":
		return "backup.sql  config.old  notes.txt\r\n"
	case "cat":
		return "cat: permission denied\r\n"
	case "exit", "logout":
		return ""
	default:
		return first + ": command not found\r\n"
	}
}

// redisReply mimics just enough of Redis's inline command protocol for a
// liveness/fingerprint check (PING -> +PONG) and a basic INFO probe
// (reporting a real, old Redis version) to succeed.
func redisReply(line string) string {
	upper := strings.ToUpper(strings.TrimSpace(line))
	switch {
	case strings.Contains(upper, "CONFIG GET REQUIREPASS"):
		// An empty value is the actual finding: not just that Redis is
		// reachable, but that it has no password set at all - the exact
		// signal behind a long string of real ransom/wiper incidents
		// against internet-facing Redis instances.
		return "*2\r\n$11\r\nrequirepass\r\n$0\r\n\r\n"
	case strings.Contains(upper, "INFO"):
		info := "# Server\r\nredis_version:2.8.4\r\nos:Linux 4.4.0-x86_64\r\n"
		return fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)
	default:
		return "+PONG\r\n"
	}
}

// memcachedReply answers the classic "version" probe; anything else gets
// a generic protocol error, same as the real thing.
func memcachedReply(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "version") {
		return "VERSION 1.4.15\r\n"
	}
	return "ERROR\r\n"
}

// zookeeperReply answers ZooKeeper's real "four-letter commands" -
// "ruok" (are you ok) and "stat", both genuinely meant to need no auth,
// but a real source of information disclosure (and historically, DDoS
// amplification via "stat"/"wchp"/"wchc") when reachable from anywhere
// but localhost - which is the actual, common misconfiguration.
func zookeeperReply(line string) string {
	cmd := strings.ToLower(strings.TrimSpace(line))
	switch cmd {
	case "ruok":
		return "imok"
	case "stat":
		return "Zookeeper version: 3.4.6-1569965, built on 02/20/2014 09:09 GMT\n" +
			"Clients:\n /127.0.0.1:52145[0](queued=0,recved=1,sent=0)\n" +
			"Latency min/avg/max: 0/0/0\nReceived: 1\nSent: 0\nOutstanding: 0\nNode count: 4\n"
	default:
		return ""
	}
}

// startMySQLService sends the real MySQL wire protocol's initial
// handshake packet immediately on connect (that's genuinely how MySQL
// greets a client) with an old, real server version string - enough for
// nmap's mysql-info or a manual banner grab to identify it. Whatever the
// client sends back (its auth response) is never read or answered.
func startMySQLService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	greeting := mysqlGreetingPacket()
	go acceptLoop(ln, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write(greeting)
	})
}

func mysqlGreetingPacket() []byte {
	serverVersion := "5.5.8-log\x00"
	threadID := []byte{0x01, 0x00, 0x00, 0x00}
	authPluginData1 := []byte{0x3a, 0x40, 0x3f, 0x5a, 0x21, 0x5e, 0x4a, 0x21}
	capabilityLower := []byte{0xff, 0xf7}
	charset := byte(0x08)
	statusFlags := []byte{0x02, 0x00}
	capabilityUpper := []byte{0x00, 0x00}
	authPluginDataLen := byte(0x00)
	reserved := make([]byte, 10)
	authPluginData2 := make([]byte, 12)

	var payload []byte
	payload = append(payload, 0x0a) // protocol version 10
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, threadID...)
	payload = append(payload, authPluginData1...)
	payload = append(payload, 0x00) // filler
	payload = append(payload, capabilityLower...)
	payload = append(payload, charset)
	payload = append(payload, statusFlags...)
	payload = append(payload, capabilityUpper...)
	payload = append(payload, authPluginDataLen)
	payload = append(payload, reserved...)
	payload = append(payload, authPluginData2...)

	length := len(payload)
	header := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0x00}
	return append(header, payload...)
}

func startFakeHTTPService(addr string, handler http.HandlerFunc) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s [T1133 External Remote Services]", r.RemoteAddr, r.Method, r.URL.String())
		handler(w, r)
	})
	srv := &http.Server{Handler: logged}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("fake service %s stopped: %v", addr, err)
		}
	}()
}

// handleFakeElasticsearch mimics Elasticsearch 1.4.2's unauthenticated
// root endpoint - the exact real-world "found an open Elasticsearch on
// the internet" fingerprint, right down to a version with its own real
// CVE history (e.g. the Groovy scripting RCEs).
func handleFakeElasticsearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "name" : "acme-es-node-1",
  "cluster_name" : "acme-supplies",
  "version" : {
    "number" : "1.4.2",
    "build_hash" : "927caff6f05403e936c20bf4529f144f0c89fd9",
    "build_timestamp" : "2014-12-16T14:11:12Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search"
}`)
}

// handleFakeDockerAPI mimics an exposed, unauthenticated Docker Engine
// API - a real, commonly-exploited misconfiguration (remote code
// execution via container creation) when left reachable without TLS.
func handleFakeDockerAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "Version": "1.12.6",
  "ApiVersion": "1.24",
  "GitCommit": "78d1802",
  "GoVersion": "go1.6.4",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "4.4.0-104-generic"
}`)
}

func handleFakeCouchDB(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"couchdb":"Welcome","version":"1.6.1","vendor":{"name":"Ubuntu","version":"16.04"}}`)
}

// handleFakeConsul mimics Consul's unauthenticated agent self-info
// endpoint, reusing the same internal IP already leaked by /api/config
// for a consistent story.
func handleFakeConsul(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "Config": {"Datacenter": "dc1", "NodeName": "acme-consul-01", "Server": true, "Version": "0.7.0"},
  "Member": {"Name": "acme-consul-01", "Addr": "10.0.4.23"}
}`)
}

// ---------------------------------------------------------------------
// Ops/dev tooling that gets spun up for a quick look and then forgotten -
// the single most common real way this class of service ends up
// reachable from the internet. Same deal as above: a faithful-looking
// first response, no real backend behind it.
// ---------------------------------------------------------------------

func handleFakeGrafana(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"commit":"4f8f3d5","database":"ok","version":"6.4.3"}`)
}

func handleFakeKibana(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "name": "acme-kibana",
  "version": {"number": "6.4.3"},
  "status": {"overall": {"state": "green"}}
}`)
}

// handleFakePrometheus answers the real /-/healthy liveness probe, and
// falls back to the same text for anything else - Prometheus's actual
// root page is a full React app, not worth faking byte-for-byte.
func handleFakePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "Prometheus Server is Healthy.\n")
}

// handleFakeRabbitMQ models the real default-credentials misconfig:
// RabbitMQ management ships with guest/guest, meant to be usable only
// from localhost - plenty of deployments leave that restriction off too.
// Any other (or missing) credentials get the real 401 challenge.
func handleFakeRabbitMQ(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "guest" || pass != "guest" {
		w.Header().Set("WWW-Authenticate", `Basic realm="RabbitMQ Management"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"rabbitmq_version":"3.6.6","management_version":"3.6.6","cluster_name":"rabbit@acme-mq01"}`)
}

// handleFakeInfluxDB mimics the real /ping endpoint: 204, no body, just
// a version header - that's genuinely all InfluxDB sends back.
func handleFakeInfluxDB(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Influxdb-Version", "1.3.1")
	w.WriteHeader(http.StatusNoContent)
}

// handleFakeVault mimics an unsealed, active Vault's /v1/sys/health -
// which, unlike almost everything else here, is meant to be reachable
// without auth. The real finding is that it's unsealed and reachable at
// all from wherever the scanner is sitting.
func handleFakeVault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"initialized":true,"sealed":false,"standby":false,"version":"0.6.4","cluster_name":"vault-cluster-acme"}`)
}

// handleFakeJupyter models the actual vulnerable misconfiguration (not
// just an exposed port): a notebook server with no token/password set,
// so its API is reachable with no auth at all - from here, a real
// Jupyter lets you create a notebook and execute arbitrary code.
func handleFakeJupyter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "TornadoServer/6.0.4")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Home Page - Select or create a notebook</title></head>
<body>Jupyter Notebook (no login required)</body></html>`)
}

// handleFakeWebmin plays on a real, specific CVE (2019-15107, RCE via
// the password-reset feature in Webmin <= 1.920's default build) by
// naming the exact vulnerable version in the page, the same way
// /phpinfo.php does for its fake PHP.
func handleFakeWebmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Login to Webmin</title></head>
<body>
<h1>Login to Webmin</h1>
<form method="post"><input name="user"><input name="pass" type="password"><button>Login</button></form>
<p><small>Webmin version 1.580</small></p>
</body></html>`)
}

// handleFakeEureka mimics an exposed Netflix Eureka service registry -
// reusing the same internal IPs already leaked by /api/config and
// /internal/metadata, so an SSRF chain through here reaches "real"
// (fake) internal hosts.
func handleFakeEureka(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "applications": {
    "application": [
      {"name": "ACME-ORDERS", "instance": [{"instanceId": "orders-01", "ipAddr": "10.0.4.23", "port": {"$": 8080}}]},
      {"name": "ACME-AUTH", "instance": [{"instanceId": "auth-01", "ipAddr": "192.168.56.10", "port": {"$": 8081}}]}
    ]
  }
}`)
}

// handleFakeJenkins models the classic worst case: anonymous read/admin
// left on, so the Groovy script console - genuinely arbitrary code
// execution on a real Jenkins - is reachable with no login at all. The
// console page here is just a static form; nothing it "submits" is ever
// executed.
func handleFakeJenkins(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Jenkins", "2.46.1")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path == "/script" {
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Script Console</title></head>
<body><h1>Script Console</h1><form method="post"><textarea name="script" rows="10" cols="80"></textarea><br><button>Run</button></form></body></html>`)
		return
	}
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title></head>
<body><h1>Dashboard</h1><p>Welcome to Jenkins (anonymous access)</p></body></html>`)
}

// handleFakePortainer's "Authentication":false is the real smoking gun
// Portainer itself exposes when someone skipped setting an admin
// password - anonymous full control over every container on the host.
func handleFakePortainer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"Authentication":false,"EndpointManagement":true,"Analytics":true,"Version":"1.24.1"}`)
}

// handleFakeNetdata mimics Netdata's unauthenticated-by-default info
// API, which happily leaks real hostnames, OS/kernel versions, and
// hardware specs to anyone who asks.
func handleFakeNetdata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "version": "v1.19.0",
  "hostname": "acme-web01",
  "os_name": "Ubuntu",
  "os_version": "16.04.6 LTS",
  "kernel_version": "4.4.0-104-generic",
  "cores_total": 4,
  "ram_total": 8589934592
}`)
}

// ---------------------------------------------------------------------
// Infrastructure/orchestration APIs - behind some of the bigger
// real-world breaches when left reachable: exposed etcd/kubelet leaking
// cluster secrets and workload details, open Docker registries leaking
// proprietary images, forgotten build-artifact repos.
// ---------------------------------------------------------------------

// handleFakeDockerRegistry mimics the Docker Registry v2 API's root
// check (`{}` + a specific header) - the real signal a scanner looks for
// to confirm "this is a registry", before trying to list/pull images
// from it with no credentials at all.
func handleFakeDockerRegistry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{}`)
}

// handleFakeActiveMQ names a specific, real, unauthenticated-RCE CVE
// (2016-3088, via the admin console's FileServer PUT handler).
func handleFakeActiveMQ(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Apache ActiveMQ</title></head>
<body><h1>Apache ActiveMQ 5.13.0</h1><p><a href="/admin">Manage ActiveMQ broker</a></p></body></html>`)
}

func handleFakeNexus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Sonatype Nexus Repository Manager</title></head>
<body>Nexus Repository Manager 3.14.0-04 (anonymous access enabled)</body></html>`)
}

// handleFakeHadoopNameNode mimics an exposed, pre-Kerberos-by-default
// NameNode UI - a real and common way an entire HDFS cluster's file
// listing ends up reachable with no auth.
func handleFakeHadoopNameNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>NameNode information</title></head>
<body><h1>acme-hadoop01</h1><p>Hadoop 2.6.0</p><p>Cluster ID: CID-acme-0001</p></body></html>`)
}

// handleFakeEtcd mimics etcd's real, genuinely-unauthenticated-by-default
// /version endpoint. The actual finding is everything *past* this -
// etcd's data API with no auth leaks every secret a cluster stored in
// it - which is exactly why this one gets the "real incident" framing in
// the README instead of being left to a generic DB entry.
func handleFakeEtcd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"etcdserver":"3.1.10","etcdcluster":"3.1.0"}`)
}

// handleFakeKubernetesAPI reproduces the real response an unauthenticated
// request gets from an API server with anonymous auth enabled: a 403,
// but one that still confirms "this is a Kubernetes API server" and
// exactly which user/role the request was evaluated as.
func handleFakeKubernetesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/\"","reason":"Forbidden","details":{},"code":403}`)
}

// handleFakeKubelet models the real historical misconfiguration (no
// authn/authz on the kubelet API) that let anyone list every pod - IPs,
// images, container names - running on the node with no credentials.
func handleFakeKubelet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "kind": "PodList",
  "items": [
    {"metadata": {"name": "orders-api-6f9d8", "namespace": "acme-prod"}, "status": {"hostIP": "10.0.4.23", "podIP": "10.244.1.7"}},
    {"metadata": {"name": "auth-svc-7c2b1", "namespace": "acme-prod"}, "status": {"hostIP": "10.0.4.23", "podIP": "10.244.1.9"}}
  ]
}`)
}

// handleFakeWinRM reproduces the real 401 challenge an unauthenticated
// WinRM request gets - still a useful fingerprint on its own (a
// confirmed remote-management endpoint reachable from wherever the scan
// is running from, a common lateral-movement target).
func handleFakeWinRM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Negotiate")
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
}
