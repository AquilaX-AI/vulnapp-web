package main

import (
	"bufio"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"time"
)

// Non-HTTP CVE/misconfiguration honeypots: raw TCP banners and simple
// protocol handshakes, UDP probes, and silent ICS/legacy listeners. Same
// ground rules as the HTTP personas in cvehoneypots.go - believable
// first-contact behavior, full logging of what the client sends, and no
// real functionality behind it.

type tcpDecoy struct {
	Port, Product, CVEs, Category string
	// Banner is sent immediately on connect (server-speaks-first
	// protocols). Reply, if set, answers each received line.
	Banner string
	Reply  func(line string) string
	// Handler, if set, replaces the line-based loop entirely (binary
	// protocols).
	Handler func(conn net.Conn)
}

type udpDecoy struct{ Port, Product, CVEs, Category string }

func cmdWord(line string) string {
	w, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return strings.ToUpper(w)
}

var tcpDecoys = []tcpDecoy{
	// ---- SSH variants: each banner is a distinct, real, exploited version ----
	{Port: ":2222", Product: "Erlang/OTP SSH", CVEs: "CVE-2025-32433", Category: "SSH Pre-Auth RCE Attempt",
		Banner: "SSH-2.0-Erlang/5.2.9\r\n"},
	{Port: ":2223", Product: "libssh", CVEs: "CVE-2018-10933", Category: "SSH Authentication Bypass Attempt",
		Banner: "SSH-2.0-libssh_0.8.1\r\n"},
	{Port: ":2224", Product: "OpenSSH 9.2p1 (regreSSHion)", CVEs: "CVE-2024-6387", Category: "SSH Race-Condition RCE Attempt",
		Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"},
	{Port: ":2226", Product: "OpenSSH 7.2p2", CVEs: "CVE-2016-6210,CVE-2018-15473", Category: "SSH User Enumeration Attempt",
		Banner: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2\r\n"},

	// ---- FTP backdoors / mod_copy ----
	{Port: ":2121", Product: "ProFTPD 1.3.5 (mod_copy)", CVEs: "CVE-2015-3306", Category: "FTP Arbitrary File Copy / RCE Attempt",
		Banner: "220 ProFTPD 1.3.5 Server (Acme FTP) [10.0.4.23]\r\n",
		Reply: func(l string) string {
			up := strings.ToUpper(strings.TrimSpace(l))
			switch {
			case strings.HasPrefix(up, "USER"):
				return "331 Password required\r\n"
			case strings.HasPrefix(up, "PASS"):
				return "230 User logged in\r\n"
			case strings.HasPrefix(up, "SITE CPFR"):
				return "350 File or directory exists, ready for destination name\r\n"
			case strings.HasPrefix(up, "SITE CPTO"):
				return "250 Copy successful\r\n"
			case up == "QUIT":
				return "221 Goodbye.\r\n"
			}
			return "500 Unknown command\r\n"
		}},
	{Port: ":2122", Product: "vsFTPd 2.3.4 (backdoored)", CVEs: "CVE-2011-2523", Category: "FTP Backdoor Trigger Attempt",
		Banner: "220 (vsFTPd 2.3.4)\r\n",
		Reply: func(l string) string {
			up := strings.ToUpper(strings.TrimSpace(l))
			switch {
			case strings.HasPrefix(up, "USER"):
				return "331 Please specify the password.\r\n"
			case strings.HasPrefix(up, "PASS"):
				return "530 Login incorrect.\r\n"
			case up == "QUIT":
				return "221 Goodbye.\r\n"
			}
			return "530 Please login with USER and PASS.\r\n"
		}},

	// ---- SMTP with RCE history ----
	{Port: ":2525", Product: "Exim 4.87", CVEs: "CVE-2019-10149,CVE-2019-15846", Category: "Mail Server RCE Attempt",
		Banner: "220 mail.acme.local ESMTP Exim 4.87 Tue, 13 Oct 2026 10:00:00 +0000\r\n", Reply: smtpDecoyReply},
	{Port: ":2526", Product: "OpenSMTPD 6.6.1", CVEs: "CVE-2020-7247", Category: "Mail Server RCE Attempt",
		Banner: "220 mx.acme.local ESMTP OpenSMTPD\r\n", Reply: smtpDecoyReply},

	// ---- Legacy daemons ----
	{Port: ":873", Product: "rsync 3.1.0", CVEs: "unauthenticated module access", Category: "Unauthenticated File Sync Access Attempt",
		Banner: "@RSYNCD: 31.0\r\n",
		Reply: func(l string) string {
			if strings.HasPrefix(l, "@RSYNCD:") {
				return ""
			}
			if strings.TrimSpace(l) == "#list" {
				return "backup         \tFull server backup\r\nwww            \tWeb root\r\n@RSYNCD: EXIT\r\n"
			}
			return "@ERROR: Unknown module '" + strings.TrimSpace(l) + "'\r\n"
		}},
	{Port: ":6667", Product: "UnrealIRCd 3.2.8.1 (backdoored)", CVEs: "CVE-2010-2075", Category: "IRC Daemon Backdoor Attempt",
		Banner: ":irc.acme.local NOTICE AUTH :*** Looking up your hostname...\r\n"},
	{Port: ":5038", Product: "Asterisk Call Manager", CVEs: "weak AMI credentials", Category: "VoIP Management Brute-Force Attempt",
		Banner: "Asterisk Call Manager/5.0.1\r\n"},
	{Port: ":3632", Product: "distccd", CVEs: "CVE-2004-2687", Category: "Distributed Compiler RCE Attempt"},
	{Port: ":4786", Product: "Cisco Smart Install", CVEs: "CVE-2018-0171", Category: "Network Device Config Theft / RCE Attempt"},
	{Port: ":541", Product: "FortiManager FGFM", CVEs: "CVE-2024-47575 (FortiJump)", Category: "Network Management Authentication Bypass Attempt"},
	{Port: ":5555", Product: "Android Debug Bridge", CVEs: "unauthenticated ADB (Mirai/crypto-miner droppers)", Category: "Unauthenticated Device Shell Attempt"},
	{Port: ":9300", Product: "Elasticsearch transport", CVEs: "CVE-2015-1427,CVE-2014-3120", Category: "Search Cluster Exploitation Attempt"},
	{Port: ":111", Product: "ONC RPC portmapper", CVEs: "rpcbind amplification / NFS enumeration", Category: "RPC Service Enumeration Attempt"},
	{Port: ":2049", Product: "NFS", CVEs: "world-exportable shares", Category: "Network File Share Access Attempt"},
	{Port: ":512", Product: "rexec", CVEs: "legacy r-services trust abuse", Category: "Legacy Remote Execution Attempt"},
	{Port: ":513", Product: "rlogin", CVEs: "legacy r-services trust abuse", Category: "Legacy Remote Login Attempt"},
	{Port: ":514", Product: "rsh", CVEs: "legacy r-services trust abuse", Category: "Legacy Remote Shell Attempt"},
	{Port: ":6000", Product: "X11", CVEs: "open X server", Category: "Unauthenticated Display Access Attempt"},
	{Port: ":25565", Product: "Minecraft Java server", CVEs: "CVE-2021-44228 (Log4Shell via chat)", Category: "Game Server Log4Shell Attempt"},
	{Port: ":2377", Product: "Docker Swarm manager", CVEs: "exposed swarm control plane", Category: "Container Orchestration Takeover Attempt"},
	{Port: ":4369", Product: "Erlang EPMD", CVEs: "exposed Erlang distribution cookie", Category: "Erlang Node RCE Attempt"},
	{Port: ":1099", Product: "Java RMI Registry", CVEs: "CVE-2011-3556 (RMI deserialization)", Category: "Java RMI Deserialization Attempt", Handler: handleRMI},
	{Port: ":5005", Product: "Java Debug Wire Protocol (JDWP)", CVEs: "unauthenticated JDWP RCE", Category: "Remote Debugger RCE Attempt", Handler: handleJDWP},
	{Port: ":8009", Product: "Apache JServ Protocol (AJP13)", CVEs: "CVE-2020-1938 (Ghostcat)", Category: "AJP File Read / RCE Attempt", Handler: handleAJP},
	{Port: ":1080", Product: "SOCKS5 open proxy", CVEs: "open proxy abuse", Category: "Open Proxy Abuse Attempt", Handler: handleSOCKS5},

	// ---- ICS / OT protocols (silent, log-only) ----
	{Port: ":20000", Product: "DNP3", CVEs: "no authentication in base protocol", Category: "Unauthenticated ICS (DNP3) Access Attempt"},
	{Port: ":44818", Product: "EtherNet/IP (CIP)", CVEs: "CVE-2022-1161,CVE-2021-22681", Category: "Unauthenticated ICS (EtherNet/IP) Access Attempt"},
	{Port: ":1911", Product: "Tridium Niagara Fox", CVEs: "CVE-2012-4027", Category: "Building Automation Access Attempt"},
	{Port: ":2404", Product: "IEC 60870-5-104", CVEs: "no authentication in base protocol", Category: "Unauthenticated ICS (IEC-104) Access Attempt"},
	{Port: ":9600", Product: "OMRON FINS", CVEs: "no authentication in base protocol", Category: "Unauthenticated ICS (OMRON FINS) Access Attempt"},
	{Port: ":1962", Product: "PCWorx", CVEs: "CVE-2019-9201", Category: "Unauthenticated ICS (PCWorx) Access Attempt"},
	{Port: ":789", Product: "Red Lion Crimson", CVEs: "CVE-2018-14829", Category: "Unauthenticated ICS (Crimson) Access Attempt"},
	{Port: ":18245", Product: "GE SRTP", CVEs: "no authentication in base protocol", Category: "Unauthenticated ICS (GE SRTP) Access Attempt"},
	{Port: ":4000", Product: "Emerson ROC", CVEs: "no authentication in base protocol", Category: "Unauthenticated ICS (ROC) Access Attempt"},
}

var udpDecoys = []udpDecoy{
	{":623", "IPMI / BMC", "CVE-2013-4786 (RAKP hash disclosure)", "BMC Credential Hash Disclosure Probe"},
	{":69", "TFTP", "unauthenticated config download", "TFTP Config Theft Probe"},
	{":5060", "SIP", "SIP scanning / toll fraud (SIPVicious)", "VoIP Toll-Fraud Probe"},
	{":1434", "MSSQL Browser", "SQL Slammer-class / amplification", "MSSQL Browser Probe"},
	{":389", "CLDAP", "CLDAP amplification", "Amplification Vector Probe"},
	{":137", "NetBIOS Name Service", "name enumeration", "NetBIOS Enumeration Probe"},
	{":111", "RPC portmapper (UDP)", "rpcbind amplification", "Amplification Vector Probe"},
	{":5353", "mDNS", "mDNS amplification / information disclosure", "Amplification Vector Probe"},
	{":3702", "WS-Discovery", "CVE-2019-17066 / amplification", "Amplification Vector Probe"},
	{":427", "SLP", "CVE-2023-29552 amplification / CVE-2021-21974 (ESXi)", "Amplification Vector Probe"},
	{":1194", "OpenVPN", "VPN fingerprinting", "VPN Fingerprinting Probe"},
	{":500", "IKE", "IKE aggressive-mode PSK capture", "VPN Fingerprinting Probe"},
	{":17185", "VxWorks WDB debug agent", "CVE-2010-2965", "Embedded Debug Agent Probe"},
	{":47808", "BACnet", "building automation discovery", "Building Automation Probe"},
	{":10001", "Ubiquiti discovery", "device fingerprinting", "Device Discovery Probe"},
	{":5683", "CoAP", "IoT amplification / discovery", "IoT Discovery Probe"},
	{":177", "XDMCP", "open X display manager", "Remote Display Probe"},
	{":1812", "RADIUS", "shared-secret brute force", "RADIUS Probe"},
}

func smtpDecoyReply(l string) string {
	u := strings.ToUpper(strings.TrimSpace(l))
	switch {
	case u == "QUIT":
		return "221 Bye\r\n"
	case strings.HasPrefix(u, "DATA"):
		return "354 Enter message, ending with \".\" on a line by itself\r\n"
	case strings.HasPrefix(u, "EHLO"):
		return "250-mail.acme.local Hello\r\n250-SIZE 52428800\r\n250 HELP\r\n"
	}
	return "250 OK\r\n"
}

func init() {
	for _, d := range tcpDecoys {
		portAttackCategory[d.Port] = d.Category + " (" + d.CVEs + ")"
		servicePortName[d.Port] = d.Product
	}
	// UDP and TCP share port numbers in the lookup map; only fill gaps,
	// never overwrite a TCP entry. Done here (package init) because the
	// map is read concurrently once listeners start.
	for _, d := range udpDecoys {
		if _, ok := servicePortName[d.Port]; !ok {
			servicePortName[d.Port] = d.Product
		}
	}
}

func startCVETCPServices() {
	for _, d := range tcpDecoys {
		d := d
		ln, err := net.Listen("tcp", d.Port)
		if err != nil {
			log.Printf("CVE honeypot %s (%s) not started: %v", d.Port, d.Product, err)
			continue
		}
		go acceptLoop(ln, func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			src := conn.RemoteAddr().String()
			if d.Handler != nil {
				d.Handler(conn)
				return
			}
			if d.Banner != "" {
				conn.Write([]byte(d.Banner))
			}
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				line := sc.Text()
				log.Printf("%s sent %q to %s [T1190 Exploit Public-Facing Application | %s (%s)] dest=%s proto=tcp",
					src, truncate(line, 200), d.Product, d.Category, d.CVEs, ln.Addr())
				if d.Reply != nil {
					if resp := d.Reply(line); resp != "" {
						conn.Write([]byte(resp))
					}
				}
			}
		})
	}
}

func logBinary(conn net.Conn, d tcpDecoyInfo, n int, first []byte) {
	log.Printf("%s sent %d bytes %x [T1190 Exploit Public-Facing Application | %s (%s)] dest=%s proto=tcp",
		conn.RemoteAddr(), n, first, d.Category, d.CVEs, conn.LocalAddr())
}

type tcpDecoyInfo struct{ Category, CVEs string }

// handleJDWP: the real handshake is the client sending the 14-byte ASCII
// string "JDWP-Handshake" and the server echoing it back.
func handleJDWP(conn net.Conn) {
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	logBinary(conn, tcpDecoyInfo{"Remote Debugger RCE Attempt", "unauthenticated JDWP"}, n, buf[:min(n, 32)])
	if string(buf[:min(n, 14)]) == "JDWP-Handshake" {
		conn.Write([]byte("JDWP-Handshake"))
	}
}

// handleRMI answers the JRMI handshake (magic "JRMI", version, protocol)
// with ProtocolAck (0x4E) + the "server" host/port, which is what scanners
// (nmap rmi-dumpregistry, Metasploit) check for.
func handleRMI(conn net.Conn) {
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	logBinary(conn, tcpDecoyInfo{"Java RMI Deserialization Attempt", "CVE-2011-3556"}, n, buf[:min(n, 32)])
	if n >= 4 && string(buf[:4]) == "JRMI" {
		host := "10.0.4.23"
		resp := []byte{0x4E}
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(host)))
		resp = append(resp, host...)
		resp = binary.BigEndian.AppendUint32(resp, 0)
		conn.Write(resp)
	}
}

// handleAJP answers an AJP13 CPing (0x1234 len=1 0x0A) with CPong
// (0x4142 len=1 0x09) - what Ghostcat scanners use to confirm the
// connector is alive - and logs any forward-request that follows.
func handleAJP(conn net.Conn) {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	logBinary(conn, tcpDecoyInfo{"AJP File Read / RCE Attempt", "CVE-2020-1938"}, n, buf[:min(n, 48)])
	if n >= 5 && buf[0] == 0x12 && buf[1] == 0x34 && buf[4] == 0x0A {
		conn.Write([]byte{0x41, 0x42, 0x00, 0x01, 0x09})
		if m, _ := conn.Read(buf); m > 0 {
			logBinary(conn, tcpDecoyInfo{"AJP File Read / RCE Attempt", "CVE-2020-1938"}, m, buf[:min(m, 48)])
		}
	}
}

// handleSOCKS5 accepts "no authentication" from any client (the open
// proxy misconfiguration) and logs the CONNECT target requested, then
// refuses it - nothing is ever relayed.
func handleSOCKS5(conn net.Conn) {
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n >= 2 && buf[0] == 5 {
		conn.Write([]byte{5, 0})
		if m, _ := conn.Read(buf); m >= 7 {
			logBinary(conn, tcpDecoyInfo{"Open Proxy Abuse Attempt", "open SOCKS5 proxy"}, m, buf[:min(m, 48)])
			conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		}
		return
	}
	logBinary(conn, tcpDecoyInfo{"Open Proxy Abuse Attempt", "open SOCKS5 proxy"}, n, buf[:min(n, 32)])
}

func startCVEUDPServices() {
	for _, d := range udpDecoys {
		d := d
		conn, err := net.ListenPacket("udp", d.Port)
		if err != nil {
			log.Printf("CVE UDP honeypot %s (%s) not started: %v", d.Port, d.Product, err)
			continue
		}
		go func() {
			buf := make([]byte, 2048)
			for {
				n, raddr, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				runRecovered(d.Port, func() {
					log.Printf("%s sent %d bytes %x to %s [T1595.002 Active Scanning: Vulnerability Scanning | %s (%s) (no reply sent)] dest=%s proto=udp",
						raddr, n, buf[:min(n, 24)], d.Product, d.Category, d.CVEs, conn.LocalAddr())
				})
			}
		}()
	}
}
