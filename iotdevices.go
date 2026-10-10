package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// startIoTDeviceServices fakes the camera/DVR/printer side of the IoT
// exposure problem - the other half of the RTSP/MQTT/Modbus coverage in
// iotservices.go. Backed by current research: a campaign dubbed
// "CameraSwarm" compromised more than 14,530 Dahua cameras, NVRs, and
// DVRs between June and July 2026 via password guessing on port 37777
// plus two CVSS 9.8 auth-bypass CVEs (2021-33044/33045); a July 2026
// report described active scanning of Hikvision's ISAPI for endpoints
// like /ISAPI/Security/users, and more than 80,000 Hikvision cameras
// remain vulnerable to CVE-2021-36260 (pre-V5.5.0 firmware).
func startIoTDeviceServices() {
	startFakeHTTPService(":8070", handleFakeHikvisionISAPI)
	startFakeHTTPService(":8090", handleFakeDahuaLogin)
	startSilentService(":37777") // Dahua's proprietary DHIP protocol -
	// undocumented and binary; no trusted client library to verify a
	// fuller fake against, so left as open-port-only like MikroTik.
	startJetDirectService(":9100")
}

// handleFakeHikvisionISAPI mimics the real unauthenticated info
// disclosure behind CVE-2021-36260: deviceInfo, and the exact two
// endpoints (Security/users, Network/UPNP) the July 2026 report
// described being actively scanned for.
func handleFakeHikvisionISAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	switch r.URL.Path {
	case "/ISAPI/System/deviceInfo":
		log.Printf("%s Hikvision ISAPI deviceInfo requested (unauthenticated) [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IP Camera Device Info Disclosure Attempt]", r.RemoteAddr)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<deviceName>Network Camera</deviceName>
<deviceID>a1b2c3d4-0000-0000-0000-000000000001</deviceID>
<model>DS-2CD2032-I</model>
<serialNumber>DS-2CD2032-I20150107AAWR000000001</serialNumber>
<firmwareVersion>V5.3.0</firmwareVersion>
<firmwareReleasedDate>build 150107</firmwareReleasedDate>
</DeviceInfo>`)
	case "/ISAPI/Security/users":
		log.Printf("%s Hikvision ISAPI user enumeration attempt (unauthenticated) [T1087 Account Discovery | Unauthenticated IP Camera Account Enumeration Attempt]", r.RemoteAddr)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<UserList version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<User><id>1</id><userName>admin</userName><userLevel>Administrator</userLevel></User>
</UserList>`)
	case "/ISAPI/System/Network/UPNP":
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<UPnP version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<enabled>true</enabled>
</UPnP>`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func handleFakeDahuaLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>NetSurveillance WEB</title></head>
<body><h1>Dahua NetSurveillance WEB</h1>
<form method="post">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button>Login</button>
</form>
<p><small>DH_IPC-HFW4431R-Z, firmware V2.420.0000.0.R, build 2017-03-22</small></p>
</body></html>`)
}

// startJetDirectService models the real behavior of raw/JetDirect
// network printing (port 9100): it's a pure data sink with no
// handshake or response at all - a real printer just accepts whatever
// PostScript/PCL/raw bytes arrive and prints them. There's nothing to
// parse or reply to; logging the contact itself is the whole finding.
func startJetDirectService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			log.Printf("%s sent %d bytes of raw print data with no authentication [T1565.001 Data Manipulation: Stored Data Manipulation | Unauthenticated Network Printer Access Attempt]", conn.RemoteAddr(), n)
		}
	})
}
