package main

import (
	"log"
	"net"
)

// startUDPServices listens on a handful of classic DDoS-amplification-
// vector UDP ports (SNMP, NTP, memcached, SSDP, chargen) purely to
// detect and log probe/abuse attempts - never to actually provide
// meaningful amplification. Unlike every TCP fake service in this repo,
// these intentionally do NOT send a large reply for a small request:
// UDP has no handshake, so the source address on any packet we receive
// could be spoofed, and a real amplifying reply would make this host a
// usable DDoS reflector against whoever that spoofed address actually
// belongs to - a real third party, not just this test box. So: log
// everything, and either stay completely silent (NTP/memcached/SSDP/
// chargen) or reply with something deliberately no larger than a
// typical request (SNMP, where the reply itself is the signal a
// scanner is checking for).
func startUDPServices() {
	startSNMPService(":161")
	startNTPService(":123")
	startUDPLogOnlyService(":11211", "memcached (UDP)")
	startUDPLogOnlyService(":1900", "SSDP/UPnP")
	startUDPLogOnlyService(":19", "chargen")
}

func startUDPLogOnlyService(addr, label string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("fake UDP service %s not started: %v", addr, err)
		return
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Printf("%s sent %d bytes to %s (%s) [T1498.002 Network Denial of Service: Reflection Amplification | Amplification Vector Probe (no reply sent)]",
				raddr, n, conn.LocalAddr(), label)
		}
	}()
}

// startNTPService detects NTP mode-7 (private/control) requests - the
// shape of the real monlist request behind CVE-2013-5211, one of the
// largest amplification-DDoS vectors ever found - and logs them. No
// reply is ever sent; see the package-level comment above for why.
func startNTPService(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("fake UDP service %s not started: %v", addr, err)
		return
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 1 {
				continue
			}
			mode := buf[0] & 0x07
			if mode == 7 {
				log.Printf("%s NTP mode-7 (private/monlist-class) request [T1498.002 Network Denial of Service: Reflection Amplification | NTP monlist (CVE-2013-5211) Amplification Probe (no reply sent)]", raddr)
			} else {
				log.Printf("%s NTP request, mode %d [T1595.002 Active Scanning: Vulnerability Scanning | NTP Service Probe (no reply sent)]", raddr, mode)
			}
		}
	}()
}

// startSNMPService responds to SNMP v1/v2c GetRequest PDUs with a small,
// fixed sysDescr value - enough to confirm the community string works
// (the actual recon signal: "does 'public' get accepted"), but
// deliberately not larger than the request, so there's no exploitable
// amplification factor here even though SNMP replies can legitimately
// be used that way against misconfigured real devices.
func startSNMPService(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("fake UDP service %s not started: %v", addr, err)
		return
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			community, requestID, ok := parseSNMPRequest(buf[:n])
			if !ok {
				continue
			}
			log.Printf("%s SNMP GetRequest community=%q [T1595.002 Active Scanning: Vulnerability Scanning | SNMP Default Community String Probe]", raddr, community)
			resp := buildSNMPResponse(community, requestID)
			conn.WriteTo(resp, raddr)
		}
	}()
}

// --- minimal BER (ASN.1) encode/decode, just enough for SNMP v1/v2c ---

// berReadTLV reads one tag-length-value triplet. Only short-form
// (<128 byte) lengths are supported - plenty for the small SNMP
// GetRequest packets real scanners send; anything else is rejected
// rather than guessed at.
func berReadTLV(data []byte, offset int) (tag byte, value []byte, next int, ok bool) {
	if offset+2 > len(data) {
		return 0, nil, 0, false
	}
	tag = data[offset]
	length := int(data[offset+1])
	if length&0x80 != 0 {
		return 0, nil, 0, false
	}
	start := offset + 2
	if start+length > len(data) {
		return 0, nil, 0, false
	}
	return tag, data[start : start+length], start + length, true
}

func parseSNMPRequest(data []byte) (community string, requestID []byte, ok bool) {
	_, seq, _, ok := berReadTLV(data, 0) // outer SEQUENCE
	if !ok {
		return "", nil, false
	}
	_, _, off, ok := berReadTLV(seq, 0) // version INTEGER
	if !ok {
		return "", nil, false
	}
	_, commBytes, off, ok := berReadTLV(seq, off) // community OCTET STRING
	if !ok {
		return "", nil, false
	}
	pduTag, pdu, _, ok := berReadTLV(seq, off) // PDU: GetRequest(0xA0)/GetNextRequest(0xA1)
	if !ok || (pduTag != 0xA0 && pduTag != 0xA1) {
		return "", nil, false
	}
	_, reqID, _, ok := berReadTLV(pdu, 0) // request-id INTEGER
	if !ok {
		return "", nil, false
	}
	return string(commBytes), reqID, true
}

func berEncode(tag byte, content []byte) []byte {
	return append([]byte{tag, byte(len(content))}, content...)
}

func buildSNMPResponse(community string, requestID []byte) []byte {
	sysDescr := "Linux acme-web01 4.4.0-104-generic #126-Ubuntu SMP x86_64"
	sysDescrOID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0

	varBind := berEncode(0x30, append(berEncode(0x06, sysDescrOID), berEncode(0x04, []byte(sysDescr))...))
	varBindList := berEncode(0x30, varBind)

	var pdu []byte
	pdu = append(pdu, berEncode(0x02, requestID)...)
	pdu = append(pdu, berEncode(0x02, []byte{0x00})...) // error-status = 0
	pdu = append(pdu, berEncode(0x02, []byte{0x00})...) // error-index = 0
	pdu = append(pdu, varBindList...)
	pduEncoded := berEncode(0xA2, pdu) // GetResponse-PDU

	var msg []byte
	msg = append(msg, berEncode(0x02, []byte{0x00})...) // version = 0 (SNMPv1)
	msg = append(msg, berEncode(0x04, []byte(community))...)
	msg = append(msg, pduEncoded...)
	return berEncode(0x30, msg)
}
