package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// startDNSAXFRService fakes a nameserver that allows unauthenticated
// zone transfers (AXFR) - a classic, specific DNS misconfiguration: a
// server that's supposed to only transfer zones to its secondaries
// instead hands the whole zone to anyone who asks (`dig axfr <zone>
// @host`). Whatever zone name a client requests, it gets back a
// believable internal zone reusing the same fake hostnames/IPs already
// leaked elsewhere in this app (/api/config, /internal/metadata), so an
// AXFR here is a genuine recon payoff, not just a port being open.
// Non-AXFR queries get REFUSED - that's not what this port demonstrates.
func startDNSAXFRService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleDNSConn)
}

func handleDNSConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	if msgLen < 12 || msgLen > 4096 {
		return
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}

	id := msg[0:2]
	qname, qtype, ok := parseDNSQuestion(msg)
	if !ok {
		return
	}

	const typeAXFR = 252

	if qtype != typeAXFR {
		resp := dnsHeader(id, 5 /* REFUSED */, 1, 0, 0, 0)
		resp = append(resp, encodeDomainName(qname)...)
		resp = append(resp, uint16Bytes(qtype)...)
		resp = append(resp, uint16Bytes(1)...) // CLASS=IN
		writeTCPDNSMessage(conn, resp)
		return
	}

	log.Printf("%s DNS AXFR request for zone %q [T1018 Remote System Discovery]", conn.RemoteAddr(), qname)

	records := buildFakeZoneRecords(qname)
	resp := dnsHeader(id, 0, 1, uint16(len(records)), 0, 0)
	resp = append(resp, encodeDomainName(qname)...)
	resp = append(resp, uint16Bytes(typeAXFR)...)
	resp = append(resp, uint16Bytes(1)...) // CLASS=IN
	for _, rr := range records {
		resp = append(resp, rr...)
	}
	writeTCPDNSMessage(conn, resp)
}

func writeTCPDNSMessage(conn net.Conn, msg []byte) {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
	conn.Write(lenBuf)
	conn.Write(msg)
}

// dnsHeader builds a 12-byte DNS message header with QR=1 (response)
// and AA=1 (authoritative) set, and the given RCODE/section counts.
func dnsHeader(id []byte, rcode int, qd, an, ns, ar uint16) []byte {
	h := make([]byte, 12)
	copy(h[0:2], id)
	flags := uint16(0x8400) | uint16(rcode)
	binary.BigEndian.PutUint16(h[2:4], flags)
	binary.BigEndian.PutUint16(h[4:6], qd)
	binary.BigEndian.PutUint16(h[6:8], an)
	binary.BigEndian.PutUint16(h[8:10], ns)
	binary.BigEndian.PutUint16(h[10:12], ar)
	return h
}

func parseDNSQuestion(msg []byte) (qname string, qtype uint16, ok bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) < 1 {
		return "", 0, false
	}
	offset := 12
	var labels []string
	for offset < len(msg) {
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if offset+length > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(msg) {
		return "", 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[offset : offset+2])
	return strings.Join(labels, "."), qtype, true
}

func encodeDomainName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0x00)
}

func uint16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func buildRR(name string, rrtype uint16, rdata []byte) []byte {
	rr := encodeDomainName(name)
	rr = append(rr, uint16Bytes(rrtype)...)
	rr = append(rr, uint16Bytes(1)...) // CLASS=IN
	rr = append(rr, uint32Bytes(3600)...)
	rr = append(rr, uint16Bytes(uint16(len(rdata)))...)
	return append(rr, rdata...)
}

// buildFakeZoneRecords returns a believable internal zone for whatever
// name the client asked to transfer, reusing the same fake internal IPs
// (10.0.4.23, 192.168.56.10) already leaked by /api/config and the
// kubelet/Consul/Eureka fakes - so a tester who's already seen those
// gets the same story confirmed from a second, independent angle.
func buildFakeZoneRecords(zone string) [][]byte {
	if zone == "" {
		zone = "acme-supplies.internal"
	}

	soaRdata := encodeDomainName("ns1." + zone)
	soaRdata = append(soaRdata, encodeDomainName("hostmaster."+zone)...)
	soaRdata = append(soaRdata, uint32Bytes(2024010101)...) // serial
	soaRdata = append(soaRdata, uint32Bytes(3600)...)       // refresh
	soaRdata = append(soaRdata, uint32Bytes(600)...)        // retry
	soaRdata = append(soaRdata, uint32Bytes(604800)...)     // expire
	soaRdata = append(soaRdata, uint32Bytes(86400)...)      // minimum

	mxRdata := append(uint16Bytes(10), encodeDomainName("mail."+zone)...)

	return [][]byte{
		buildRR(zone, 6, soaRdata),                                      // SOA
		buildRR(zone, 2, encodeDomainName("ns1."+zone)),                 // NS
		buildRR(zone, 15, mxRdata),                                      // MX
		buildRR("mail."+zone, 1, net.ParseIP("10.0.4.23").To4()),        // A
		buildRR("db."+zone, 1, net.ParseIP("10.0.4.23").To4()),          // A
		buildRR("vpn."+zone, 1, net.ParseIP("192.168.56.10").To4()),     // A
		buildRR("ns1."+zone, 1, net.ParseIP("192.168.56.10").To4()),     // A
		buildRR(zone, 6, soaRdata),                                      // closing SOA (AXFR convention)
	}
}
