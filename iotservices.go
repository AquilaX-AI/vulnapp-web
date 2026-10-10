package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// startIoTServices fakes the protocol families actually driving most
// internet-wide IoT/ICS scanning traffic in 2026, based on current
// research rather than guesswork:
//
//   - MQTT: a near-ubiquitous IoT messaging protocol frequently
//     deployed with no authentication at all, leaking smart-home and
//     industrial telemetry to anyone who connects.
//   - Modbus TCP: has no authentication mechanism in the protocol
//     itself - Shadowserver's daily scans found 6,300+ exposed
//     instances, and a 2026 Cyble scan confirmed ~179 real-world
//     industrial devices on port 502 after filtering honeypots.
//   - RTSP: Modat's March 2026 scan found 973,819 active RTSP services,
//     with 8,074 yielding an unauthenticated frame - including feeds
//     co-located with SCADA dashboards and power infrastructure.
//   - DICOM: TrendAI/Rapid7 research in early 2026 found 3,627
//     internet-reachable medical imaging servers, 99.56% accepting
//     connections with no AE-Title validation at all.
func startIoTServices() {
	startMQTTService(":1883")
	startModbusService(":502")
	startRTSPService(":554")
	startDICOMService(":104")
	startDICOMService(":11112") // common alternate DICOM port
}

// startMQTTService answers a real MQTT CONNECT packet with CONNACK
// "accepted" - MQTT 3.1.1's CONNACK is a fixed 4-byte reply, so there's
// no ambiguity in what a correct response looks like. Verified against
// a real client (paho-mqtt) completing a full connect/subscribe/publish
// round trip.
func startMQTTService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleMQTTConn)
}

func handleMQTTConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Fixed header: 1 byte (packet type << 4 | flags) + variable-length
	// remaining-length field (1-4 bytes, MQTT's standard varint).
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	packetType := header[0] >> 4
	if packetType != 1 { // CONNECT
		return
	}
	remainingLen, ok := readMQTTVarint(conn)
	if !ok {
		return
	}
	payload := make([]byte, remainingLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}

	log.Printf("%s MQTT CONNECT accepted with no authentication [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IoT Message Broker Access Attempt]", conn.RemoteAddr())

	// CONNACK: packet type 0x20, remaining length 2, session-present=0,
	// return code 0 (accepted).
	conn.Write([]byte{0x20, 0x02, 0x00, 0x00})

	// Log any PUBLISH/SUBSCRIBE that follows - topics on a real broker
	// often reveal exactly what the device/system does.
	for {
		h := make([]byte, 1)
		if _, err := io.ReadFull(conn, h); err != nil {
			return
		}
		pType := h[0] >> 4
		length, ok := readMQTTVarint(conn)
		if !ok {
			return
		}
		body := make([]byte, length)
		io.ReadFull(conn, body)
		switch pType {
		case 3: // PUBLISH
			log.Printf("%s MQTT PUBLISH received (topic/payload accepted with no auth) [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IoT Telemetry Access Attempt]", conn.RemoteAddr())
		case 8: // SUBSCRIBE
			log.Printf("%s MQTT SUBSCRIBE received [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IoT Telemetry Access Attempt]", conn.RemoteAddr())
			// SUBACK: echo packet id, grant QoS 0 for one topic filter.
			pktID := []byte{0x00, 0x01}
			if length >= 2 {
				pktID = body[0:2]
			}
			resp := append([]byte{0x90, 0x03}, pktID...)
			resp = append(resp, 0x00)
			conn.Write(resp)
		case 12: // PINGREQ
			conn.Write([]byte{0xd0, 0x00}) // PINGRESP
		case 14: // DISCONNECT
			return
		}
	}
}

func readMQTTVarint(r io.Reader) (int, bool) {
	value := 0
	multiplier := 1
	for i := 0; i < 4; i++ {
		b := make([]byte, 1)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, false
		}
		value += int(b[0]&0x7f) * multiplier
		if b[0]&0x80 == 0 {
			return value, true
		}
		multiplier *= 128
	}
	return 0, false
}

// startModbusService answers Modbus TCP read requests with fake
// register data - the actual vulnerability, not just an open port:
// Modbus has no authentication mechanism in the protocol at all, so
// anyone who can reach the port can read (and on a real device, write)
// process data directly.
func startModbusService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleModbusConn)
}

func handleModbusConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	for {
		// MBAP header: transaction ID(2), protocol ID(2), length(2), unit ID(1).
		header := make([]byte, 7)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		transactionID := header[0:2]
		pduLen := int(binary.BigEndian.Uint16(header[4:6])) - 1
		if pduLen < 1 || pduLen > 252 {
			return
		}
		pdu := make([]byte, pduLen)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			return
		}
		functionCode := pdu[0]

		log.Printf("%s Modbus request, function code %d, no authentication [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated ICS/SCADA Read-Write Attempt]", conn.RemoteAddr(), functionCode)

		switch functionCode {
		case 0x03, 0x04: // Read Holding/Input Registers
			if len(pdu) < 5 {
				return
			}
			quantity := int(binary.BigEndian.Uint16(pdu[3:5]))
			if quantity < 1 || quantity > 125 {
				quantity = 2
			}
			data := make([]byte, quantity*2)
			for i := 0; i < quantity; i++ {
				binary.BigEndian.PutUint16(data[i*2:], uint16(1000+i)) // plausible fake process values
			}
			resp := append([]byte{functionCode, byte(len(data))}, data...)
			writeModbusResponse(conn, transactionID, header[6], resp)
		default:
			// Echo back as an exception response (illegal function) -
			// still confirms the port is a live, unauthenticated Modbus
			// device.
			resp := []byte{functionCode | 0x80, 0x01}
			writeModbusResponse(conn, transactionID, header[6], resp)
		}
	}
}

func writeModbusResponse(conn net.Conn, transactionID []byte, unitID byte, pdu []byte) {
	length := len(pdu) + 1
	msg := make([]byte, 0, 7+len(pdu))
	msg = append(msg, transactionID...)
	msg = append(msg, 0x00, 0x00) // protocol ID
	msg = append(msg, byte(length>>8), byte(length))
	msg = append(msg, unitID)
	msg = append(msg, pdu...)
	conn.Write(msg)
}

// startRTSPService answers real RTSP/1.0 requests (RFC 2326, a text
// protocol much like HTTP). OPTIONS/DESCRIBE/SETUP all succeed with no
// authentication challenge at all - that's the actual finding Modat's
// 2026 internet-wide scan methodology checks for (an unauthenticated
// stream description/session, not necessarily decoding real video).
func startRTSPService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleRTSPConn)
}

func handleRTSPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	reader := bufio.NewReader(conn)
	for {
		requestLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		requestLine = strings.TrimRight(requestLine, "\r\n")
		if requestLine == "" {
			continue
		}
		fields := strings.Fields(requestLine)
		if len(fields) < 2 {
			return
		}
		method := fields[0]

		cseq := "1"
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "cseq") {
				cseq = strings.TrimSpace(v)
			}
		}

		switch method {
		case "OPTIONS":
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS\r\n\r\n", cseq)
		case "DESCRIBE":
			log.Printf("%s RTSP DESCRIBE - unauthenticated camera stream description served [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IP Camera Access Attempt]", conn.RemoteAddr())
			sdp := "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Camera1 - Front Door\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Base: rtsp://%s/\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", cseq, conn.LocalAddr(), len(sdp), sdp)
		case "SETUP":
			log.Printf("%s RTSP SETUP - stream session established with no authentication [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated IP Camera Access Attempt]", conn.RemoteAddr())
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 1234567890\r\nTransport: RTP/AVP;unicast;client_port=50000-50001\r\n\r\n", cseq)
		case "TEARDOWN":
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\n\r\n", cseq)
			return
		default:
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\n\r\n", cseq)
		}
	}
}

// startDICOMService implements enough of the real DICOM Upper Layer
// Protocol (PS3.8) association handshake to confirm the actual finding
// TrendAI/Rapid7's 2026 research checks for: a medical imaging server
// that completes a real DICOM association with no AE-Title validation
// or authentication of any kind. Verified against pynetdicom (a real
// DICOM toolkit) completing a genuine association negotiation.
func startDICOMService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleDICOMConn)
}

func handleDICOMConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	pduType, pdu, ok := readDICOMPDU(conn)
	if !ok || pduType != 0x01 || len(pdu) < 68 { // A-ASSOCIATE-RQ, with a full fixed header
		return
	}

	callingAE := "UNKNOWN"
	if len(pdu) >= 36 {
		callingAE = strings.TrimSpace(string(pdu[20:36]))
	}
	log.Printf("%s DICOM A-ASSOCIATE-RQ accepted with no AE-Title validation (calling AE %q) [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated Medical Imaging (DICOM) Server Access Attempt]", conn.RemoteAddr(), callingAE)

	presentationContexts := parseDICOMPresentationContexts(pdu)
	ac := buildDICOMAssociateAC(pdu, presentationContexts)
	conn.Write(ac)

	// A real association would continue with DIMSE commands (e.g.
	// C-ECHO, C-FIND, C-STORE) over this association; this fake stops
	// at a successfully negotiated association, which is already the
	// finding the research above is about.
}

const (
	dicomImplicitVRLittleEndian = "1.2.840.10008.1.2"
	dicomApplicationContextUID  = "1.2.840.10008.3.1.1.1"
)

func readDICOMPDU(conn net.Conn) (pduType byte, data []byte, ok bool) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, false
	}
	pduType = header[0]
	length := binary.BigEndian.Uint32(header[2:6])
	if length > 1<<20 {
		return 0, nil, false
	}
	data = make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return 0, nil, false
	}
	return pduType, data, true
}

type dicomPresentationContext struct {
	id             byte
	transferSyntax string
}

// parseDICOMPresentationContexts walks the variable items following the
// fixed 68-byte header of an A-ASSOCIATE-RQ, picking out each proposed
// presentation context's ID and its first offered transfer syntax -
// enough to build a matching accept response.
func parseDICOMPresentationContexts(pdu []byte) []dicomPresentationContext {
	var contexts []dicomPresentationContext
	if len(pdu) < 68 {
		return contexts
	}
	offset := 68
	for offset+4 <= len(pdu) {
		itemType := pdu[offset]
		itemLen := int(binary.BigEndian.Uint16(pdu[offset+2 : offset+4]))
		itemStart := offset + 4
		if itemStart+itemLen > len(pdu) {
			break
		}
		item := pdu[itemStart : itemStart+itemLen]

		if itemType == 0x20 && len(item) >= 4 { // Presentation Context Item
			ctxID := item[0]
			var transferSyntax string
			subOffset := 4
			for subOffset+4 <= len(item) {
				subType := item[subOffset]
				subLen := int(binary.BigEndian.Uint16(item[subOffset+2 : subOffset+4]))
				subStart := subOffset + 4
				if subStart+subLen > len(item) {
					break
				}
				if subType == 0x40 && transferSyntax == "" { // first Transfer Syntax offered
					transferSyntax = strings.TrimRight(string(item[subStart:subStart+subLen]), "\x00")
				}
				subOffset = subStart + subLen
			}
			if transferSyntax == "" {
				transferSyntax = dicomImplicitVRLittleEndian
			}
			contexts = append(contexts, dicomPresentationContext{id: ctxID, transferSyntax: transferSyntax})
		}
		offset = itemStart + itemLen
	}
	return contexts
}

// buildDICOMAssociateAC builds an A-ASSOCIATE-AC that accepts every
// presentation context the client proposed, echoing back its own first
// offered transfer syntax - the simplest response a real client will
// reliably treat as a fully negotiated, usable association.
// buildDICOMAssociateAC expects rq to be the A-ASSOCIATE-RQ's content
// *after* the 6-byte outer PDU header (type/reserved/length) has already
// been stripped off by readDICOMPDU - so protocol version starts at
// rq[0], not rq[6].
func buildDICOMAssociateAC(rq []byte, contexts []dicomPresentationContext) []byte {
	var body []byte
	body = append(body, rq[0:4]...)   // protocol version (2) + reserved (2)
	body = append(body, rq[4:20]...)  // called AE title (16 bytes) - echoed
	body = append(body, rq[20:36]...) // calling AE title (16 bytes) - echoed
	body = append(body, make([]byte, 32)...)

	body = append(body, dicomItem(0x10, []byte(dicomApplicationContextUID))...)

	for _, ctx := range contexts {
		transferSyntaxItem := dicomItem(0x40, []byte(ctx.transferSyntax))
		pcBody := []byte{ctx.id, 0x00, 0x00, 0x00} // id, reserved, result=0 (accepted), reserved
		pcBody = append(pcBody, transferSyntaxItem...)
		body = append(body, dicomItem(0x21, pcBody)...)
	}

	userInfo := dicomItem(0x51, []byte{0x00, 0x00, 0x40, 0x00}) // max PDU length = 16384
	userInfo = append(userInfo, dicomItem(0x52, []byte("1.2.40.0.13.1.1"))...)
	body = append(body, dicomItem(0x50, userInfo)...)

	pdu := make([]byte, 0, 6+len(body))
	pdu = append(pdu, 0x02, 0x00) // A-ASSOCIATE-AC
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(body)))
	pdu = append(pdu, lengthBytes...)
	pdu = append(pdu, body...)
	return pdu
}

func dicomItem(itemType byte, value []byte) []byte {
	item := []byte{itemType, 0x00, byte(len(value) >> 8), byte(len(value))}
	return append(item, value...)
}
