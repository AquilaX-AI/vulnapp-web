package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

// startICSServices fakes two more industrial/OT protocols beyond
// Modbus (iotservices.go), chosen for how current the evidence is:
//
//   - S7comm (port 102): a joint NSA/CISA/FBI/DOE/EPA advisory
//     (AA26-231A, Aug 2026) warned that unattributed actors are using
//     AI-written scripts against internet-exposed Siemens S7-200
//     through S7-1500 PLCs, with "take any S7 PLC reachable on public
//     port 102 offline immediately" as its first recommendation. Modat
//     found 7,435 exposed S7 services the day after the advisory.
//   - OPC UA (port 4840): Bitsight's exposure snapshot found 14,220
//     internet-reachable OPC UA devices, 7,358 of them accepting
//     anonymous connections with no credentials at all.
func startICSServices() {
	startS7CommService(":102")
	startOPCUAService(":4840")
}

// --- S7comm: TPKT (RFC1006) + COTP (ISO 8073) + S7 "Setup Communication" ---
//
// Verified against python-snap7 (the real library snap7 wraps)
// completing a full client.connect() - not just a banner guess.

func startS7CommService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleS7Conn)
}

func handleS7Conn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// --- COTP Connection Request/Confirm ---
	cotpCR, ok := readTPKT(conn)
	if !ok || len(cotpCR) < 7 || cotpCR[1] != 0xe0 { // 0xe0 = CR TPDU
		return
	}
	srcRef := cotpCR[4:6]  // client's source reference
	variable := cotpCR[7:] // TPDU-size/TSAP parameters - echoed back as-is

	cc := []byte{0xd0}           // CC TPDU
	cc = append(cc, srcRef...)   // dst-ref = their src-ref (what we call them)
	cc = append(cc, 0x00, 0x01)  // src-ref = ours
	cc = append(cc, 0x00)        // class/options
	cc = append(cc, variable...) // echo the same TPDU-size/TSAP params
	cotpBody := append([]byte{byte(len(cc))}, cc...)
	writeTPKT(conn, cotpBody)

	log.Printf("%s S7comm/COTP connection established with no authentication [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated ICS/SCADA (Siemens S7) Access Attempt]", conn.RemoteAddr())

	// --- S7 "Setup Communication" ---
	dt, ok := readTPKT(conn)
	if !ok || len(dt) < 3 || dt[1] != 0xf0 { // 0xf0 = DT TPDU
		return
	}
	s7 := dt[3:] // S7 header follows the 3-byte COTP DT header
	if len(s7) < 10 || s7[0] != 0x32 {
		return
	}
	pduRef := s7[4:6]

	log.Printf("%s S7 Setup Communication accepted [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated ICS/SCADA (Siemens S7) Access Attempt]", conn.RemoteAddr())

	ack := []byte{0x32, 0x03, 0x00, 0x00}
	ack = append(ack, pduRef...)
	ack = append(ack, 0x00, 0x08) // parameter length = 8
	ack = append(ack, 0x00, 0x00) // data length = 0
	ack = append(ack, 0x00, 0x00) // error class, error code
	ack = append(ack, 0xf0, 0x00) // function = Setup Communication, reserved
	ack = append(ack, 0x00, 0x01) // max AMQ caller
	ack = append(ack, 0x00, 0x01) // max AMQ callee
	ack = append(ack, 0x01, 0xe0) // negotiated PDU length (480)

	cotpData := append([]byte{0x02, 0xf0, 0x80}, ack...) // DT header: LI, type, EOT
	writeTPKT(conn, cotpData)

	// A real S7 session stays open after Setup Communication for
	// subsequent read/write requests - closing immediately here was an
	// early bug this exact fake caught during testing: snap7 received a
	// byte-correct handshake but still reported itself disconnected,
	// because the connection dropped right after. Keep reading (and
	// extending the deadline) so the session looks genuinely alive;
	// nothing beyond Setup Communication is implemented, so anything
	// further just gets drained and ignored.
	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func readTPKT(conn net.Conn) ([]byte, bool) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x03 {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 4 || length > 4096 {
		return nil, false
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, false
	}
	return body, true
}

func writeTPKT(conn net.Conn, body []byte) {
	header := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(header[2:4], uint16(len(body)+4))
	conn.Write(header)
	conn.Write(body)
}

// --- OPC UA: UACP "Hello"/"Acknowledge" ---
//
// Deliberately scoped to just the Hello/Acknowledge handshake, not a
// full session - a real client's next steps (OpenSecureChannel,
// CreateSession, ActivateSession) involve certificate/nonce exchange
// and extension-object encoding substantially more complex than
// Modbus or even S7comm above. That's also honestly the level mass
// internet-wide scanners (the kind behind Bitsight's exposure counts)
// actually check: "does this port speak real UACP and send back a
// valid Acknowledge", not a fully authenticated session. Tested with
// asyncua's real Client.connect(): it accepted our Acknowledge with no
// protocol/decode error and progressed to sending OpenSecureChannel
// (then timed out waiting for a reply, since that part isn't
// implemented) - good evidence the handshake itself is byte-correct,
// short of claiming more fidelity than this actually has.

func startOPCUAService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleOPCUAConn)
}

func handleOPCUAConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if string(header[0:3]) != "HEL" {
		return
	}
	messageSize := binary.LittleEndian.Uint32(header[4:8])
	if messageSize < 8 || messageSize > 1<<16 {
		return
	}
	rest := make([]byte, messageSize-8)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return
	}

	log.Printf("%s OPC UA Hello accepted with no authentication [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated OPC UA Server Access Attempt]", conn.RemoteAddr())

	// ACK message body: protocolVersion, receiveBufferSize,
	// sendBufferSize, maxMessageSize, maxChunkCount (all UInt32, LE).
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 0)       // protocol version
	binary.LittleEndian.PutUint32(body[4:8], 65536)   // receive buffer size
	binary.LittleEndian.PutUint32(body[8:12], 65536)  // send buffer size
	binary.LittleEndian.PutUint32(body[12:16], 1<<20) // max message size
	binary.LittleEndian.PutUint32(body[16:20], 0)     // max chunk count (0 = unlimited)

	msg := make([]byte, 8+len(body))
	copy(msg[0:3], "ACK")
	msg[3] = 'F'
	binary.LittleEndian.PutUint32(msg[4:8], uint32(len(msg)))
	copy(msg[8:], body)
	conn.Write(msg)

	// Same lesson as S7comm above: a real OPC UA client immediately
	// follows Hello/Acknowledge with OpenSecureChannel and CreateSession
	// requests on the same connection - closing right after the
	// handshake here made a real client (asyncua) see the connection
	// drop and report "connection lost" even though the handshake bytes
	// themselves were correct. Nothing past Hello/Acknowledge is
	// implemented, so just keep draining whatever follows.
	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
