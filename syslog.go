package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// instanceID is a random, stable-per-run identifier used in place of
// this deployment's real hostname anywhere a log line might be exported
// or shared - e.g. with a threat-intel feed. It lets an analyst tell
// "these events came from the same honeypot instance" without that
// identifier revealing which instance, or who runs it, or where.
var instanceID = generateInstanceID()

func generateInstanceID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "vulnapp-unknown"
	}
	return "vulnapp-" + hex.EncodeToString(b)
}

// initSyslog wires a real syslog (RFC 5424) forwarder into Go's standard
// log package if SYSLOG_ADDR is set, so every existing log.Printf call
// in this codebase - no per-call-site changes needed - also reaches a
// real syslog/SIEM destination, in addition to stderr. Disabled by
// default: with no SYSLOG_ADDR, logging behaves exactly as before.
func initSyslog() {
	addr := os.Getenv("SYSLOG_ADDR")
	if addr == "" {
		return
	}
	proto := getenvDefault("SYSLOG_PROTO", "udp")

	conn, err := net.Dial(proto, addr)
	if err != nil {
		log.Printf("syslog forwarding to %s not started: %v", addr, err)
		return
	}

	log.SetOutput(io.MultiWriter(os.Stderr, &syslogWriter{conn: conn}))
	log.Printf("syslog forwarding enabled: %s://%s (instance id %s)", proto, addr, instanceID)
}

type syslogWriter struct {
	conn net.Conn
}

// Write formats one RFC 5424 message per call. Go's log package calls
// Write once per log.Printf/Print/Println with the full formatted line
// (including the trailing newline stripped here), so this maps cleanly
// onto "one syslog message per log line". The HOSTNAME field is
// instanceID, never this process's real hostname - that's the
// anonymization: every other field describes the attacker and what
// they did, not which deployment logged it.
func (w *syslogWriter) Write(p []byte) (int, error) {
	const (
		facility = 4 // security/authorization messages
		severity = 5 // notice
	)
	pri := facility*8 + severity
	msg := strings.TrimRight(string(p), "\n")
	timestamp := time.Now().UTC().Format(time.RFC3339)

	formatted := fmt.Sprintf("<%d>1 %s %s vulnapp-web %d - - %s\n",
		pri, timestamp, instanceID, os.Getpid(), msg)

	if _, err := w.conn.Write([]byte(formatted)); err != nil {
		return 0, err
	}
	return len(p), nil
}
