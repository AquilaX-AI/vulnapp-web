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

// initLogging composes every configured log sink - stderr always, plus
// syslog and/or OneFirewall threat-intel reporting if their env vars are
// set - into the one io.Writer Go's standard log package uses. Every
// existing log.Printf call site in this codebase - no per-call-site
// changes needed - reaches all of them. With nothing configured, logging
// behaves exactly as before (stderr only).
func initLogging() {
	writers := []io.Writer{os.Stderr}
	var enabled []string

	if w, desc := syslogOutput(); w != nil {
		writers = append(writers, w)
		enabled = append(enabled, desc)
	}
	if w, desc := oneFirewallOutput(); w != nil {
		writers = append(writers, w)
		enabled = append(enabled, desc)
	}

	if len(writers) > 1 {
		log.SetOutput(io.MultiWriter(writers...))
		log.Printf("logging sinks enabled: %s (instance id %s)", strings.Join(enabled, ", "), instanceID)
	}
}

// syslogOutput returns a writer forwarding to a real syslog (RFC 5424)
// destination if SYSLOG_ADDR is set, or (nil, "") if it isn't.
func syslogOutput() (io.Writer, string) {
	addr := os.Getenv("SYSLOG_ADDR")
	if addr == "" {
		return nil, ""
	}
	proto := getenvDefault("SYSLOG_PROTO", "udp")

	conn, err := net.Dial(proto, addr)
	if err != nil {
		log.Printf("syslog forwarding to %s not started: %v", addr, err)
		return nil, ""
	}

	return &syslogWriter{conn: conn}, fmt.Sprintf("syslog(%s://%s)", proto, addr)
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

	// Always report success to the caller regardless of whether the
	// write actually reached the syslog server: this writer sits inside
	// an io.MultiWriter alongside stderr and (optionally) the
	// OneFirewall reporter in initLogging, and MultiWriter aborts every
	// remaining writer the moment any one of them returns an error. A
	// dead syslog connection should never silently take logging (or
	// OneFirewall reporting) down with it.
	w.conn.Write([]byte(formatted))
	return len(p), nil
}
