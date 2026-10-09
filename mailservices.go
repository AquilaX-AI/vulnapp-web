package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// startMailServices fakes the mail stack an MX record would point at:
// SMTP (plus the submission/SMTPS ports), IMAP, and POP3. Each one
// models a specific, real misconfiguration class - not just "the port is
// open" - the same way the FTP/Telnet fakes in fakeservices.go do.
func startMailServices() {
	startSMTPService(":25")  // MTA / what the MX record points at
	startSMTPService(":587") // submission
	startSMTPService(":465") // "SMTPS" - plaintext fake, no real TLS either way

	startIMAPService(":143")
	startBannerService(":993", "* OK Dovecot ready.\r\n", nil) // IMAPS: banner only

	startPOP3Service(":110")
	startBannerService(":995", "+OK POP3 ready\r\n", nil) // POP3S: banner only
}

// handleSMTPConn models two real, specific SMTP misconfigurations in one
// session: an open relay (RCPT TO is accepted for *any* domain, not just
// ones this server should be responsible for - the classic test is
// EHLO, MAIL FROM, then RCPT TO an address at a completely unrelated
// domain), and VRFY-based user enumeration (confirms whether a local
// account exists). DATA is accepted and its body silently discarded -
// nothing is ever actually queued or sent anywhere.
func startSMTPService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleSMTPConn)
}

func handleSMTPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	fmt.Fprint(conn, "220 mail.acme-supplies.internal ESMTP Postfix (Ubuntu)\r\n")

	scanner := bufio.NewScanner(conn)
	inData := false
	queueNum := 0
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")

		if inData {
			if line == "." {
				inData = false
				queueNum++
				fmt.Fprintf(conn, "250 2.0.0 Ok: queued as ACME%06d\r\n", queueNum)
			}
			continue // body is never stored, parsed, or forwarded anywhere
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			fmt.Fprint(conn, "250-mail.acme-supplies.internal\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 HELP\r\n")
		case strings.HasPrefix(upper, "MAIL FROM"):
			fmt.Fprint(conn, "250 2.1.0 Ok\r\n")
		case strings.HasPrefix(upper, "RCPT TO"):
			// The bug: accepted regardless of the recipient's domain -
			// a real open relay would let this message go anywhere.
			log.Printf("%s SMTP RCPT TO %s accepted (open relay) [T1133 External Remote Services | Open Mail Relay Abuse Attempt]", conn.RemoteAddr(), strings.TrimSpace(line[7:]))
			fmt.Fprint(conn, "250 2.1.5 Ok\r\n")
		case strings.HasPrefix(upper, "VRFY"):
			user := strings.TrimSpace(line[4:])
			log.Printf("%s SMTP VRFY %q [T1087 Account Discovery | User Enumeration Attempt]", conn.RemoteAddr(), user)
			if knownMailUser(user) {
				fmt.Fprintf(conn, "250 2.0.0 <%s@acme-supplies.internal>\r\n", strings.Trim(user, "<>"))
			} else {
				fmt.Fprint(conn, "550 5.1.1 <"+user+">: Recipient address rejected: User unknown\r\n")
			}
		case strings.HasPrefix(upper, "DATA"):
			inData = true
			fmt.Fprint(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "221 2.0.0 Bye\r\n")
			return
		case strings.HasPrefix(upper, "RSET"):
			fmt.Fprint(conn, "250 2.0.0 Ok\r\n")
		default:
			fmt.Fprint(conn, "502 5.5.2 Error: command not recognized\r\n")
		}
	}
}

// knownMailUser backs the VRFY enumeration above: real usernames (plus
// a couple of standard mail aliases) are confirmed, anything else is
// rejected - exactly the oracle a VRFY-enabled mail server gives you.
func knownMailUser(user string) bool {
	user = strings.ToLower(strings.Trim(user, "<>"))
	if local, _, found := strings.Cut(user, "@"); found {
		user = local
	}
	switch user {
	case "root", "admin", "postmaster", "webmaster":
		return true
	}
	for _, u := range fakeUsers {
		if strings.EqualFold(u.Username, user) {
			return true
		}
	}
	return false
}

// startIMAPService models the real, commonly-flagged finding: the
// CAPABILITY response advertises AUTH=PLAIN/AUTH=LOGIN with no
// STARTTLS and no LOGINDISABLED, meaning plaintext credentials over an
// unencrypted connection are accepted - the thing a compliance/pentest
// check specifically greps the CAPABILITY line for.
func startIMAPService(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handleIMAPConn)
}

func handleIMAPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprint(conn, "* OK IMAP4rev1 Service Ready\r\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		tag, cmd := fields[0], strings.ToUpper(fields[1])
		switch cmd {
		case "CAPABILITY":
			fmt.Fprint(conn, "* CAPABILITY IMAP4rev1 LOGIN-REFERRALS AUTH=PLAIN AUTH=LOGIN\r\n")
			fmt.Fprintf(conn, "%s OK CAPABILITY completed\r\n", tag)
		case "LOGIN":
			log.Printf("%s IMAP plaintext LOGIN accepted [T1040 Network Sniffing | Plaintext Credential Interception Risk]", conn.RemoteAddr())
			fmt.Fprintf(conn, "%s OK LOGIN completed\r\n", tag)
		case "LOGOUT":
			fmt.Fprint(conn, "* BYE IMAP4rev1 Server logging out\r\n")
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		default:
			fmt.Fprintf(conn, "%s BAD Command unknown\r\n", tag)
		}
	}
}

// startPOP3Service: same plaintext-auth story as IMAP, in POP3's
// USER/PASS shape.
func startPOP3Service(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake service %s not started: %v", addr, err)
		return
	}
	go acceptLoop(ln, handlePOP3Conn)
}

func handlePOP3Conn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprint(conn, "+OK POP3 server ready\r\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER"):
			fmt.Fprint(conn, "+OK User accepted\r\n")
		case strings.HasPrefix(upper, "PASS"):
			log.Printf("%s POP3 plaintext PASS accepted [T1040 Network Sniffing | Plaintext Credential Interception Risk]", conn.RemoteAddr())
			fmt.Fprint(conn, "+OK Logged in\r\n")
		case strings.HasPrefix(upper, "STAT"):
			fmt.Fprint(conn, "+OK 0 0\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "+OK Bye\r\n")
			return
		default:
			fmt.Fprint(conn, "-ERR Unknown command\r\n")
		}
	}
}
