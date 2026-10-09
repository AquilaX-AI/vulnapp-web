package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// ja3Listener wraps the HTTPS listener so every accepted connection has
// its ClientHello sniffed and reduced to a JA3 fingerprint before being
// handed off to the TLS layer. JA3 survives User-Agent spoofing: it's
// derived from how the underlying TLS library actually negotiates
// (cipher suite list, extensions, elliptic curves - all in the order
// the client sent them), not anything the request content claims to be.
// A tool that rotates its User-Agent per request but reuses the same
// HTTP client library will still produce the same JA3 hash every time,
// which is what makes it useful for correlating requests back to the
// same underlying script/tool regardless of what it calls itself.
type ja3Listener struct {
	net.Listener
}

func newJA3Listener(ln net.Listener) *ja3Listener {
	return &ja3Listener{Listener: ln}
}

func (l *ja3Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ja3SniffConn{Conn: conn}, nil
}

type ja3SniffConn struct {
	net.Conn
	buffered []byte
	sniffed  bool
}

func (c *ja3SniffConn) Read(p []byte) (int, error) {
	if !c.sniffed {
		c.sniffed = true
		peek := make([]byte, 4096)
		n, err := c.Conn.Read(peek)
		if n > 0 {
			c.buffered = peek[:n]
			if hash, raw := computeJA3(c.buffered); hash != "" {
				log.Printf("%s TLS ClientHello JA3=%s (%s) [T1595.002 Active Scanning: Vulnerability Scanning | TLS Client Fingerprinted]", c.Conn.RemoteAddr(), hash, raw)
			}
		}
		if err != nil && n == 0 {
			return 0, err
		}
	}
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// computeJA3 parses a raw TLS record containing a ClientHello and
// returns its JA3 hash plus the human-readable field string it was
// built from (SSLVersion,Ciphers,Extensions,EllipticCurves,
// EllipticCurvePointFormats - GREASE values excluded, same algorithm
// https://github.com/salesforce/ja3 defines). Returns ("", "") on
// anything that doesn't parse as a plausible ClientHello - this only
// ever adds a log line, so failing closed is correct.
func computeJA3(record []byte) (hash, raw string) {
	r := &byteReader{data: record}

	if b, ok := r.byte(); !ok || b != 0x16 { // TLS record type: handshake
		return "", ""
	}
	r.skip(2) // record version
	r.skip(2) // record length

	if b, ok := r.byte(); !ok || b != 0x01 { // handshake type: ClientHello
		return "", ""
	}
	r.skip(3) // handshake length

	version, ok := r.uint16()
	if !ok {
		return "", ""
	}
	r.skip(32) // random

	sessionIDLen, ok := r.byte()
	if !ok {
		return "", ""
	}
	r.skip(int(sessionIDLen))

	cipherSuitesLen, ok := r.uint16()
	if !ok {
		return "", ""
	}
	var ciphers []string
	cipherBytes, ok := r.bytes(int(cipherSuitesLen))
	if !ok {
		return "", ""
	}
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		v := uint16(cipherBytes[i])<<8 | uint16(cipherBytes[i+1])
		if isGREASE(v) {
			continue
		}
		ciphers = append(ciphers, strconv.Itoa(int(v)))
	}

	compressionLen, ok := r.byte()
	if !ok {
		return "", ""
	}
	r.skip(int(compressionLen))

	var extensions, curves, pointFormats []string
	if extTotalLen, ok := r.uint16(); ok {
		extData, ok := r.bytes(int(extTotalLen))
		if ok {
			er := &byteReader{data: extData}
			for er.remaining() > 0 {
				extType, ok1 := er.uint16()
				extLen, ok2 := er.uint16()
				if !ok1 || !ok2 {
					break
				}
				extContent, ok3 := er.bytes(int(extLen))
				if !ok3 {
					break
				}
				if !isGREASE(extType) {
					extensions = append(extensions, strconv.Itoa(int(extType)))
				}
				switch extType {
				case 10: // supported_groups (elliptic curves)
					cr := &byteReader{data: extContent}
					if listLen, ok := cr.uint16(); ok {
						if list, ok := cr.bytes(int(listLen)); ok {
							for i := 0; i+1 < len(list); i += 2 {
								v := uint16(list[i])<<8 | uint16(list[i+1])
								if !isGREASE(v) {
									curves = append(curves, strconv.Itoa(int(v)))
								}
							}
						}
					}
				case 11: // ec_point_formats
					cr := &byteReader{data: extContent}
					if listLen, ok := cr.byte(); ok {
						if list, ok := cr.bytes(int(listLen)); ok {
							for _, v := range list {
								pointFormats = append(pointFormats, strconv.Itoa(int(v)))
							}
						}
					}
				}
			}
		}
	}

	raw = fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(pointFormats, "-"),
	)
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:]), raw
}

// isGREASE reports whether v is one of TLS's reserved GREASE values
// (RFC 8701) - placeholder values some clients send to test server
// tolerance of unknown values. JA3 excludes them since they vary
// randomly per-connection and would otherwise make the fingerprint
// unstable for the same client.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// byteReader is a tiny bounds-checked cursor over a byte slice - every
// method fails closed (returns ok=false) on underrun instead of
// panicking, since this is parsing untrusted network input.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) remaining() int { return len(r.data) - r.pos }

func (r *byteReader) byte() (byte, bool) {
	if r.pos+1 > len(r.data) {
		return 0, false
	}
	b := r.data[r.pos]
	r.pos++
	return b, true
}

func (r *byteReader) uint16() (uint16, bool) {
	if r.pos+2 > len(r.data) {
		return 0, false
	}
	v := uint16(r.data[r.pos])<<8 | uint16(r.data[r.pos+1])
	r.pos += 2
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, false
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, true
}

func (r *byteReader) skip(n int) {
	r.pos += n
}
