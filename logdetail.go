package main

import (
	"fmt"
	"net/http"
)

// attackDetails builds a compact, single-line summary of request
// context useful for actually analyzing an attack - protocol,
// User-Agent, Referer, any X-Forwarded-For the client presented, and a
// truncated snippet of the submitted body - without ever including the
// Host header. Host is deliberately excluded: it's the one field here
// that would identify which hostname this specific deployment answers
// to, which is exactly what should stay anonymous if these logs get
// exported or shared with a threat-intel feed. Everything else here
// describes the attacker and what they sent, not us.
func attackDetails(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	ua := orDash(r.Header.Get("User-Agent"))
	ref := orDash(r.Header.Get("Referer"))
	xff := orDash(r.Header.Get("X-Forwarded-For"))

	body := "-"
	if bodyValues := peekFormValues(r); len(bodyValues) > 0 {
		body = truncate(bodyValues.Encode(), 200)
	}

	return fmt.Sprintf("proto=%s ua=%q referer=%q xff=%q content_length=%d body=%q",
		proto, ua, ref, xff, r.ContentLength, body)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
