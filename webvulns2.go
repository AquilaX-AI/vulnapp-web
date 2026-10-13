package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------
// Second batch of intentional web-app vulnerabilities. Same ground rules
// as the first batch: every one is simulated entirely in-process against
// fake in-memory data - nothing here reads real files, runs real
// commands, or makes real LDAP/XPath/NoSQL queries.
// ---------------------------------------------------------------------

// webVuln2Categories maps each new endpoint to the plain-English label
// used in the MITRE-tagged log line (see the rule in mitre.go).
var webVuln2Categories = map[string]string{
	"/api/xml/import":       "XXE Injection Attempt",
	"/api/prefs/import":     "Insecure Deserialization Attempt",
	"/api/nosql/login":      "NoSQL Authentication Bypass Attempt",
	"/graphql":              "GraphQL Introspection / Abuse Attempt",
	"/api/jwt/me":           "JWT Algorithm-None Forgery Attempt",
	"/directory":            "LDAP Injection Attempt",
	"/api/xpath-login":      "XPath Injection Attempt",
	"/api/archive/extract":  "Zip Slip Path Traversal Attempt",
	"/api/settings/merge":   "Prototype Pollution Attempt",
	"/feedback":             "Log Injection Attempt",
	"/api/2fa/verify":       "2FA Bypass Attempt",
	"/api/v2/orders/":       "Broken Object Level Authorization (BOLA) Attempt",
	"/api/v2/users":         "Excessive Data Exposure Attempt",
	"/admin-panel":          "Access Control Bypass (403 Bypass) Attempt",
	"/api/invite":           "Predictable Token Guessing Attempt",
	"/greet":                "Format String Injection Attempt",
	"/api/status":           "Hidden Debug Parameter Abuse Attempt",
	"/landing":              "Web Cache Poisoning Attempt",
	"/widget":               "DOM-Based XSS / postMessage Abuse Attempt",
	"/support":              "Blind Stored XSS Attempt",
	"/api/account/password": "Account Takeover (No Current-Password Check) Attempt",
	"/server-status":        "Sensitive File / Debug Endpoint Exposure Attempt",
	"/actuator/env":         "Sensitive File / Debug Endpoint Exposure Attempt",
	"/actuator/heapdump":    "Sensitive File / Debug Endpoint Exposure Attempt",
	"/.htpasswd":            "Sensitive File / Debug Endpoint Exposure Attempt",
	"/WEB-INF/web.xml":      "Sensitive File / Debug Endpoint Exposure Attempt",
	"/.aws/credentials":     "Sensitive File / Debug Endpoint Exposure Attempt",
	"/docker-compose.yml":   "Sensitive File / Debug Endpoint Exposure Attempt",
	"/.DS_Store":            "Sensitive File / Debug Endpoint Exposure Attempt",
	"/composer.json":        "Sensitive File / Debug Endpoint Exposure Attempt",
	"/backup.zip":           "Sensitive File / Debug Endpoint Exposure Attempt",
	"/server-info":          "Sensitive File / Debug Endpoint Exposure Attempt",
	"/actuator":             "Sensitive File / Debug Endpoint Exposure Attempt",
}

func webVuln2Category(path string) string {
	if c, ok := webVuln2Categories[path]; ok {
		return c
	}
	if strings.HasPrefix(path, "/api/v2/orders/") {
		return webVuln2Categories["/api/v2/orders/"]
	}
	return ""
}

func registerWebVulns2(mux *http.ServeMux) {
	mux.HandleFunc("/api/xml/import", handleXXE)
	mux.HandleFunc("/api/prefs/import", handleInsecureDeserialization)
	mux.HandleFunc("/api/nosql/login", handleNoSQLLogin)
	mux.HandleFunc("/graphql", handleGraphQL)
	mux.HandleFunc("/api/jwt/me", handleJWTNone)
	mux.HandleFunc("/directory", handleLDAPInjection)
	mux.HandleFunc("/api/xpath-login", handleXPathLogin)
	mux.HandleFunc("/api/archive/extract", handleZipSlip)
	mux.HandleFunc("/api/settings/merge", handlePrototypePollution)
	mux.HandleFunc("/api/settings/whoami", handleSettingsWhoami)
	mux.HandleFunc("/feedback", handleLogInjection)
	mux.HandleFunc("/api/2fa/verify", handle2FABypass)
	mux.HandleFunc("/api/v2/orders/", handleBOLAOrders)
	mux.HandleFunc("/api/v2/users", handleExcessiveDataExposure)
	mux.HandleFunc("/admin-panel", handle403Bypass)
	mux.HandleFunc("/api/invite", handlePredictableInvite)
	mux.HandleFunc("/greet", handleFormatString)
	mux.HandleFunc("/api/status", handleHiddenDebug)
	mux.HandleFunc("/landing", handleCachePoisoning)
	mux.HandleFunc("/widget", handleDOMXSS)
	mux.HandleFunc("/support", handleBlindXSS)
	mux.HandleFunc("/support/agent", handleBlindXSSAgent)
	mux.HandleFunc("/api/account/password", handlePasswordChangeNoCurrent)

	for p := range sensitiveFiles {
		mux.HandleFunc(p, handleSensitiveFile)
	}
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request, max int64) []byte {
	if r.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, max))
	return b
}

// --- 1. XXE ----------------------------------------------------------

var entityDecl = regexp.MustCompile(`<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">`)

// handleXXE "parses" an XML order import. External entities are resolved
// the way a vulnerable parser would - but file:// targets are looked up
// in the decoy file set by basename (never the real filesystem), and
// http(s):// targets are never fetched (logged only), so blind/OOB XXE
// payloads still show up in the attack log.
func handleXXE(w http.ResponseWriter, r *http.Request) {
	body := string(readBody(r, 64<<10))
	if body == "" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "POST an XML document, e.g. <order><item>widget</item></order>\n")
		return
	}
	out := body
	for _, m := range entityDecl.FindAllStringSubmatch(body, -1) {
		name, target := m[1], m[2]
		val := ""
		switch {
		case strings.HasPrefix(target, "file://"):
			base := strings.ToLower(target[strings.LastIndexAny(target, `/\`)+1:])
			val = decoyFiles[base]
			if val == "" {
				val = "[Errno 2] No such file or directory: " + target
			}
		default:
			log.Printf("%s XXE out-of-band entity %q never fetched [T1190 Exploit Public-Facing Application | Blind/OOB XXE Callback Attempt]", r.RemoteAddr, target)
		}
		out = strings.ReplaceAll(out, "&"+name+";", val)
	}
	out = regexp.MustCompile(`(?s)<!DOCTYPE.*?\]>`).ReplaceAllString(out, "")
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, "<result><status>imported</status><echo>%s</echo></result>", out)
}

// --- 2. Insecure deserialization --------------------------------------

// handleInsecureDeserialization restores "preferences" from a base64
// JSON blob and honors a "_type":"Command" gadget - modeling the shape of
// real unsafe-deserialization bugs. The "command" is never executed; a
// canned shell reply stands in for the output.
func handleInsecureDeserialization(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("data")
	if raw == "" {
		raw = string(readBody(r, 16<<10))
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": "gob/base64 decode failed: " + err.Error()})
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(dec, &obj); err != nil {
		jsonOut(w, 400, map[string]string{"error": "unmarshal: " + err.Error()})
		return
	}
	if t, _ := obj["_type"].(string); t == "Command" {
		cmd, _ := obj["cmd"].(string)
		log.Printf("%s deserialization gadget cmd=%q [T1059 Command and Scripting Interpreter | Deserialization Gadget Command Attempt (never executed)]", r.RemoteAddr, truncate(cmd, 120))
		jsonOut(w, 200, map[string]string{"restored": "Command", "output": strings.TrimSpace(fakeShellOutput(cmd))})
		return
	}
	jsonOut(w, 200, map[string]any{"restored": obj})
}

// --- 3. NoSQL injection ------------------------------------------------

func handleNoSQLLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User any `json:"user"`
		Pass any `json:"pass"`
	}
	if err := json.Unmarshal(readBody(r, 8<<10), &req); err != nil {
		jsonOut(w, 400, map[string]string{"error": "send JSON {\"user\":..., \"pass\":...}"})
		return
	}
	isOp := func(v any) bool { m, ok := v.(map[string]any); return ok && len(m) > 0 }
	if isOp(req.User) || isOp(req.Pass) {
		jsonOut(w, 200, map[string]any{"ok": true, "user": "admin", "role": "admin", "token": "nosql-fake-session-9f2c"})
		return
	}
	if req.User == "admin" && req.Pass == "SuperSecretPass!2024" {
		jsonOut(w, 200, map[string]any{"ok": true, "user": "admin"})
		return
	}
	jsonOut(w, 401, map[string]any{"ok": false})
}

// --- 4. GraphQL ----------------------------------------------------------

var gqlUserRe = regexp.MustCompile(`user\s*\(\s*id\s*:\s*"?(\d+)"?\s*\)`)
var gqlLoginRe = regexp.MustCompile(`login\s*\(\s*username\s*:\s*"([^"]*)"\s*,\s*password\s*:\s*"([^"]*)"`)

// handleGraphQL: introspection enabled, no depth/complexity limit, no
// auth on user(id:) (IDOR), field-suggestion errors, and alias batching
// of login() with no lockout (credential stuffing in one request).
func handleGraphQL(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("query")
	if r.Method == http.MethodPost {
		var req struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(readBody(r, 64<<10), &req) == nil {
			q = req.Query
		}
	}
	switch {
	case strings.Contains(q, "__schema") || strings.Contains(q, "__type"):
		jsonOut(w, 200, map[string]any{"data": map[string]any{"__schema": map[string]any{
			"queryType":    map[string]string{"name": "Query"},
			"mutationType": map[string]string{"name": "Mutation"},
			"types": []map[string]any{
				{"name": "Query", "fields": []string{"user(id: ID!)", "users", "orders(userId: ID!)", "internalConfig"}},
				{"name": "Mutation", "fields": []string{"login(username: String!, password: String!)", "updateRole(id: ID!, role: String!)", "deleteUser(id: ID!)"}},
				{"name": "User", "fields": []string{"id", "username", "email", "ssn", "passwordHash", "role"}},
			}}}})
	case gqlLoginRe.MatchString(q):
		data := map[string]any{}
		for i, m := range gqlLoginRe.FindAllStringSubmatch(q, -1) {
			ok := m[1] == "admin" && m[2] == "SuperSecretPass!2024"
			data["login"+strconv.Itoa(i)] = ok
		}
		jsonOut(w, 200, map[string]any{"data": data})
	case gqlUserRe.MatchString(q):
		id, _ := strconv.Atoi(gqlUserRe.FindStringSubmatch(q)[1])
		for _, u := range fakeUsers {
			if u.ID == id {
				sum := md5.Sum([]byte(u.Password))
				jsonOut(w, 200, map[string]any{"data": map[string]any{"user": map[string]any{
					"id": u.ID, "username": u.Username, "email": u.Email, "ssn": u.SSN,
					"passwordHash": hex.EncodeToString(sum[:]), "role": u.Role}}})
				return
			}
		}
		jsonOut(w, 200, map[string]any{"data": map[string]any{"user": nil}})
	case q == "":
		jsonOut(w, 400, map[string]any{"errors": []map[string]string{{"message": "Must provide query string. Try {__schema{types{name}}}"}}})
	default:
		jsonOut(w, 200, map[string]any{"errors": []map[string]string{{"message": `Cannot query field "usr" on type "Query". Did you mean "user" or "users"?`}}})
	}
}

// --- 5. JWT alg=none -----------------------------------------------------

func handleJWTNone(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		jsonOut(w, 401, map[string]string{"error": "send Authorization: Bearer <jwt>"})
		return
	}
	dec := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); return b }
	var hdr, claims map[string]any
	json.Unmarshal(dec(parts[0]), &hdr)
	if json.Unmarshal(dec(parts[1]), &claims) != nil {
		jsonOut(w, 401, map[string]string{"error": "bad claims"})
		return
	}
	// The flaw: "none" (any casing) skips signature verification entirely.
	if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
		jsonOut(w, 200, map[string]any{"verified": false, "accepted": true, "claims": claims})
		return
	}
	jsonOut(w, 401, map[string]string{"error": "signature verification failed"})
}

// --- 6. LDAP injection ------------------------------------------------------

func handleLDAPInjection(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("user")
	filter := "(&(objectClass=person)(uid=" + u + "))"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if strings.Count(filter, "(") != strings.Count(filter, ")") {
		fmt.Fprintf(w, "LDAP error 87: Bad search filter\nfilter: %s\nbase: ou=people,dc=acme,dc=local\n", filter)
		return
	}
	if strings.Contains(u, "*") || strings.Contains(u, ")(") || strings.Contains(u, "|") {
		for _, x := range fakeUsers {
			fmt.Fprintf(w, "dn: uid=%s,ou=people,dc=acme,dc=local\nmail: %s\nuserPassword: {MD5}%s\n\n", x.Username, x.Email, base64.StdEncoding.EncodeToString([]byte(x.Password)))
		}
		return
	}
	for _, x := range fakeUsers {
		if x.Username == u {
			fmt.Fprintf(w, "dn: uid=%s,ou=people,dc=acme,dc=local\nmail: %s\n", x.Username, x.Email)
			return
		}
	}
	fmt.Fprint(w, "no entries\n")
}

// --- 7. XPath injection --------------------------------------------------------

func handleXPathLogin(w http.ResponseWriter, r *http.Request) {
	user, pass := r.FormValue("username"), r.FormValue("password")
	expr := fmt.Sprintf("//user[name/text()='%s' and pass/text()='%s']", user, pass)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if strings.Count(expr, "'")%2 == 1 {
		fmt.Fprintf(w, "XPathException: Invalid expression: %s\n", expr)
		return
	}
	if regexp.MustCompile(`(?i)'\s*or\s*'?\w+'?\s*=\s*'?\w+|'\s*\]\s*\|`).MatchString(user + pass) {
		fmt.Fprintf(w, "authenticated as: admin (xpath: %s)\n", expr)
		return
	}
	if user == "admin" && pass == "SuperSecretPass!2024" {
		fmt.Fprint(w, "authenticated as: admin\n")
		return
	}
	w.WriteHeader(401)
	fmt.Fprint(w, "invalid credentials\n")
}

// --- 8. Zip Slip --------------------------------------------------------------------

// handleZipSlip lists where each archive entry WOULD be written, joined
// onto the upload dir with no sanitization - nothing is ever written.
func handleZipSlip(w http.ResponseWriter, r *http.Request) {
	data := readBody(r, 4<<20)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": "POST a .zip body: " + err.Error()})
		return
	}
	var out []string
	for _, f := range zr.File {
		out = append(out, "/var/www/uploads/tmp/"+f.Name)
	}
	jsonOut(w, 200, map[string]any{"extracted": out})
}

// --- 9. Prototype pollution -----------------------------------------------------------

var (
	protoMu   sync.Mutex
	protoPoll = map[string]any{}
)

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if k == "__proto__" || k == "constructor" || k == "prototype" {
			// The "polluted" object is shared by every request - exactly
			// the class of bug.
			if m, ok := v.(map[string]any); ok {
				deepMerge(protoPoll, m)
			}
			continue
		}
		if sm, ok := v.(map[string]any); ok {
			dm, _ := dst[k].(map[string]any)
			if dm == nil {
				dm = map[string]any{}
				dst[k] = dm
			}
			deepMerge(dm, sm)
			continue
		}
		dst[k] = v
	}
}

func handlePrototypePollution(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if json.Unmarshal(readBody(r, 16<<10), &in) != nil {
		jsonOut(w, 400, map[string]string{"error": "send a JSON object"})
		return
	}
	protoMu.Lock()
	defer protoMu.Unlock()
	merged := map[string]any{}
	deepMerge(merged, in)
	jsonOut(w, 200, map[string]any{"merged": merged})
}

func handleSettingsWhoami(w http.ResponseWriter, r *http.Request) {
	protoMu.Lock()
	defer protoMu.Unlock()
	// Reads fall through to the polluted "prototype".
	jsonOut(w, 200, map[string]any{"user": "guest", "isAdmin": protoPoll["isAdmin"] == true})
}

// --- 10. Log injection -----------------------------------------------------------------

func handleLogInjection(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("message")
	// Intentionally unsanitized and unquoted: CR/LF lets a caller forge
	// extra log lines.
	log.Printf("feedback received: %s", msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Feedback"))
	fmt.Fprint(w, `<h1>Feedback</h1><form method="post"><input name="message" placeholder="Tell us what you think"><button class="btn">Send</button></form>`)
	if msg != "" {
		fmt.Fprint(w, `<p>Thanks - we logged your feedback.</p>`)
	}
	fmt.Fprint(w, pageFooter)
}

// --- 11. 2FA bypass ---------------------------------------------------------------------

func handle2FABypass(w http.ResponseWriter, r *http.Request) {
	// Flaws: OTP leaked in a debug header, no attempt limit, empty/array
	// codes treated as "skip".
	w.Header().Set("X-Debug-Otp", "493021")
	code := r.FormValue("code")
	if code == "493021" || code == "" || code == "null" || code == "[]" || code == "000000" {
		jsonOut(w, 200, map[string]any{"verified": true, "session": "2fa-fake-session"})
		return
	}
	jsonOut(w, 401, map[string]any{"verified": false})
}

// --- 12. BOLA ------------------------------------------------------------------------------

func handleBOLAOrders(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v2/orders/"))
	if err != nil || id < 1 || id > 5000 {
		jsonOut(w, 404, map[string]string{"error": "not found"})
		return
	}
	owner := fakeUsers[id%len(fakeUsers)]
	jsonOut(w, 200, map[string]any{
		"order_id": id, "owner": owner.Username, "email": owner.Email,
		"ship_to": owner.Address, "card_last4": fmt.Sprintf("%04d", (id*7919)%10000), "total": float64(id%97) + 0.99,
	})
}

// --- 13. Excessive data exposure ------------------------------------------------------------

func handleExcessiveDataExposure(w http.ResponseWriter, r *http.Request) {
	var out []map[string]any
	for _, u := range fakeUsers {
		sum := md5.Sum([]byte(u.Password))
		out = append(out, map[string]any{
			"id": u.ID, "username": u.Username, "email": u.Email, "role": u.Role,
			"ssn": u.SSN, "address": u.Address, "password": u.Password,
			"password_md5": hex.EncodeToString(sum[:]), "api_key": fmt.Sprintf("ak_live_FAKE%04d", u.ID),
		})
	}
	jsonOut(w, 200, out)
}

// --- 14. 403 bypass via X-Original-URL / path tricks ------------------------------------------

func handle403Bypass(w http.ResponseWriter, r *http.Request) {
	// A fronting-proxy-style override header is trusted for the access
	// decision.
	eff := r.URL.Path
	if h := r.Header.Get("X-Original-URL"); h != "" {
		eff = h
	} else if h := r.Header.Get("X-Rewrite-URL"); h != "" {
		eff = h
	}
	if strings.HasPrefix(eff, "/admin-panel") && r.Header.Get("X-Original-URL") == "" && r.Header.Get("X-Rewrite-URL") == "" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "403 Forbidden")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Admin Panel"))
	fmt.Fprint(w, `<h1>Internal admin panel</h1><ul><li>Users: 3</li><li>Backup key: AKIAFAKEFAKEFAKE0042</li></ul>`)
	fmt.Fprint(w, pageFooter)
}

// --- 15. Predictable invite token -----------------------------------------------------------------

func handlePredictableInvite(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")
	sum := md5.Sum([]byte(strings.ToLower(email)))
	want := hex.EncodeToString(sum[:])[:8]
	if code == "" {
		// Issuing path leaks the algorithm's output for any email.
		jsonOut(w, 200, map[string]string{"message": "invite sent", "debug_code": want})
		return
	}
	jsonOut(w, 200, map[string]bool{"valid": code == want})
}

// --- 16. Format string -------------------------------------------------------------------------------

type greetCtx struct {
	Name       string
	DBPassword string
	APIKey     string
}

func handleFormatString(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	f := r.URL.Query().Get("fmt")
	if f == "" {
		f = "Hello, %s!"
	}
	// CWE-134: attacker-controlled format string. %+v / %#v dump the
	// struct including its (fake) secrets.
	fmt.Fprintf(w, f, greetCtx{Name: "guest", DBPassword: "Pr0d-DB-FAKE!", APIKey: "sk_live_FAKEFAKEFAKE"})
	fmt.Fprintln(w)
}

// --- 17. Hidden debug parameter ---------------------------------------------------------------------------

func handleHiddenDebug(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"status": "ok", "uptime": "14d"}
	if r.URL.Query().Get("debug") == "1" || r.URL.Query().Get("debug") == "true" || r.Header.Get("X-Debug") != "" {
		resp["env"] = map[string]string{
			"DB_URL": "postgres://app:Pr0d-DB-FAKE!@10.0.4.23:5432/acme", "AWS_SECRET_ACCESS_KEY": "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0001",
			"JWT_SECRET": jwtSecret, "GOFLAGS": "-mod=vendor",
		}
		resp["goroutines"] = 42
	}
	jsonOut(w, 200, resp)
}

// --- 18. Web cache poisoning -----------------------------------------------------------------------------

func handleCachePoisoning(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h // unkeyed header reflected into a cacheable page
	}
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Spring Sale</title><script src="//%s/static/app.js"></script></head><body><h1>Spring Sale</h1></body></html>`, host)
}

// --- 19. DOM XSS + postMessage ------------------------------------------------------------------------------

func handleDOMXSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Widget</title></head><body>
<h1>Promo widget</h1><div id="banner"></div><div id="msg"></div>
<script>
// DOM XSS: location.hash flows straight into innerHTML.
document.getElementById('banner').innerHTML = decodeURIComponent(location.hash.slice(1));
// postMessage handler with no origin check.
window.addEventListener('message', function (e) { document.getElementById('msg').innerHTML = e.data; });
</script></body></html>`)
}

// --- 20. Blind stored XSS ------------------------------------------------------------------------------------

var (
	ticketsMu sync.Mutex
	tickets   []string
)

func handleBlindXSS(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		ticketsMu.Lock()
		if len(tickets) < 200 {
			tickets = append(tickets, r.FormValue("message"))
		}
		ticketsMu.Unlock()
		http.Redirect(w, r, "/support?sent=1", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Support"))
	fmt.Fprint(w, `<h1>Contact support</h1><form method="post"><textarea name="message" placeholder="How can we help?"></textarea><button class="btn">Submit ticket</button></form>`)
	if r.URL.Query().Get("sent") != "" {
		fmt.Fprint(w, `<p>Ticket submitted - an agent will review it shortly.</p>`)
	}
	fmt.Fprint(w, pageFooter)
}

// handleBlindXSSAgent is the "agent view" where the payload fires - the
// stored message is rendered unescaped, but the submitter never sees it.
func handleBlindXSSAgent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Agent queue"))
	ticketsMu.Lock()
	for i, t := range tickets {
		fmt.Fprintf(w, `<div class="comment"><b>#%d</b>: %s</div>`, i+1, t)
	}
	ticketsMu.Unlock()
	fmt.Fprint(w, pageFooter)
}

// --- 21. Password change without current password (+CSRF) ------------------------------------------------------

func handlePasswordChangeNoCurrent(w http.ResponseWriter, r *http.Request) {
	u, p := r.FormValue("username"), r.FormValue("new_password")
	if u == "" || p == "" {
		jsonOut(w, 400, map[string]string{"error": "username and new_password required"})
		return
	}
	// Any caller, any method, no session, no current password, no CSRF
	// token. (Nothing is actually changed.)
	jsonOut(w, 200, map[string]string{"changed": u, "note": "password updated"})
}

// --- 22. Common sensitive file / debug endpoint exposure ---------------------------------------------------------

var sensitiveFiles = map[string]string{
	"/server-status":      "Apache Server Status for acme-web01\nServer Version: Apache/2.2.15 (CentOS)\nCurrent Time: now\n12 requests currently being processed\n10.0.4.17 GET /admin?token=FAKE-TOKEN HTTP/1.1\n",
	"/server-info":        "Apache Server Information\nModule Name: mod_php5.c\nServer Root: /etc/httpd\n",
	"/actuator":           `{"_links":{"env":{"href":"/actuator/env"},"heapdump":{"href":"/actuator/heapdump"},"beans":{"href":"/actuator/beans"}}}`,
	"/actuator/env":       `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASSWORD":{"value":"Pr0d-DB-FAKE!"},"AWS_SECRET_ACCESS_KEY":{"value":"******"}}}]}`,
	"/actuator/heapdump":  "JAVA PROFILE 1.0.2\x00FAKE-HEAP-DUMP\x00password=Pr0d-DB-FAKE!\x00",
	"/.htpasswd":          "admin:$apr1$fake$3dlUO9Jk1h5s8k2m9bFake0\nbackup:$apr1$fake$9zQp1xFakeHash00000000\n",
	"/WEB-INF/web.xml":    `<?xml version="1.0"?><web-app><context-param><param-name>db.password</param-name><param-value>Pr0d-DB-FAKE!</param-value></context-param></web-app>`,
	"/.aws/credentials":   "[default]\naws_access_key_id = AKIAFAKEFAKEFAKE0042\naws_secret_access_key = FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0001\n",
	"/docker-compose.yml": "services:\n  db:\n    image: postgres:9.6\n    environment:\n      POSTGRES_PASSWORD: Pr0d-DB-FAKE!\n    ports: [\"5432:5432\"]\n",
	"/.DS_Store":          "\x00\x00\x00\x01Bud1\x00\x00\x10\x00backup.sql\x00admin_old\x00",
	"/composer.json":      `{"require":{"php":"5.3.3","laravel/framework":"4.2.0","phpunit/phpunit":"4.8.0"}}`,
	"/backup.zip":         "PK\x03\x04FAKE-BACKUP-ARCHIVE-NOT-REAL",
}

func handleSensitiveFile(w http.ResponseWriter, r *http.Request) {
	body, ok := sensitiveFiles[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, ".json") || r.URL.Path == "/actuator" || r.URL.Path == "/actuator/env":
		w.Header().Set("Content-Type", "application/json")
	case strings.HasSuffix(r.URL.Path, ".zip") || strings.HasSuffix(r.URL.Path, "heapdump") || strings.HasSuffix(r.URL.Path, ".DS_Store"):
		w.Header().Set("Content-Type", "application/octet-stream")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	fmt.Fprint(w, body)
}
