package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// ---------------------------------------------------------------------
// Home page
// ---------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Hardcoded credentials leaked via an HTML comment: a classic
	// "sensitive information in source" finding.
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>vulnapp-web</title>
  <link rel="stylesheet" href="/static/style.css">
  <!-- TODO: remove before prod. Backdoor admin login: admin / SuperSecretPass!2024 -->
</head>
<body>
  <h1>vulnapp-web</h1>
  <p>Intentionally vulnerable demo app for DAST scanner testing. See the README for the full findings catalog.</p>

  <h2>Reflected XSS</h2>
  <form action="/search" method="get">
    <input name="q" value="test"><button>Search</button>
  </form>

  <h2>Stored XSS / guestbook</h2>
  <form action="/comments" method="post">
    <input name="author" value="guest">
    <input name="body" value="hello">
    <button>Post comment</button>
  </form>
  <a href="/comments">View comments</a>

  <h2>SQL injection - login</h2>
  <form action="/login" method="post">
    <input name="username" value="admin">
    <input name="password" type="password" value="wrong">
    <button>Login</button>
  </form>

  <h2>SQL injection - products</h2>
  <a href="/products?id=1">/products?id=1</a>

  <h2>Fake path traversal</h2>
  <a href="/files?name=report.txt">/files?name=report.txt</a> |
  <a href="/files?name=../../../../etc/passwd">/files?name=../../../../etc/passwd</a>

  <h2>Open redirect</h2>
  <a href="/redirect?url=https://example.com">/redirect?url=https://example.com</a>

  <h2>IDOR</h2>
  <a href="/profile?id=1">/profile?id=1</a>

  <h2>Broken access control</h2>
  <a href="/admin">/admin</a> (set cookie role=admin to bypass)

  <h2>Sensitive data exposure</h2>
  <a href="/api/config">/api/config</a> | <a href="/.env">/.env</a> | <a href="/uploads/">/uploads/</a>

  <h2>CORS misconfiguration</h2>
  <a href="/api/data">/api/data</a>

  <h2>Fake command injection</h2>
  <a href="/ping?host=127.0.0.1">/ping?host=127.0.0.1</a>

  <h2>Fake SSTI</h2>
  <a href="/render?name=Guest">/render?name=Guest</a>

  <h2>CSRF</h2>
  <a href="/transfer?to=attacker&amp;amount=100">/transfer?to=attacker&amp;amount=100</a>

  <h2>SSRF</h2>
  <a href="/fetch?url=http://localhost:8080/internal/metadata">/fetch?url=http://localhost:8080/internal/metadata</a>

  <h2>Stack trace disclosure</h2>
  <a href="/crash?tenant=acme">/crash?tenant=acme</a>

  <script src="/static/app.js"></script>
</body>
</html>`)
}

// ---------------------------------------------------------------------
// Exposed .env
// ---------------------------------------------------------------------

func handleEnvFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(envFileContent)
}

// ---------------------------------------------------------------------
// Reflected XSS
// ---------------------------------------------------------------------

func handleSearchXSS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Intentionally unescaped: the query is written straight into the
	// response body.
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h1>Search results</h1>
<p>You searched for: %s</p>
<p>No results found.</p>
<a href="/">Home</a>
</body></html>`, q)
}

// ---------------------------------------------------------------------
// Stored XSS (guestbook)
// ---------------------------------------------------------------------

func handleComments(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		author := r.FormValue("author")
		body := r.FormValue("body")
		commentsMu.Lock()
		comments = append(comments, Comment{ID: nextCommentID, Author: author, Body: body})
		nextCommentID++
		commentsMu.Unlock()
		http.Redirect(w, r, "/comments", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><body><h1>Guestbook</h1>`)

	commentsMu.Lock()
	for _, c := range comments {
		// Intentionally unescaped: stored author/body rendered as raw HTML.
		fmt.Fprintf(w, `<div class="comment"><b>%s</b>: %s</div>`, c.Author, c.Body)
	}
	commentsMu.Unlock()

	fmt.Fprint(w, `
<form action="/comments" method="post">
  <input name="author" placeholder="name">
  <input name="body" placeholder="comment">
  <button>Post</button>
</form>
<a href="/">Home</a>
</body></html>`)
}

// ---------------------------------------------------------------------
// SQL injection - login (string-concatenated query, auth bypass,
// error-based disclosure, username enumeration)
// ---------------------------------------------------------------------

func handleLoginSQLi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.Method != http.MethodPost {
		fmt.Fprint(w, `<form action="/login" method="post">
<input name="username"><input name="password" type="password"><button>Login</button>
</form>`)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Deliberately vulnerable: query built via string concatenation.
	query := fmt.Sprintf(
		"SELECT id, username, role FROM users WHERE username='%s' AND password='%s'",
		username, password,
	)

	rows, err := db.Query(query)
	if err != nil {
		// Error-based SQLi: the raw database error is reflected back.
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<pre>SQL error: %s\nquery: %s</pre>", err.Error(), query)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id int
		var uname, role string
		rows.Scan(&id, &uname, &role)

		// Insecure cookie: no Secure, HttpOnly, or SameSite attributes,
		// and the value is client-trusted on every later request.
		http.SetCookie(w, &http.Cookie{Name: "role", Value: role})
		http.SetCookie(w, &http.Cookie{Name: "username", Value: uname})

		fmt.Fprintf(w, "<p>Welcome, %s! Role: %s</p><a href=\"/\">Home</a>", uname, role)
		return
	}

	// Username enumeration: a second, equally vulnerable query decides
	// which error message to show.
	existsQuery := fmt.Sprintf("SELECT 1 FROM users WHERE username='%s'", username)
	existsRows, err := db.Query(existsQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<pre>SQL error: %s\nquery: %s</pre>", err.Error(), existsQuery)
		return
	}
	defer existsRows.Close()

	if existsRows.Next() {
		fmt.Fprint(w, "<p>Incorrect password.</p>")
	} else {
		fmt.Fprint(w, "<p>No such user.</p>")
	}
}

// ---------------------------------------------------------------------
// SQL injection - products (numeric context, UNION-based)
// ---------------------------------------------------------------------

func handleProductsSQLi(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Deliberately vulnerable: numeric parameter spliced in without
	// quoting or validation, enabling UNION-based injection, e.g.
	// /products?id=0 UNION SELECT username, password, 0 FROM users
	query := fmt.Sprintf("SELECT id, name, price FROM products WHERE id = %s", id)

	rows, err := db.Query(query)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<pre>SQL error: %s\nquery: %s</pre>", err.Error(), query)
		return
	}
	defer rows.Close()

	fmt.Fprint(w, "<table border=1><tr><th>ID</th><th>Name</th><th>Price</th></tr>")
	for rows.Next() {
		var colID sql.NullString
		var name sql.NullString
		var price sql.NullString
		if err := rows.Scan(&colID, &name, &price); err != nil {
			fmt.Fprintf(w, "<tr><td colspan=3>scan error: %s</td></tr>", err.Error())
			continue
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", colID.String, name.String, price.String)
	}
	fmt.Fprint(w, "</table><a href=\"/\">Home</a>")
}

// ---------------------------------------------------------------------
// Fake path traversal (see decoy.go - no real filesystem access occurs
// for traversal payloads)
// ---------------------------------------------------------------------

func handleFilesTraversal(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	base := name
	if idx := strings.LastIndexAny(name, "/\\"); idx != -1 {
		base = name[idx+1:]
	}
	base = strings.ToLower(base)

	if strings.Contains(name, "..") {
		if content, ok := decoyFiles[base]; ok {
			fmt.Fprint(w, content)
			return
		}
	}

	// Non-traversal path: serve a small set of "legitimate" sample files.
	safeFiles := map[string]string{
		"report.txt": "Quarterly report: everything is fine.\n",
		"readme.txt": "This is a sample file served by /files.\n",
	}
	if content, ok := safeFiles[base]; ok {
		fmt.Fprint(w, content)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "file not found")
}

// ---------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------

func handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/"
	}
	// Deliberately unvalidated: any scheme/host is accepted.
	http.Redirect(w, r, target, http.StatusFound)
}

// ---------------------------------------------------------------------
// IDOR
// ---------------------------------------------------------------------

func handleProfileIDOR(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		id = 1
	}

	w.Header().Set("Content-Type", "application/json")

	// No check that the caller is authorized to view this profile: any
	// id can be enumerated to dump every user's PII.
	for _, u := range fakeUsers {
		if u.ID == id {
			json.NewEncoder(w).Encode(map[string]any{
				"id":       u.ID,
				"username": u.Username,
				"email":    u.Email,
				"ssn":      u.SSN,
				"address":  u.Address,
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"error":"not found"}`)
}

// ---------------------------------------------------------------------
// Broken access control (client-controlled, unsigned role cookie)
// ---------------------------------------------------------------------

func handleAdminBrokenAccess(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("role")
	if err != nil || cookie.Value != "admin" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "403 Forbidden")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<h1>Admin panel</h1><table border=1><tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>")
	for _, u := range fakeUsers {
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", u.ID, u.Username, u.Password, u.Role)
	}
	fmt.Fprint(w, "</table>")
}

// ---------------------------------------------------------------------
// Sensitive data exposure via a "debug" config endpoint
// ---------------------------------------------------------------------

func handleAPIConfigExposure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Api-Key", "sk_live_FAKE1234567890abcdef")
	json.NewEncoder(w).Encode(map[string]any{
		"debug":        true,
		"version":      "0.1.0-dev",
		"database_dsn": "postgres://vulnapp:SuperSecretDBPass!@localhost:5432/vulnapp",
		"internal_api_key": "fake-internal-key-7788990011",
		"jwt_secret":   "changeme",
	})
}

// ---------------------------------------------------------------------
// CORS misconfiguration (reflected origin + credentials)
// ---------------------------------------------------------------------

func handleAPIDataCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")

	var emails []string
	for _, u := range fakeUsers {
		emails = append(emails, u.Email)
	}
	json.NewEncoder(w).Encode(map[string]any{"emails": emails})
}

// ---------------------------------------------------------------------
// Fake command injection: looks like a shell-backed ping diagnostic but
// never executes a real command. Time-based payloads (";sleep N") cause a
// capped in-process delay instead of a real sleep(1) call, and
// "echo TOKEN" payloads get their token reflected, so both classic
// blind-command-injection detection techniques still work.
// ---------------------------------------------------------------------

var (
	sleepPattern = regexp.MustCompile(`(?i)sleep\s+(\d+)`)
	echoPattern  = regexp.MustCompile(`(?i)echo\s+([A-Za-z0-9_\-]{1,64})`)
)

func handlePingCmdInjection(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if m := sleepPattern.FindStringSubmatch(host); m != nil {
		secs, _ := strconv.Atoi(m[1])
		if secs > 10 {
			secs = 10 // capped so this can never be used to hang the server
		}
		time.Sleep(time.Duration(secs) * time.Second)
	}

	echoOutput := ""
	if m := echoPattern.FindStringSubmatch(host); m != nil {
		echoOutput = "\n" + m[1]
	}

	// Intentionally unescaped reflection of the raw host value.
	fmt.Fprintf(w, `<pre>PING %s: 1 packets transmitted, 1 received, 0%% packet loss%s</pre><a href="/">Home</a>`, host, echoOutput)
}

// ---------------------------------------------------------------------
// Fake server-side template injection. The template body is built from
// user input and parsed/executed with text/template; the exposed data
// only has a Name field and a decoy SecretToken, and no functions are
// registered, so this can leak the token but cannot reach the filesystem
// or execute code.
// ---------------------------------------------------------------------

func handleRenderSSTI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmplText := "<h1>Hello, " + name + "!</h1>"
	tmpl, err := template.New("render").Parse(tmplText)
	if err != nil {
		fmt.Fprintf(w, "<pre>template error: %s</pre>", err.Error())
		return
	}

	data := map[string]string{
		"Name":        name,
		"SecretToken": "fake-session-secret-9f8e7d6c",
	}
	if err := tmpl.Execute(w, data); err != nil {
		fmt.Fprintf(w, "<pre>template execution error: %s</pre>", err.Error())
	}
}

// ---------------------------------------------------------------------
// CSRF: a state-changing GET endpoint with no token/origin check.
// Mutates only an in-memory demo balance (resets on restart).
// ---------------------------------------------------------------------

func handleTransferCSRF(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	amountStr := r.URL.Query().Get("amount")
	amount, err := strconv.Atoi(amountStr)
	if err != nil {
		amount = 0
	}

	balanceMu.Lock()
	balance -= amount
	newBalance := balance
	balanceMu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<p>Transferred %d to %s. New balance: %d</p><a href=\"/\">Home</a>", amount, to, newBalance)
}

// ---------------------------------------------------------------------
// SSRF: makes a real outbound request to the attacker-supplied URL, but
// bounded by a short timeout and a response size cap so it cannot be used
// to exhaust server resources. /internal/metadata below gives it a safe,
// self-contained target to demonstrate the classic
// "SSRF -> internal metadata disclosure" chain without touching anything
// outside this process.
// ---------------------------------------------------------------------

func handleFetchSSRF(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if target == "" {
		fmt.Fprint(w, "missing url parameter")
		return
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintf(w, "fetch error: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	fmt.Fprintf(w, "status: %s\n\n%s", resp.Status, body)
}

func handleInternalMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"instance_id":      "i-0fakeinstance00",
		"iam_role":         "vulnapp-fake-role",
		"access_key_id":    "AKIAFAKEFAKEFAKEFAKE",
		"secret_access_key": "FakeSecretAccessKeyDoNotUseThisIsADemoValue",
	})
}

// ---------------------------------------------------------------------
// Verbose error / stack trace disclosure
// ---------------------------------------------------------------------

func handleCrashStackTrace(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	// Deliberate panic, caught by recoverMiddleware, which writes the
	// stack trace (and this fake secret-bearing message) to the response.
	panic(fmt.Sprintf(
		"unexpected nil config for tenant=%q (dsn=postgres://vulnapp:SuperSecretDBPass!@localhost:5432/vulnapp)",
		tenant,
	))
}
