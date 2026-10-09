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
// Shared layout. The site is themed as an ordinary small-business page
// ("Acme Supplies") on purpose: the vulnerabilities live behind normal
// looking features (search, catalog, account page, referral program,
// staff portal, ...) rather than a page that announces what's broken.
// ---------------------------------------------------------------------

func pageHeader(title string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s - Acme Supplies</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css">
  <!-- maintenance: temporary admin login left enabled for the launch team, admin / SuperSecretPass!2024 - remove before go-live -->
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="/">&#128230; Acme Supplies</a>
    <nav>
      <a href="/products">Products</a>
      <a href="/search">Search</a>
      <a href="/comments">Reviews</a>
      <a href="/account?id=1">My Account</a>
      <a class="btn-ghost" href="/login">Sign in</a>
    </nav>
  </div>
</header>
<main class="wrap">
`, title)
}

const pageFooter = `
</main>
<footer class="site-footer">
  <div class="wrap">
    <a href="/redirect?url=https://partners.example.com/distributors">Partner network</a>
    <span class="dot">&middot;</span>
    <a href="/ping">Network status</a>
    <span class="dot">&middot;</span>
    <a href="/admin">Staff portal</a>
    <p>&copy; 2026 Acme Supplies Co.</p>
  </div>
</footer>
<script src="/static/app.js"></script>
</body>
</html>`

// ---------------------------------------------------------------------
// Home page
// ---------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Home"))

	fmt.Fprint(w, `<section class="hero">
  <h1>Wholesale office &amp; warehouse supplies, delivered fast</h1>
  <p>Acme Supplies has been equipping small businesses since 1998. Browse our catalog, read reviews, or sign in to manage your account.</p>
</section>

<section class="section">
  <h2>Featured products</h2>
  <div class="grid">`)
	for _, p := range fakeProducts {
		fmt.Fprintf(w, `<a class="card" href="/products?id=%d"><div class="card-title">%s</div><div class="card-price">$%.2f</div></a>`, p.ID, p.Name, p.Price)
	}
	fmt.Fprint(w, `</div>
</section>

<section class="section split">
  <div class="card">
    <h2>Personalize your welcome message</h2>
    <form action="/render" method="get" class="form-inline">
      <input name="name" placeholder="Your name">
      <button class="btn">Preview</button>
    </form>
  </div>
  <div class="card">
    <h2>Refer a friend</h2>
    <p>Give $10, get $10.</p>
    <a class="btn" href="/transfer?to=friend@example.com&amp;amount=10">Send referral credit</a>
  </div>
</section>

<section class="section">
  <h2>What customers are saying</h2>`)

	commentsMu.Lock()
	start := 0
	if len(comments) > 2 {
		start = len(comments) - 2
	}
	for _, c := range comments[start:] {
		fmt.Fprintf(w, `<div class="comment"><b>%s</b>: %s</div>`, c.Author, c.Body)
	}
	commentsMu.Unlock()
	fmt.Fprint(w, `<a href="/comments">Read all reviews &rarr;</a>
</section>`)

	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// Exposed .env
// ---------------------------------------------------------------------

func handleEnvFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(envFileContent)
}

// ---------------------------------------------------------------------
// Reflected XSS (site search)
// ---------------------------------------------------------------------

func handleSearchXSS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Search"))
	fmt.Fprint(w, `<h1>Search our catalog</h1>
<form action="/search" method="get">
  <input name="q" placeholder="e.g. widget" value="`+q+`">
  <button class="btn">Search</button>
</form>`)
	if q != "" {
		// Intentionally unescaped: the query is written straight into
		// the response body, as if to say "no results, did you mean...".
		fmt.Fprintf(w, `<p>No results found for: %s</p>`, q)
	}
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// Stored XSS ("customer reviews")
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
	fmt.Fprint(w, pageHeader("Reviews"))
	fmt.Fprint(w, `<h1>Customer reviews</h1>`)

	commentsMu.Lock()
	for _, c := range comments {
		// Intentionally unescaped: stored author/body rendered as raw HTML.
		fmt.Fprintf(w, `<div class="comment"><b>%s</b>: %s</div>`, c.Author, c.Body)
	}
	commentsMu.Unlock()

	fmt.Fprint(w, `
<h2>Leave a review</h2>
<form action="/comments" method="post">
  <input name="author" placeholder="Your name">
  <input name="body" placeholder="Your review">
  <button class="btn">Post review</button>
</form>`)
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// SQL injection - login (string-concatenated query, auth bypass,
// error-based disclosure, username enumeration)
// ---------------------------------------------------------------------

func handleLoginSQLi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Sign in"))

	if r.Method != http.MethodPost {
		fmt.Fprint(w, `<h1>Sign in</h1>
<form action="/login" method="post">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button class="btn">Sign in</button>
</form>`)
		fmt.Fprint(w, pageFooter)
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
		fmt.Fprintf(w, "<pre>Sign-in failed: %s</pre>", err.Error())
		fmt.Fprint(w, pageFooter)
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

		fmt.Fprintf(w, `<h1>Welcome back, %s</h1><p><a href="/account?id=%d">Go to my account</a></p>`, uname, id)
		fmt.Fprint(w, pageFooter)
		return
	}

	// Username enumeration: a second, equally vulnerable query decides
	// which error message to show.
	existsQuery := fmt.Sprintf("SELECT 1 FROM users WHERE username='%s'", username)
	existsRows, err := db.Query(existsQuery)
	if err != nil {
		fmt.Fprintf(w, "<pre>Sign-in failed: %s</pre>", err.Error())
		fmt.Fprint(w, pageFooter)
		return
	}
	defer existsRows.Close()

	if existsRows.Next() {
		fmt.Fprint(w, "<p>That password doesn't look right. Please try again.</p>")
	} else {
		fmt.Fprint(w, "<p>We couldn't find an account with that username.</p>")
	}
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// SQL injection - product catalog (numeric context, UNION-based)
// ---------------------------------------------------------------------

func handleProductsSQLi(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Products"))

	if id == "" {
		fmt.Fprint(w, `<section class="section"><h1>Our products</h1><div class="grid">`)
		for _, p := range fakeProducts {
			fmt.Fprintf(w, `<a class="card" href="/products?id=%d"><div class="card-title">%s</div><div class="card-price">$%.2f</div></a>`, p.ID, p.Name, p.Price)
		}
		fmt.Fprint(w, `</div></section>`)
		fmt.Fprint(w, pageFooter)
		return
	}

	// Deliberately vulnerable: numeric parameter spliced in without
	// quoting or validation, enabling UNION-based injection, e.g.
	// /products?id=0 UNION SELECT username, password, 0 FROM users
	query := fmt.Sprintf("SELECT id, name, price FROM products WHERE id = %s", id)

	rows, err := db.Query(query)
	if err != nil {
		fmt.Fprintf(w, "<pre>Couldn't load that product: %s</pre>", err.Error())
		fmt.Fprint(w, pageFooter)
		return
	}
	defer rows.Close()

	fmt.Fprint(w, `<section class="section"><h1>Product details</h1><table><tr><th>ID</th><th>Name</th><th>Price</th></tr>`)
	var firstName string
	for rows.Next() {
		var colID sql.NullString
		var name sql.NullString
		var price sql.NullString
		if err := rows.Scan(&colID, &name, &price); err != nil {
			fmt.Fprintf(w, "<tr><td colspan=3>%s</td></tr>", err.Error())
			continue
		}
		if firstName == "" {
			firstName = name.String
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", colID.String, name.String, price.String)
	}
	fmt.Fprint(w, "</table>")

	if firstName != "" {
		slug := strings.ToLower(strings.ReplaceAll(firstName, " ", "-"))
		fmt.Fprintf(w, `<p><a href="/files?name=%s-spec.txt">Download spec sheet</a></p>`, slug)
	}
	fmt.Fprint(w, "</section>")
	fmt.Fprint(w, pageFooter)
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
		"widget-spec.txt": "Widget - 10x10cm, 250g, aluminium. Rated for warehouse use.\n",
		"gadget-spec.txt": "Gadget - 5x5cm, 80g, ABS plastic. Batteries not included.\n",
		"gizmo-spec.txt":  "Gizmo - 15x8cm, 400g, steel. Ships in a reinforced box.\n",
		"report.txt":      "Quarterly report: everything is fine.\n",
		"readme.txt":      "This is a sample file served by /files.\n",
	}
	if content, ok := safeFiles[base]; ok {
		fmt.Fprint(w, content)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "file not found")
}

// ---------------------------------------------------------------------
// Open redirect ("partner network" link)
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
// My Account page: a normal-looking page whose inline script quietly
// calls the IDOR-vulnerable /profile API to fill itself in.
// ---------------------------------------------------------------------

func handleAccountPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("My Account"))
	fmt.Fprintf(w, `<h1>My account</h1>
<div id="account">Loading your details&hellip;</div>
<script>
fetch('/profile?id=%s')
  .then(function(r){ return r.json(); })
  .then(function(d){
    document.getElementById('account').innerHTML =
      '<p>Username: ' + d.username + '</p>' +
      '<p>Email: ' + d.email + '</p>' +
      '<p>Address: ' + d.address + '</p>';
  });
</script>`, id)
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// IDOR: the JSON API the account page above calls, with no check that
// the caller is allowed to see this particular id.
// ---------------------------------------------------------------------

func handleProfileIDOR(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		id = 1
	}

	w.Header().Set("Content-Type", "application/json")

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err != nil || cookie.Value != "admin" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, pageHeader("Staff Portal"))
		fmt.Fprint(w, `<h1>Staff portal</h1><p>Please <a href="/login">sign in</a> with a staff account to continue.</p>`)
		fmt.Fprint(w, pageFooter)
		return
	}

	fmt.Fprint(w, pageHeader("Staff Portal"))
	fmt.Fprint(w, `<h1>Staff portal</h1><h2>Customers</h2><table border=1><tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>`)
	for _, u := range fakeUsers {
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", u.ID, u.Username, u.Password, u.Role)
	}
	fmt.Fprint(w, `</table>
<h2>Import product image</h2>
<p>Paste a URL and we'll pull the image into the catalog.</p>
<form action="/fetch" method="get">
  <input name="url" placeholder="https://cdn.example.com/widget.png" style="width:300px">
  <button class="btn">Import</button>
</form>`)
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// Sensitive data exposure via a "debug" config endpoint
// ---------------------------------------------------------------------

func handleAPIConfigExposure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Api-Key", "sk_live_FAKE1234567890abcdef")
	json.NewEncoder(w).Encode(map[string]any{
		"debug":             true,
		"version":           "0.1.0-dev",
		"database_dsn":      "postgres://vulnapp:SuperSecretDBPass!@localhost:5432/vulnapp",
		"internal_api_key":  "fake-internal-key-7788990011",
		"jwt_secret":        "changeme",
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
// Fake command injection: looks like a shell-backed network diagnostic
// but never executes a real command. Time-based payloads ("; sleep N")
// cause a capped in-process delay instead of a real sleep(1) call, and
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
	fmt.Fprint(w, pageHeader("Network Status"))
	fmt.Fprint(w, `<h1>Network status</h1>
<p>Check connectivity to one of our regional warehouses.</p>
<form action="/ping" method="get">
  <input name="host" placeholder="warehouse-east.acme.internal" value="`+host+`">
  <button class="btn">Check</button>
</form>`)

	if host != "" {
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
		fmt.Fprintf(w, `<pre>PING %s: 1 packets transmitted, 1 received, 0%% packet loss%s</pre>`, host, echoOutput)
	}
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// Fake server-side template injection, behind a "preview your welcome
// email" feature. The template body is built from user input and
// parsed/executed with text/template; the exposed data only has a Name
// field and a decoy SecretToken, and no functions are registered, so
// this can leak the token but cannot reach the filesystem or execute
// code.
// ---------------------------------------------------------------------

func handleRenderSSTI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Welcome Preview"))
	fmt.Fprint(w, `<h1>Preview your welcome message</h1>
<form action="/render" method="get">
  <input name="name" placeholder="Your name" value="`+name+`">
  <button class="btn">Preview</button>
</form>`)

	if name != "" {
		tmplText := "<p>Hello, " + name + "! Thanks for joining Acme Supplies.</p>"
		tmpl, err := template.New("render").Parse(tmplText)
		if err != nil {
			fmt.Fprintf(w, "<pre>Couldn't render preview: %s</pre>", err.Error())
		} else {
			data := map[string]string{
				"Name":        name,
				"SecretToken": "fake-session-secret-9f8e7d6c",
			}
			if err := tmpl.Execute(w, data); err != nil {
				fmt.Fprintf(w, "<pre>Couldn't render preview: %s</pre>", err.Error())
			}
		}
	}
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// CSRF: a state-changing GET endpoint ("send referral credit") with no
// token/origin check. Mutates only an in-memory demo balance (resets on
// restart).
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
	fmt.Fprint(w, pageHeader("Referral Credit"))
	fmt.Fprintf(w, "<h1>Referral credit sent</h1><p>Sent $%d to %s. Your remaining referral balance: $%d</p>", amount, to, newBalance)
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// SSRF, behind the staff portal's "import product image from URL"
// feature. Makes a real outbound request to the attacker-supplied URL,
// but bounded by a short timeout and a response size cap so it cannot be
// used to exhaust server resources. /internal/metadata below gives it a
// safe, self-contained target to demonstrate the classic
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
		fmt.Fprintf(w, "couldn't import image: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	fmt.Fprintf(w, "status: %s\n\n%s", resp.Status, body)
}

func handleInternalMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"instance_id":       "i-0fakeinstance00",
		"iam_role":          "vulnapp-fake-role",
		"access_key_id":     "AKIAFAKEFAKEFAKEFAKE",
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
