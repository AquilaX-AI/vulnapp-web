package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
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
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
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

// sqlErrorBanner renders a database error the way a naive PHP/MySQL app
// from the Server banner's era would: the raw driver error, wrapped in a
// classic, instantly-recognizable MySQL warning line and a file path, so
// even a scanner that just greps for known error-disclosure signatures
// (rather than actually parsing SQLite's own error format) picks it up.
func sqlErrorBanner(file string, err error) string {
	return fmt.Sprintf(
		"<pre>Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in %s\n\n%s</pre>",
		file, err.Error(),
	)
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
  <!-- honeytoken: hidden from any real visitor, exists only so an
       automated crawler following every href finds it -->
  <a href="/__trap/audit-export" style="position:absolute;left:-9999px" aria-hidden="true" tabindex="-1">internal audit export</a>
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
  <div class="card">
    <h2>Have a promo code?</h2>
    <form action="/api/validate-coupon" method="get" class="form-inline">
      <input name="code" placeholder="e.g. SAVE10">
      <button class="btn">Check format</button>
    </form>
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

	if r.Method != http.MethodPost {
		fmt.Fprint(w, pageHeader("Sign in"))
		fmt.Fprint(w, `<h1>Sign in</h1>
<form action="/login" method="post">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <label><input type="checkbox" name="remember" value="1"> Remember me</label>
  <button class="btn">Sign in</button>
</form>
<p><a href="/forgot-password">Forgot your password?</a></p>`)
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
		fmt.Fprint(w, pageHeader("Sign in"))
		fmt.Fprint(w, sqlErrorBanner("/var/www/html/login.php", err))
		fmt.Fprint(w, pageFooter)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id int
		var uname, role string
		rows.Scan(&id, &uname, &role)

		// Insecure cookie: no Secure, HttpOnly, or SameSite attributes,
		// and the value is client-trusted on every later request. These
		// MUST be set before any body bytes are written (below), or
		// Go's http package flushes a 200 with no Set-Cookie headers
		// and they're silently dropped.
		http.SetCookie(w, &http.Cookie{Name: "role", Value: role})
		http.SetCookie(w, &http.Cookie{Name: "username", Value: uname})

		// Session fixation: whatever session_id was already attached to
		// this request (see sessionFixationMiddleware) - including one an
		// attacker set via a crafted link before the victim ever logged
		// in - becomes the authenticated session. It's never rotated.
		if sid, _ := r.Context().Value(sessionIDKey).(string); sid != "" {
			sessionsMu.Lock()
			sessions[sid] = uname
			sessionsMu.Unlock()
		}

		if r.FormValue("remember") != "" {
			// "Remember me" token: signed with the same weak, hardcoded
			// secret that /api/config leaks as "jwt_secret", via a
			// long-deprecated JWT library with a known signature-forgery
			// CVE (GO-2020-0017 / CVE-2020-26160). Anyone who reads that
			// config endpoint can mint their own token for any username
			// and role.
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": uname,
				"role":     role,
				"exp":      time.Now().Add(30 * 24 * time.Hour).Unix(),
			})
			signed, err := token.SignedString([]byte(jwtSecret))
			if err == nil {
				http.SetCookie(w, &http.Cookie{Name: "remember_token", Value: signed})
			}
		}

		fmt.Fprint(w, pageHeader("Sign in"))
		fmt.Fprintf(w, `<h1>Welcome back, %s</h1><p><a href="/account?id=%d">Go to my account</a></p>`, uname, id)
		fmt.Fprint(w, pageFooter)
		return
	}

	// Username enumeration: a second, equally vulnerable query decides
	// which error message to show.
	existsQuery := fmt.Sprintf("SELECT 1 FROM users WHERE username='%s'", username)
	existsRows, err := db.Query(existsQuery)
	if err != nil {
		fmt.Fprint(w, pageHeader("Sign in"))
		fmt.Fprint(w, sqlErrorBanner("/var/www/html/login.php", err))
		fmt.Fprint(w, pageFooter)
		return
	}
	defer existsRows.Close()

	fmt.Fprint(w, pageHeader("Sign in"))
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
		fmt.Fprint(w, sqlErrorBanner("/var/www/html/products.php", err))
		fmt.Fprint(w, pageFooter)
		return
	}
	defer rows.Close()

	fmt.Fprint(w, `<section class="section"><h1>Product details</h1><table><tr><th>ID</th><th>Name</th><th>Price</th></tr>`)
	var firstID, firstName, firstPrice string
	for rows.Next() {
		var colID sql.NullString
		var name sql.NullString
		var price sql.NullString
		if err := rows.Scan(&colID, &name, &price); err != nil {
			fmt.Fprintf(w, "<tr><td colspan=3>%s</td></tr>", err.Error())
			continue
		}
		if firstName == "" {
			firstID, firstName, firstPrice = colID.String, name.String, price.String
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", colID.String, name.String, price.String)
	}
	fmt.Fprint(w, "</table>")

	if firstName != "" {
		slug := strings.ToLower(strings.ReplaceAll(firstName, " ", "-"))
		fmt.Fprintf(w, `<p><a href="/files?name=%s-spec.txt">Download spec sheet</a></p>`, slug)

		// Business logic flaw: price travels as a plain, client-editable
		// form field instead of being re-looked-up server-side at
		// checkout.
		fmt.Fprintf(w, `<form action="/checkout" method="get" class="form-inline">
  <input type="hidden" name="product_id" value="%s">
  <input type="hidden" name="price" value="%s">
  <input name="quantity" value="1" size="3">
  <input name="promo" placeholder="Promo code (optional)">
  <button class="btn">Buy now</button>
</form>`, firstID, firstPrice)
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
<p><a href="/api/export?api_key=%s&amp;id=%s">Export my data (CSV)</a></p>
<div id="live-updates"></div>
<script>
fetch('/profile?id=%s')
  .then(function(r){ return r.json(); })
  .then(function(d){
    document.getElementById('account').innerHTML =
      '<img src="https://www.gravatar.com/avatar/' + d.avatar_hash + '?d=mp" width="48" height="48">' +
      '<p>Username: ' + d.username + '</p>' +
      '<p>Email: ' + d.email + '</p>' +
      '<p>Address: ' + d.address + '</p>';
  });
fetch('/api/me')
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d.username) {
      document.getElementById('account').innerHTML +=
        '<p><small>Remembered sign-in: ' + d.username + ' (' + d.role + ')</small></p>';
    }
  });

// Live order updates over a WebSocket - see /ws in pentest.go.
var wsProto = location.protocol === 'https:' ? 'wss://' : 'ws://';
var ws = new WebSocket(wsProto + location.host + '/ws');
ws.onmessage = function(evt) {
  var msg = JSON.parse(evt.data);
  document.getElementById('live-updates').innerText = msg.message;
};
</script>`, exportAPIKey, id, id)
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
	// Sensitive, per-user PII, cacheable by any shared proxy/CDN in front
	// of this for an hour - a different (and worse) finding than simply
	// having no Cache-Control header at all.
	w.Header().Set("Cache-Control", "public, max-age=3600")

	usersMu.Lock()
	defer usersMu.Unlock()

	for _, u := range fakeUsers {
		if u.ID == id {
			json.NewEncoder(w).Encode(map[string]any{
				"id":          u.ID,
				"username":    u.Username,
				"email":       u.Email,
				"ssn":         u.SSN,
				"address":     u.Address,
				"avatar_hash": gravatarHash(u.Email),
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"error":"not found"}`)
}

// gravatarHash mirrors the real Gravatar scheme (MD5 of the lowercased,
// trimmed email) to build an avatar URL. It's a legitimate, widely-used
// pattern - and also a textbook "use of a weak cryptographic primitive"
// finding (gosec G401/G501) for a SAST tool to flag, since MD5 is doing
// real (if low-stakes) identity work here.
func gravatarHash(email string) string {
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------
// "Remember me" JWT: the classic insecure validation pattern. keyFunc
// hands back the HMAC secret for *any* token without checking
// token.Method, so a token signed with a different algorithm than the
// server expects is still accepted as long as the attacker can satisfy
// whatever keyFunc blindly returns - here that's moot since HS256 with a
// known/leaked secret is already enough to forge any claim set.
// ---------------------------------------------------------------------

func handleAPIMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, err := r.Cookie("remember_token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"not signed in"}`)
		return
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid token: %s"}`, err)
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	json.NewEncoder(w).Encode(claims)
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
	usersMu.Lock()
	for _, u := range fakeUsers {
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", u.ID, u.Username, u.Password, u.Role)
	}
	usersMu.Unlock()
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
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(map[string]any{
		"debug":            true,
		"version":          "0.1.0-dev",
		"database_dsn":     "postgres://vulnapp:SuperSecretDBPass!@10.0.4.23:5432/vulnapp",
		"internal_lb_ip":   "192.168.56.10",
		"internal_api_key": "fake-internal-key-7788990011",
		"jwt_secret":       jwtSecret,
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
		"access_key_id":     canaryOr("CANARY_AWS_ACCESS_KEY_ID", "AKIAFAKEFAKEFAKEFAKE"),
		"secret_access_key": canaryOr("CANARY_AWS_SECRET_ACCESS_KEY", "FakeSecretAccessKeyDoNotUseThisIsADemoValue"),
	})
}

// canaryOr returns a real canary-token credential if one's configured
// via the given env var, falling back to the static fake value
// otherwise. A canary token (e.g. a free one from canarytokens.org) is a
// real, working-looking AWS key that does nothing on its own but alerts
// you - by email/webhook, completely outside this app - the moment
// someone actually tries to use it against the real AWS API. That turns
// "someone extracted this fake secret" from a log line here into
// external, out-of-band proof that it happened and got used.
func canaryOr(envVar, fallback string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fallback
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

// ---------------------------------------------------------------------
// robots.txt pointing straight at the "sensitive" areas - a classic
// recon source that also helps a scanner's spider actually find them.
// ---------------------------------------------------------------------

func handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `User-agent: *
Disallow: /admin
Disallow: /uploads/
Disallow: /api/
Disallow: /internal/
Disallow: /crash
Disallow: /.git/
Disallow: /config.php.bak
Disallow: /phpinfo.php
Disallow: /__trap/
`)
}

// handleHoneytokenTrap backs the hidden, off-screen link in pageFooter
// (and the robots.txt Disallow above - some aggressive scanners
// specifically check Disallow'd paths). No real visitor can click a
// link positioned off-screen with aria-hidden set, so reaching this
// path at all is a near-certain sign of an automated crawler/scanner,
// independent of anything about the request's content.
func handleHoneytokenTrap(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s followed hidden honeytoken link %s [T1595.002 Active Scanning: Vulnerability Scanning | Automated Crawler/Scanner Confirmed (no human would click a hidden link)]", r.RemoteAddr, r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 page not found")
}

// ---------------------------------------------------------------------
// Fake exposed .git metadata (source control exposure), with a
// credential leaked straight in the remote URL.
// ---------------------------------------------------------------------

func handleGitHead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "ref: refs/heads/main\n")
}

func handleGitConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://admin:SuperSecretPass!2024@github.com/acme-supplies/vulnapp-web-internal.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)
}

// ---------------------------------------------------------------------
// Fake leftover PHP backup/debug files, consistent with the fake
// Apache/PHP Server and X-Powered-By banner.
// ---------------------------------------------------------------------

func handleConfigPhpBak(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `<?php
// legacy config, superseded - left here by mistake (fake, for demo purposes)
define('DB_HOST', 'db.internal');
define('DB_USER', 'vulnapp');
define('DB_PASS', 'SuperSecretDBPass!');
define('SECRET_KEY', 'FakeAppSecretDoNotUseThisIsADemoValue000111222');
?>
`)
}

func handlePhpInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 5.3.3</h1>
<table border=1>
<tr><td>System</td><td>Linux acme-web01 2.6.32-696.el6.x86_64</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
<tr><td>SERVER_SOFTWARE</td><td>Apache/2.2.15 (CentOS)</td></tr>
<tr><td>DB_PASS</td><td>SuperSecretDBPass!</td></tr>
<tr><td>allow_url_fopen</td><td>On</td></tr>
<tr><td>register_globals</td><td>On</td></tr>
</table>
</body></html>`)
}

// ---------------------------------------------------------------------
// Weak password reset: a predictable 6-digit code generated with
// math/rand (not crypto/rand - a textbook gosec G404 finding), with no
// rate limiting and no expiry, so it's brute-forceable in well under a
// million requests. The "forgot password" step also happily confirms
// whether the username exists (further username enumeration) and prints
// the code straight into the response instead of actually emailing it.
// ---------------------------------------------------------------------

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Forgot Password"))

	if r.Method != http.MethodPost {
		fmt.Fprint(w, `<h1>Forgot your password?</h1>
<form action="/forgot-password" method="post">
  <input name="username" placeholder="Username">
  <button class="btn">Send reset code</button>
</form>`)
		fmt.Fprint(w, pageFooter)
		return
	}

	username := r.FormValue("username")

	usersMu.Lock()
	found := false
	for _, u := range fakeUsers {
		if u.Username == username {
			found = true
			break
		}
	}
	usersMu.Unlock()

	if !found {
		fmt.Fprint(w, "<p>We couldn't find an account with that username.</p>")
		fmt.Fprint(w, pageFooter)
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	resetTokensMu.Lock()
	resetTokens[username] = code
	resetTokensMu.Unlock()

	// Host header injection: the "link we'd email you" is built from the
	// request's own Host header with no validation against an allowlist.
	// A real app that actually emails this would let an attacker who can
	// set an arbitrary Host header (trivial - it's just a request header)
	// redirect a victim's password-reset flow to a domain of their
	// choosing, leaking the code when the victim clicks it.
	resetLink := fmt.Sprintf("https://%s/reset-password?username=%s&code=%s", r.Host, username, code)

	// A real app would email this instead of printing it on screen -
	// that part's a separate, intentional information-disclosure shortcut.
	fmt.Fprintf(w, `<h1>Reset code sent</h1>
<p>(Demo shortcut: your code is <b>%s</b> - a real app would email you this link instead: <code>%s</code>)</p>
<form action="/reset-password" method="post">
  <input type="hidden" name="username" value="%s">
  <input name="code" placeholder="6-digit code">
  <input name="new_password" type="password" placeholder="New password">
  <button class="btn">Reset password</button>
</form>`, code, resetLink, username)
	fmt.Fprint(w, pageFooter)
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Reset Password"))

	if r.Method != http.MethodPost {
		fmt.Fprint(w, `<h1>Reset password</h1>
<form action="/reset-password" method="post">
  <input name="username" placeholder="Username">
  <input name="code" placeholder="6-digit code">
  <input name="new_password" type="password" placeholder="New password">
  <button class="btn">Reset password</button>
</form>`)
		fmt.Fprint(w, pageFooter)
		return
	}

	username := r.FormValue("username")
	code := r.FormValue("code")
	newPassword := r.FormValue("new_password")

	resetTokensMu.Lock()
	expected, ok := resetTokens[username]
	resetTokensMu.Unlock()

	// No rate limiting on this comparison: a fuzzer/intruder can just
	// try all 1,000,000 codes.
	if !ok || code != expected {
		fmt.Fprint(w, "<p>That code is invalid or has expired.</p>")
		fmt.Fprint(w, pageFooter)
		return
	}

	// Race condition (CWE-367): the code is checked here but not deleted
	// until after this delay (standing in for a real DB write), so two
	// concurrent requests using the same still-valid code both pass the
	// check above before either one consumes it - a one-time code usable
	// more than once.
	time.Sleep(50 * time.Millisecond)

	usersMu.Lock()
	for i := range fakeUsers {
		if fakeUsers[i].Username == username {
			fakeUsers[i].Password = newPassword
		}
	}
	usersMu.Unlock()
	db.Exec("UPDATE users SET password = ? WHERE username = ?", newPassword, username)

	resetTokensMu.Lock()
	delete(resetTokens, username)
	resetTokensMu.Unlock()

	fmt.Fprint(w, `<h1>Password updated</h1><p><a href="/login">Sign in</a> with your new password.</p>`)
	fmt.Fprint(w, pageFooter)
}

// ---------------------------------------------------------------------
// Unchecked array index (CWE-129): "related products" indexed straight
// from a query param with no bounds check. Any index outside [0,3)
// panics - recovered safely by recoverMiddleware - which is exactly the
// kind of crash a basic fuzzer finds within seconds of throwing
// out-of-range integers at an endpoint.
// ---------------------------------------------------------------------

func handleRelatedProductCrash(w http.ResponseWriter, r *http.Request) {
	index, _ := strconv.Atoi(r.URL.Query().Get("index"))
	w.Header().Set("Content-Type", "application/json")
	p := fakeProducts[index]
	json.NewEncoder(w).Encode(p)
}
