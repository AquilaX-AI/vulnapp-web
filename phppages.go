package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------
// PHP deception layer.
//
// The whole app already claims to be Apache/2.2.15 + PHP/5.3.3 in its
// Server / X-Powered-By banners (see logMiddleware in main.go). This
// file makes that story believable past the banner: a spread of the
// .php pages a real legacy LAMP app would have, so a scanner that
// fingerprints the stack as PHP and starts probing .php endpoints,
// LFI/RFI params, and dropped-webshell filenames finds exactly what it
// expects to find - and every probe gets logged and MITRE-tagged.
//
// Same safety model as the rest of the repo: nothing here runs PHP,
// touches the real filesystem, or executes a command. LFI payloads
// resolve against the in-memory decoyFiles fingerprints (same as
// /files), the fake webshell echoes canned output, and SQLi-looking
// params return a canned mysql_fetch_array() banner. Every page sets a
// per-request PHPSESSID so the session cookie looks authentically PHP.
// ---------------------------------------------------------------------

// phpPoweredBy is deliberately a slightly different, equally-EOL PHP
// build than the global PHP/5.3.3 banner - a real server often reports a
// more specific version on dynamic pages than the generic one a proxy
// adds. Both are long past end-of-life and have ample CVE history, which
// is the point.
const phpPoweredBy = "PHP/5.4.45"

// phpRoutes are registered on the main mux. Keeping them in one table
// (rather than scattered mux.HandleFunc calls) makes the fake site map
// easy to see at a glance and easy to keep in sync with the fake
// robots.txt / sitemap below.
var phpRoutes = map[string]http.HandlerFunc{
	"/index.php":           handlePHPIndex,
	"/home.php":            handlePHPIndex,
	"/login.php":           handlePHPLogin,
	"/logout.php":          handlePHPLogout,
	"/register.php":        handlePHPRegister,
	"/admin/":              handlePHPAdmin,
	"/admin/index.php":     handlePHPAdmin,
	"/admin/login.php":     handlePHPAdminLogin,
	"/product.php":         handlePHPProduct,
	"/news.php":            handlePHPProduct,
	"/cart.php":            handlePHPCart,
	"/search.php":          handlePHPSearch,
	"/contact.php":         handlePHPContact,
	"/download.php":        handlePHPDownload,
	"/view.php":            handlePHPInclude,
	"/page.php":            handlePHPInclude,
	"/upload.php":          handlePHPUpload,
	"/info.php":            handlePhpInfo,
	"/test.php":            handlePhpInfo,
	"/db.php":              handlePHPSourceLeak,
	"/config.php":          handlePHPSourceLeak,
	"/includes/config.php": handlePHPSourceLeak,
}

// phpBackdoorNames are the filenames of webshells that get sprayed at
// every PHP-looking site on the internet. A request to any of them is a
// strong signal on its own, so they share one handler that serves a
// believable (inert) webshell UI and tags the hit as web-shell access.
var phpBackdoorNames = []string{
	"/shell.php", "/cmd.php", "/c99.php", "/c100.php", "/r57.php",
	"/wso.php", "/b374k.php", "/alfa.php", "/up.php", "/webshell.php",
	"/backdoor.php", "/eval.php", "/adminer.php",
}

// isPHPBackdoorPath reports whether path is one of the sprayed webshell
// filenames - used both to route the request and to MITRE-tag it.
func isPHPBackdoorPath(path string) bool {
	for _, name := range phpBackdoorNames {
		if path == name {
			return true
		}
	}
	return false
}

func registerPHPPages(mux *http.ServeMux) {
	for path, h := range phpRoutes {
		mux.HandleFunc(path, h)
	}
	for _, name := range phpBackdoorNames {
		mux.HandleFunc(name, handlePHPWebshell)
	}
}

// phpSessionID returns a believable 26-char lowercase-hex PHPSESSID.
// Derived from the remote address so repeated requests from one client
// look like one session, but it carries no real state.
func phpSessionID(r *http.Request) string {
	var a, b uint64 = 1469598103934665603, 1099511628211
	for _, c := range []byte(r.RemoteAddr + "|" + r.UserAgent()) {
		a ^= uint64(c)
		a *= 1099511628211
		b = b*31 + uint64(c)
	}
	// 26 lowercase-hex chars, the shape of a default PHPSESSID.
	return fmt.Sprintf("%016x%010x", a, b&0xffffffffff)
}

// phpHeader sets the headers a real PHP page would send: the specific
// X-Powered-By build and a session cookie. The global middleware already
// set a generic X-Powered-By; this overrides it with the page-level one.
func phpHeader(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Powered-By", phpPoweredBy)
	w.Header().Set("Set-Cookie", "PHPSESSID="+phpSessionID(r)+"; path=/")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func phpDoc(title, body string) string {
	return "<!DOCTYPE html>\n<html><head><title>" + title + "</title></head><body>\n" + body +
		"\n<hr><address>Apache/2.2.15 (CentOS) Server at acme-supplies.local Port 80</address>\n</body></html>"
}

func handlePHPIndex(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	fmt.Fprint(w, phpDoc("Acme Supplies", `<h1>Welcome to Acme Supplies</h1>
<p>Your one-stop shop for widgets, gadgets and gizmos.</p>
<ul>
  <li><a href="/product.php?id=1">Widgets</a></li>
  <li><a href="/product.php?id=2">Gadgets</a></li>
  <li><a href="/search.php?q=">Search</a></li>
  <li><a href="/login.php">Member login</a></li>
  <li><a href="/cart.php">Your cart</a></li>
</ul>
<!-- TODO: remove admin/ before launch. default creds still admin/admin123 -->`))
}

func handlePHPLogin(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	msg := ""
	if r.Method == http.MethodPost {
		// Looks like it authenticates; never actually does anything.
		msg = `<p style="color:red">Invalid username or password.</p>`
	}
	fmt.Fprint(w, phpDoc("Login - Acme Supplies", msg+`<h1>Member Login</h1>
<form method="post" action="/login.php">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Sign in</button>
</form>
<p><a href="/register.php">Create an account</a> &middot; <a href="/admin/login.php">Staff login</a></p>`))
}

func handlePHPLogout(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	w.Header().Set("Set-Cookie", "PHPSESSID=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
	http.Redirect(w, r, "/index.php", http.StatusFound)
}

func handlePHPRegister(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	fmt.Fprint(w, phpDoc("Register - Acme Supplies", `<h1>Create an account</h1>
<form method="post" action="/register.php">
  <input name="username" placeholder="Username"><br>
  <input name="email" placeholder="Email"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Register</button>
</form>`))
}

func handlePHPAdmin(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	// "Protected" area that just shows a login gate - the point is the
	// path exists and is discoverable, not that there's anything behind
	// it.
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, phpDoc("403 Forbidden", `<h1>Admin Area</h1>
<p>You must <a href="/admin/login.php">log in</a> to access the control panel.</p>`))
}

func handlePHPAdminLogin(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	msg := ""
	if r.Method == http.MethodPost {
		msg = `<p style="color:red">Access denied.</p>`
	}
	fmt.Fprint(w, phpDoc("Admin Login", msg+`<h1>Acme Admin Panel</h1>
<form method="post" action="/admin/login.php">
  <input name="user" placeholder="Admin user"><br>
  <input name="pass" type="password" placeholder="Password"><br>
  <button type="submit">Log in</button>
</form>
<p><small>Powered by AcmeCMS 1.4</small></p>`))
}

// handlePHPProduct looks like a classic id= SQL-injection sink. A quote
// (or other obvious SQLi marker) produces the canned MySQL error banner;
// otherwise it renders a static product. It never touches the real DB.
func handlePHPProduct(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	id := r.URL.Query().Get("id")
	if strings.ContainsAny(id, "'\"\\") || strings.Contains(strings.ToLower(id), "union") {
		fmt.Fprint(w, phpDoc("Database Error", sqlErrorBanner(
			"/var/www/html/product.php",
			errors.New("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"+id+"' at line 1"),
		)))
		return
	}
	fmt.Fprintf(w, phpDoc("Product - Acme Supplies", `<h1>Product #%s</h1>
<p>A fine product from the Acme catalog. In stock.</p>
<form method="post" action="/cart.php"><button>Add to cart</button></form>`), orDash(id))
}

func handlePHPCart(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	fmt.Fprint(w, phpDoc("Your Cart", `<h1>Shopping Cart</h1><p>Your cart is empty.</p>`))
}

// handlePHPSearch reflects the query unescaped - same reflected-XSS shape
// as the main /search endpoint, but on the PHP-looking path a scanner
// expects after fingerprinting the stack.
func handlePHPSearch(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, phpDoc("Search Results", `<h1>Search</h1>
<form method="get" action="/search.php"><input name="q" value="%s"><button>Go</button></form>
<p>You searched for: %s</p>
<p>No results found.</p>`), q, q)
}

func handlePHPContact(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	if r.Method == http.MethodPost {
		fmt.Fprint(w, phpDoc("Thanks", `<h1>Thank you</h1><p>Your message has been sent.</p>`))
		return
	}
	fmt.Fprint(w, phpDoc("Contact Us", `<h1>Contact Us</h1>
<form method="post" action="/contact.php">
  <input name="name" placeholder="Name"><br>
  <input name="email" placeholder="Email"><br>
  <textarea name="message" placeholder="Message"></textarea><br>
  <button>Send</button>
</form>`))
}

// handlePHPDownload / handlePHPInclude model the LFI/RFI sinks every PHP
// scanner tests (download.php?file=, view.php?page=). Traversal payloads
// resolve against the in-memory decoyFiles fingerprints - never the real
// filesystem - exactly like handleFilesTraversal. Remote (http://) include
// targets are logged as an RFI attempt and never fetched.
func handlePHPDownload(w http.ResponseWriter, r *http.Request) {
	servePHPFileParam(w, r, r.URL.Query().Get("file"), "/var/www/html/download.php")
}

func handlePHPInclude(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("page")
	if name == "" {
		name = r.URL.Query().Get("inc")
	}
	if name == "" {
		name = r.URL.Query().Get("file")
	}
	servePHPFileParam(w, r, name, "/var/www/html/view.php")
}

func servePHPFileParam(w http.ResponseWriter, r *http.Request, name, script string) {
	phpHeader(w, r)

	if strings.HasPrefix(strings.ToLower(name), "http://") || strings.HasPrefix(strings.ToLower(name), "https://") || strings.HasPrefix(name, "//") {
		// Remote file inclusion attempt: log it, never fetch it.
		log.Printf("%s %s %s RFI target %q never fetched [T1190 Exploit Public-Facing Application | Remote File Inclusion Attempt (never fetched)] proto=http dest=php",
			r.RemoteAddr, r.Method, r.URL.RequestURI(), truncate(name, 200))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Warning: include(%s): failed to open stream: HTTP request failed in %s on line 12\n", name, script)
		return
	}

	base := name
	if idx := strings.LastIndexAny(name, "/\\"); idx != -1 {
		base = name[idx+1:]
	}
	base = strings.ToLower(strings.TrimSuffix(base, "\x00")) // null-byte trick
	base = strings.TrimSuffix(base, ".php")

	if strings.Contains(name, "..") {
		if content, ok := decoyFiles[base]; ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, content)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Warning: include(%s): failed to open stream: No such file or directory in %s on line 12\n", name, script)
		return
	}

	// Benign include of a known section.
	fmt.Fprint(w, phpDoc("Acme Supplies", "<h1>Page: "+orDash(base)+"</h1><p>Content coming soon.</p>"))
}

func handlePHPUpload(w http.ResponseWriter, r *http.Request) {
	phpHeader(w, r)
	if r.Method == http.MethodPost {
		// Pretend to accept it; store nothing.
		fmt.Fprint(w, phpDoc("Upload", `<h1>Upload complete</h1><p>File received.</p>`))
		return
	}
	fmt.Fprint(w, phpDoc("File Upload", `<h1>Upload a file</h1>
<form method="post" enctype="multipart/form-data" action="/upload.php">
  <input type="file" name="userfile"><br>
  <button>Upload</button>
</form>
<p><small>Max size: 2M. Allowed: jpg, png, gif, pdf</small></p>`))
}

// handlePHPSourceLeak serves what looks like the raw PHP source of a
// config include left world-readable - the fake credentials match the
// rest of the app's story (config.php.bak, phpinfo, .env).
func handlePHPSourceLeak(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Powered-By", phpPoweredBy)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `<?php
// Acme Supplies DB config (fake - demo data only)
$DB_HOST = "db.internal";
$DB_NAME = "acme_prod";
$DB_USER = "acme_app";
$DB_PASS = "SuperSecretDBPass!";
define('SMTP_PASS', 'FakeMailPassword123');
define('SECRET_SALT', 'FakeAppSaltDoNotUseDemoOnly00011122');
?>
`)
}

// handlePHPWebshell serves an inert replica of a dropped PHP webshell.
// A cmd= parameter returns canned fakeShellOutput (same as the Telnet
// honeypot) so an attacker who thinks they've found a live backdoor gets
// believable-but-fake output; nothing is ever executed. The hit is
// tagged as web-shell access, one of the highest-signal events there is.
func handlePHPWebshell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Powered-By", phpPoweredBy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	cmd := r.FormValue("cmd")
	if cmd == "" {
		cmd = r.URL.Query().Get("c")
	}
	output := ""
	if cmd != "" {
		log.Printf("%s %s %s webshell cmd=%q (never executed) [T1505.003 Server Software Component: Web Shell | Web Shell Command Execution Attempt] proto=http dest=php",
			r.RemoteAddr, r.Method, r.URL.Path, truncate(cmd, 200))
		output = "<pre>" + htmlishEscape(strings.TrimRight(rootShellOutput(cmd), "\r\n")) + "</pre>"
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>sh</title></head><body bgcolor="#000000" text="#00ff00">
<h3>uname -a: Linux acme-web01 2.6.32-696.el6.x86_64 #1 SMP x86_64 GNU/Linux</h3>
<form method="get"><input name="c" size="80" value="%s"> <button>run</button></form>
%s
</body></html>`, htmlishEscape(cmd), output)
}

// htmlishEscape is a minimal escaper so reflected command text in the
// fake webshell UI can't be used to actually inject script into the
// page (the page is a honeypot, not an XSS demo).
func htmlishEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
