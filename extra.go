package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"sync"
)

// ---------------------------------------------------------------------
// Exposed pprof (CWE-215-ish information exposure): the quintessential
// real-world Go misconfiguration. net/http/pprof self-registers on
// http.DefaultServeMux via its init(), which we don't use, so it's wired
// in by hand here - leaking goroutine stacks, heap profiles, command
// line, and build info to anyone who finds /debug/pprof/.
// ---------------------------------------------------------------------

func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// ---------------------------------------------------------------------
// Fake OpenAPI/Swagger spec: a normal-looking API discovery document
// that, like robots.txt, happens to list every endpoint in this app -
// including the ones nothing on the site links to (/admin,
// /internal/metadata, /api/config, /debug/pprof/, the .git decoys, ...).
// Real APIs expose this deliberately; real attackers read it first.
// ---------------------------------------------------------------------

func handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Acme Supplies API", "version": "0.1.0-dev"},
  "paths": {
    "/search": {"get": {"summary": "Search the catalog"}},
    "/comments": {"get": {"summary": "List reviews"}, "post": {"summary": "Post a review"}},
    "/login": {"post": {"summary": "Sign in"}},
    "/forgot-password": {"post": {"summary": "Request a password reset code"}},
    "/reset-password": {"post": {"summary": "Reset password with a code"}},
    "/products": {"get": {"summary": "Product catalog / detail by id"}},
    "/files": {"get": {"summary": "Download a spec sheet by name"}},
    "/redirect": {"get": {"summary": "Outbound redirect"}},
    "/account": {"get": {"summary": "Account page"}},
    "/profile": {"get": {"summary": "Account details by id"}},
    "/api/profile": {"put": {"summary": "Update account details"}},
    "/admin": {"get": {"summary": "Staff portal"}},
    "/api/config": {"get": {"summary": "Runtime config (internal)"}},
    "/api/data": {"get": {"summary": "Customer directory (internal)"}},
    "/api/me": {"get": {"summary": "Remembered session"}},
    "/api/related": {"get": {"summary": "Related products by index"}},
    "/ping": {"get": {"summary": "Network status check"}},
    "/render": {"get": {"summary": "Welcome message preview"}},
    "/transfer": {"get": {"summary": "Send referral credit"}},
    "/fetch": {"get": {"summary": "Import an image by URL (internal)"}},
    "/internal/metadata": {"get": {"summary": "Instance metadata (internal)"}},
    "/upload": {"post": {"summary": "Upload a profile picture"}},
    "/crash": {"get": {"summary": "Diagnostics (internal)"}},
    "/debug/pprof/": {"get": {"summary": "Runtime profiling (internal)"}}
  }
}`)
}

// ---------------------------------------------------------------------
// Mass assignment (CWE-915): decodes the request body straight onto the
// same User struct that has a Role field, and writes back every
// non-empty field the client sent - including "role". Intended for
// "update my email/address"; nothing stops a client from also sending
// {"role":"admin"}.
// ---------------------------------------------------------------------

func handleProfileUpdateMassAssignment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("username")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"not signed in"}`)
		return
	}

	var body User
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid body"}`)
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()
	for i := range fakeUsers {
		if fakeUsers[i].Username != cookie.Value {
			continue
		}
		if body.Email != "" {
			fakeUsers[i].Email = body.Email
		}
		if body.Address != "" {
			fakeUsers[i].Address = body.Address
		}
		if body.Role != "" {
			// The bug: a field the client was never meant to control.
			fakeUsers[i].Role = body.Role
		}
		// Kept in sync with the SQLite-backed /login so the escalation
		// actually grants access on the next sign-in, not just in this
		// response body.
		db.Exec(
			"UPDATE users SET email = ?, role = ? WHERE username = ?",
			fakeUsers[i].Email, fakeUsers[i].Role, fakeUsers[i].Username,
		)
		json.NewEncoder(w).Encode(fakeUsers[i])
		return
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"error":"not found"}`)
}

// ---------------------------------------------------------------------
// Unrestricted file upload (CWE-434): no extension/content-type
// allowlist at all. Held in memory only (never touches disk) and capped
// at 5MB so it can't be used to exhaust server resources - but anything
// up to that size, with any name and any content, is accepted and
// served straight back. Uploading a .html/.svg file and viewing it is
// the classic chain into stored XSS: the serving handler deliberately
// never sets a Content-Type, so Go's http.ResponseWriter sniffs one from
// the content itself.
// ---------------------------------------------------------------------

var (
	uploadsMu     sync.Mutex
	uploadedFiles = map[string][]byte{}
)

func handleUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeader("Upload"))

	if r.Method != http.MethodPost {
		fmt.Fprint(w, `<h1>Upload a profile picture</h1>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <button class="btn">Upload</button>
</form>`)
		fmt.Fprint(w, pageFooter)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		fmt.Fprintf(w, "<p>Upload failed: %s</p>", err.Error())
		fmt.Fprint(w, pageFooter)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		fmt.Fprintf(w, "<p>Upload failed: %s</p>", err.Error())
		fmt.Fprint(w, pageFooter)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Fprintf(w, "<p>Upload failed: %s</p>", err.Error())
		fmt.Fprint(w, pageFooter)
		return
	}

	uploadsMu.Lock()
	uploadedFiles[header.Filename] = content
	uploadsMu.Unlock()

	fmt.Fprintf(w, `<h1>Uploaded</h1><p><a href="/uploads/user/%s">View your file</a></p>`, header.Filename)
	fmt.Fprint(w, pageFooter)
}

func handleServeUpload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/uploads/user/"):]

	uploadsMu.Lock()
	content, ok := uploadedFiles[name]
	uploadsMu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}

	// No Content-Type set on purpose: Go sniffs one from the body, so an
	// uploaded .html/.svg file comes back as text/html and renders.
	w.Write(content)
}

// ---------------------------------------------------------------------
// Fake exposed .git/logs/HEAD: a reflog with a commit message that
// confesses to a leaked (fake) credential, rounding out the existing
// .git/HEAD + .git/config decoys.
// ---------------------------------------------------------------------

func handleGitLogsHead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `0000000000000000000000000000000000000000 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 Acme Deploy <deploy@acme-supplies.com> 1700000000 +0000	commit (initial): initial import
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 Acme Deploy <deploy@acme-supplies.com> 1700003600 +0000	commit: add staging config
b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2 Jane Dev <jane@acme-supplies.com> 1700007200 +0000	commit: remove hardcoded password (oops, already pushed - rotate SuperSecretDBPass! ASAP)
`)
}
