# vulnapp-web

**An intentionally vulnerable web application, built to be scanned.**

This repository exists for one purpose: to give **DAST (Dynamic Application
Security Testing) tools** a realistic, predictable, and *safe* target to
scan. It is co-hosted by [AquilaX](https://aquilax.ai) and
[OneFirewall](https://onefirewall.co.uk) and used internally to validate
and benchmark scanner coverage - i.e. does a given DAST product actually
find the bugs this app is known to contain?

It is **not** a real product, a template for a real product, or an example
of how to write Go web services. Every "weakness" below was added on
purpose. All secrets, API keys, passwords, and personal data in this
codebase (including the `.env` file) are **fake** and generated for this
project only.

> [!WARNING]
> Do not deploy this anywhere reachable from the public internet, and do
> not reuse any code, pattern, or dependency from this repo in a real
> application. Run it only inside an isolated lab/VM/container that your
> scanner can reach and nothing else can.

## Why it looks like a normal website

The UI is deliberately styled as an ordinary small business site ("Acme
Supplies") rather than a page that lists vulnerability names. The idea is
to mimic what a DAST tool actually encounters in the field: a crawlable
site with a search box, a product catalog, a login form, a guestbook, a
staff portal, etc. - where the vulnerabilities live *underneath*
normal-looking features instead of being announced up front.

## Quick start

```sh
go run .
```

By default the app listens on **:80** for plain HTTP and **:443** for
HTTPS, using a self-signed certificate generated fresh at every startup
(see below) - no reverse proxy needed. Binding those ports on Linux
requires root or `CAP_NET_BIND_SERVICE`:

```sh
sudo ./vulnapp-web
# or, without root:
sudo setcap 'cap_net_bind_service=+ep' ./vulnapp-web
./vulnapp-web
```

For a non-root local run, override the ports:

```sh
HTTP_ADDR=:8080 HTTPS_ADDR=:8443 go run .
```

| Env var         | Default | Purpose                                            |
|------------------|---------|-----------------------------------------------------|
| `HTTP_ADDR`      | `:80`   | Plain HTTP listener address                         |
| `HTTPS_ADDR`     | `:443`  | HTTPS listener address                              |
| `TLS_HOSTNAME`   | `velocity-labs.dev` | CN/SAN used when a client connects with no SNI hostname at all |
| `TLS_CERT_FILE`  | *(none)* | Path to a real certificate (skips self-signed gen) |
| `TLS_KEY_FILE`   | *(none)* | Path to the matching private key                    |

The HTTPS listener mints a fresh self-signed certificate on the fly for
*whatever* hostname the client asks for via SNI (CN + `<host>` +
`*.<host>` as SAN), so it's valid for any domain you point at it - not
just `velocity-labs.dev`. It's still self-signed, so visitors get the
normal untrusted-certificate warning from their browser/client regardless
of hostname - that's expected, not a bug. They can still reach the site
by explicitly accepting the risk (e.g. "Advanced -> Proceed" in a browser,
or `curl -k`); there's just never a *second*, hostname-mismatch warning on
top of it. `TLS_HOSTNAME` only matters for the rare connection with no SNI
at all (e.g. a bare IP connection from an old client).

## Downloading a release

Every tag (`vN.N.N`) is built by GitHub Actions into standalone binaries
for Linux, macOS, and Windows (see
[`.github/workflows/release.yml`](.github/workflows/release.yml)) and
attached to the corresponding [GitHub Release](../../releases). All web
assets, fake secrets, and the TLS cert generator are embedded in the
binary at build time, so there is nothing else to download or configure:

```sh
curl -LO https://github.com/AquilaX-AI/vulnapp-web/releases/download/vX.Y.Z/vulnapp-web-vX.Y.Z-linux-amd64
chmod +x vulnapp-web-vX.Y.Z-linux-amd64
sudo ./vulnapp-web-vX.Y.Z-linux-amd64
```

## What's intentionally broken

| Area | Endpoint(s) | What's wrong |
|---|---|---|
| Exposed secrets file | `/.env` | Env file with fake credentials served directly over HTTP |
| Reflected XSS | `/search?q=` | Query echoed into the page unescaped |
| Stored XSS | `/comments` | Posted review author/body rendered unescaped |
| SQL injection (auth bypass + error-based) | `/login` | Login query built via string concatenation |
| SQL injection (UNION-based) | `/products?id=` | Numeric parameter spliced into the query unquoted |
| Username enumeration | `/login` | Different message for "no such user" vs "wrong password" |
| Fake path traversal | `/files?name=` | `../` payloads resolve against a decoy in-memory file set (fingerprints like `/etc/passwd`, `/etc/shadow`, `win.ini`) - never touches the real filesystem |
| Open redirect | `/redirect?url=` | Unvalidated redirect target |
| IDOR | `/profile?id=` (used by `/account?id=`) | Any user's PII readable by changing the id |
| Broken access control | `/admin` | Access gated only by a client-settable, unsigned `role` cookie |
| Sensitive data exposure | `/api/config` | Fake DB DSN, API keys, JWT secret in a "debug" endpoint |
| CORS misconfiguration | `/api/data` | Reflects `Origin` into `Access-Control-Allow-Origin` with `Allow-Credentials: true` |
| Fake OS command injection | `/ping?host=` | `; sleep N` causes a capped in-process delay (no real shell call); `echo TOKEN` payloads get reflected - both common blind-injection detection techniques still work, safely |
| Fake SSTI | `/render?name=` | User input parsed/executed as a Go template; can leak a decoy token, can't reach the filesystem or exec code |
| CSRF | `/transfer?to=&amount=` | State-changing GET with no token/origin check (toy in-memory balance only) |
| SSRF | `/fetch?url=` (linked from `/admin`) | Real outbound request, timeout- and size-capped; `/internal/metadata` gives it a safe, self-contained "cloud metadata" target to chain into |
| Verbose error disclosure | `/crash?tenant=` | Deliberate panic recovered and returned as a full stack trace |
| Missing security headers | *(global)* | No CSP, `X-Frame-Options`, HSTS, or `X-Content-Type-Options` anywhere |
| Insecure cookies | `/login` | Session cookies set without `Secure`, `HttpOnly`, or `SameSite` |
| Hardcoded secrets in source | `/` (HTML comment), `/static/app.js` | Fake credentials/API key left in comments |
| Directory listing + backup exposure | `/uploads/` | Fake `backup.sql`, `config.old`, `notes.txt` with no index page |
| Verbose server banner | *(global)* | `Server: Apache/2.2.15 (CentOS)` + `X-Powered-By: PHP/5.3.3` - a fake, long-EOL stack fingerprint (this is actually Go) |
| Insecure HTTP methods / XST | any path, `TRACE` | TRACE is naively reflected back (classic Cross-Site Tracing); every other method (PUT, DELETE, PATCH, ...) is accepted identically to GET |
| Permissive `OPTIONS` | any path | `Allow` header advertises `TRACE`, `CONNECT`, etc. with no real restriction |
| Source control exposure | `/.git/HEAD`, `/.git/config` | Fake exposed git metadata, with a credential leaked in the remote URL |
| Backup/debug file exposure | `/config.php.bak`, `/phpinfo.php` | Fake leftover PHP config + `phpinfo()` output, consistent with the fake PHP banner |
| Recon via robots.txt | `/robots.txt` | Points straight at `/admin`, `/uploads/`, `/api/`, `/.git/`, etc. |
| Private IP disclosure | `/api/config` | Internal DB host and load-balancer IP (`10.0.4.23`, `192.168.56.10`) in a public response |
| Hash disclosure | `/uploads/backup.sql` | A recognizable MD5-looking digest left in a comment |
| Classic DB error signature | `/login`, `/products?id=` | SQLi error paths wrap the real error in a canned `mysql_fetch_array()` warning, so even a naive error-signature scanner catches it |
| Missing SRI / cross-domain script | every page | `<script src="https://code.jquery.com/...">` with no `integrity`/`crossorigin` attribute |
| Predictable password reset token | `/forgot-password`, `/reset-password` | 6-digit code from `math/rand`, no rate limit, no expiry, printed in the response instead of emailed - brute-forceable and leaked in one step |
| JWT forgery via leaked secret | `/login` ("remember me") -> `/api/me` | Signed with the exact secret `/api/config` leaks as `jwt_secret`; `keyFunc` never checks `token.Method`, the classic alg-confusion-enabling pattern |
| Unchecked array index (CWE-129) | `/api/related?index=` | Any `index` outside `[0,3)` panics (recovered safely) - the kind of crash a basic fuzzer finds in seconds |

See [`handlers.go`](handlers.go) for the implementation of each, and
[`decoy.go`](decoy.go) for the fake path-traversal fingerprints.

## What different kinds of scanners will find

The table above is mostly DAST bait - a live crawl/active-scan finds it.
Other tool categories look at different signals entirely, so the app
plants findings for those too. Everything below was verified against a
real run of the named tool, not just asserted.

### TLS scanners (testssl.sh, sslyze, nmap `ssl-enum-ciphers`, SSL Labs)

[`tls.go`](tls.go) deliberately sets a weak `tls.Config`:

- `MinVersion: tls.VersionTLS10` - re-enables TLS 1.0/1.1 (Go's own
  default floor is TLS 1.2).
- `MaxVersion: tls.VersionTLS12` - so TLS 1.3 (whose cipher suites aren't
  configurable in Go, and are always strong) never gets negotiated over
  this.
- `CipherSuites` - only plain-RSA key-exchange suites (no ECDHE), so
  **no forward secrecy** on any negotiated session, with several in
  CBC mode (BEAST/Lucky13 family).
- HTTP/2 is explicitly disabled on the HTTPS listener (`TLSNextProto` set
  to an empty map) - h2 requires an ECDHE+AES-GCM suite, which this list
  doesn't offer, so Go refuses to start otherwise. Fitting, too: the fake
  Apache 2.2/PHP 5.3 stack predates HTTP/2 entirely.
- The certificate is self-signed (see below) and `HSTS` is never sent.

Verified with a Go TLS client forcing each version/cipher pair: the
server completes real TLS 1.0, 1.1, and 1.2 handshakes using
`TLS_RSA_WITH_AES_128_CBC_SHA`/`TLS_RSA_WITH_AES_128_GCM_SHA256`. A modern
browser or plain `curl`/`openssl` won't reproduce this on their own
anymore (they no longer offer non-PFS suites or TLS 1.0/1.1 by default) -
exactly why a dedicated TLS scanner, which forces each version/cipher
combination explicitly, is the right tool to find it.

### Fuzzing

- **`/api/related?index=`** - no bounds check on a slice index (CWE-129).
  Any fuzzer that throws negative numbers or large integers at a numeric
  param finds a 500 (safely recovered, not a crash of the process) within
  the first few dozen tries.
- **`/reset-password`** - the 6-digit reset code has no rate limit, so a
  simple numeric fuzzer/intruder attack (1,000,000 requests, or far fewer
  with clustering) recovers it.
- **`/transfer?amount=`** - unvalidated integer parsing; negative, huge,
  or non-numeric amounts are accepted without complaint (`strconv.Atoi`
  failures silently become `0`).
- More generally: every handler is wrapped by `recoverMiddleware`
  ([`main.go`](main.go)), so whatever a fuzzer manages to crash comes back
  as a 500 with a full stack trace instead of taking the process down -
  crashes are discoverable, but never destructive.

### SAST (gosec, Semgrep, CodeQL, ...)

Running [gosec](https://github.com/securego/gosec) against this repo
reports **43 findings across 15 rule IDs**, including:

| Rule | What | Where |
|---|---|---|
| G701 (CWE-89) | SQL injection | `handleLoginSQLi`, `handleProductsSQLi` (`fmt.Sprintf` straight into a query) |
| G705 (CWE-79) | XSS sink | every unescaped `fmt.Fprintf` into an HTML response (13 hits) |
| G708 (CWE-94) | Server-side template injection | `handleRenderSSTI` |
| G704 (CWE-918) | SSRF | `handleFetchSSRF` |
| G710 | Open redirect | `handleOpenRedirect` |
| G402 (CWE-295) | TLS MinVersion too low | `tls.go` (both `tls.Config` literals) |
| G404 (CWE-338) | Weak RNG (`math/rand`, not `crypto/rand`) | `handleForgotPassword`'s reset code |
| G501/G401 (CWE-327/328) | Weak crypto primitive (MD5) | `gravatarHash` |
| G101 (CWE-798) | Hardcoded credentials | `store.go`, `decoy.go`, `/api/config`, `/internal/metadata` literals |
| G124 (CWE-614) | Cookie missing `Secure`/`HttpOnly` | the `role`/`username`/`remember_token` cookies |
| G706 (CWE-117) | Log injection | `logMiddleware`'s unsanitized `log.Printf` of the request path |
| G112/G114 (CWE-400/676) | No read/header timeout on `http.Server` (Slowloris-class) | `main.go`'s HTTP and HTTPS listeners |
| G104 (CWE-703) | Unchecked errors | scattered throughout (10 hits) |

Run it yourself: `gosec ./...`.

### SCA (govulncheck, Snyk, Dependabot, Trivy, OSV-Scanner)

- **`github.com/dgrijalva/jwt-go`** ([go.mod](go.mod)), used by the
  "remember me" JWT feature, is archived/deprecated with a published
  advisory (GHSA-w73w-5m7g-f7qc / CVE-2020-26160, covering the
  signature-confusion class of bug the maintainers never fixed before
  abandoning the project). Dependency-graph scanners that match against
  the GitHub Advisory Database / OSV (Snyk, Dependabot, Trivy,
  OSV-Scanner) flag this import directly. `govulncheck` in particular
  *won't* - that advisory is about a usage pattern, not a buggy exported
  symbol, which is the kind of gap worth knowing about between SCA tools.
- **The Go toolchain itself.** `go.mod`'s `go` directive pins the minimum
  language version this module builds with; `govulncheck ./...` checks
  that version's standard library against the Go vulnerability database
  and will flag anything outstanding for whatever version is current when
  you run it. This project doesn't pin a specific vulnerable version on
  purpose (that would go stale the moment Go ships a patch) - it's listed
  here as a category of finding to expect, not a fixed one.

## Design notes

## Design notes

- **Self-contained binary.** Static assets, upload decoys, and the fake
  `.env` are embedded via `go:embed` ([`assets.go`](assets.go)); there's an
  in-memory SQLite database ([`store.go`](store.go)) seeded with fake data.
  Nothing is read from disk at runtime.
- **Nothing here can meaningfully harm the host.** Command injection and
  path traversal are faked (no real shell exec, no real filesystem
  access); the one feature that makes a real network call (SSRF via
  `/fetch`) is timeout- and size-bounded; the one panic (`/crash`) is
  recovered.
- **TLS.** No cert/key files needed: the HTTPS listener mints a self-signed
  certificate in memory for whatever hostname a client asks for via SNI,
  caching it per hostname ([`tls.go`](tls.go)). Browsers and scanners will
  (correctly) flag it as untrusted - that's the point, not a bug.
- **Fake outdated stack.** The binary is Go, but every response claims to
  be `Apache/2.2.15 (CentOS)` + `X-Powered-By: PHP/5.3.3`, and a handful of
  endpoints (`/config.php.bak`, `/phpinfo.php`, the SQLi error banners)
  play along with that story, so version-fingerprinting and
  error-signature checks have something real to find.
- **A real, working exploit chain.** `/api/config` leaks a `jwt_secret`;
  the login flow's "remember me" option signs a JWT with that exact
  secret; `/api/me` validates it without checking the signing method. Read
  the config, forge a token claiming any username/role, and `/api/me`
  accepts it - no password needed. It's a genuine end-to-end bug in this
  app, not a simulation, which is why it's the one place a deprecated
  third-party library ([`github.com/dgrijalva/jwt-go`](go.mod)) was used
  on purpose.

## CI / Releases

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds and vets
  the module on every push/PR.
- [`.github/workflows/release.yml`](.github/workflows/release.yml) builds
  the binaries above and publishes them to GitHub Releases whenever a
  `vN.N.N` tag is pushed.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
