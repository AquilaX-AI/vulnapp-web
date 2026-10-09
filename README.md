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
staff portal, etc. - where the vulnerabilities live *underneath* normal
-looking features instead of being announced up front.

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
| `TLS_CERT_FILE`  | *(none)* | Path to a real certificate (skips self-signed gen) |
| `TLS_KEY_FILE`   | *(none)* | Path to the matching private key                    |

## Downloading a release

Every tag (`vN.N.N`) is built by GitHub Actions into standalone binaries
for Linux, macOS, and Windows (see
[`.github/workflows/release.yml`](.github/workflows/release.yml)) and
attached to the corresponding [GitHub Release](../../releases). All web
assets, fake secrets, and the TLS cert generator are embedded in the
binary at build time, so there is nothing else to download or configure:

```sh
curl -LO https://github.com/aquilax/vulnapp-web/releases/download/vX.Y.Z/vulnapp-web-vX.Y.Z-linux-amd64
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
| Verbose server banner | *(global)* | `Server` header advertises stack details |

See [`handlers.go`](handlers.go) for the implementation of each, and
[`decoy.go`](decoy.go) for the fake path-traversal fingerprints.

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
- **TLS.** A fresh self-signed certificate is generated in memory on every
  startup ([`tls.go`](tls.go)) so HTTPS works out of the box with zero
  configuration; browsers and scanners will (correctly) flag it as
  untrusted.

## CI / Releases

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds and vets
  the module on every push/PR.
- [`.github/workflows/release.yml`](.github/workflows/release.yml) builds
  the binaries above and publishes them to GitHub Releases whenever a
  `vN.N.N` tag is pushed.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
