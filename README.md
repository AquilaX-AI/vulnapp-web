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
(see below) - no reverse proxy needed. It also opens a batch of fake
internal-service ports (databases, caches, remote admin, container APIs -
see [below](#exposed-internal-services)), three of which (21, 23, 25) are
also privileged. Binding privileged ports on Linux requires root or
`CAP_NET_BIND_SERVICE`; any fake-service port that's already taken by a
real service on the host is logged and skipped rather than treated as
fatal:

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
| Exposed profiling endpoint | `/debug/pprof/` | Standard `net/http/pprof`, wired in on purpose - goroutine stacks, heap profile, command line, all public |
| API discovery document | `/swagger.json` | Lists every endpoint in the app, including the ones nothing on the site links to |
| Mass assignment (CWE-915) | `PUT`/`PATCH /api/profile` | Request body decodes straight onto the `User` struct; sending `{"role":"admin"}` escalates your own account - and the response echoes the plaintext password back too |
| Unrestricted file upload (CWE-434) | `POST /upload` -> `/uploads/user/<name>` | No type/extension allowlist; upload an `.html` file with a `<script>` tag and it's served back with a sniffed `text/html` content type - stored XSS |
| CSP present but useless | every page | `default-src *; script-src * 'unsafe-inline' 'unsafe-eval'` - blocks nothing, looks like a control |
| Cacheable sensitive responses | `/profile`, `/api/config` | `Cache-Control: public, max-age=3600` on responses containing PII/secrets |
| Host header injection | `/forgot-password` | The "reset link" is built from the request's own `Host` header with no allowlist |
| Git reflog exposure | `/.git/logs/HEAD` | A commit message that confesses to a leaked (fake) credential |
| Race condition / TOCTOU (CWE-367) | `GET /api/withdraw?amount=` | Balance is checked, then deducted 50ms later with no lock held across the gap - concurrent requests all pass the check before any of them deducts, driving the balance negative |
| Race condition / one-time code reuse (CWE-367) | `/reset-password` | Same gap between validating a reset code and deleting it - concurrent requests with the same code can all succeed |
| ReDoS (CWE-1333) | `GET /api/validate-coupon?code=` | A backtracking regex (via `regexp2`, since Go's stdlib `regexp` is immune by design) with no match timeout - exponential time growth confirmed (9ms -> 90ms -> 2.6s -> 21s for 10/20/25/28 repeated characters) |
| Cross-Site WebSocket Hijacking | `/ws` (used by `/account`) | `CheckOrigin` hardcoded to accept any origin - confirmed a cross-origin upgrade with the victim's cookies attached completes (`101 Switching Protocols`) |
| Session fixation (CWE-384) | global (`session_id`), `/login` | A client-supplied `session_id` - even via a URL query param - is adopted instead of only trusting a server-issued one, and it's never rotated on login |
| Business logic / price tampering (CWE-840) | `/checkout` (linked from product pages) | Price is a plain, client-editable form field, never re-checked against the real catalog price; any non-empty promo code zeroes the total |
| Secret passed via URL (CWE-598) | `/api/export?api_key=` (linked from `/account`) | A real-looking API key travels in the URL instead of a header, so it lands in this app's own access logs, browser history, and would leak via Referer |
| Multi-cloud SSRF targets | `/computeMetadata/v1/...` (GCP), `/metadata/instance` (Azure) | Mirror the real header-based anti-SSRF checks those providers actually ship - reachable directly, but (correctly) *not* chainable through this app's own `/fetch`, which can't inject the required header |
| Blind SSRF | `/api/webhook-test?url=` | Fetches server-side but never echoes the response - confirming it fired requires an out-of-band listener (Collaborator/webhook.site-style), unlike the "visible" SSRF on `/fetch` |

See [`handlers.go`](handlers.go) and [`pentest.go`](pentest.go) for the
implementation of each, and [`decoy.go`](decoy.go) for the fake
path-traversal fingerprints.

## Exposed internal services

Past the web app itself, the binary also opens a batch of ports that, in
a real deployment, should never be reachable - the network-level version
of the same idea, for port scanners (nmap, masscan) and recon tooling
(Shodan-style dorking) to find. None of these implement the real
protocol beyond a first-contact banner or response; see
[`fakeservices.go`](fakeservices.go). Port 22 (SSH) is deliberately left
alone rather than faked, since a real SSH server commonly runs there for
box/VM management and this app should never contend with it for the port.

| Port | Pretends to be | Fidelity |
|---|---|---|
| 21 | FTP (vsFTPd 2.3.4) | **Stateful**: accepts anonymous login (any USER/PASS) and lists real-looking sensitive files via `LIST` |
| 23 | Telnet | **Stateful**: a light interactive honeypot - accepts any credentials, then answers common recon commands (`whoami`, `id`, `uname`, `ls`, ...) and logs every command typed |
| 3306 | MySQL 5.5.8 | Real binary protocol greeting packet |
| 6379 | Redis 2.8.4 | `PING` -> `+PONG`, `INFO` -> a fake info block, `CONFIG GET requirepass` -> empty (confirms no password set at all) |
| 11211 | Memcached 1.4.15 | Replies to the `version` command |
| 9200 | Elasticsearch 1.4.2 | Full fake HTTP root response (real unauth-RCE-history version) |
| 2375 | Docker Engine API (no TLS) | Full fake HTTP `/version` response |
| 5984 | CouchDB 1.6.1 | Full fake HTTP root response |
| 8500 | Consul 0.7.0 | Full fake HTTP agent-self response |
| 5432, 1433, 3389, 5900, 27017 | PostgreSQL, MSSQL, RDP, VNC, MongoDB | Port accepts the connection and stays silent - protocol-accurate, since real clients speak first on all five |

The mail stack an MX record would actually point at ([`mailservices.go`](mailservices.go)), plus a DNS nameserver that allows zone transfers ([`dns.go`](dns.go)) - these are **stateful, multi-step protocol simulations**, not single banners, modeling the specific real misconfiguration behind each one:

| Port | Pretends to be | The actual finding |
|---|---|---|
| 25, 587, 465 | SMTP (Postfix) - MTA, submission, "SMTPS" | **Open relay**: `RCPT TO` is accepted for any domain, not just ones this server should handle. **User enumeration**: `VRFY <user>` confirms whether a local account exists. |
| 143, 993 | IMAP (Dovecot on 993) | `CAPABILITY` advertises `AUTH=PLAIN`/`AUTH=LOGIN` with no `STARTTLS` and no `LOGINDISABLED` - plaintext credentials over an unencrypted connection are accepted |
| 110, 995 | POP3 | Same plaintext-auth story, in `USER`/`PASS` form |
| 53 (TCP) | A nameserver | Allows unauthenticated **zone transfer (AXFR)** for any zone name asked - responds with a full fake internal zone (SOA/NS/MX/A records) reusing the same fake IPs `/api/config` and the kubelet/Consul/Eureka fakes already leak. Verified with a real `dig axfr <zone> @host` |

Plus a batch of ops/dev tooling - the single most common way this class
of service actually ends up reachable: someone spins it up for a quick
look and forgets it's there.

| Port | Pretends to be | Fidelity |
|---|---|---|
| 3000 | Grafana 6.4.3 | Fake `/api/health` response |
| 5601 | Kibana 6.4.3 | Fake `/api/status`-style response |
| 9090 | Prometheus | Real `/-/healthy` liveness text |
| 15672 | RabbitMQ Management | Models the real default-creds misconfig: 401 unless `guest:guest`, then the overview JSON |
| 8086 | InfluxDB 1.3.1 | Real `/ping` behavior: 204, no body, version header only |
| 8200 | HashiCorp Vault | Fake `/v1/sys/health` reporting unsealed + active |
| 8888 | Jupyter Notebook | No-token misconfig: API reachable with zero auth, same as the real RCE-enabling case |
| 10000 | Webmin 1.580 | Login page naming the exact version with a real unauthenticated-RCE CVE (2019-15107) |
| 8761 | Netflix Eureka | Fake service registry listing "internal" hosts - reuses the same fake IPs as `/api/config` |
| 8080 | Jenkins (anonymous access) | Fake dashboard + a `/script` Groovy console page - the classic exposed-Jenkins RCE vector |
| 9000 | Portainer | `Authentication:false` in the fake API response - the real smoking gun for an unsecured instance |
| 19999 | Netdata | Fake `/api/v1/info` leaking hostname/OS/kernel/hardware - matches the real default (no auth) |

Plus infrastructure/orchestration APIs (behind some of the bigger
real-world breaches: exposed etcd/kubelet leaking cluster secrets, open
registries leaking proprietary images) and a last round of
binary-protocol databases/brokers:

| Port | Pretends to be | Fidelity |
|---|---|---|
| 2181 | ZooKeeper | Real "four-letter commands": `ruok` -> `imok`, `stat` -> a real-shaped stat block |
| 5000 | Docker Registry v2 | Real root-check response (`{}` + the `Docker-Distribution-Api-Version` header) |
| 8161 | ActiveMQ 5.13.0 admin console | Names a real unauthenticated-RCE CVE (2016-3088) |
| 8081 | Sonatype Nexus 3.14.0 | "Anonymous access enabled" banner |
| 50070 | Hadoop NameNode | Fake cluster-info page |
| 2379 | etcd | Real, genuinely-unauthenticated-by-default `/version` response |
| 6443 | Kubernetes API server | The real 403 an anonymous request gets - confirms the server without needing more |
| 10250 | kubelet API | Fake `/pods` PodList - the real historical no-authn/authz misconfiguration |
| 5985 | WinRM | Real 401 + `Negotiate` challenge - still fingerprints a reachable remote-management endpoint |
| 1521, 9042, 9092, 5672, 61616, 445 | Oracle, Cassandra, Kafka, RabbitMQ (AMQP), ActiveMQ (OpenWire), SMB | Port accepts the connection and stays silent - protocol-accurate, clients speak first on all six |

## MITRE ATT&CK tagging in the logs

Every contact with this app - a web request or a connection to any fake
service above - gets logged with the client IP and, where the request
matches a known signature, a best-fit [MITRE ATT&CK](https://attack.mitre.org/)
technique, the same way a WAF/SIEM rule set tags traffic:

```
2026/01/15 09:12:03 203.0.113.7 POST /login [T1190 Exploit Public-Facing Application (SQL injection)]
2026/01/15 09:12:05 203.0.113.7 GET /.env [T1552.001 Unsecured Credentials: Credentials In Files]
2026/01/15 09:12:08 203.0.113.7 connected to [::]:3306 [T1133 External Remote Services]
```

[`mitre.go`](mitre.go) holds the classifier: it inspects the path, query
string, form body (read and restored, so the real handler still sees it
normally), and `User-Agent` against a prioritized set of regex
signatures - SQL injection, XSS, path traversal, command/template
injection, credential/cloud-metadata file hits, mass-assignment writes,
brute-force attempts against `/login`/`/reset-password`, and known
scanner User-Agents - and returns the first match. The fake TCP/HTTP
services tag every connection as `T1133 External Remote Services`
uniformly, plus a couple of more specific tags for particular commands
(SMTP `VRFY` -> `T1087 Account Discovery`, FTP/Telnet login -> `T1078.001
Valid Accounts: Default Accounts`, IMAP/POP3 plaintext auth -> `T1040
Network Sniffing`, DNS `AXFR` -> `T1018 Remote System Discovery`).

This is advisory classification from a single request in isolation, the
same limitation any signature-based detector has - it's meant to make
the logs legible at a glance, not to be a certified detector. A gap
worth knowing about if you're comparing it against a real EDR/SIEM rule
set: it has no equivalent for the race conditions or the ReDoS in
[`pentest.go`](pentest.go), since spotting those needs request *timing/
sequencing*, not a pattern in a single request's content.

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
reports **80 findings across 18 rule IDs**, including:

| Rule | What | Where |
|---|---|---|
| G701 (CWE-89) | SQL injection | `handleLoginSQLi`, `handleProductsSQLi` (`fmt.Sprintf` straight into a query) |
| G705 (CWE-79) | XSS sink | every unescaped `fmt.Fprintf` into an HTML response (19 hits) |
| G708 (CWE-94) | Server-side template injection | `handleRenderSSTI` |
| G704 (CWE-918) | SSRF | `handleFetchSSRF`, `handleWebhookTest` |
| G710 | Open redirect | `handleOpenRedirect` |
| G402 (CWE-295) | TLS MinVersion too low | `tls.go` (both `tls.Config` literals) |
| G404 (CWE-338) | Weak RNG (`math/rand`, not `crypto/rand`) | `handleForgotPassword`'s reset code |
| G501/G401 (CWE-327/328) | Weak crypto primitive (MD5) | `gravatarHash` |
| G101 (CWE-798) | Hardcoded credentials | `store.go`, `decoy.go`, `pentest.go`'s `exportAPIKey`, `/api/config`, `/internal/metadata` literals |
| G124 (CWE-614) | Cookie missing `Secure`/`HttpOnly` | the `role`/`username`/`remember_token`/`session_id` cookies |
| G706 (CWE-117) | Log injection | `logMiddleware`'s unsanitized `log.Printf` of the request path/IP |
| G112/G114 (CWE-400/676) | No read/header timeout on `http.Server` (Slowloris-class) | `main.go`'s and `fakeservices.go`'s HTTP listeners |
| G117 (CWE-499) | Secret-shaped field marshaled into a JSON response | `handleProfileUpdateMassAssignment` echoes `User.Password` back |
| G120 (CWE-400) | Unbounded multipart form parsing | `handleUpload` |
| G115 (CWE-190) | Int->byte conversion that could overflow | `mysqlGreetingPacket`'s length prefix |
| G104 (CWE-703) | Unchecked errors | scattered throughout (23 hits) |

gosec doesn't have a rule for the ReDoS or race conditions in `pentest.go`
(those need a dedicated taint/timing analysis, not pattern matching) -
worth knowing as a gap when comparing SAST tools, not a gosec bug.

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

- **Self-contained binary.** Static assets, upload decoys, and the fake
  `.env` are embedded via `go:embed` ([`assets.go`](assets.go)); there's an
  in-memory SQLite database ([`store.go`](store.go)) seeded with fake data.
  Nothing is read from disk at runtime. The DB connection is pinned to a
  single pooled connection (`db.SetMaxOpenConns(1)`) - without it, any
  concurrent load forces `database/sql` to open a second connection, and
  SQLite doesn't share an in-memory database across connections, so that
  second one would see an empty schema. This was a real, unintentional
  bug (not a planted finding) that the race-condition features in
  [`pentest.go`](pentest.go) exposed during testing, since they were the
  first thing to actually hit the DB concurrently.
- **Nothing here can meaningfully harm the host.** Command injection and
  path traversal are faked (no real shell exec, no real filesystem
  access); every feature that makes a real network call (SSRF via
  `/fetch` and `/api/webhook-test`) is timeout- and size-bounded; every
  panic (`/crash`, `/api/related`) is recovered; file uploads are held in
  memory only and capped at 5MB; every fake service in
  `fakeservices.go` only ever reads from or writes a fixed banner/
  response to the socket - none of them parse, store, or act on what a
  client sends. The ReDoS on `/api/validate-coupon` is real CPU cost, but
  it's scoped to the one goroutine handling that request - confirmed the
  rest of the app stays fully responsive while a 20+ second match runs -
  and input is capped at 1000 characters.
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
