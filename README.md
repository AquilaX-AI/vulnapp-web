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
| `SYSLOG_ADDR`    | *(none)* | `host:port` of a real syslog/SIEM destination to forward every log line to (RFC 5424) |
| `SYSLOG_PROTO`   | `udp`    | `udp` or `tcp`, for `SYSLOG_ADDR`                    |
| `CTI_API_KEY`    | *(none)* | [OneFirewall](https://onefirewall.co.uk) threat-intel API key - if set, reports attacker IPs there (see below) |

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
| 5900 | VNC | **Stateful**: real RFB handshake offering security-type `None` - verified with a real `nmap --script vnc-info`, which reports "Server does not require authentication" |
| 30000 | Kubernetes Dashboard | Landing page + a "Skip" link to a fake cluster overview - the exact misconfiguration behind the 2018 Tesla cryptomining breach (NodePort reachable, no RBAC) |
| 3001 | Open WebUI | Fake `/api/config` + signup page with no auth - the self-hosted-LLM-era version of the same "forgot to lock it down" mistake |
| 5432, 1433, 3389, 27017 | PostgreSQL, MSSQL, RDP, MongoDB | Port accepts the connection and stays silent - protocol-accurate, since real clients speak first on all four |

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

The newest category - AI/LLM infrastructure ([`aiservices.go`](aiservices.go)) - researched against what's actually being found and exploited right now rather than guessed at: SentinelLABS/Censys counted ~175,000 exposed Ollama instances in early 2026, and the "Operation Bizarre Bazaar" campaign (Sysdig/Pillar Security, Feb 2026) scanned for Ollama and unauthenticated MCP servers side by side.

| Port | Pretends to be | Fidelity |
|---|---|---|
| 11434 | Ollama | Real root response (`Ollama is running`), `/api/tags` model inventory, `/api/pull` (models the model-theft vector behind the real exposure reports), `/api/generate` (models LLMjacking - free inference on someone else's GPU) |
| 6277 | An MCP server | JSON-RPC `tools/list` reveals a capability manifest (filesystem/shell/database/cloud access) - the exact thing real scanning campaigns check for |
| 8000 | ChromaDB | Fake `/api/v1/collections` - names CVE-2026-45829 ("ChromaToast"), a CVSS 10.0 pre-auth RCE reportedly affecting most exposed instances |
| 9091 | Milvus | Fake unauthenticated management API on the metrics port - names CVE-2026-26190 |

And edge devices - VPN/firewall/remote-access appliances - which GreyNoise's 2026 State of the Edge report found absorb more sustained, systematic internet-wide exploitation than any other category (Palo Alto GlobalProtect alone drew 3.5x the combined traffic Cisco and Fortinet saw), matching Mandiant M-Trends 2025's top four most-exploited CVE families (PAN-OS, Ivanti Connect Secure, Ivanti Policy Secure, FortiClient EMS):

| Port | Pretends to be | Fidelity |
|---|---|---|
| 4433 | Palo Alto GlobalProtect Portal | Login page naming a PAN-OS version |
| 4434 | Fortinet FortiGate | Login page naming a FortiOS version |
| 4435 | Ivanti Connect Secure | Login page naming a version |
| 4436 | SonicWall | Login page naming a SonicOS version |
| 8291, 8728 | MikroTik RouterOS (WinBox, RouterOS API) | Port accepts the connection and stays silent - both are binary protocols I didn't have a trusted client to verify a fuller fake against |

(Real deployments put edge-device portals on :443 of their own dedicated appliance IP; faked here on distinct ports purely to avoid colliding with this app's own HTTPS listener.)

And the IoT/ICS/medical protocol families actually driving most internet-wide scanning traffic right now ([`iotservices.go`](iotservices.go)) - researched the same way as the AI-stack batch, not guessed at: JPCERT/CC's TSUBAME data names TCP/23 (Telnet) the single most-targeted port in 2026, largely Mirai; Modat's March 2026 scan found 973,819 active RTSP services with 8,074 giving up an unauthenticated frame; Shadowserver's daily Modbus scans find 6,300+ exposed instances (the protocol has no authentication mechanism at all); and TrendAI/Rapid7 research found 3,627 internet-reachable DICOM medical imaging servers, 99.56% accepting connections with no AE-Title validation. Three of these (MQTT, Modbus, DICOM) are **verified against real client libraries** completing genuine protocol handshakes, not just "looks right":

| Port | Pretends to be | Fidelity |
|---|---|---|
| 1883 | MQTT broker | Real CONNACK/SUBACK - verified with `paho-mqtt` completing a full connect/subscribe/publish round trip |
| 502 | Modbus TCP (ICS/SCADA) | Real register-read responses - verified with `pymodbus` successfully reading back fake register values |
| 554 | RTSP (IP camera) | Real `OPTIONS`/`DESCRIBE` responses with a valid SDP body - no auth challenge at any step |
| 104, 11112 | DICOM (medical imaging) | A real DICOM Upper Layer Protocol association handshake (PS3.8) - verified with `pynetdicom` reporting `is_established: True` and the correct accepted presentation context |
| 23, 2323 | Telnet | Both ports Mirai's scanner specifically probes, per JPCERT/CC - same handler as the existing Telnet honeypot |

`wp-login.php`, `xmlrpc.php`, and `wp-json/` are also faked directly on the main app's own ports ([`handlers.go`](handlers.go)) - not because this is a WordPress site, but because WordPress's market share means these paths get scanned on essentially every site regardless of what it actually runs. `xmlrpc.php`'s `system.listMethods` and `wp.getUsersBlogs`/`system.multicall` get distinct tags, since the latter is specifically the pingback-abuse/credential-brute-force vector XML-RPC is best known for.

Two more industrial protocols ([`icsservices.go`](icsservices.go)) and the camera/DVR/printer side of IoT exposure ([`iotdevices.go`](iotdevices.go)), researched the same way: a joint NSA/CISA/FBI/DOE/EPA advisory (AA26-231A, Aug 2026) warned of AI-written scripts attacking internet-exposed Siemens S7 PLCs, with "take any S7 PLC on port 102 offline immediately" as its first recommendation; Bitsight found 14,220 exposed OPC UA devices, 7,358 accepting anonymous connections; and a campaign called "CameraSwarm" compromised 14,530+ Dahua cameras/DVRs in June-July 2026 via port 37777 and two CVSS 9.8 auth-bypass CVEs, while 80,000+ Hikvision cameras remain vulnerable to CVE-2021-36260:

| Port | Pretends to be | Fidelity |
|---|---|---|
| 102 | Siemens S7 PLC (S7comm) | A real TPKT/COTP/S7 "Setup Communication" handshake - verified with `python-snap7` (the library real S7 tooling is built on) reporting `get_connected(): True`. Caught and fixed a real bug here: the handshake bytes were correct on the first attempt, but closing the connection right after it made `snap7` report itself disconnected anyway - a real S7 session stays open for further requests |
| 4840 | OPC UA server | Real Hello/Acknowledge (UACP) handshake only, not a full session - honestly scoped, since a full session needs certificate/nonce exchange well beyond what mass internet-wide scanners actually check for. Verified with `asyncua`'s real client: it accepted our Acknowledge with no protocol error and progressed to the next stage, which isn't implemented |
| 8070 | Hikvision ISAPI | Fake `deviceInfo` (names the exact pre-fix firmware range for CVE-2021-36260) and `/ISAPI/Security/users` - the exact two endpoints a July 2026 report described being actively scanned |
| 8090 | Dahua NetSurveillance WEB | Login page naming a firmware version |
| 37777 | Dahua DHIP (proprietary) | Port accepts the connection and stays silent - undocumented binary protocol, no trusted client available to verify a fuller fake against |
| 9100 | Raw/JetDirect network printing | Logs whatever's sent with no reply - that's the real protocol: a printer is a pure data sink, nothing to parse or respond to |

## MITRE ATT&CK tagging in the logs

Every contact with this app - a web request or a connection to any fake
service above - gets logged with the client IP, a best-fit
[MITRE ATT&CK](https://attack.mitre.org/) technique, and a plain-English
attack-type/exploitability label, the same way a WAF/SIEM rule set tags
traffic:

```
2026/01/15 09:12:03 203.0.113.7:51234 POST /login [T1190 Exploit Public-Facing Application | SQL Injection Attempt] proto=http ua="sqlmap/1.7" referer="-" xff="-" content_length=33 body="username=admin%27+OR+%271%27%3D%271&password=x"
2026/01/15 09:12:05 203.0.113.7:51235 GET /.env [T1552.001 Unsecured Credentials: Credentials In Files | Credential/Secrets Exposure Attempt] proto=http ua="curl/8.1.2" referer="-" xff="-" content_length=0 body="-"
2026/01/15 09:12:08 203.0.113.7:51236 connected to [::]:3306 [T1133 External Remote Services | Database Exploitation Attempt]
```

The MITRE technique name is intentionally abstract (the real ATT&CK
technique "Exploit Public-Facing Application" covers SQLi, SSTI, and a
lot else) - the part after the `|` is this app's own label for what kind
of attack that specific match actually represents, so the line is
readable without a MITRE lookup.

Every HTTP log line also carries protocol, `User-Agent`, `Referer`,
`X-Forwarded-For`, content length, and a truncated body snippet
([`logdetail.go`](logdetail.go)) - everything useful for actually
analyzing what an attacker sent. The one thing deliberately **never**
logged is the `Host` header: every other field here describes the
attacker, but `Host` is the one piece of a request that identifies which
hostname *this specific deployment* answers to - exactly what should
stay anonymous if these logs get exported or shared with a threat-intel
feed. (Sent a request with `Host: totally-real-internal-hostname.corp.
acme.com` during testing - confirmed it never appears in the log line.)

### Forwarding to real syslog

Set `SYSLOG_ADDR` (and optionally `SYSLOG_PROTO`, default `udp`) and
every log line - every one of the hundreds of `log.Printf` calls already
in this codebase, no per-call-site changes - also gets forwarded as a
real RFC 5424 syslog message ([`syslog.go`](syslog.go)):

```sh
SYSLOG_ADDR=siem.example.com:514 ./vulnapp-web
```

Verified against a real UDP listener:

```
<37>1 2026-01-15T09:12:03Z vulnapp-7d8e6b735808 vulnapp-web 40856 - - 2026/01/15 09:12:03 203.0.113.7:51234 GET /products?id=1 proto=http ...
```

The `HOSTNAME` field is never this process's real hostname - it's a
random, stable-per-run `instanceID` generated at startup. That's the
same anonymization principle as the `Host` header above, applied to the
transport layer: an analyst can tell every line in a run came from "the
same honeypot instance" without that identifier revealing which one, who
runs it, or where.

### Reporting attackers to OneFirewall

Set `CTI_API_KEY` to a [OneFirewall](https://onefirewall.co.uk)
threat-intel API key and this becomes a live sensor feeding it
([`onefirewall.go`](onefirewall.go)): the same writer mechanism as the
syslog forwarder above watches every log line for the `[T1234 Name |
Category]` bracket, and for each one found, reports the attacker's IP to
`POST https://app.onefirewall.com/api/v1/ips`:

```json
{
  "ip": "203.0.113.7",
  "confidence": 0.95,
  "source": "velocitylabs",
  "notes": "<the full log line - everything logdetail.go captured>",
  "tags": ["T1190", "details#SQL Injection Attempt", "velocitylab", "honeynet"]
}
```

- **`confidence`** is a per-MITRE-technique lookup table (`mitreConfidence`
  in `onefirewall.go`): an actual exploit payload (SQLi, Log4Shell,
  command injection, ...) scores 0.9-0.95; merely connecting to a fake
  service with no further action (`T1133` alone) scores 0.5 - suspicious
  on its own, but not proof of intent the way a live payload is.
- **`tags`** always carries the MITRE code, a `details#`-prefixed plain-
  English description (this part is public per OneFirewall's API), and
  the two static tags `velocitylab`/`honeynet`.
- Verified end-to-end against a local mock server (not the real API -
  there's nothing to safely test against without a real key): confirmed
  the exact JSON shape above, the raw (non-`Bearer`) `Authorization`
  header, and that it fires from the same log line that drives the
  syslog/MITRE-tagging output.
- **Never reports private/loopback/link-local IPs** - confirmed by
  testing that a real attack from `::1` produces zero outbound calls.
  Without this, every bit of local testing of this very app would get
  reported as a live attacker.
- **Per-IP cooldown** of 5 minutes, so one scan burst (which can
  generate hundreds of tagged lines in seconds) can't flood OneFirewall's
  API or spin up hundreds of outbound goroutines.
- Fire-and-forget: the actual HTTP call happens in a background
  goroutine, so it can never add latency to the request/connection that
  triggered it. Disabled by default - with no `CTI_API_KEY`, this is a
  complete no-op, confirmed by testing with the variable unset.

[`mitre.go`](mitre.go) holds the web-request classifier: it inspects the
path, query string, form body (read and restored, so the real handler
still sees it normally), and `User-Agent` against a prioritized set of
regex signatures - SQL injection, XSS, path traversal, command/template
injection, credential/cloud-metadata file hits, mass-assignment writes,
brute-force attempts against `/login`/`/reset-password`, and known
scanner User-Agents - and returns the first match. The fake TCP/HTTP
services tag every connection as `T1133 External Remote Services`, with
the category label varying by port/service family (`portAttackCategory`
in [`fakeservices.go`](fakeservices.go) - e.g. "Database Exploitation
Attempt" for the DB ports, "Remote Code Execution Attempt" for
Jenkins/Jupyter/Webmin), plus a few more specific MITRE tags for
particular commands (SMTP `VRFY` -> `T1087 Account Discovery` | User
Enumeration Attempt, FTP/Telnet login -> `T1078.001 Valid Accounts:
Default Accounts` | Default/Weak Credential Access Attempt, IMAP/POP3
plaintext auth -> `T1040 Network Sniffing` | Plaintext Credential
Interception Risk, DNS `AXFR` -> `T1018 Remote System Discovery` | DNS
Zone Transfer / Information Disclosure Attempt).

This is advisory classification from a single request in isolation, the
same limitation any signature-based detector has - it's meant to make
the logs legible at a glance, not to be a certified detector. A gap
worth knowing about if you're comparing it against a real EDR/SIEM rule
set: it has no equivalent for the race conditions or the ReDoS in
[`pentest.go`](pentest.go), since spotting those needs request *timing/
sequencing*, not a pattern in a single request's content.

### Beyond pattern matching

A few detection mechanisms that don't fit the "does this one request
contain a known bad string" model above:

- **Known mass-exploitation CVE payloads.** Log4Shell (`${jndi:...}`),
  Spring4Shell (`class.module.classLoader...`), and Shellshock
  (`() { :; };`) all get tagged in `mitre.go` even though nothing here
  could actually be vulnerable to any of them (no Java, no Bash CGI) -
  internet-wide scanners blast these at literally everything regardless,
  so catching the attempt is valuable signal on its own.
- **Header-based injection.** The classifier doesn't just check the
  query string and body - it also scans `X-Forwarded-For`,
  `X-Forwarded-Host`, `X-Real-IP`, `Referer`, `User-Agent`, and `Cookie`
  for the same injection patterns, since a lot of real attacks
  (Log4Shell especially) ride in headers specifically to dodge
  body-only WAFs.
- **TLS JA3 fingerprinting** ([`ja3.go`](ja3.go)). Every HTTPS connection
  has its raw ClientHello sniffed before the TLS layer consumes it, and
  reduced to a JA3 hash - a fingerprint of how the client's TLS library
  actually negotiates (cipher suite list, extension order, elliptic
  curves), not anything the request claims to be. It survives
  User-Agent spoofing: a tool that rotates its UA per request but reuses
  the same underlying HTTP client library still produces the same JA3
  hash every time, which is what lets you correlate requests back to
  one actor regardless of what they call themselves. Verified against
  real clients: three `curl` requests produced an identical hash,
  Python's `ssl` module produced a different one.
- **Rate-based scanning detection** ([`ratedetect.go`](ratedetect.go)).
  Tracks request timestamps per IP in memory; more than 20 requests from
  the same IP within 5 seconds gets tagged as `T1595.002 Active
  Scanning` even if no single request matched any payload signature -
  catching careful scanners that avoid obvious strings but still crawl
  far faster than any human.
- **A hidden honeytoken link.** Every page footer includes an
  `aria-hidden`, off-screen-positioned link to `/__trap/audit-export`
  (also listed in `robots.txt`'s `Disallow`, since some aggressive
  scanners specifically check disallowed paths). No real visitor can
  click it. Reaching it at all is about as close to proof of automation
  as a single request gets.
- **UDP amplification-vector probes** ([`udpservices.go`](udpservices.go)).
  SNMP (161), NTP (123), memcached (11211/UDP), SSDP (1900), and chargen
  (19) all get a listener purely to detect and log probe/abuse attempts.
  These intentionally behave differently from every TCP fake service in
  this repo: UDP has no handshake, so the source address on any packet
  could be spoofed, and a real amplifying reply would make this host a
  usable DDoS reflector against whoever that spoofed address actually
  belongs to - a real third party, not just this test box. So NTP,
  memcached, SSDP, and chargen get logged and **never answered**, and
  SNMP's reply (the actual recon signal - confirming the `public`
  community string works) is kept deliberately small, with no
  exploitable amplification factor. Verified against real tooling: a
  genuine `snmpget` correctly read back the fake `sysDescr` value.
- **Canary-token hook.** `/internal/metadata`'s AWS-style access key
  pair can be swapped for a real one via `CANARY_AWS_ACCESS_KEY_ID` /
  `CANARY_AWS_SECRET_ACCESS_KEY`. A free canary token (e.g. from
  [canarytokens.org](https://canarytokens.org)) looks like a working AWS
  key and does nothing on its own, but alerts you - by email/webhook,
  completely outside this app - the moment someone actually tries to use
  it against the real AWS API. That turns "someone extracted this fake
  secret" from a log line here into external, out-of-band proof it
  happened and got used. Nothing is provisioned by default; without the
  env vars set, the static fake key is used exactly as before.

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
reports **132 findings across 18 rule IDs**, including:

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
- **Nothing here can meaningfully harm the host - audited, not just
  claimed.** A full pass confirmed: zero `os/exec` calls anywhere in the
  codebase (command injection is entirely simulated via regex matching,
  never a real shell); zero real file writes and zero `os.Open`/
  `os.ReadFile` calls with a variable path anywhere (path traversal and
  file upload are both in-memory only); every SSRF-capable feature
  (`/fetch`, `/api/webhook-test`) is timeout- and size-bounded; every
  HTTP panic is recovered by `recoverMiddleware`.
  - **Every raw TCP/UDP fake-service handler is now wrapped in its own
    panic recovery** (`runRecovered` in `fakeservices.go`), added after
    this audit. Without it, a single malformed packet triggering a bug
    in any one of the many hand-rolled binary parsers here (SNMP BER,
    Modbus, MQTT, DICOM, JA3's TLS ClientHello parser, ...) would have
    crashed the *entire process* - Go panics propagate up and kill the
    whole program, not just the offending goroutine, unless recovered.
    Proved this concretely: temporarily injected a real `panic()` into
    the Modbus handler, confirmed the triggering connection died but the
    main web app, FTP, and every other service kept running, then
    reverted it.
  - **The file-upload size cap was real only in the README, not in the
    code**, until this audit caught it: `ParseMultipartForm`'s size
    argument only bounds what's buffered in memory - it does **not**
    reject a larger request body. A 50MB upload against the old code
    succeeded with no error at all. Fixed with `http.MaxBytesReader`,
    which actually enforces the limit; re-verified the same 50MB upload
    now fails with `request body too large`. The upload map is also now
    capped at 50 stored files (FIFO eviction), so repeated uploads under
    the size cap can't still grow memory without bound over time.
  - The ReDoS on `/api/validate-coupon` is real CPU cost, but it's scoped
    to the one goroutine handling that request - confirmed the rest of
    the app stays fully responsive while a 20+ second match runs - and
    input is capped at 1000 characters.
  - Every fake service that doesn't need to respond meaningfully
    (NTP/memcached/SSDP/chargen) sends no reply at all, so none of them
    can be used as a real-world amplification reflector against a third
    party, regardless of what's in the request.
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
