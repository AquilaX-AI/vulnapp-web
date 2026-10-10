// Command vulnapp-web is an intentionally vulnerable Go web application.
//
// It exists ONLY to give a DAST (dynamic application security testing)
// scanner a predictable set of findings to detect. Every vulnerability
// below is deliberate. Secrets, keys, and PII in this repository are all
// fake. Nothing here should ever be deployed on a public network or reused
// in a real application.
//
// Run it with:
//
//	go run .
//
// By default it listens for plain HTTP on :80 and HTTPS (self-signed
// certificate, generated at startup) on :443, so it can sit directly on a
// VM with no reverse proxy in front of it. Override with the HTTP_ADDR /
// HTTPS_ADDR env vars (e.g. HTTP_ADDR=:8080 HTTPS_ADDR=:8443 for a
// non-root dev run). Binding :80/:443 on Linux requires root or
// CAP_NET_BIND_SERVICE - see the README.
package main

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	initSyslog()

	if err := initStore(); err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}

	mux := http.NewServeMux()

	// Static assets, served from the embedded filesystem so the compiled
	// binary needs nothing else on disk.
	staticSub, err := fs.Sub(staticFS, "assets/static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	// Directory listing + sensitive backup file exposure: no index.html
	// is present, so http.FileServerFS lists the directory contents.
	uploadsSub, err := fs.Sub(uploadsFS, "assets/uploads")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServerFS(uploadsSub)))

	// Unrestricted file upload: more specific than "/uploads/" above, so
	// it wins for this one subpath. No type/extension checks at all.
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/uploads/user/", handleServeUpload)

	// .env served directly at the web root for maximum DAST-discoverability.
	mux.HandleFunc("/.env", handleEnvFile)

	// robots.txt that points a crawler straight at the "sensitive" areas -
	// a very common real-world recon source.
	mux.HandleFunc("/robots.txt", handleRobotsTxt)
	mux.HandleFunc("/wp-login.php", handleWPLogin)
	mux.HandleFunc("/xmlrpc.php", handleXMLRPC)
	mux.HandleFunc("/wp-json/", handleWPJSON)
	mux.HandleFunc("/__trap/", handleHoneytokenTrap)

	// A fake OpenAPI spec is an even better recon source than robots.txt:
	// it names every endpoint, including the ones nothing on the site
	// links to.
	mux.HandleFunc("/swagger.json", handleSwaggerJSON)

	// Fake exposed .git metadata, with a credential leaked in the remote
	// URL and a reflog entry confessing to another one.
	mux.HandleFunc("/.git/HEAD", handleGitHead)
	mux.HandleFunc("/.git/config", handleGitConfig)
	mux.HandleFunc("/.git/logs/HEAD", handleGitLogsHead)

	// Fake leftover PHP backup/debug files, consistent with the Server /
	// X-Powered-By banner above.
	mux.HandleFunc("/config.php.bak", handleConfigPhpBak)
	mux.HandleFunc("/phpinfo.php", handlePhpInfo)

	// Exposed pprof - the classic real-world Go misconfiguration.
	registerPprof(mux)

	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/search", handleSearchXSS)
	mux.HandleFunc("/comments", handleComments)
	mux.HandleFunc("/login", handleLoginSQLi)
	mux.HandleFunc("/forgot-password", handleForgotPassword)
	mux.HandleFunc("/reset-password", handleResetPassword)
	mux.HandleFunc("/products", handleProductsSQLi)
	mux.HandleFunc("/files", handleFilesTraversal)
	mux.HandleFunc("/redirect", handleOpenRedirect)
	mux.HandleFunc("/account", handleAccountPage)
	mux.HandleFunc("/profile", handleProfileIDOR)
	mux.HandleFunc("/admin", handleAdminBrokenAccess)
	mux.HandleFunc("/api/config", handleAPIConfigExposure)
	mux.HandleFunc("/api/data", handleAPIDataCORS)
	mux.HandleFunc("/api/me", handleAPIMe)
	mux.HandleFunc("/api/related", handleRelatedProductCrash)
	mux.HandleFunc("/api/profile", handleProfileUpdateMassAssignment)
	mux.HandleFunc("/ping", handlePingCmdInjection)
	mux.HandleFunc("/render", handleRenderSSTI)
	mux.HandleFunc("/transfer", handleTransferCSRF)
	mux.HandleFunc("/fetch", handleFetchSSRF)
	mux.HandleFunc("/internal/metadata", handleInternalMetadata)
	mux.HandleFunc("/crash", handleCrashStackTrace)

	// Race condition, ReDoS, CSWSH, session fixation, business logic,
	// token-in-URL, multi-cloud SSRF targets, and blind SSRF - see
	// pentest.go.
	mux.HandleFunc("/api/withdraw", handleWithdrawRace)
	mux.HandleFunc("/api/validate-coupon", handleValidateCoupon)
	mux.HandleFunc("/ws", handleWebSocket)
	mux.HandleFunc("/api/session", handleAPISession)
	mux.HandleFunc("/checkout", handleCheckout)
	mux.HandleFunc("/api/export", handleExportAPI)
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", handleGCPMetadata)
	mux.HandleFunc("/metadata/instance", handleAzureMetadata)
	mux.HandleFunc("/api/webhook-test", handleWebhookTest)

	handler := recoverMiddleware(logMiddleware(sessionFixationMiddleware(methodProbeMiddleware(mux))))

	fmt.Printf("vulnapp-web %s\n", version)

	// Fake TCP/HTTP services on a batch of ports that should never be
	// internet-facing (databases, caches, remote admin, container APIs,
	// ...) - the same idea as the web app, one layer down the stack.
	startFakeServices()
	startUDPServices()
	startAIServices()
	startIoTServices()
	startICSServices()
	startIoTDeviceServices()
	startRateDetectCleanup()

	httpAddr := getenvDefault("HTTP_ADDR", ":80")
	httpsAddr := getenvDefault("HTTPS_ADDR", ":443")

	tlsConfig, err := certSource()
	if err != nil {
		log.Fatalf("failed to prepare TLS certificate: %v", err)
	}

	errCh := make(chan error, 2)

	go func() {
		fmt.Printf("vulnapp-web listening on http://%s (plain, intentionally vulnerable - do not expose publicly)\n", httpAddr)
		errCh <- http.ListenAndServe(httpAddr, handler)
	}()

	go func() {
		srv := &http.Server{
			Addr:      httpsAddr,
			Handler:   handler,
			TLSConfig: tlsConfig,
			// HTTP/2 requires at least one ECDHE+AES-GCM cipher suite,
			// which our deliberately weak, RSA-key-exchange-only
			// CipherSuites list doesn't offer - Go refuses to start
			// otherwise. Disabling h2 here is also period-accurate: the
			// Apache 2.2/PHP 5.3 stack this app pretends to be predates
			// HTTP/2 entirely.
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		}
		fmt.Printf("vulnapp-web listening on https://%s (self-signed certificate, minted per-hostname on connect, intentionally vulnerable - do not expose publicly)\n", httpsAddr)

		// A plain net.Listen + manual wrapping, rather than
		// ListenAndServeTLS, so the JA3 sniffer (ja3.go) gets to see each
		// connection's raw ClientHello bytes before the TLS layer
		// consumes them.
		rawLn, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			errCh <- err
			return
		}
		tlsLn := tls.NewListener(newJA3Listener(rawLn), srv.TLSConfig)
		errCh <- srv.Serve(tlsLn)
	}()

	log.Fatal(<-errCh)
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// logMiddleware logs each request. It intentionally does not set most
// security headers (no X-Frame-Options, HSTS, or X-Content-Type-Options),
// which is itself one of the vulnerable findings (clickjacking / missing
// hardening headers). The one header it does set, CSP, is deliberately
// useless - "present but ineffective" is a distinct finding from
// "missing entirely".
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := classifyRequest(r)
		if tag == "" {
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if detectHighFrequencyScanning(ip) {
				tag = "T1595.002 Active Scanning: Vulnerability Scanning | High-Frequency Automated Scanning Detected"
			}
		}
		details := attackDetails(r)
		if tag != "" {
			log.Printf("%s %s %s [%s] %s", r.RemoteAddr, r.Method, r.URL.String(), tag, details)
		} else {
			log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.String(), details)
		}
		// Verbose, deliberately outdated server banner disclosure: this is
		// a Go binary, but it claims to be a long-EOL Apache/PHP stack so
		// scanners that fingerprint software versions have something to
		// flag (and, if they check, plenty of known CVEs to suggest).
		w.Header().Set("Server", "Apache/2.2.15 (CentOS)")
		w.Header().Set("X-Powered-By", "PHP/5.3.3")
		// A wildcard, 'unsafe-inline'/'unsafe-eval' CSP blocks nothing -
		// it just looks like a security control to anyone not reading it.
		w.Header().Set("Content-Security-Policy", "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// methodProbeMiddleware answers HTTP methods that a hardened server would
// normally reject. TRACE gets the classic Cross-Site Tracing (XST)
// treatment - naively reflecting the raw request back instead of
// rejecting it - and OPTIONS advertises a broad, unrestricted Allow list.
// Everything else just falls through to the normal handler, which is
// itself already method-agnostic (another intentional "insecure HTTP
// methods" finding: GET, PUT, DELETE, PATCH, ... all behave the same).
func methodProbeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodTrace:
			w.Header().Set("Content-Type", "message/http")
			r.Write(w)
			return
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, POST, PUT, DELETE, PATCH, TRACE, CONNECT, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware catches panics and writes the stack trace back to the
// client (verbose error / information disclosure), instead of returning a
// generic 500. It still prevents the process from crashing.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "panic: %v\n\nstack trace:\n%s", rec, debug.Stack())
			}
		}()
		next.ServeHTTP(w, r)
	})
}
