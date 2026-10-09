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
	"net/http"
	"os"
	"runtime/debug"
)

func main() {
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

	// .env served directly at the web root for maximum DAST-discoverability.
	mux.HandleFunc("/.env", handleEnvFile)

	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/search", handleSearchXSS)
	mux.HandleFunc("/comments", handleComments)
	mux.HandleFunc("/login", handleLoginSQLi)
	mux.HandleFunc("/products", handleProductsSQLi)
	mux.HandleFunc("/files", handleFilesTraversal)
	mux.HandleFunc("/redirect", handleOpenRedirect)
	mux.HandleFunc("/account", handleAccountPage)
	mux.HandleFunc("/profile", handleProfileIDOR)
	mux.HandleFunc("/admin", handleAdminBrokenAccess)
	mux.HandleFunc("/api/config", handleAPIConfigExposure)
	mux.HandleFunc("/api/data", handleAPIDataCORS)
	mux.HandleFunc("/ping", handlePingCmdInjection)
	mux.HandleFunc("/render", handleRenderSSTI)
	mux.HandleFunc("/transfer", handleTransferCSRF)
	mux.HandleFunc("/fetch", handleFetchSSRF)
	mux.HandleFunc("/internal/metadata", handleInternalMetadata)
	mux.HandleFunc("/crash", handleCrashStackTrace)

	handler := recoverMiddleware(logMiddleware(mux))

	httpAddr := getenvDefault("HTTP_ADDR", ":80")
	httpsAddr := getenvDefault("HTTPS_ADDR", ":443")

	cert, err := loadOrGenerateCert()
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
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		fmt.Printf("vulnapp-web listening on https://%s (self-signed certificate, intentionally vulnerable - do not expose publicly)\n", httpsAddr)
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	log.Fatal(<-errCh)
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// logMiddleware logs each request. It intentionally does not set any
// security headers (no CSP, X-Frame-Options, HSTS, X-Content-Type-Options),
// which is itself one of the vulnerable findings (clickjacking / missing
// hardening headers).
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		// Verbose server banner disclosure.
		w.Header().Set("Server", "vulnapp-web/0.1 (Go net/http)")
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
