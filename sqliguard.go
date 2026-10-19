package main

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// sqliGuard blocks the one class of payload that would escape this
// app's "contained, fake" SQL injection model and actually touch the
// real host: a statement stacked onto the vulnerable query via a
// semicolon. Everything else this app intends to expose - UNION-based
// extraction, auth bypass (' OR '1'='1), comment termination (--), and
// error-based disclosure - is single-statement and stays unfiltered.
//
// database/sql's SQLite driver here (modernc.org/sqlite) will execute a
// full multi-statement script handed to Query/Exec, not just the first
// statement. Confirmed against a real running instance: a payload like
// `' ; ATTACH DATABASE '/tmp/x.db' AS p; CREATE TABLE p.t(x);--`
// genuinely created a file on the host filesystem. A stacked `; DROP
// TABLE users;` is just as real - it would actually drop this app's own
// table, not a decoy. Both are a materially different, unintended risk
// from the single-statement SQLi this app is designed to demonstrate,
// so they're blocked here rather than silently executed.
// \b only trails the alternatives that are always standalone keywords;
// "pragma" deliberately has no trailing \b so it also catches the
// pragma_*() table-valued functions (pragma_table_info, ...), which are
// callable from an ordinary expression with no semicolon needed at all.
var dangerousSQLPattern = regexp.MustCompile(`(?i)\b(attach\b|detach\b|pragma|vacuum\b|load_extension|readfile|writefile|fts[35]_tokenizer)`)

// errSQLiSandboxEscape is returned instead of running the query. From
// the caller's (and attacker's) point of view this looks exactly like
// the database rejecting malformed SQL - which is also literally true:
// a real production DB role is very often locked down from ATTACH/
// PRAGMA/DDL the same way.
var errSQLiSandboxEscape = errors.New(`near "ATTACH": syntax error`)

// hasStackedStatement reports whether query contains a second statement
// after a semicolon - as opposed to a semicolon that's just part of a
// trailing SQL comment (`'; --`), which is harmless and common in real
// auth-bypass/comment-termination SQLi payloads and must keep working.
func hasStackedStatement(query string) bool {
	parts := strings.Split(query, ";")
	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "/*") {
			continue // nothing after the semicolon but a comment
		}
		return true
	}
	return false
}

// sqliSandboxEscape reports whether query carries a payload capable of
// escaping the intended single-statement SQLi sandbox.
func sqliSandboxEscape(query string) bool {
	return hasStackedStatement(query) || dangerousSQLPattern.MatchString(query)
}

// guardedQuery is the one path every handler that builds a query via
// string concatenation (handleLoginSQLi, handleProductsSQLi) must use
// instead of calling db.Query directly.
func guardedQuery(query string) (*sql.Rows, error) {
	if sqliSandboxEscape(query) {
		return nil, errSQLiSandboxEscape
	}
	return db.Query(query)
}
