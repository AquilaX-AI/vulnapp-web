package main

import (
	"database/sql"
	"sync"

	_ "modernc.org/sqlite"
)

// User is a fake account. Passwords are stored in plaintext on purpose
// (another intentional weakness: no hashing) alongside fake PII used to
// demonstrate IDOR / sensitive data exposure.
type User struct {
	ID      int
	Username string
	Password string
	Role     string
	Email    string
	SSN      string
	Address  string
}

type Product struct {
	ID    int
	Name  string
	Price float64
}

type Comment struct {
	ID     int
	Author string
	Body   string
}

var (
	db *sql.DB

	commentsMu sync.Mutex
	comments   []Comment
	nextCommentID = 3

	balanceMu sync.Mutex
	// Fake in-memory "account balance" used only to demonstrate CSRF.
	// Resets to 1000 whenever the process restarts; no real money or
	// persistence is involved.
	balance = 1000

	usersMu sync.Mutex

	// resetTokens backs the weak password-reset flow: username -> a
	// predictable 6-digit code generated with math/rand (see
	// handleForgotPassword). Brute-forceable in well under a million
	// guesses - exactly what a fuzzer/intruder would find quickly.
	resetTokensMu sync.Mutex
	resetTokens   = map[string]string{}
)

// jwtSecret signs the "remember me" token (see handleLoginSQLi /
// handleAPIMe) and is also - deliberately - the exact same value leaked
// by /api/config's "jwt_secret" field, so reading that endpoint is enough
// to forge a token for any user/role.
const jwtSecret = "changeme"

var fakeUsers = []User{
	{1, "admin", "SuperSecretPass!2024", "admin", "admin@vulnapp.local", "000-00-0001", "1 Admin Way, HQ"},
	{2, "alice", "alicepass123", "user", "alice@vulnapp.local", "123-45-6789", "22 Baker Street"},
	{3, "bob", "bobpassword", "user", "bob@vulnapp.local", "987-65-4321", "9 Elm Street"},
}

var fakeProducts = []Product{
	{1, "Widget", 9.99},
	{2, "Gadget", 19.99},
	{3, "Gizmo", 29.99},
}

// initStore seeds an in-memory SQLite database. Tables are populated with
// fake data only; nothing here is real user information.
func initStore() error {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	// database/sql pools multiple underlying connections, and each one
	// gets its own independent, empty ":memory:" database - SQLite
	// doesn't share in-memory data across connections by default. Without
	// this, any concurrent load that forces the pool to open a second
	// connection sees a database with no tables at all.
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		username TEXT,
		password TEXT,
		role TEXT,
		email TEXT
	);
	CREATE TABLE products (
		id INTEGER PRIMARY KEY,
		name TEXT,
		price REAL
	);
	`
	if _, err = db.Exec(schema); err != nil {
		return err
	}

	for _, u := range fakeUsers {
		if _, err = db.Exec(
			"INSERT INTO users (id, username, password, role, email) VALUES (?, ?, ?, ?, ?)",
			u.ID, u.Username, u.Password, u.Role, u.Email,
		); err != nil {
			return err
		}
	}
	for _, p := range fakeProducts {
		if _, err = db.Exec(
			"INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
			p.ID, p.Name, p.Price,
		); err != nil {
			return err
		}
	}

	comments = []Comment{
		{1, "alice", "Great app, very fast!"},
		{2, "bob", "Looking forward to v2 :)"},
	}

	return nil
}
