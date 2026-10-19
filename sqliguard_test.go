package main

import "testing"

func TestSqliSandboxEscape(t *testing.T) {
	cases := []struct {
		name, query string
		wantBlocked bool
	}{
		{"plain select", `SELECT id, username, role FROM users WHERE username='admin' AND password='x'`, false},
		{"auth bypass OR", `SELECT id, username, role FROM users WHERE username='admin' OR '1'='1' AND password='x'`, false},
		{"comment-terminated auth bypass", `SELECT id, username, role FROM users WHERE username='admin'--' AND password='x'`, false},
		{"trailing semicolon + comment only", `SELECT id, username, role FROM users WHERE username='admin'; -- ' AND password='x'`, false},
		{"union based", `SELECT id, name, price FROM products WHERE id = 0 UNION SELECT username, password, 1 FROM users`, false},
		{"stacked attach+create (real finding)", `SELECT id, username, role FROM users WHERE username='x'; ATTACH DATABASE '/tmp/pwn.db' AS p; CREATE TABLE p.t(x TEXT);--' AND password='a'`, true},
		{"stacked drop table", `SELECT id, name, price FROM products WHERE id = 1; DROP TABLE users;--`, true},
		{"pragma without semicolon stacking context", `SELECT id, name, price FROM products WHERE id = 1 OR pragma_table_info('users')`, true},
		{"bare semicolon with trailing whitespace", `SELECT 1 FROM users WHERE username='admin';   `, false},
		{"empty stacked segment", `SELECT 1 FROM users WHERE username='admin';;`, false},
	}
	for _, c := range cases {
		got := sqliSandboxEscape(c.query)
		if got != c.wantBlocked {
			t.Errorf("%s: sqliSandboxEscape(%q) = %v, want %v", c.name, c.query, got, c.wantBlocked)
		}
	}
}

func TestGuardedQueryBlocksEscape(t *testing.T) {
	if err := initStore(); err != nil {
		t.Fatalf("initStore: %v", err)
	}
	_, err := guardedQuery(`SELECT id FROM users WHERE username='x'; ATTACH DATABASE '/tmp/vulnapp-guard-test.db' AS p; CREATE TABLE p.t(x);--'`)
	if err != errSQLiSandboxEscape {
		t.Fatalf("guardedQuery: got err %v, want errSQLiSandboxEscape", err)
	}

	rows, err := guardedQuery(`SELECT id, username, role FROM users WHERE username='admin' AND password='SuperSecretPass!2024'`)
	if err != nil {
		t.Fatalf("legitimate query was blocked: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected one row for valid admin login")
	}
}
