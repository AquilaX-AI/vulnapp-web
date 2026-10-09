-- fake database dump, exposed via directory listing on /uploads/
-- for demonstrating sensitive backup file exposure.

-- legacy password_hash column, pre-plaintext-migration (fake MD5 digest):
-- 5f4dcc3b5aa765d61d8327deb882cf99

INSERT INTO users (id, username, password, role, email) VALUES
  (1, 'admin', 'SuperSecretPass!2024', 'admin', 'admin@vulnapp.local'),
  (2, 'alice', 'alicepass123', 'user', 'alice@vulnapp.local'),
  (3, 'bob', 'bobpassword', 'user', 'bob@vulnapp.local');
