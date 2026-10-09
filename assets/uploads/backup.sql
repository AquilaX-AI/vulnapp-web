-- fake database dump, exposed via directory listing on /uploads/
-- for demonstrating sensitive backup file exposure.

INSERT INTO users (id, username, password, role, email) VALUES
  (1, 'admin', 'SuperSecretPass!2024', 'admin', 'admin@vulnapp.local'),
  (2, 'alice', 'alicepass123', 'user', 'alice@vulnapp.local'),
  (3, 'bob', 'bobpassword', 'user', 'bob@vulnapp.local');
