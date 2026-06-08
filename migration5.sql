-- Multi-user system

CREATE TABLE IF NOT EXISTS users (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  username      text        UNIQUE NOT NULL,
  password_hash text        NOT NULL,
  is_admin      boolean     DEFAULT false,
  created_at    timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_accounts (
  user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
  account_id text NOT NULL,
  PRIMARY KEY (user_id, account_id)
);

-- Track which user owns each session (allows per-user revocation on delete)
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username text;
