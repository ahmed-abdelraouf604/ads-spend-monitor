-- Device Manager: one row per active login session
CREATE TABLE IF NOT EXISTS sessions (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id   text        UNIQUE NOT NULL,
  ip_address   text,
  user_agent   text,
  created_at   timestamptz DEFAULT now(),
  last_seen_at timestamptz DEFAULT now()
);

-- Index for fast lookup by session_id on every authenticated request
CREATE INDEX IF NOT EXISTS sessions_session_id_idx ON sessions (session_id);
