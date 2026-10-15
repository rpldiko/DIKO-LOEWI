PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_number INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  level TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS point_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  admin_id INTEGER,
  old_points INTEGER NOT NULL,
  change_amount INTEGER NOT NULL,
  new_points INTEGER NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (participant_id) REFERENCES participants(id) ON DELETE CASCADE,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  action TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_participants_points ON participants(points DESC);
CREATE INDEX IF NOT EXISTS idx_history_participant ON point_history(participant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
