CREATE TABLE IF NOT EXISTS heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tail TEXT,
    iface TEXT,
    timestamp TEXT
);
