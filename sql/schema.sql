CREATE TABLE IF NOT EXISTS log_events (
    id          BIGSERIAL PRIMARY KEY,
    event_time  TIMESTAMPTZ NOT NULL,
    source_ip   INET,
    username    TEXT,
    service     TEXT,
    event_type  TEXT NOT NULL,      -- login_failed, login_success, ...
    raw_line    TEXT,
    source      TEXT NOT NULL       -- auth.log, cowrie, ...
);

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    alert_type  TEXT NOT NULL,      -- brute_force, suspicious_ip, odd_hour
    source_ip   INET,
    severity    TEXT NOT NULL,      -- low, medium, high
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_time ON log_events (event_time);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON log_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON log_events (event_type);

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_dedup
    ON log_events (source, event_time, md5(raw_line));
