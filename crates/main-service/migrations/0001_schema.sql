-- FromChat main-service schema, matching the Python SQLAlchemy models.
-- `user` is quoted because "user" is a reserved word in PostgreSQL.
CREATE TABLE IF NOT EXISTS "user" (
    id           BIGINT PRIMARY KEY,
    username     VARCHAR(50)  NOT NULL,
    display_name VARCHAR(64)  NOT NULL DEFAULT '',
    password_hash VARCHAR(200) NOT NULL DEFAULT '',
    profile_picture TEXT,
    bio          TEXT,
    online       BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen    TIMESTAMPTZ,
    created_at   TIMESTAMPTZ,
    verified     BOOLEAN NOT NULL DEFAULT FALSE,
    suspended    BOOLEAN NOT NULL DEFAULT FALSE,
    suspension_reason TEXT,
    deleted      BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at   TIMESTAMPTZ,
    yandex_id    VARCHAR(128) UNIQUE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_username_lower ON "user" (lower(username));
CREATE INDEX IF NOT EXISTS ix_user_id ON "user" (id);
CREATE INDEX IF NOT EXISTS ix_user_deleted_at ON "user" (deleted_at);
CREATE INDEX IF NOT EXISTS ix_user_yandex_id ON "user" (yandex_id);

CREATE TABLE IF NOT EXISTS message (
    id         BIGSERIAL PRIMARY KEY,
    content    TEXT NOT NULL,
    timestamp  TIMESTAMPTZ DEFAULT now(),
    user_id    BIGINT NOT NULL REFERENCES "user"(id),
    is_read    BOOLEAN NOT NULL DEFAULT FALSE,
    reply_to_id BIGINT,
    is_edited  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS ix_message_id ON message (id);
CREATE INDEX IF NOT EXISTS ix_message_user_id ON message (user_id);

CREATE TABLE IF NOT EXISTS message_file (
    id         BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES message(id),
    path       TEXT NOT NULL,
    name       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_message_file_message_id ON message_file (message_id);

CREATE TABLE IF NOT EXISTS crypto_public_key (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL UNIQUE REFERENCES "user"(id),
    public_key_b64 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crypto_backup (
    id        BIGSERIAL PRIMARY KEY,
    user_id   BIGINT NOT NULL UNIQUE REFERENCES "user"(id),
    blob_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dm_envelope (
    id                    BIGSERIAL PRIMARY KEY,
    sender_id             BIGINT NOT NULL REFERENCES "user"(id),
    recipient_id          BIGINT NOT NULL REFERENCES "user"(id),
    iv_b64                TEXT NOT NULL,
    ciphertext_b64        TEXT NOT NULL,
    sender_wrapped_mek_b64 TEXT NOT NULL,
    recipient_wrapped_mek_b64 TEXT NOT NULL,
    compliance_wrapped_mek_b64 TEXT,
    reply_to_id           BIGINT,
    timestamp             TIMESTAMPTZ DEFAULT now(),
    is_edited             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ DEFAULT now(),
    deleted_at            TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS dm_file (
    id         BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES dm_envelope(id),
    sender_id  BIGINT NOT NULL REFERENCES "user"(id),
    recipient_id BIGINT NOT NULL REFERENCES "user"(id),
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    nonce_b64  TEXT
);

CREATE TABLE IF NOT EXISTS push_subscription (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES "user"(id),
    endpoint    TEXT NOT NULL,
    p256dh_key  TEXT NOT NULL,
    auth_key    TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fcm_token (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES "user"(id),
    token       TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reaction (
    id         BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES message(id),
    user_id    BIGINT NOT NULL REFERENCES "user"(id),
    emoji      VARCHAR(10) NOT NULL,
    timestamp  TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT unique_reaction UNIQUE (message_id, user_id, emoji)
);

CREATE TABLE IF NOT EXISTS dm_reaction (
    id             BIGSERIAL PRIMARY KEY,
    dm_envelope_id BIGINT NOT NULL REFERENCES dm_envelope(id),
    user_id        BIGINT NOT NULL REFERENCES "user"(id),
    emoji          VARCHAR(10) NOT NULL,
    timestamp      TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT unique_dm_reaction UNIQUE (dm_envelope_id, user_id, emoji)
);

CREATE TABLE IF NOT EXISTS dm_conversation_preference (
    id                    BIGSERIAL PRIMARY KEY,
    user_id               BIGINT NOT NULL REFERENCES "user"(id),
    other_user_id         BIGINT NOT NULL REFERENCES "user"(id),
    archived              BOOLEAN NOT NULL DEFAULT FALSE,
    last_read_envelope_id BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT unique_dm_conversation_preference UNIQUE (user_id, other_user_id)
);

CREATE TABLE IF NOT EXISTS dm_read_receipt (
    user_id      BIGINT NOT NULL REFERENCES "user"(id),
    envelope_id  BIGINT NOT NULL REFERENCES dm_envelope(id),
    other_user_id BIGINT NOT NULL REFERENCES "user"(id),
    PRIMARY KEY (user_id, envelope_id)
);

CREATE TABLE IF NOT EXISTS device_session (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES "user"(id),
    raw_user_agent TEXT,
    device_name  VARCHAR(128),
    device_type  VARCHAR(32),
    os_name      VARCHAR(64),
    os_version   VARCHAR(64),
    browser_name VARCHAR(64),
    browser_version VARCHAR(64),
    brand        VARCHAR(64),
    model        VARCHAR(64),
    session_id   VARCHAR(64) NOT NULL UNIQUE,
    session_kind VARCHAR(32) NOT NULL DEFAULT 'standard',
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT now(),
    last_seen    TIMESTAMPTZ DEFAULT now(),
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS ix_device_session_user_id ON device_session (user_id);
CREATE INDEX IF NOT EXISTS ix_device_session_session_id ON device_session (session_id);
CREATE INDEX IF NOT EXISTS ix_device_session_session_kind ON device_session (session_kind);

CREATE TABLE IF NOT EXISTS update_log (
    id        BIGSERIAL PRIMARY KEY,
    user_id   BIGINT NOT NULL REFERENCES "user"(id),
    sequence  BIGINT NOT NULL,
    updates   TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT uq_user_sequence UNIQUE (user_id, sequence)
);

CREATE TABLE IF NOT EXISTS message_edit_history (
    id              BIGSERIAL PRIMARY KEY,
    message_id      BIGINT NOT NULL REFERENCES message(id),
    previous_content TEXT NOT NULL,
    edited_at       TIMESTAMPTZ DEFAULT now(),
    edited_by_user_id BIGINT NOT NULL REFERENCES "user"(id)
);

CREATE TABLE IF NOT EXISTS dm_edit_history (
    id             BIGSERIAL PRIMARY KEY,
    message_id     BIGINT NOT NULL REFERENCES dm_envelope(id),
    dm_envelope_id BIGINT NOT NULL REFERENCES dm_envelope(id),
    previous_ciphertext_b64 TEXT NOT NULL,
    previous_iv_b64 TEXT NOT NULL,
    previous_compliance_wrapped_mek_b64 TEXT NOT NULL,
    edited_at      TIMESTAMPTZ DEFAULT now(),
    edited_by      BIGINT NOT NULL,
    edited_by_user_id BIGINT NOT NULL
);