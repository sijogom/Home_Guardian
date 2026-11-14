-- PostgreSQL 마이그레이션 DDL — Home Guardian 듀얼 백엔드.
-- SQLite 스키마와 컬럼/타입을 1:1 호환되게 유지한다.
-- 사용: psql $DATABASE_URL -f postgres_schema.sql

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    nickname TEXT NOT NULL,
    role TEXT NOT NULL,
    email_verified INTEGER NOT NULL,
    home_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS homes (
    home_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    home_id TEXT NOT NULL,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    model TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    online INTEGER NOT NULL,
    last_seen TEXT NOT NULL,
    open_ports_json TEXT NOT NULL,
    services_json TEXT NOT NULL DEFAULT '[]',
    default_credentials INTEGER NOT NULL,
    encryption TEXT NOT NULL,
    firmware TEXT NOT NULL,
    vulnerabilities_json TEXT NOT NULL,
    discovery_sources_json TEXT NOT NULL DEFAULT '[]',
    fingerprints_json TEXT NOT NULL DEFAULT '[]',
    risk_signals_json TEXT NOT NULL DEFAULT '[]',
    scan_source TEXT NOT NULL CHECK (scan_source = 'android-native'),
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.85,
    is_unresolved INTEGER NOT NULL DEFAULT 0,
    is_phantom INTEGER NOT NULL DEFAULT 0,
    security_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    risk_summary TEXT NOT NULL,
    recommended_actions_json TEXT NOT NULL,
    risk_rank INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    home_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    device_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    action_guide TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    home_id TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL,
    scan_profile TEXT NOT NULL,
    scan_source TEXT NOT NULL CHECK (scan_source IN ('android-native', 'windows-port-probe')),
    network_context_json TEXT NOT NULL DEFAULT '{}',
    network_scope_id TEXT,
    current_step TEXT NOT NULL,
    devices_found INTEGER NOT NULL,
    high_risk_devices INTEGER NOT NULL,
    security_score_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_devices (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    device_snapshot_json TEXT NOT NULL
);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS network_scope_id TEXT;

CREATE TABLE IF NOT EXISTS device_identity_history (
    resolution_id TEXT PRIMARY KEY,
    home_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    network_scope_id TEXT,
    physical_mac TEXT,
    observed_at TEXT NOT NULL,
    identity_status TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    device_type TEXT NOT NULL,
    model TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    evidence_json TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    note TEXT NOT NULL,
    resolver_version TEXT NOT NULL
);

ALTER TABLE device_identity_history ADD COLUMN IF NOT EXISTS network_scope_id TEXT;
ALTER TABLE device_identity_history ADD COLUMN IF NOT EXISTS physical_mac TEXT;

CREATE TABLE IF NOT EXISTS identity_enrichment_jobs (
    job_id TEXT PRIMARY KEY,
    job_key TEXT NOT NULL UNIQUE,
    home_id TEXT NOT NULL REFERENCES homes(home_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    network_scope_id TEXT,
    physical_mac TEXT,
    evidence_binding_signature TEXT,
    status TEXT NOT NULL CHECK (status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')),
    blocked_reason TEXT,
    evidence_json TEXT NOT NULL,
    evidence_signature TEXT NOT NULL,
    seen_count INTEGER NOT NULL CHECK (seen_count >= 1),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolution_json TEXT,
    source_reference TEXT,
    resolution_provenance TEXT CHECK (
        resolution_provenance IS NULL OR
        resolution_provenance IN (
            'operator-reviewed',
            'automated-official-web-search',
            'automated-official-http'
        )
    ),
    resolution_signature TEXT,
    research_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (research_attempt_count >= 0),
    research_last_attempt_at TEXT,
    research_next_attempt_at TEXT,
    research_policy_version TEXT,
    catalog_reconcile_version TEXT,
    resolved_at TEXT,
    CHECK (
        status <> 'resolved' OR (
            network_scope_id IS NOT NULL AND
            (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND
            resolution_json IS NOT NULL AND
            source_reference IS NOT NULL AND
            resolved_at IS NOT NULL
        )
    )
);

ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS resolution_provenance TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS resolution_signature TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS evidence_binding_signature TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS research_attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS research_last_attempt_at TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS research_next_attempt_at TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS research_policy_version TEXT;
ALTER TABLE identity_enrichment_jobs
    ADD COLUMN IF NOT EXISTS catalog_reconcile_version TEXT;

-- Legacy builds could mark a product resolved before signed provenance and
-- strong network/device binding were mandatory.  Quarantine those rows before
-- replacing either CHECK constraint; adding the new constraint first would
-- reject the existing data and abort the complete deployment migration.
UPDATE identity_enrichment_jobs
SET status = 'review_required',
    blocked_reason = 'UNSIGNED_LEGACY_RESOLUTION_REVIEW_REQUIRED',
    resolution_json = NULL,
    source_reference = NULL,
    resolution_provenance = NULL,
    resolution_signature = NULL,
    research_attempt_count = 0,
    research_last_attempt_at = NULL,
    research_next_attempt_at = NULL,
    resolved_at = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE status = 'resolved'
  AND COALESCE(resolution_signature, '') = '';

UPDATE identity_enrichment_jobs
SET status = 'review_required',
    blocked_reason = 'INVALID_LEGACY_RESOLUTION_REVIEW_REQUIRED',
    resolution_json = NULL,
    source_reference = NULL,
    resolution_provenance = NULL,
    resolution_signature = NULL,
    research_attempt_count = 0,
    research_last_attempt_at = NULL,
    research_next_attempt_at = NULL,
    resolved_at = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE status = 'resolved'
  AND (
      network_scope_id IS NULL
      OR network_scope_id !~ '^hgns1[gb]-[0-9a-f]{32}$'
      OR NOT (
          (
              physical_mac IS NOT NULL
              AND UPPER(physical_mac) ~ '^[0-9A-F][02468ACE](:[0-9A-F]{2}){5}$'
              AND UPPER(REPLACE(physical_mac, ':', '')) NOT IN (
                  '000000000000', '020000000000', 'FFFFFFFFFFFF'
              )
          )
          OR COALESCE(evidence_binding_signature, '') ~ '^hges1-[0-9a-f]{64}$'
      )
      OR COALESCE(resolution_json, '') = ''
      OR COALESCE(source_reference, '') = ''
      OR COALESCE(resolution_provenance, '') NOT IN (
          'operator-reviewed',
          'automated-official-web-search',
          'automated-official-http'
      )
      OR resolved_at IS NULL
  );

DO $$
DECLARE
    status_constraint RECORD;
BEGIN
    FOR status_constraint IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'identity_enrichment_jobs'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%status%review_required%'
    LOOP
        EXECUTE format(
            'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT %I',
            status_constraint.conname
        );
    END LOOP;
    ALTER TABLE identity_enrichment_jobs
        ADD CONSTRAINT ck_identity_enrichment_jobs_status CHECK (
            status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')
        );
END $$;

DO $$
DECLARE
    provenance_constraint RECORD;
BEGIN
    FOR provenance_constraint IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'identity_enrichment_jobs'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%resolution_provenance%'
    LOOP
        EXECUTE format(
            'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT %I',
            provenance_constraint.conname
        );
    END LOOP;
    ALTER TABLE identity_enrichment_jobs
        ADD CONSTRAINT ck_identity_enrichment_jobs_provenance CHECK (
            resolution_provenance IS NULL OR
            resolution_provenance IN (
                'operator-reviewed',
                'automated-official-web-search',
                'automated-official-http'
            )
        );
END $$;

DO $$
DECLARE
    resolved_binding_constraint RECORD;
BEGIN
    FOR resolved_binding_constraint IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'identity_enrichment_jobs'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%resolved%'
          AND pg_get_constraintdef(oid) LIKE '%network_scope_id%'
          AND pg_get_constraintdef(oid) LIKE '%resolution_json%'
    LOOP
        EXECUTE format(
            'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT %I',
            resolved_binding_constraint.conname
        );
    END LOOP;
    ALTER TABLE identity_enrichment_jobs
        ADD CONSTRAINT ck_identity_enrichment_jobs_resolved_binding CHECK (
            status <> 'resolved' OR (
                network_scope_id IS NOT NULL AND
                (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND
                resolution_json IS NOT NULL AND
                source_reference IS NOT NULL AND
                resolved_at IS NOT NULL
            )
        );
END $$;

CREATE TABLE IF NOT EXISTS verified_product_catalog (
    manufacturer TEXT NOT NULL,
    manufacturer_key TEXT NOT NULL,
    exact_model TEXT NOT NULL,
    model_key TEXT NOT NULL,
    device_type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (
        provenance IN (
            'operator-reviewed',
            'automated-official-web-search',
            'automated-official-http'
        )
    ),
    verified_at TEXT NOT NULL,
    catalog_signature TEXT NOT NULL,
    UNIQUE (manufacturer_key, model_key)
);

CREATE TABLE IF NOT EXISTS guardian_invites (
    invite_id TEXT PRIMARY KEY,
    home_id TEXT NOT NULL,
    email TEXT NOT NULL,
    relation TEXT NOT NULL,
    display_name TEXT,
    ward_account_name TEXT,
    short_code TEXT UNIQUE,
    deep_link TEXT,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    accepted_at TEXT,
    revoked_at TEXT,
    last_viewed_at TEXT,
    guardian_token_hash TEXT UNIQUE,
    session_created_at TEXT,
    session_last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS guardian_accounts (
    guardian_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT,
    provider TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guardian_ward_links (
    link_id TEXT PRIMARY KEY,
    guardian_id TEXT NOT NULL,
    invite_id TEXT NOT NULL UNIQUE,
    home_id TEXT NOT NULL,
    ward_account_name TEXT,
    ward_alias TEXT,
    ward_display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    revoked_at TEXT,
    last_viewed_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    notification_id TEXT NOT NULL UNIQUE,
    home_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    scan_id TEXT,
    scan_source TEXT,
    read INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fcm_tokens (
    fcm_token TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    user_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS scan_id TEXT;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS scan_source TEXT;

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    home_id TEXT NOT NULL,
    role TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    previous_refresh_token_hash TEXT,
    refresh_retry_id TEXT,
    refresh_retry_until TEXT,
    activation_state TEXT NOT NULL DEFAULT 'active',
    handoff_predecessor_session_id TEXT,
    handoff_predecessor_refresh_token_hash TEXT,
    handoff_id_hash TEXT,
    handoff_expires_at TEXT,
    handoff_completed_at TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS device_aliases (
    home_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    network_scope_id TEXT,
    physical_mac TEXT,
    alias TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (home_id, device_id)
);

ALTER TABLE device_aliases ADD COLUMN IF NOT EXISTS network_scope_id TEXT;
ALTER TABLE device_aliases ADD COLUMN IF NOT EXISTS physical_mac TEXT;

-- Remove unsafe defaults and exact fixture principals created by pre-v1
-- runtime paths. Historic scan/device rows are retained: old migrations added
-- source columns with defaults, so the source value alone is not reliable
-- deletion provenance. Public/current repository reads accept only validated
-- Android observations.
ALTER TABLE devices ALTER COLUMN scan_source DROP DEFAULT;
ALTER TABLE scans ALTER COLUMN scan_source DROP DEFAULT;
ALTER TABLE security_events ALTER COLUMN home_id DROP DEFAULT;
ALTER TABLE guardian_invites ALTER COLUMN home_id DROP DEFAULT;
ALTER TABLE notifications ALTER COLUMN home_id DROP DEFAULT;

DELETE FROM auth_sessions
WHERE user_id = 'user-0001'
   OR user_id IN (SELECT guardian_id FROM guardian_accounts WHERE provider = 'test');
DELETE FROM fcm_tokens WHERE user_id = 'user-0001';
UPDATE guardian_invites AS invites
SET status = CASE WHEN invites.revoked_at IS NULL THEN 'pending' ELSE 'revoked' END,
    message = CASE
        WHEN invites.revoked_at IS NULL THEN '보호자 연결을 다시 진행해 주세요.'
        ELSE invites.message
    END,
    accepted_at = NULL,
    last_viewed_at = NULL,
    guardian_token_hash = NULL,
    session_created_at = NULL,
    session_last_used_at = NULL
WHERE invites.invite_id IN (
    SELECT links.invite_id
    FROM guardian_ward_links AS links
    JOIN guardian_accounts AS accounts ON accounts.guardian_id = links.guardian_id
    WHERE accounts.provider = 'test'
);
DELETE FROM guardian_ward_links
WHERE guardian_id IN (SELECT guardian_id FROM guardian_accounts WHERE provider = 'test');
DELETE FROM guardian_accounts WHERE provider = 'test';
DELETE FROM users
WHERE user_id = 'user-0001' OR email = 'tester@homeguardian.local';
UPDATE guardian_ward_links
SET status = 'revoked'
WHERE revoked_at IS NOT NULL AND status <> 'revoked';

-- Accepted state is trusted only while the matching link, Google guardian,
-- resident owner and home all still exist. Preserve the invitation itself so
-- the resident can reconnect deliberately after legacy cleanup.
UPDATE guardian_invites AS invites
SET status = CASE WHEN invites.revoked_at IS NULL THEN 'pending' ELSE 'revoked' END,
    message = CASE
        WHEN invites.revoked_at IS NULL THEN '보호자 연결을 다시 진행해 주세요.'
        ELSE invites.message
    END,
    accepted_at = NULL,
    last_viewed_at = NULL,
    guardian_token_hash = NULL,
    session_created_at = NULL,
    session_last_used_at = NULL
WHERE (invites.accepted_at IS NOT NULL OR LOWER(COALESCE(invites.status, '')) = 'accepted')
  AND NOT EXISTS (
        SELECT 1
        FROM guardian_ward_links AS links
        JOIN guardian_accounts AS accounts ON accounts.guardian_id = links.guardian_id
        JOIN homes ON homes.home_id = links.home_id
        JOIN users ON users.home_id = links.home_id
        WHERE links.invite_id = invites.invite_id
          AND links.home_id = invites.home_id
          AND links.status = 'active'
          AND links.revoked_at IS NULL
          AND LOWER(BTRIM(accounts.provider)) = 'google'
          AND BTRIM(COALESCE(accounts.email, '')) <> ''
          AND BTRIM(COALESCE(accounts.display_name, '')) <> ''
          AND users.role = 'user'
          AND BTRIM(COALESCE(users.email, '')) <> ''
          AND BTRIM(COALESCE(users.nickname, '')) <> ''
   );

DELETE FROM guardian_ward_links AS links
WHERE links.home_id IS NULL OR BTRIM(links.home_id) = ''
   OR NOT EXISTS (
        SELECT 1 FROM homes
        JOIN users ON users.home_id = homes.home_id
        WHERE homes.home_id = links.home_id
          AND users.role = 'user'
          AND BTRIM(COALESCE(users.email, '')) <> ''
          AND BTRIM(COALESCE(users.nickname, '')) <> ''
   )
   OR NOT EXISTS (
        SELECT 1 FROM guardian_invites AS invites
        WHERE invites.invite_id = links.invite_id
          AND invites.home_id = links.home_id
   )
   OR NOT EXISTS (
        SELECT 1 FROM guardian_accounts AS accounts
        WHERE accounts.guardian_id = links.guardian_id
          AND LOWER(BTRIM(accounts.provider)) = 'google'
          AND BTRIM(COALESCE(accounts.email, '')) <> ''
          AND BTRIM(COALESCE(accounts.display_name, '')) <> ''
   );
DELETE FROM guardian_invites AS invites
WHERE invites.home_id IS NULL OR BTRIM(invites.home_id) = ''
   OR NOT EXISTS (
        SELECT 1 FROM homes
        JOIN users ON users.home_id = homes.home_id
        WHERE homes.home_id = invites.home_id
          AND users.role = 'user'
          AND BTRIM(COALESCE(users.email, '')) <> ''
          AND BTRIM(COALESCE(users.nickname, '')) <> ''
   );


-- v1.0.0 role-handoff migration for databases created before auth_sessions
-- gained staged successor support. Existing sessions stay active by default.
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS activation_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS handoff_predecessor_session_id TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS handoff_predecessor_refresh_token_hash TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS handoff_id_hash TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS handoff_expires_at TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS handoff_completed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_scan_devices_scan_id ON scan_devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_device_identity_history_device ON device_identity_history(home_id, device_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_identity_history_physical_scope
    ON device_identity_history(home_id, network_scope_id, physical_mac, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home
    ON identity_enrichment_jobs(home_id);
CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_status_updated
    ON identity_enrichment_jobs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home_status_seen
    ON identity_enrichment_jobs(home_id, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_verified_product_catalog_model
    ON verified_product_catalog(model_key);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_previous_refresh ON auth_sessions(previous_refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_handoff_predecessor ON auth_sessions(handoff_predecessor_session_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_active_previous_refresh
    ON auth_sessions(previous_refresh_token_hash)
    WHERE previous_refresh_token_hash IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_devices_home_source ON devices(home_id, scan_source);
CREATE INDEX IF NOT EXISTS idx_devices_scan_source ON devices(scan_source);
CREATE INDEX IF NOT EXISTS idx_scans_home_created_at ON scans(home_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_home_scope_created_at ON scans(home_id, network_scope_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_home_id_desc ON notifications(home_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_id_desc ON notifications(id DESC);
CREATE INDEX IF NOT EXISTS idx_guardian_invites_home ON guardian_invites(home_id);
CREATE INDEX IF NOT EXISTS idx_guardian_accounts_email ON guardian_accounts(email);
CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_guardian ON guardian_ward_links(guardian_id);
CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_invite ON guardian_ward_links(invite_id);
CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_status ON guardian_ward_links(status);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_aliases_home ON device_aliases(home_id);
