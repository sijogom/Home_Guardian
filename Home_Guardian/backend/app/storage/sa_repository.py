"""SQLAlchemy 2.0 기반 듀얼 백엔드 repository.

SQLite/PostgreSQL 양쪽에서 동일하게 동작하며, ``DATABASE_URL`` 환경변수가 설정된
경우에만 활성화된다. 메서드 시그니처는 ``SQLiteRepository`` 와 1:1 동일.

PostgreSQL 모드:
- ``DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname``
- ``psql $DATABASE_URL -f postgres_schema.sql`` 로 스키마 사전 적용 필요
- 사용자/홈은 검증된 로그인 직후에만 생성된다.

SQLite (DATABASE_URL=sqlite+pysqlite:///path) 도 동일하게 동작 (테스트용).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from copy import deepcopy
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Sequence
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    and_,
    case,
    create_engine,
    delete,
    desc,
    event,
    func,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine, Row

_ML_PATH = Path(__file__).resolve().parents[3] / "ml"
if str(_ML_PATH) not in sys.path:
    sys.path.append(str(_ML_PATH))

from home_guardian_ml.hybrid_scoring import score_device_hybrid as score_device
from home_guardian_ml.scoring import _is_phantom_signal

from .constants import HOME, default_home_id_for_user
from .scoring_helpers import (
    build_public_identity_findings,
    confirmed_public_red_count,
    public_score_status,
    scan_completed_message,
    score_device_with_current_cve,
    scoring_with_cve,
    summarize_public_security,
    visible_identity_findings,
)
from .network_scope import (
    derive_network_scope_id,
    derive_strong_network_scope_ids,
    is_strong_network_scope_id,
    normalized_physical_mac,
)
from .scan_state import (
    IDENTITY_PENDING_STEP,
    PARTIAL_SCAN_NOTIFICATION,
    PARTIAL_SCAN_STEP,
    annotate_identity_incomplete_security,
    project_partial_security,
)
from ..scan_validation import (
    actual_android_scan_rejection_reasons,
    enforce_declared_subnet_boundary,
    scan_is_partial,
    strip_untrusted_self_claims,
)
from ..services.device_presentation import (
    apply_device_presentation,
    bind_trusted_manual_identity,
    build_identity_finding,
    is_self_observation,
    is_safe_device_alias,
    legacy_device_id_ip_address,
    normalize_stored_network_context,
    normalized_storage_fields,
    public_device_id,
    sanitize_public_notification,
    sanitize_public_network_context,
)
from ..services.identity_enrichment import (
    IDENTITY_ENRICHMENT_REJECT_REASONS,
    IDENTITY_ENRICHMENT_RESOLVER_VERSION,
    IDENTITY_RESOLUTION_PROVENANCES,
    IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
    IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
    IdentityEnrichmentError,
    authenticated_self_android_binding,
    bind_authenticated_self_android_claim,
    blocked_binding_reason,
    build_evidence_signature,
    build_identity_job_key,
    build_resolution_signature,
    build_verified_product_catalog_entry,
    evidence_signature_matches,
    identity_job_key_matches,
    is_automated_identity_resolution_provenance,
    resolution_history_evidence,
    source_matches_registered_official_domain,
    stable_identity_evidence_signature,
    strip_untrusted_authenticated_self_android,
    structured_identity_evidence,
    trusted_identity_resolution,
    validate_identity_resolution,
    verified_product_catalog_entry_matches,
)
from ..services.device_identity import (
    bind_verified_appliance_family_history,
    bind_verified_catalog_history,
)
from .identity_history import (
    exact_spotify_mdns_mac_token,
    verified_authenticated_self_android_history_identity,
    verified_family_hub_advertised_token_identity,
    verified_family_hub_snapshot_identity,
)
from .guardian_invites import (
    build_deep_link,
    clean_optional_name,
    default_display_name,
    effective_invite_status,
    generate_short_code,
    guardian_invite_summary,
    hash_guardian_session_token,
    invite_expires_at,
    is_generic_ward_display_name,
    normalize_guardian_invite,
    normalize_invite_lookup,
    parse_utc_text,
)

metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("user_id", Text, primary_key=True),
    Column("email", Text, nullable=False, unique=True),
    Column("nickname", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("email_verified", Integer, nullable=False),
    Column("home_id", Text, nullable=False),
)

homes_table = Table(
    "homes",
    metadata,
    Column("home_id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("mode", Text, nullable=False),
)

devices_table = Table(
    "devices",
    metadata,
    Column("device_id", Text, primary_key=True),
    Column("home_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("device_type", Text, nullable=False),
    Column("manufacturer", Text, nullable=False),
    Column("model", Text, nullable=False),
    Column("ip_address", Text, nullable=False),
    Column("mac_address", Text, nullable=False),
    Column("online", Integer, nullable=False),
    Column("last_seen", Text, nullable=False),
    Column("open_ports_json", Text, nullable=False),
    Column("services_json", Text, nullable=False, server_default="[]"),
    Column("default_credentials", Integer, nullable=False),
    Column("encryption", Text, nullable=False),
    Column("firmware", Text, nullable=False),
    Column("vulnerabilities_json", Text, nullable=False),
    Column("discovery_sources_json", Text, nullable=False, server_default="[]"),
    Column("fingerprints_json", Text, nullable=False, server_default="[]"),
    Column("risk_signals_json", Text, nullable=False, server_default="[]"),
    Column("scan_source", Text, nullable=False),
    Column("confidence", Float, nullable=False, server_default="0.85"),
    Column("is_unresolved", Integer, nullable=False, server_default="0"),
    Column("is_phantom", Integer, nullable=False, server_default="0"),
    Column("security_score", Integer, nullable=False),
    Column("risk_level", Text, nullable=False),
    Column("risk_summary", Text, nullable=False),
    Column("recommended_actions_json", Text, nullable=False),
    Column("risk_rank", Integer, nullable=False),
    Index("idx_devices_scan_source", "scan_source"),
)

security_events_table = Table(
    "security_events",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("home_id", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("description", Text, nullable=False),
    Column("device_id", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("action_guide", Text, nullable=False),
)

scans_table = Table(
    "scans",
    metadata,
    Column("scan_id", Text, primary_key=True),
    Column("home_id", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("progress", Integer, nullable=False),
    Column("scan_profile", Text, nullable=False),
    Column("scan_source", Text, nullable=False),
    Column("network_context_json", Text, nullable=False, server_default="{}"),
    Column("network_scope_id", Text),
    Column("current_step", Text, nullable=False),
    Column("devices_found", Integer, nullable=False),
    Column("high_risk_devices", Integer, nullable=False),
    Column("security_score_json", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("idx_scans_created_at", "created_at"),
    Index("idx_scans_home_scope_created_at", "home_id", "network_scope_id", "created_at"),
)

_STABLE_EVIDENCE_BINDING_SIGNATURE = re.compile(r"^hges1-[0-9a-f]{64}$")


_AUTHORITATIVE_SCAN_SOURCE = "android-native"


def _project_security_events(
    home_id: str,
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project resident alerts only from validated Android observations."""

    events: list[dict[str, Any]] = []
    for observation in observations:
        severity = str(observation.get("risk_level") or "").lower()
        if severity not in {"red", "yellow"}:
            continue
        device_id = str(observation.get("device_id") or "")
        unresolved = bool(observation.get("is_unresolved")) or str(
            observation.get("identity_status") or ""
        ).casefold() in {"enriching", "unresolved"}
        if unresolved:
            title = (
                "점검 중 확인된 보안 위험"
                if severity == "red"
                else "점검 중 확인된 보안 주의"
            )
            description = (
                "점검 중 즉시 확인이 필요한 보안 위험을 발견했어요."
                if severity == "red"
                else "점검 중 보안 설정 확인이 필요한 신호를 발견했어요."
            )
            action_guide = "위험 안내를 확인하고 필요하면 해당 연결을 제한해 주세요."
        else:
            display_name = str(
                observation.get("canonical_name")
                or observation.get("name")
                or observation.get("display_name")
                or "기기"
            )
            title = f"{display_name} 보안 안내"
            description = (
                "확인된 연결에 즉시 점검이 필요한 보안 위험이 있어요."
                if severity == "red"
                else "확인된 기기의 보안 설정과 업데이트를 확인해 주세요."
            )
            action_guide = "기기 제조사 앱과 펌웨어를 확인하고, 필요하면 네트워크에서 분리해 주세요."
        event = sanitize_public_notification(
            {
                "event_id": "event-"
                + hashlib.sha256(f"{home_id}:{device_id}:{severity}".encode("utf-8")).hexdigest()[:24],
                "severity": severity,
                "title": title,
                "description": description,
                "message": description,
                "device_id": device_id,
                "created_at": str(observation.get("last_seen") or observation.get("first_seen") or ""),
                "action_guide": action_guide,
            }
        )
        event["description"] = event.pop("message")
        events.append(event)
    return events


def _validated_authoritative_snapshot(
    network_context: dict[str, Any] | None,
    devices: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Revalidate a stored Android snapshot before it becomes current state."""

    from .sqlite_repository import _is_unverified_presence_only_observation

    context = normalize_stored_network_context(network_context)
    if actual_android_scan_rejection_reasons(context, devices):
        return None
    bounded = enforce_declared_subnet_boundary(context, devices)
    current_devices: list[dict[str, Any]] = []
    for raw_device in bounded.devices:
        device = dict(raw_device)
        if _is_unverified_presence_only_observation(device):
            device["is_phantom"] = True
        current_devices.append(device)
    return bounded.network_context, current_devices
scan_devices_table = Table(
    "scan_devices",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Text, nullable=False),
    Column("device_snapshot_json", Text, nullable=False),
    Index("idx_scan_devices_scan_id", "scan_id"),
)

guardian_invites_table = Table(
    "guardian_invites",
    metadata,
    Column("invite_id", Text, primary_key=True),
    Column("home_id", Text, nullable=False),
    Column("email", Text, nullable=False),
    Column("relation", Text, nullable=False),
    Column("display_name", Text),
    Column("ward_account_name", Text),
    Column("short_code", Text, unique=True),
    Column("deep_link", Text),
    Column("status", Text, nullable=False),
    Column("message", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text),
    Column("accepted_at", Text),
    Column("revoked_at", Text),
    Column("last_viewed_at", Text),
    Column("guardian_token_hash", Text, unique=True),
    Column("session_created_at", Text),
    Column("session_last_used_at", Text),
)

guardian_accounts_table = Table(
    "guardian_accounts",
    metadata,
    Column("guardian_id", Text, primary_key=True),
    Column("email", Text, nullable=False, index=True),
    Column("display_name", Text),
    Column("provider", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("last_login_at", Text, nullable=False),
)

guardian_ward_links_table = Table(
    "guardian_ward_links",
    metadata,
    Column("link_id", Text, primary_key=True),
    Column("guardian_id", Text, nullable=False, index=True),
    Column("invite_id", Text, nullable=False, unique=True, index=True),
    Column("home_id", Text, nullable=False),
    Column("ward_account_name", Text),
    Column("ward_alias", Text),
    Column("ward_display_name", Text, nullable=False),
    Column("status", Text, nullable=False, index=True),
    Column("accepted_at", Text, nullable=False),
    Column("revoked_at", Text),
    Column("last_viewed_at", Text),
)

notifications_table = Table(
    "notifications",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("notification_id", Text, nullable=False, unique=True),
    Column("home_id", Text, nullable=False),
    Column("type", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("message", Text, nullable=False),
    Column("scan_id", Text),
    Column("scan_source", Text),
    Column("read", Integer, nullable=False),
    Column("created_at", Text, nullable=False),
)

fcm_tokens_table = Table(
    "fcm_tokens",
    metadata,
    Column("fcm_token", Text, primary_key=True),
    Column("platform", Text, nullable=False),
    Column("user_id", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

device_identity_history_table = Table(
    "device_identity_history",
    metadata,
    Column("resolution_id", Text, primary_key=True),
    Column("home_id", Text, nullable=False),
    Column("device_id", Text, nullable=False),
    Column("network_scope_id", Text),
    Column("physical_mac", Text),
    Column("observed_at", Text, nullable=False),
    Column("identity_status", Text, nullable=False),
    Column("manufacturer", Text, nullable=False),
    Column("device_type", Text, nullable=False),
    Column("model", Text, nullable=False),
    Column("canonical_name", Text, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("evidence_json", Text, nullable=False),
    Column("candidates_json", Text, nullable=False),
    Column("note", Text, nullable=False),
    Column("resolver_version", Text, nullable=False),
    Index("idx_device_identity_history_device", "home_id", "device_id", "observed_at"),
)

identity_enrichment_jobs_table = Table(
    "identity_enrichment_jobs",
    metadata,
    Column("job_id", Text, primary_key=True),
    Column("job_key", Text, nullable=False, unique=True),
    Column("home_id", Text, ForeignKey("homes.home_id", ondelete="CASCADE"), nullable=False),
    Column("device_id", Text, nullable=False),
    Column("network_scope_id", Text),
    Column("physical_mac", Text),
    Column("evidence_binding_signature", Text),
    Column("status", Text, nullable=False),
    Column("blocked_reason", Text),
    Column("evidence_json", Text, nullable=False),
    Column("evidence_signature", Text, nullable=False),
    Column("seen_count", Integer, nullable=False),
    Column("first_seen_at", Text, nullable=False),
    Column("last_seen_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
    Column("resolution_json", Text),
    Column("source_reference", Text),
    Column("resolution_provenance", Text),
    Column("resolution_signature", Text),
    Column("research_attempt_count", Integer, nullable=False, default=0),
    Column("research_last_attempt_at", Text),
    Column("research_next_attempt_at", Text),
    Column("research_policy_version", Text),
    Column("catalog_reconcile_version", Text),
    Column("resolved_at", Text),
    CheckConstraint(
        "status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')",
        name="ck_identity_enrichment_jobs_status",
    ),
    CheckConstraint("seen_count >= 1", name="ck_identity_enrichment_jobs_seen_count"),
    CheckConstraint(
        "resolution_provenance IS NULL OR resolution_provenance IN "
        "('operator-reviewed', 'automated-official-web-search', 'automated-official-http')",
        name="ck_identity_enrichment_jobs_provenance",
    ),
    CheckConstraint(
        "status <> 'resolved' OR (network_scope_id IS NOT NULL "
        "AND (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) "
        "AND resolution_json IS NOT NULL AND source_reference IS NOT NULL AND resolved_at IS NOT NULL)",
        name="ck_identity_enrichment_jobs_resolved_binding",
    ),
    Index("idx_identity_enrichment_jobs_home", "home_id"),
    Index("idx_identity_enrichment_jobs_status_updated", "status", "updated_at"),
    Index("idx_identity_enrichment_jobs_home_status_seen", "home_id", "status", "last_seen_at"),
)

verified_product_catalog_table = Table(
    "verified_product_catalog",
    metadata,
    Column("manufacturer", Text, nullable=False),
    Column("manufacturer_key", Text, nullable=False),
    Column("exact_model", Text, nullable=False),
    Column("model_key", Text, nullable=False),
    Column("device_type", Text, nullable=False),
    Column("source_url", Text, nullable=False),
    Column("provenance", Text, nullable=False),
    Column("verified_at", Text, nullable=False),
    Column("catalog_signature", Text, nullable=False),
    CheckConstraint(
        "provenance IN "
        "('operator-reviewed', 'automated-official-web-search', 'automated-official-http')",
        name="ck_verified_product_catalog_provenance",
    ),
    UniqueConstraint(
        "manufacturer_key",
        "model_key",
        name="uq_verified_product_catalog_product",
    ),
    Index("idx_verified_product_catalog_model", "model_key"),
)

auth_sessions_table = Table(
    "auth_sessions",
    metadata,
    Column("session_id", Text, primary_key=True),
    Column("user_id", Text, nullable=False, index=True),
    Column("home_id", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("refresh_token_hash", Text, nullable=False, unique=True),
    Column("previous_refresh_token_hash", Text, index=True),
    Column("refresh_retry_id", Text),
    Column("refresh_retry_until", Text),
    Column("activation_state", Text, nullable=False, server_default=text("'active'")),
    Column("handoff_predecessor_session_id", Text, index=True),
    Column("handoff_predecessor_refresh_token_hash", Text),
    Column("handoff_id_hash", Text),
    Column("handoff_expires_at", Text),
    Column("handoff_completed_at", Text),
    Column("created_at", Text, nullable=False),
    Column("last_used_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False, index=True),
    Column("revoked_at", Text),
)

device_aliases_table = Table(
    "device_aliases",
    metadata,
    Column("home_id", Text, primary_key=True),
    Column("device_id", Text, primary_key=True),
    Column("network_scope_id", Text),
    Column("physical_mac", Text),
    Column("alias", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _ambiguous_physical_macs(devices: Sequence[Mapping[str, Any]]) -> set[str]:
    # Keep the dual repositories on one exact ambiguity contract without
    # importing sqlite_repository during module initialization.
    from .sqlite_repository import _ambiguous_physical_macs as classify

    return classify(devices)


def _prepare_identity_enrichment_jobs(
    devices: Sequence[Mapping[str, Any]],
    *,
    home_id: str,
    network_scope_id: str | None,
    ambiguity_devices: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    from .sqlite_repository import _prepare_identity_enrichment_jobs as prepare

    return prepare(
        devices,
        home_id=home_id,
        network_scope_id=network_scope_id,
        ambiguity_devices=ambiguity_devices,
    )


def _hold_identity_incomplete_security(
    summary: dict[str, Any],
    identity_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compatibility wrapper for the identity-pending score annotation."""

    return annotate_identity_incomplete_security(summary, identity_findings)


def row_to_dict(row: Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row._mapping)


class SqlAlchemyRepository:
    """SQLAlchemy 2.0 기반 SQLite/PostgreSQL 듀얼 repository."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.engine: Engine = create_engine(database_url, future=True, pool_pre_ping=True)
        self.dialect = self.engine.dialect.name  # 'sqlite' or 'postgresql'
        if self.dialect == "sqlite":
            @event.listens_for(self.engine, "connect")
            def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                finally:
                    cursor.close()
        self._initialize()

    def close(self) -> None:
        """Release pooled database connections when this repository is no longer used."""
        self.engine.dispose()

    def _initialize(self) -> None:
        metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            self._migrate_schema(conn)
            self._backfill_guardian_names(conn)

    def _migrate_schema(self, conn) -> None:
        self._ensure_column(conn, "devices", "scan_source", "TEXT")
        self._ensure_column(conn, "scans", "scan_source", "TEXT")
        self._ensure_column(conn, "security_events", "home_id", "TEXT")
        self._ensure_column(conn, "guardian_invites", "home_id", "TEXT")
        self._ensure_column(conn, "guardian_invites", "ward_account_name", "TEXT")
        self._ensure_column(conn, "guardian_ward_links", "ward_account_name", "TEXT")
        self._ensure_column(conn, "guardian_ward_links", "ward_alias", "TEXT")
        self._ensure_column(conn, "notifications", "home_id", "TEXT")
        self._ensure_column(conn, "notifications", "scan_id", "TEXT")
        self._ensure_column(conn, "notifications", "scan_source", "TEXT")
        self._ensure_column(conn, "devices", "is_unresolved", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "devices", "is_phantom", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "device_identity_history", "network_scope_id", "TEXT")
        self._ensure_column(conn, "device_identity_history", "physical_mac", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "resolution_provenance", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "resolution_signature", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "evidence_binding_signature", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_attempt_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_last_attempt_at", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_next_attempt_at", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_policy_version", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "catalog_reconcile_version", "TEXT")
        # Quarantine legacy resolved rows before either SQLite table-copy or
        # PostgreSQL CHECK replacement.  Otherwise one old row without a
        # current strong binding can abort the whole deployment migration.
        self._quarantine_unsigned_legacy_resolutions(conn)
        self._quarantine_invalid_legacy_resolutions(conn)
        if self.dialect == "sqlite":
            self._migrate_sqlite_identity_enrichment_status_constraint(conn)
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home "
                "ON identity_enrichment_jobs(home_id)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_status_updated "
                "ON identity_enrichment_jobs(status, updated_at)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home_status_seen "
                "ON identity_enrichment_jobs(home_id, status, last_seen_at)"
            )
        )
        self._ensure_column(conn, "scans", "network_scope_id", "TEXT")
        self._ensure_column(conn, "auth_sessions", "previous_refresh_token_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "refresh_retry_id", "TEXT")
        self._ensure_column(conn, "auth_sessions", "refresh_retry_until", "TEXT")
        self._ensure_column(conn, "auth_sessions", "activation_state", "TEXT NOT NULL DEFAULT 'active'")
        self._ensure_column(conn, "auth_sessions", "handoff_predecessor_session_id", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_predecessor_refresh_token_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_id_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_expires_at", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_completed_at", "TEXT")
        self._ensure_column(conn, "device_aliases", "network_scope_id", "TEXT")
        self._ensure_column(conn, "device_aliases", "physical_mac", "TEXT")
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_sessions_previous_refresh ON auth_sessions(previous_refresh_token_hash)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_sessions_handoff_predecessor ON auth_sessions(handoff_predecessor_session_id)"))
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_scans_home_scope_created_at "
                "ON scans(home_id, network_scope_id, created_at)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_device_identity_history_physical_scope "
                "ON device_identity_history(home_id, network_scope_id, physical_mac, observed_at)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_auth_sessions_active_previous_refresh "
                "ON auth_sessions(previous_refresh_token_hash) "
                "WHERE previous_refresh_token_hash IS NOT NULL AND revoked_at IS NULL"
            )
        )
        if self.dialect == "postgresql":
            binding_constraints = conn.execute(
                text(
                    """
                    SELECT conname
                    FROM pg_constraint
                    WHERE conrelid = 'identity_enrichment_jobs'::regclass
                      AND contype = 'c'
                      AND pg_get_constraintdef(oid) LIKE '%status%resolved%network_scope_id%'
                    """
                )
            ).scalars().all()
            for constraint_name in binding_constraints:
                safe_name = str(constraint_name).replace('"', '""')
                conn.execute(
                    text(
                        f'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT "{safe_name}"'
                    )
                )
            conn.execute(
                text(
                    "ALTER TABLE identity_enrichment_jobs "
                    "ADD CONSTRAINT ck_identity_enrichment_jobs_resolved_binding CHECK "
                    "(status <> 'resolved' OR (network_scope_id IS NOT NULL AND "
                    "(physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND "
                    "resolution_json IS NOT NULL AND source_reference IS NOT NULL AND "
                    "resolved_at IS NOT NULL))"
                )
            )
            status_constraints = conn.execute(
                text(
                    """
                    SELECT conname
                    FROM pg_constraint
                    WHERE conrelid = 'identity_enrichment_jobs'::regclass
                      AND contype = 'c'
                      AND pg_get_constraintdef(oid) LIKE '%status%review_required%'
                    """
                )
            ).scalars().all()
            for constraint_name in status_constraints:
                safe_name = str(constraint_name).replace('"', '""')
                conn.execute(
                    text(
                        f'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT "{safe_name}"'
                    )
                )
            conn.execute(
                text(
                    "ALTER TABLE identity_enrichment_jobs "
                    "ADD CONSTRAINT ck_identity_enrichment_jobs_status CHECK "
                    "(status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded'))"
                )
            )
            provenance_constraints = conn.execute(
                text(
                    """
                    SELECT conname
                    FROM pg_constraint
                    WHERE conrelid = 'identity_enrichment_jobs'::regclass
                      AND contype = 'c'
                      AND pg_get_constraintdef(oid) LIKE '%resolution_provenance%'
                    """
                )
            ).scalars().all()
            for constraint_name in provenance_constraints:
                safe_name = str(constraint_name).replace('"', '""')
                conn.execute(
                    text(
                        f'ALTER TABLE identity_enrichment_jobs DROP CONSTRAINT "{safe_name}"'
                    )
                )
            conn.execute(
                text(
                    "ALTER TABLE identity_enrichment_jobs "
                    "ADD CONSTRAINT ck_identity_enrichment_jobs_provenance CHECK "
                    "(resolution_provenance IS NULL OR resolution_provenance IN "
                    "('operator-reviewed', 'automated-official-web-search', "
                    "'automated-official-http'))"
                )
            )
            for table_name, column_name in (
                ("devices", "scan_source"),
                ("scans", "scan_source"),
                ("security_events", "home_id"),
                ("guardian_invites", "home_id"),
                ("notifications", "home_id"),
            ):
                conn.execute(
                    text(
                        f'ALTER TABLE "{table_name}" ALTER COLUMN "{column_name}" DROP DEFAULT'
                    )
                )
        self._purge_legacy_synthetic_state(conn)
        self._normalize_legacy_public_device_data(conn)
        self._backfill_network_scope_ids(conn)
        self._supersede_stale_identity_jobs_from_latest_scans(conn)
        self._backfill_verified_product_catalog(conn)

    @staticmethod
    def _quarantine_unsigned_legacy_resolutions(conn) -> None:
        """Never manufacture provenance for a resolution created before signing."""

        conn.execute(
            update(identity_enrichment_jobs_table)
            .where(
                identity_enrichment_jobs_table.c.status == "resolved",
                or_(
                    identity_enrichment_jobs_table.c.resolution_signature.is_(None),
                    identity_enrichment_jobs_table.c.resolution_signature == "",
                ),
            )
            .values(
                status="review_required",
                blocked_reason="UNSIGNED_LEGACY_RESOLUTION_REVIEW_REQUIRED",
                resolution_json=None,
                source_reference=None,
                resolution_provenance=None,
                resolution_signature=None,
                research_attempt_count=0,
                research_last_attempt_at=None,
                research_next_attempt_at=None,
                resolved_at=None,
                updated_at=utc_now(),
            )
        )

    @staticmethod
    def _quarantine_invalid_legacy_resolutions(conn) -> None:
        """Downgrade signed legacy resolutions lacking a current safe binding."""

        rows = conn.execute(
            select(
                identity_enrichment_jobs_table.c.job_id,
                identity_enrichment_jobs_table.c.network_scope_id,
                identity_enrichment_jobs_table.c.physical_mac,
                identity_enrichment_jobs_table.c.evidence_binding_signature,
                identity_enrichment_jobs_table.c.resolution_json,
                identity_enrichment_jobs_table.c.source_reference,
                identity_enrichment_jobs_table.c.resolution_provenance,
                identity_enrichment_jobs_table.c.resolved_at,
            ).where(identity_enrichment_jobs_table.c.status == "resolved")
        ).mappings().all()
        invalid_job_ids: list[str] = []
        for row in rows:
            scope_is_strong = is_strong_network_scope_id(row["network_scope_id"])
            physical_mac = normalized_physical_mac(row["physical_mac"])
            evidence_binding = str(row["evidence_binding_signature"] or "").strip()
            binding_is_valid = physical_mac is not None or bool(
                _STABLE_EVIDENCE_BINDING_SIGNATURE.fullmatch(evidence_binding)
            )
            resolution_is_complete = all(
                str(row[column] or "").strip()
                for column in ("resolution_json", "source_reference", "resolved_at")
            )
            provenance_is_valid = row["resolution_provenance"] in IDENTITY_RESOLUTION_PROVENANCES
            if not (
                scope_is_strong
                and binding_is_valid
                and resolution_is_complete
                and provenance_is_valid
            ):
                invalid_job_ids.append(str(row["job_id"]))

        if not invalid_job_ids:
            return
        conn.execute(
            update(identity_enrichment_jobs_table)
            .where(
                identity_enrichment_jobs_table.c.job_id.in_(invalid_job_ids),
                identity_enrichment_jobs_table.c.status == "resolved",
            )
            .values(
                status="review_required",
                blocked_reason="INVALID_LEGACY_RESOLUTION_REVIEW_REQUIRED",
                resolution_json=None,
                source_reference=None,
                resolution_provenance=None,
                resolution_signature=None,
                research_attempt_count=0,
                research_last_attempt_at=None,
                research_next_attempt_at=None,
                resolved_at=None,
                updated_at=utc_now(),
            )
        )

    def _backfill_verified_product_catalog(self, conn) -> None:
        """Promote only signed job/history pairs; never infer legacy facts."""

        rows = conn.execute(
            select(identity_enrichment_jobs_table)
            .where(identity_enrichment_jobs_table.c.status == "resolved")
            .order_by(
                identity_enrichment_jobs_table.c.resolved_at,
                identity_enrichment_jobs_table.c.job_id,
            )
        ).all()
        for row in rows:
            job = self._identity_enrichment_job_from_row(row)
            resolution = (job or {}).get("resolution")
            if not isinstance(job, Mapping) or not isinstance(resolution, Mapping):
                continue
            resolution_id = str(resolution.get("history_resolution_id") or "")
            if not resolution_id:
                continue
            history_row = conn.execute(
                select(device_identity_history_table).where(
                    device_identity_history_table.c.resolution_id == resolution_id
                )
            ).first()
            history = row_to_dict(history_row)
            if history is None:
                continue
            try:
                identity_evidence = json.loads(history.get("evidence_json") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            history["identity_evidence"] = (
                identity_evidence if isinstance(identity_evidence, list) else []
            )
            trusted = trusted_identity_resolution(history, job)
            if trusted is None:
                continue
            try:
                validated = validate_identity_resolution(
                    manufacturer=trusted["manufacturer"],
                    device_type=trusted["device_type"],
                    model=trusted["model"],
                    source_reference=job.get("source_reference"),
                )
                self._register_verified_product_catalog(
                    conn,
                    validated=validated,
                    provenance=str(job.get("resolution_provenance") or ""),
                    verified_at=str(job.get("resolved_at") or ""),
                )
            except IdentityEnrichmentError:
                continue

    def _purge_legacy_synthetic_state(self, conn) -> None:
        """Delete exact legacy fixture principals without touching real evidence.

        Historic scan/device rows stay private but intact. Older schema
        migrations applied source defaults to rows that predated those columns,
        so the source value by itself cannot prove that an observation is fake.
        """

        legacy_user_id = "user-0001"
        legacy_user_email = "tester@homeguardian.local"

        synthetic_guardian_ids = [
            str(row[0])
            for row in conn.execute(
                select(guardian_accounts_table.c.guardian_id).where(
                    guardian_accounts_table.c.provider == "test"
                )
            ).all()
        ]
        if synthetic_guardian_ids:
            synthetic_invite_ids = [
                str(row[0])
                for row in conn.execute(
                    select(guardian_ward_links_table.c.invite_id).where(
                        guardian_ward_links_table.c.guardian_id.in_(synthetic_guardian_ids)
                    )
                ).all()
            ]
            if synthetic_invite_ids:
                conn.execute(
                    update(guardian_invites_table)
                    .where(guardian_invites_table.c.invite_id.in_(synthetic_invite_ids))
                    .values(
                        status=case(
                            (guardian_invites_table.c.revoked_at.is_(None), "pending"),
                            else_="revoked",
                        ),
                        message=case(
                            (
                                guardian_invites_table.c.revoked_at.is_(None),
                                "보호자 연결을 다시 진행해 주세요.",
                            ),
                            else_=guardian_invites_table.c.message,
                        ),
                        accepted_at=None,
                        last_viewed_at=None,
                        guardian_token_hash=None,
                        session_created_at=None,
                        session_last_used_at=None,
                    )
                )
            conn.execute(
                delete(auth_sessions_table).where(
                    auth_sessions_table.c.user_id.in_(synthetic_guardian_ids)
                )
            )
            conn.execute(
                delete(guardian_ward_links_table).where(
                    guardian_ward_links_table.c.guardian_id.in_(synthetic_guardian_ids)
                )
            )
            conn.execute(
                delete(guardian_accounts_table).where(
                    guardian_accounts_table.c.guardian_id.in_(synthetic_guardian_ids)
                )
            )

        conn.execute(delete(auth_sessions_table).where(auth_sessions_table.c.user_id == legacy_user_id))
        conn.execute(delete(fcm_tokens_table).where(fcm_tokens_table.c.user_id == legacy_user_id))
        conn.execute(
            delete(users_table).where(
                or_(users_table.c.user_id == legacy_user_id, users_table.c.email == legacy_user_email)
            )
        )
        conn.execute(
            update(guardian_ward_links_table)
            .where(
                guardian_ward_links_table.c.revoked_at.is_not(None),
                guardian_ward_links_table.c.status != "revoked",
            )
            .values(status="revoked")
        )

        conn.execute(
            text(
                """
                UPDATE guardian_invites
                SET status = CASE WHEN revoked_at IS NULL THEN 'pending' ELSE 'revoked' END,
                    message = CASE
                        WHEN revoked_at IS NULL THEN '보호자 연결을 다시 진행해 주세요.'
                        ELSE message
                    END,
                    accepted_at = NULL,
                    last_viewed_at = NULL,
                    guardian_token_hash = NULL,
                    session_created_at = NULL,
                    session_last_used_at = NULL
                WHERE (accepted_at IS NOT NULL OR LOWER(COALESCE(status, '')) = 'accepted')
                  AND NOT EXISTS (
                        SELECT 1
                        FROM guardian_ward_links AS links
                        JOIN guardian_accounts AS accounts
                          ON accounts.guardian_id = links.guardian_id
                        JOIN homes ON homes.home_id = links.home_id
                        JOIN users ON users.home_id = links.home_id
                        WHERE links.invite_id = guardian_invites.invite_id
                          AND links.home_id = guardian_invites.home_id
                          AND links.status = 'active'
                          AND links.revoked_at IS NULL
                          AND LOWER(TRIM(accounts.provider)) = 'google'
                          AND TRIM(COALESCE(accounts.email, '')) <> ''
                          AND TRIM(COALESCE(accounts.display_name, '')) <> ''
                          AND users.role = 'user'
                          AND TRIM(COALESCE(users.email, '')) <> ''
                          AND TRIM(COALESCE(users.nickname, '')) <> ''
                   )
                """
            )
        )

        valid_homes = {
            str(row[0])
            for row in conn.execute(
                select(homes_table.c.home_id)
                .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                .where(
                    users_table.c.role == "user",
                    func.trim(func.coalesce(users_table.c.email, "")) != "",
                    func.trim(func.coalesce(users_table.c.nickname, "")) != "",
                )
                .distinct()
            ).all()
        }
        invite_homes = {
            str(row[0]): str(row[1] or "")
            for row in conn.execute(
                select(guardian_invites_table.c.invite_id, guardian_invites_table.c.home_id)
            ).all()
        }
        valid_guardian_ids = {
            str(row[0])
            for row in conn.execute(
                select(guardian_accounts_table.c.guardian_id).where(
                    func.lower(func.trim(guardian_accounts_table.c.provider)) == "google",
                    func.trim(func.coalesce(guardian_accounts_table.c.email, "")) != "",
                    func.trim(func.coalesce(guardian_accounts_table.c.display_name, "")) != "",
                )
            ).all()
        }
        invalid_link_ids = [
            str(row[0])
            for row in conn.execute(
                select(
                    guardian_ward_links_table.c.link_id,
                    guardian_ward_links_table.c.invite_id,
                    guardian_ward_links_table.c.home_id,
                    guardian_ward_links_table.c.guardian_id,
                )
            ).all()
            if not str(row[2] or "").strip()
            or str(row[2]) not in valid_homes
            or invite_homes.get(str(row[1])) != str(row[2])
            or str(row[3]) not in valid_guardian_ids
        ]
        if invalid_link_ids:
            conn.execute(
                delete(guardian_ward_links_table).where(
                    guardian_ward_links_table.c.link_id.in_(invalid_link_ids)
                )
            )
        invalid_invite_ids = [
            invite_id
            for invite_id, home_id in invite_homes.items()
            if not home_id.strip() or home_id not in valid_homes
        ]
        if invalid_invite_ids:
            conn.execute(
                delete(guardian_invites_table).where(
                    guardian_invites_table.c.invite_id.in_(invalid_invite_ids)
                )
            )


    def _normalize_legacy_public_device_data(self, conn) -> None:
        """Rewrite legacy public identity fields while retaining private scan evidence.

        The same routine runs for SQLite and PostgreSQL through SQLAlchemy so a
        historic row cannot reintroduce a banned placeholder via a later fallback
        read, notification or frozen scan result.
        """
        from .sqlite_repository import _is_unverified_presence_only_observation

        for row in conn.execute(select(devices_table)).all():
            device = _device_from_row(row_to_dict(row))
            fields = normalized_storage_fields(device)
            is_phantom = bool(
                device.get("is_phantom", False)
            ) or _is_unverified_presence_only_observation(device)
            conn.execute(
                update(devices_table)
                .where(devices_table.c.device_id == device["device_id"])
                .values(
                    name=fields["name"],
                    manufacturer=fields["manufacturer"],
                    model=fields["model"],
                    device_type=fields["device_type"],
                    is_unresolved=int(bool(fields.get("is_unresolved", False))),
                    is_phantom=int(is_phantom),
                )
            )

        scan_rows = conn.execute(
            select(
                scans_table.c.scan_id,
                scans_table.c.home_id,
                scans_table.c.status,
                scans_table.c.current_step,
                scans_table.c.scan_source,
                scans_table.c.network_context_json,
            )
        ).all()
        for scan_row in scan_rows:
            scan_data = row_to_dict(scan_row) or {}
            scan_id = scan_data.get("scan_id")
            home_id = scan_data.get("home_id")
            snapshots: list[dict[str, Any]] = []
            snapshot_rows = conn.execute(
                select(scan_devices_table.c.id, scan_devices_table.c.device_snapshot_json)
                .where(scan_devices_table.c.scan_id == scan_id)
                .order_by(scan_devices_table.c.id.asc())
            ).all()
            for snapshot_row in snapshot_rows:
                snapshot_id, snapshot_json = snapshot_row
                try:
                    snapshot = json.loads(snapshot_json)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(snapshot, dict):
                    continue
                snapshot.setdefault("home_id", home_id)
                snapshot.update(normalized_storage_fields(snapshot))
                if _is_unverified_presence_only_observation(snapshot):
                    snapshot["is_phantom"] = True
                conn.execute(
                    update(scan_devices_table)
                    .where(scan_devices_table.c.id == snapshot_id)
                    .values(device_snapshot_json=json.dumps(snapshot, ensure_ascii=False))
                )
                snapshots.append(snapshot)

            try:
                raw_scan_context = json.loads(scan_data.get("network_context_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_scan_context = {}
            public_snapshots = snapshots
            public_scan_context = raw_scan_context
            if (
                scan_data.get("scan_source") == _AUTHORITATIVE_SCAN_SOURCE
                and not actual_android_scan_rejection_reasons(raw_scan_context, snapshots)
            ):
                # Keep pre-boundary evidence intact. Public/current projections
                # apply the LAN boundary without treating a legacy label as
                # deletion provenance.
                bounded = enforce_declared_subnet_boundary(raw_scan_context, snapshots)
                public_snapshots = bounded.devices
                public_scan_context = bounded.network_context

            household_snapshots = [
                snapshot for snapshot in public_snapshots if not is_self_observation(snapshot)
            ]
            partial_scan = scan_is_partial(normalize_stored_network_context(public_scan_context))
            public_devices, summary = summarize_public_security(
                household_snapshots,
                coverage_complete=not partial_scan,
            )
            raw_identity_findings = build_public_identity_findings(
                household_snapshots,
                public_devices,
            )
            identity_findings = visible_identity_findings(raw_identity_findings)
            incomplete_scan = partial_scan
            if partial_scan:
                summary = project_partial_security(summary)
            elif identity_findings:
                summary = _hold_identity_incomplete_security(summary, identity_findings)
            real_devices = public_devices
            update_values: dict[str, Any] = {
                "status": "partial" if incomplete_scan else scan_data.get("status"),
                "current_step": (
                    (
                        PARTIAL_SCAN_STEP
                        if partial_scan
                        else IDENTITY_PENDING_STEP
                        if identity_findings
                        else scan_data.get("current_step")
                    )
                ),
                "devices_found": len(real_devices) + len(identity_findings),
                "high_risk_devices": confirmed_public_red_count(real_devices, identity_findings),
                "security_score_json": json.dumps(
                    {
                        "home_id": home_id,
                        "score": summary["score"],
                        "risk_level": summary["risk_level"],
                        "summary": summary["summary"],
                        "device_scores": summary["device_scores"],
                        "score_status": public_score_status(summary, coverage_complete=not partial_scan),
                        "identity_incomplete": bool(identity_findings),
                        "identity_pending_count": len(identity_findings),
                        "scan_complete": not incomplete_scan,
                        "coverage_complete": not partial_scan,
                    },
                    ensure_ascii=False,
                ),
            }
            conn.execute(
                update(scans_table)
                .where(scans_table.c.scan_id == scan_id)
                .values(**update_values)
            )
            completion_copy = sanitize_public_notification(
                {
                    "title": "보안 점검 일부 완료" if partial_scan else "보안 점검 완료",
                    "message": (
                        PARTIAL_SCAN_NOTIFICATION
                        if partial_scan
                        else scan_completed_message(real_devices, identity_findings, summary)
                    ),
                }
            )
            conn.execute(
                update(notifications_table)
                .where(
                    notifications_table.c.home_id == home_id,
                    notifications_table.c.scan_id == scan_id,
                    notifications_table.c.type == "scan_completed",
                )
                .values(
                    title=completion_copy["title"],
                    message=completion_copy["message"],
                )
            )

        for row in conn.execute(select(security_events_table)).all():
            event = row_to_dict(row) or {}
            safe = sanitize_public_notification(
                {
                    "title": event.get("title"),
                    "message": event.get("description"),
                    "action_guide": event.get("action_guide"),
                }
            )
            conn.execute(
                update(security_events_table)
                .where(security_events_table.c.event_id == event.get("event_id"))
                .values(
                    title=safe.get("title") or "보안 안내",
                    description=safe.get("message") or "보안 상태를 다시 확인해 주세요.",
                    action_guide=safe.get("action_guide") or "다음 검사 후 확인된 기기만 알려드릴게요.",
                )
            )

        for row in conn.execute(select(notifications_table)).all():
            notification = row_to_dict(row) or {}
            safe = sanitize_public_notification(
                {"title": notification.get("title"), "message": notification.get("message")}
            )
            conn.execute(
                update(notifications_table)
                .where(notifications_table.c.notification_id == notification.get("notification_id"))
                .values(
                    title=safe.get("title") or "보안 안내",
                    message=safe.get("message") or "보안 상태를 다시 확인해 주세요.",
                )
            )

        # Historical notification rows are audit evidence.  Duplicate cards are
        # collapsed only in the public projection, never by deleting stored rows.

        for row in conn.execute(select(device_aliases_table)).all():
            alias = row_to_dict(row) or {}
            if not is_safe_device_alias(alias.get("alias")):
                conn.execute(
                    delete(device_aliases_table).where(
                        device_aliases_table.c.home_id == alias.get("home_id"),
                        device_aliases_table.c.device_id == alias.get("device_id"),
                    )
                )

    def _supersede_stale_identity_jobs_from_latest_scans(self, conn) -> None:
        """Close stale enrichment work using each home's latest real phone scan."""

        home_rows = conn.execute(
            select(scans_table.c.home_id)
            .where(scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE)
            .distinct()
        ).all()
        updated_at = utc_now()
        for home_row in home_rows:
            home_id = str(home_row[0] or "")
            candidate_rows = conn.execute(
                select(
                    scans_table.c.scan_id,
                    scans_table.c.network_context_json,
                    scans_table.c.network_scope_id,
                    scans_table.c.created_at,
                )
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .order_by(scans_table.c.created_at.desc(), scans_table.c.scan_id.desc())
            ).all()
            network_scope_id: str | None = None
            snapshots: list[dict[str, Any]] = []
            public_snapshots: list[dict[str, Any]] = []
            latest_is_valid = False
            for candidate_row in candidate_rows:
                scan_id, network_context_json, candidate_scope_id, _created_at = candidate_row
                candidate_snapshots: list[dict[str, Any]] = []
                for snapshot_row in conn.execute(
                    select(scan_devices_table.c.device_snapshot_json)
                    .where(scan_devices_table.c.scan_id == scan_id)
                    .order_by(scan_devices_table.c.id.asc())
                ).all():
                    try:
                        snapshot = json.loads(snapshot_row[0] or "{}")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if isinstance(snapshot, dict):
                        snapshot.setdefault("home_id", home_id)
                        candidate_snapshots.append(snapshot)
                try:
                    network_context = json.loads(network_context_json or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    network_context = {}
                validated = _validated_authoritative_snapshot(
                    network_context,
                    candidate_snapshots,
                )
                if validated is None:
                    continue
                network_scope_id = candidate_scope_id
                snapshots = candidate_snapshots
                _bounded_context, public_snapshots = validated
                latest_is_valid = True
                break
            if not latest_is_valid:
                continue
            household_snapshots = [
                snapshot for snapshot in public_snapshots if not is_self_observation(snapshot)
            ]
            public_devices, _summary = summarize_public_security(household_snapshots)
            finding_ids = {
                str(finding.get("device_id") or "")
                for finding in build_public_identity_findings(
                    household_snapshots,
                    public_devices,
                )
            }
            strong_scope = (
                str(network_scope_id)
                if is_strong_network_scope_id(network_scope_id)
                else None
            )
            prepared_jobs = _prepare_identity_enrichment_jobs(
                [
                    snapshot
                    for snapshot in snapshots
                    if public_device_id(snapshot.get("device_id"), home_id) in finding_ids
                ],
                home_id=home_id,
                network_scope_id=strong_scope,
                ambiguity_devices=snapshots,
            )
            active_job_keys = {
                str(prepared["job_key"]) for prepared in prepared_jobs
            }
            for prepared in prepared_jobs:
                device = prepared["device"]
                evidence = prepared["evidence"]
                observed_at = str(device.get("last_seen") or _created_at or updated_at)
                values = {
                    "job_id": f"identity-job-{uuid4()}",
                    "job_key": prepared["job_key"],
                    "home_id": home_id,
                    "device_id": str(device.get("device_id") or ""),
                    "network_scope_id": strong_scope,
                    "physical_mac": prepared["physical_mac"],
                    "evidence_binding_signature": prepared["evidence_binding_signature"],
                    "status": prepared["status"],
                    "blocked_reason": prepared["blocked_reason"],
                    "evidence_json": json.dumps(
                        evidence,
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "evidence_signature": build_evidence_signature(evidence),
                    "seen_count": 1,
                    "first_seen_at": observed_at,
                    "last_seen_at": observed_at,
                    "updated_at": observed_at,
                    "resolution_json": None,
                    "source_reference": None,
                    "resolution_provenance": None,
                    "resolution_signature": None,
                    "research_attempt_count": 0,
                    "research_last_attempt_at": None,
                    "research_next_attempt_at": None,
                    "resolved_at": None,
                }
                base = (
                    pg_insert(identity_enrichment_jobs_table)
                    if self.dialect == "postgresql"
                    else sqlite_insert(identity_enrichment_jobs_table)
                ).values(**values)
                conn.execute(
                    base.on_conflict_do_update(
                        index_elements=["job_key"],
                        set_={
                            "device_id": base.excluded.device_id,
                            "network_scope_id": base.excluded.network_scope_id,
                            "physical_mac": base.excluded.physical_mac,
                            "evidence_binding_signature": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_binding_signature,
                                ),
                                else_=base.excluded.evidence_binding_signature,
                            ),
                            "status": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.status,
                                ),
                                else_=base.excluded.status,
                            ),
                            "blocked_reason": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.blocked_reason,
                                ),
                                else_=base.excluded.blocked_reason,
                            ),
                            "evidence_json": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_json,
                                ),
                                else_=base.excluded.evidence_json,
                            ),
                            "evidence_signature": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_signature,
                                ),
                                else_=base.excluded.evidence_signature,
                            ),
                            "research_attempt_count": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_attempt_count,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    0,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_attempt_count,
                            ),
                            "research_last_attempt_at": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_last_attempt_at,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    None,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_last_attempt_at,
                            ),
                            "research_next_attempt_at": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_next_attempt_at,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    None,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_next_attempt_at,
                            ),
                            # Reopening is not a new observation.
                            "last_seen_at": base.excluded.last_seen_at,
                            "updated_at": base.excluded.updated_at,
                        },
                    )
                )
            statement = update(identity_enrichment_jobs_table).where(
                identity_enrichment_jobs_table.c.home_id == home_id,
                identity_enrichment_jobs_table.c.status.in_(("review_required", "blocked")),
            )
            if active_job_keys:
                statement = statement.where(
                    identity_enrichment_jobs_table.c.job_key.notin_(
                        sorted(active_job_keys)
                    )
                )
            conn.execute(
                statement.values(
                    status="superseded",
                    blocked_reason="NOT_IN_LATEST_SCAN",
                    research_next_attempt_at=None,
                    updated_at=updated_at,
                )
            )

    def _backfill_network_scope_ids(self, conn) -> None:
        """Backfill opaque scan scope ids and erase legacy raw Wi-Fi ids."""

        for row in conn.execute(select(scans_table)).all():
            scan = row_to_dict(row) or {}
            try:
                raw_context = json.loads(scan.get("network_context_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_context = {}
            if not isinstance(raw_context, dict):
                raw_context = {}
            snapshot_rows = conn.execute(
                select(scan_devices_table.c.device_snapshot_json)
                .where(scan_devices_table.c.scan_id == scan.get("scan_id"))
                .order_by(scan_devices_table.c.id.asc())
            ).all()
            snapshots: list[dict[str, Any]] = []
            for snapshot_row in snapshot_rows:
                try:
                    snapshot = json.loads(snapshot_row[0])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(snapshot, dict):
                    snapshots.append(snapshot)
            scope_id = scan.get("network_scope_id")
            if not scope_id and scan.get("scan_source") in {_AUTHORITATIVE_SCAN_SOURCE, "windows-port-probe"}:
                scope_id = derive_network_scope_id(
                    home_id=str(scan.get("home_id") or HOME["home_id"]),
                    network_context=raw_context,
                    discovered_devices=snapshots,
                )
            conn.execute(
                update(scans_table)
                .where(scans_table.c.scan_id == scan.get("scan_id"))
                .values(
                    network_context_json=json.dumps(
                        normalize_stored_network_context(raw_context),
                        ensure_ascii=False,
                    ),
                    network_scope_id=scope_id,
                )
            )

    @staticmethod
    def _migrate_sqlite_identity_enrichment_status_constraint(conn) -> None:
        create_sql = conn.execute(
            text(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' AND name = 'identity_enrichment_jobs'"
            )
        ).scalar_one_or_none()
        if (
            "'superseded'" in str(create_sql or "")
            and "evidence_binding_signature IS NOT NULL" in str(create_sql or "")
            and "'automated-official-http'" in str(create_sql or "")
        ):
            return

        columns = (
            "job_id, job_key, home_id, device_id, network_scope_id, physical_mac, "
            "evidence_binding_signature, status, "
            "blocked_reason, evidence_json, evidence_signature, seen_count, first_seen_at, "
            "last_seen_at, updated_at, resolution_json, source_reference, resolution_provenance, "
            "resolution_signature, research_attempt_count, research_last_attempt_at, "
            "research_next_attempt_at, research_policy_version, catalog_reconcile_version, resolved_at"
        )
        original_count = int(
            conn.execute(text("SELECT COUNT(*) FROM identity_enrichment_jobs")).scalar_one()
        )
        conn.execute(text("DROP TABLE IF EXISTS identity_enrichment_jobs_status_v2"))
        conn.execute(
            text(
                """
                CREATE TABLE identity_enrichment_jobs_status_v2 (
                    job_id TEXT PRIMARY KEY,
                    job_key TEXT NOT NULL UNIQUE,
                    home_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    network_scope_id TEXT,
                    physical_mac TEXT,
                    evidence_binding_signature TEXT,
                    status TEXT NOT NULL CHECK (
                        status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')
                    ),
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
                    FOREIGN KEY (home_id) REFERENCES homes(home_id) ON DELETE CASCADE,
                    CHECK (
                        status <> 'resolved' OR (
                            network_scope_id IS NOT NULL AND
                            (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND
                            resolution_json IS NOT NULL AND source_reference IS NOT NULL AND
                            resolved_at IS NOT NULL
                        )
                    )
                )
                """
            )
        )
        conn.execute(
            text(
                f"INSERT INTO identity_enrichment_jobs_status_v2 ({columns}) "
                f"SELECT {columns} FROM identity_enrichment_jobs"
            )
        )
        migrated_count = int(
            conn.execute(text("SELECT COUNT(*) FROM identity_enrichment_jobs_status_v2")).scalar_one()
        )
        if migrated_count != original_count:
            raise RuntimeError("identity enrichment status migration row-count mismatch")
        conn.execute(text("DROP TABLE identity_enrichment_jobs"))
        conn.execute(
            text(
                "ALTER TABLE identity_enrichment_jobs_status_v2 "
                "RENAME TO identity_enrichment_jobs"
            )
        )

    def _ensure_column(self, conn, table_name: str, column_name: str, definition: str) -> None:
        if self.dialect == "postgresql":
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {definition}"))
            return
        columns = {row["name"] for row in conn.execute(text(f"PRAGMA table_info({table_name})")).mappings()}
        if column_name not in columns:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"))

    def _fallback_ward_account_name(self, conn, home_id: str = HOME["home_id"]) -> str:
        row = conn.execute(
            select(users_table.c.nickname, users_table.c.email)
            .where(users_table.c.home_id == home_id)
            .order_by(users_table.c.user_id.desc())
            .limit(1)
        ).first()
        return (
            clean_optional_name(row[0] if row else None)
            or clean_optional_name(row[1] if row else None)
            or ""
        )

    def _backfill_guardian_names(self, conn) -> None:
        invite_rows = conn.execute(select(guardian_invites_table)).all()
        for row in invite_rows:
            data = row_to_dict(row) or {}
            home_id = str(data.get("home_id") or HOME["home_id"])
            ward_account_name = clean_optional_name(data.get("ward_account_name")) or self._fallback_ward_account_name(conn, home_id)
            conn.execute(
                update(guardian_invites_table)
                .where(guardian_invites_table.c.invite_id == data["invite_id"])
                .values(ward_account_name=ward_account_name)
            )

        link_rows = conn.execute(
            select(guardian_ward_links_table, guardian_invites_table.c.ward_account_name.label("invite_ward_account_name"))
            .select_from(
                guardian_ward_links_table.outerjoin(
                    guardian_invites_table,
                    guardian_invites_table.c.invite_id == guardian_ward_links_table.c.invite_id,
                )
            )
        ).all()
        for row in link_rows:
            data = dict(row._mapping)
            raw_display_name = clean_optional_name(data.get("ward_display_name"))
            ward_account_name = (
                clean_optional_name(data.get("ward_account_name"))
                or clean_optional_name(data.get("invite_ward_account_name"))
                or self._fallback_ward_account_name(conn, str(data.get("home_id") or HOME["home_id"]))
            )
            ward_alias = clean_optional_name(data.get("ward_alias"))
            if ward_alias is None and raw_display_name and raw_display_name != ward_account_name:
                ward_alias = None if is_generic_ward_display_name(raw_display_name) else raw_display_name
            conn.execute(
                update(guardian_ward_links_table)
                .where(guardian_ward_links_table.c.link_id == data["link_id"])
                .values(
                    ward_account_name=ward_account_name,
                    ward_alias=ward_alias,
                    ward_display_name=ward_alias or ward_account_name,
                )
            )

    def _upsert_ignore(self, conn, table: Table, values: dict[str, Any]) -> None:
        if self.dialect == "postgresql":
            stmt = pg_insert(table).values(**values).on_conflict_do_nothing()
        else:
            stmt = sqlite_insert(table).values(**values).on_conflict_do_nothing()
        conn.execute(stmt)

    def _upsert(self, conn, table: Table, values: dict[str, Any], index_elements: list[str]) -> None:
        if self.dialect == "postgresql":
            base = pg_insert(table).values(**values)
            update_set = {col: base.excluded[col] for col in values.keys() if col not in index_elements}
            stmt = base.on_conflict_do_update(index_elements=index_elements, set_=update_set)
        else:
            base = sqlite_insert(table).values(**values)
            update_set = {col: base.excluded[col] for col in values.keys() if col not in index_elements}
            stmt = base.on_conflict_do_update(index_elements=index_elements, set_=update_set)
        conn.execute(stmt)

    # ---------------- 사용자 ----------------

    def user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(select(users_table).where(users_table.c.user_id == user_id)).first()
        data = row_to_dict(row)
        if data is None:
            return None
        return _user_from_row(data)

    def upsert_user(self, user: dict[str, Any]) -> dict[str, Any]:
        user_id = str(user.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        home_id = str(user.get("home_id") or default_home_id_for_user(user_id)).strip()
        email = str(user.get("email") or "").strip()
        nickname = str(user.get("nickname") or user.get("name") or "").strip()
        if not home_id or not email or not nickname:
            raise ValueError("user_id, email, nickname and home_id are required")
        values = {
            "user_id": user_id,
            "email": email,
            "nickname": nickname,
            "role": str(user.get("role") or "user").strip(),
            "email_verified": int(bool(user.get("email_verified", True))),
            "home_id": home_id,
        }
        with self.engine.begin() as conn:
            self._upsert(conn, users_table, values, index_elements=["user_id"])
            self._upsert_ignore(conn, homes_table, {"home_id": home_id, "name": "우리집", "mode": HOME["mode"]})
        stored = self.user_by_id(user_id)
        if stored is None:
            raise RuntimeError("user upsert did not persist")
        return stored

    # ---------------- 홈/대시보드 ----------------

    def home(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        with self.engine.begin() as conn:
            row = conn.execute(select(homes_table).where(homes_table.c.home_id == home_id)).first()
            data = row_to_dict(row)
            if data is None:
                raise KeyError("home does not exist")
            return {
                "home_id": data.get("home_id"),
                "name": data.get("name"),
                "mode": data.get("mode"),
            }

    def dashboard(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        # phantom(미확증 유령 신호)은 카운트·top_risks 에서 제외(sqlite_repository 와 동일 기준).
        devices = [d for d in self.devices(home_id=home_id) if not _is_phantom_signal(d)]
        identity_findings = visible_identity_findings(
            self.identity_findings(home_id=home_id)
        )
        score = self.security_score(home_id=home_id)
        events = self.security_events(home_id=home_id)
        risky_devices = [d for d in devices if d["risk_level"] in {"red", "yellow"}]
        return {
            "home": {
                **self.home(home_id=home_id),
                "security_score": score["score"],
                "device_count": len(devices),
                "identified_device_count": len(devices),
                "identity_pending_count": len(identity_findings),
            },
            "summary": {
                "score": score["score"],
                "score_status": score["score_status"],
                "risk_level": score["risk_level"],
                "scan_complete": score["scan_complete"],
                "coverage_complete": score["coverage_complete"],
                "online_devices": sum(1 for d in devices if d["online"]),
                "high_risk_devices": confirmed_public_red_count(devices, identity_findings),
                "identity_pending_count": len(identity_findings),
                "recent_event_count": len(events),
            },
            "top_risks": [
                {
                    "device_id": d["device_id"],
                    "device_name": d["name"],
                    "risk_level": d["risk_level"],
                    "message": d.get("risk_summary") or "보안 상태를 다시 확인해 주세요.",
                }
                for d in risky_devices
            ],
            "identity_findings": identity_findings,
            "recent_events": events[:3],
            "guardian_status": {
                "connected_guardians": self.guardian_count(home_id=home_id),
                "last_alert_status": "앱 알림 대체 흐름으로 보호자에게 전달된 상태입니다.",
            },
        }

    # ---------------- 기기 ----------------

    def _stored_devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        latest = self._latest_observed_scan_devices(home_id=home_id)
        if latest is not None:
            return self._apply_aliases(
                [device for device in latest if not is_self_observation(device)],
                home_id,
            )
        return []

    def devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        return self._public_devices(self._stored_devices(home_id))

    def latest_scan_context(self, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        """Return the newest valid Android scan context for server-side policy."""

        with self.engine.begin() as conn:
            rows = conn.execute(
                select(
                    scans_table.c.scan_id,
                    scans_table.c.network_context_json,
                    scans_table.c.network_scope_id,
                )
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .order_by(scans_table.c.created_at.desc())
            ).all()
            for row in rows:
                scan = row_to_dict(row) or {}
                snapshots = conn.execute(
                    select(scan_devices_table.c.device_snapshot_json)
                    .where(scan_devices_table.c.scan_id == scan.get("scan_id"))
                    .order_by(scan_devices_table.c.id.asc())
                ).all()
                devices = [json.loads(item[0]) for item in snapshots]
                bounded = _validated_authoritative_snapshot(
                    json.loads(scan.get("network_context_json") or "{}"),
                    devices,
                )
                if bounded is None:
                    continue
                context, _bounded_devices = bounded
                return context
        return None

    def _latest_scan_devices_only(self, home_id: str) -> list[dict[str, Any]] | None:
        """Return snapshots from the newest valid Android scan, without history merge."""
        from .sqlite_repository import apply_verified_product_catalog_projection

        catalog_entries = self.verified_product_catalog_entries()
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(
                    scans_table.c.scan_id,
                    scans_table.c.network_context_json,
                    scans_table.c.network_scope_id,
                )
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .order_by(scans_table.c.created_at.desc())
            ).all()
            for row in rows:
                data = row_to_dict(row) or {}
                snapshot_rows = conn.execute(
                    select(scan_devices_table.c.device_snapshot_json)
                    .where(scan_devices_table.c.scan_id == data.get("scan_id"))
                    .order_by(scan_devices_table.c.id.asc())
                ).all()
                devices = [json.loads(item[0]) for item in snapshot_rows]
                bounded = _validated_authoritative_snapshot(
                    json.loads(data.get("network_context_json") or "{}"),
                    devices,
                )
                if bounded is None:
                    continue
                _network_context, devices = bounded
                devices = apply_verified_product_catalog_projection(
                    devices,
                    catalog_entries,
                )
                devices = self._apply_approved_manual_identities(
                    devices,
                    home_id=home_id,
                    network_scope_id=data.get("network_scope_id"),
                    conn=conn,
                )
                return self._apply_aliases(
                    [device for device in devices if not is_self_observation(device)],
                    home_id,
                    network_scope_id=data.get("network_scope_id"),
                    observed_scope_supplied=True,
                )
        return None

    def identity_findings(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        latest = self._latest_scan_devices_only(home_id)
        devices = self._stored_devices(home_id) if latest is None else latest
        return build_public_identity_findings(devices, self.devices(home_id=home_id))

    def identity_history(
        self,
        device_id: str | None = None,
        home_id: str = HOME["home_id"],
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 200))
        requested_public_id: str | None = None
        if device_id:
            stored_id = self._resolve_stored_device_id(device_id, home_id) or device_id
            requested_public_id = public_device_id(stored_id, home_id)
            has_observed_scan, active_scope = self._latest_valid_network_scope(home_id)
            current_devices = self._latest_observed_scan_devices(home_id) or []
            current = next(
                (
                    item
                    for item in current_devices
                    if str(item.get("device_id") or "") == stored_id
                    or public_device_id(item.get("device_id"), home_id) == device_id
                ),
                None,
            )
            current_mac = normalized_physical_mac((current or {}).get("mac_address"))
            if current_mac in _ambiguous_physical_macs(current_devices):
                current_mac = None
            if not (
                current is not None
                and has_observed_scan
                and is_strong_network_scope_id(active_scope)
            ):
                return []
            if current_mac:
                statement = (
                    select(device_identity_history_table)
                    .where(
                        device_identity_history_table.c.home_id == home_id,
                        device_identity_history_table.c.network_scope_id == active_scope,
                        func.upper(device_identity_history_table.c.physical_mac) == current_mac,
                    )
                    .order_by(device_identity_history_table.c.observed_at.desc())
                    .limit(bounded_limit)
                )
            else:
                statement = (
                    select(device_identity_history_table)
                    .where(
                        device_identity_history_table.c.home_id == home_id,
                        device_identity_history_table.c.network_scope_id == active_scope,
                        device_identity_history_table.c.device_id.in_((device_id, stored_id)),
                    )
                    .order_by(device_identity_history_table.c.observed_at.desc())
                    .limit(1)
                )
        else:
            statement = (
                select(device_identity_history_table)
                .where(device_identity_history_table.c.home_id == home_id)
                .order_by(device_identity_history_table.c.observed_at.desc())
                .limit(bounded_limit)
            )
        with self.engine.begin() as conn:
            rows = conn.execute(statement).all()
        result: list[dict[str, Any]] = []
        for row in rows:
            data = row_to_dict(row) or {}
            result.append(
                {
                    "resolution_id": data.get("resolution_id"),
                    "home_id": data.get("home_id"),
                    "device_id": requested_public_id or public_device_id(data.get("device_id"), home_id),
                    "observed_at": data.get("observed_at"),
                    "identity_status": data.get("identity_status"),
                    "manufacturer": data.get("manufacturer", ""),
                    "device_type": data.get("device_type", ""),
                    "model": data.get("model", ""),
                    "canonical_name": data.get("canonical_name", ""),
                    "confidence": data.get("confidence", 0.0),
                    "identity_evidence": json.loads(data.get("evidence_json") or "[]"),
                    "identity_candidates": json.loads(data.get("candidates_json") or "[]"),
                    "identity_note": data.get("note", ""),
                    "resolver_version": data.get("resolver_version", ""),
                }
            )
        return result

    @staticmethod
    def _identity_enrichment_job_from_row(row: Row | None) -> dict[str, Any] | None:
        data = row_to_dict(row)
        if data is None:
            return None
        try:
            evidence = json.loads(data.get("evidence_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = {}
        try:
            resolution = json.loads(data.get("resolution_json") or "null")
        except (TypeError, ValueError, json.JSONDecodeError):
            resolution = None
        return {
            **data,
            "evidence": evidence if isinstance(evidence, dict) else {},
            "resolution": resolution if isinstance(resolution, dict) else None,
        }

    def _upsert_identity_enrichment_jobs(
        self,
        devices: list[dict[str, Any]],
        *,
        home_id: str,
        network_scope_id: str | None,
        ambiguity_devices: list[dict[str, Any]] | None = None,
    ) -> None:
        strong_scope = network_scope_id if is_strong_network_scope_id(network_scope_id) else None
        now = utc_now()
        prepared_jobs = _prepare_identity_enrichment_jobs(
            devices,
            home_id=home_id,
            network_scope_id=strong_scope,
            ambiguity_devices=ambiguity_devices,
        )
        active_job_keys = {
            str(prepared["job_key"]) for prepared in prepared_jobs
        }
        with self.engine.begin() as conn:
            owner = conn.execute(
                select(users_table.c.user_id)
                .join(homes_table, homes_table.c.home_id == users_table.c.home_id)
                .where(homes_table.c.home_id == home_id)
                .limit(1)
            ).first()
            if owner is None:
                raise ValueError("authenticated home does not exist")
            # Insert/revive canonical keys before superseding prior key formats.
            for prepared in prepared_jobs:
                device = prepared["device"]
                physical_mac = prepared["physical_mac"]
                evidence = prepared["evidence"]
                evidence_binding_signature = prepared["evidence_binding_signature"]
                job_key = str(prepared["job_key"])
                blocked_reason = prepared["blocked_reason"]
                values = {
                    "job_id": f"identity-job-{uuid4()}",
                    "job_key": job_key,
                    "home_id": home_id,
                    "device_id": str(device.get("device_id") or ""),
                    "network_scope_id": strong_scope,
                    "physical_mac": physical_mac,
                    "evidence_binding_signature": evidence_binding_signature,
                    "status": prepared["status"],
                    "blocked_reason": blocked_reason,
                    "evidence_json": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                    "evidence_signature": build_evidence_signature(evidence),
                    "seen_count": 1,
                    "first_seen_at": now,
                    "last_seen_at": now,
                    "updated_at": now,
                    "resolution_json": None,
                    "source_reference": None,
                    "resolution_provenance": None,
                    "resolution_signature": None,
                    "research_attempt_count": 0,
                    "research_last_attempt_at": None,
                    "research_next_attempt_at": None,
                    "resolved_at": None,
                }
                base = (
                    pg_insert(identity_enrichment_jobs_table)
                    if self.dialect == "postgresql"
                    else sqlite_insert(identity_enrichment_jobs_table)
                ).values(**values)
                conn.execute(
                    base.on_conflict_do_update(
                        index_elements=["job_key"],
                        set_={
                            "device_id": base.excluded.device_id,
                            "network_scope_id": base.excluded.network_scope_id,
                            "physical_mac": base.excluded.physical_mac,
                            "evidence_binding_signature": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_binding_signature,
                                ),
                                else_=base.excluded.evidence_binding_signature,
                            ),
                            "status": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.status,
                                ),
                                else_=base.excluded.status,
                            ),
                            "blocked_reason": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.blocked_reason,
                                ),
                                else_=base.excluded.blocked_reason,
                            ),
                            "evidence_json": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_json,
                                ),
                                else_=base.excluded.evidence_json,
                            ),
                            "evidence_signature": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.evidence_signature,
                                ),
                                else_=base.excluded.evidence_signature,
                            ),
                            "research_attempt_count": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_attempt_count,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    0,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_attempt_count,
                            ),
                            "research_last_attempt_at": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_last_attempt_at,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    None,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_last_attempt_at,
                            ),
                            "research_next_attempt_at": case(
                                (
                                    identity_enrichment_jobs_table.c.status.in_(("resolved", "rejected")),
                                    identity_enrichment_jobs_table.c.research_next_attempt_at,
                                ),
                                (
                                    identity_enrichment_jobs_table.c.evidence_signature
                                    != base.excluded.evidence_signature,
                                    None,
                                ),
                                else_=identity_enrichment_jobs_table.c.research_next_attempt_at,
                            ),
                            "seen_count": identity_enrichment_jobs_table.c.seen_count + 1,
                            "last_seen_at": base.excluded.last_seen_at,
                            "updated_at": base.excluded.updated_at,
                        },
                    )
                )
            stale_jobs = update(identity_enrichment_jobs_table).where(
                identity_enrichment_jobs_table.c.home_id == home_id,
                identity_enrichment_jobs_table.c.status.in_(("review_required", "blocked")),
            )
            if active_job_keys:
                stale_jobs = stale_jobs.where(
                    identity_enrichment_jobs_table.c.job_key.notin_(sorted(active_job_keys))
                )
            conn.execute(
                stale_jobs.values(
                    status="superseded",
                    blocked_reason="NOT_IN_LATEST_SCAN",
                    research_next_attempt_at=None,
                    updated_at=now,
                )
            )

    def identity_enrichment_jobs(
        self,
        *,
        status_filter: str | None = None,
        limit: int = 100,
        home_id: str | None = None,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 200))
        statement = select(identity_enrichment_jobs_table)
        if status_filter:
            statement = statement.where(identity_enrichment_jobs_table.c.status == status_filter)
        if home_id:
            statement = statement.where(identity_enrichment_jobs_table.c.home_id == home_id)
        statement = statement.order_by(identity_enrichment_jobs_table.c.updated_at.desc()).limit(bounded_limit)
        with self.engine.begin() as conn:
            rows = conn.execute(statement).all()
        return [
            job
            for row in rows
            if (job := self._identity_enrichment_job_from_row(row)) is not None
        ]

    def identity_research_due_home_ids(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
    ) -> list[str]:
        """Return due homes without truncating them through the job listing API."""

        bounded_limit = max(1, min(int(limit), 2000))
        bounded_offset = max(0, int(offset))
        attempted_rank = case(
            (func.max(identity_enrichment_jobs_table.c.research_last_attempt_at).is_(None), 0),
            else_=1,
        )
        last_processed_at = func.max(
            identity_enrichment_jobs_table.c.research_last_attempt_at
        )
        oldest_at = func.min(identity_enrichment_jobs_table.c.first_seen_at)
        home_activity = (
            select(
                identity_enrichment_jobs_table.c.home_id.label("home_id"),
                attempted_rank.label("attempted_rank"),
                last_processed_at.label("last_processed_at"),
                oldest_at.label("oldest_at"),
            )
            .where(identity_enrichment_jobs_table.c.status == "review_required")
            .group_by(identity_enrichment_jobs_table.c.home_id)
            .subquery()
        )
        due_homes = (
            select(identity_enrichment_jobs_table.c.home_id.label("home_id"))
            .where(
                identity_enrichment_jobs_table.c.status == "review_required",
                or_(
                    identity_enrichment_jobs_table.c.research_next_attempt_at.is_(None),
                    identity_enrichment_jobs_table.c.research_next_attempt_at <= utc_now(),
                ),
            )
            .distinct()
            .subquery()
        )
        statement = (
            select(home_activity.c.home_id)
            .join(due_homes, due_homes.c.home_id == home_activity.c.home_id)
            .order_by(
                home_activity.c.attempted_rank.asc(),
                func.coalesce(
                    home_activity.c.last_processed_at,
                    home_activity.c.oldest_at,
                ).asc(),
                home_activity.c.oldest_at.asc(),
                home_activity.c.home_id.asc(),
            )
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        with self.engine.begin() as conn:
            rows = conn.execute(statement).all()
        return [str(row[0]) for row in rows if str(row[0] or "").strip()]

    def identity_research_due_jobs(
        self,
        *,
        home_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Page due jobs in the same deterministic order used by claim."""

        bounded_limit = max(1, min(int(limit), 200))
        bounded_offset = max(0, int(offset))
        statement = (
            select(identity_enrichment_jobs_table)
            .where(
                identity_enrichment_jobs_table.c.home_id == home_id,
                identity_enrichment_jobs_table.c.status == "review_required",
                or_(
                    identity_enrichment_jobs_table.c.research_next_attempt_at.is_(None),
                    identity_enrichment_jobs_table.c.research_next_attempt_at <= utc_now(),
                ),
            )
            .order_by(
                func.coalesce(
                    identity_enrichment_jobs_table.c.research_last_attempt_at,
                    identity_enrichment_jobs_table.c.first_seen_at,
                ).asc(),
                identity_enrichment_jobs_table.c.first_seen_at.asc(),
                identity_enrichment_jobs_table.c.job_id.asc(),
            )
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        with self.engine.begin() as conn:
            rows = conn.execute(statement).all()
        return [
            job
            for row in rows
            if (job := self._identity_enrichment_job_from_row(row)) is not None
        ]

    @staticmethod
    def _verified_product_catalog_row(row: Row | None) -> dict[str, str] | None:
        data = row_to_dict(row)
        if data is None:
            return None
        entry = {key: str(value or "") for key, value in data.items()}
        return entry if verified_product_catalog_entry_matches(entry) else None

    @staticmethod
    def _register_verified_product_catalog(
        conn,
        *,
        validated: Mapping[str, Any],
        provenance: str,
        verified_at: str,
    ) -> dict[str, str]:
        entry = build_verified_product_catalog_entry(
            manufacturer=validated.get("manufacturer"),
            device_type=validated.get("device_type"),
            exact_model=validated.get("model"),
            source_url=validated.get("source_reference"),
            provenance=provenance,
            verified_at=verified_at,
        )
        existing_row = conn.execute(
            select(verified_product_catalog_table).where(
                verified_product_catalog_table.c.manufacturer_key
                == entry["manufacturer_key"],
                verified_product_catalog_table.c.model_key == entry["model_key"],
            )
        ).first()
        existing = SqlAlchemyRepository._verified_product_catalog_row(existing_row)
        if existing is not None:
            if existing["device_type"] != entry["device_type"]:
                raise IdentityEnrichmentError("IDENTITY_CATALOG_CONFLICT")
            return existing
        if existing_row is not None:
            conn.execute(
                delete(verified_product_catalog_table).where(
                    verified_product_catalog_table.c.manufacturer_key
                    == entry["manufacturer_key"],
                    verified_product_catalog_table.c.model_key == entry["model_key"],
                )
            )
        conn.execute(insert(verified_product_catalog_table).values(**entry))
        return entry

    def verified_product_catalog_entries(self) -> list[dict[str, str]]:
        """Return only HMAC-verified, household-independent product facts."""

        with self.engine.begin() as conn:
            rows = conn.execute(
                select(verified_product_catalog_table).order_by(
                    verified_product_catalog_table.c.manufacturer_key,
                    verified_product_catalog_table.c.model_key,
                )
            ).all()
        return [
            entry
            for row in rows
            if (entry := self._verified_product_catalog_row(row)) is not None
        ]

    def resolve_identity_enrichment_job(
        self,
        job_id: str,
        *,
        manufacturer: str,
        device_type: str,
        model: str,
        source_reference: str,
        resolution_provenance: str = IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
        expected_evidence_signature: str | None = None,
        expected_job_key: str | None = None,
        _propagate_catalog: bool = True,
        _catalog_reuse: bool = False,
        _device_scoped: bool = False,
    ) -> dict[str, Any]:
        if resolution_provenance not in IDENTITY_RESOLUTION_PROVENANCES:
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        if _device_scoped and (
            resolution_provenance != IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP
            or _propagate_catalog
            or _catalog_reuse
        ):
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        validated = validate_identity_resolution(
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=source_reference,
        )
        with self.engine.begin() as conn:
            row = conn.execute(
                select(identity_enrichment_jobs_table).where(
                    identity_enrichment_jobs_table.c.job_id == job_id
                )
            ).first()
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_FOUND")
            if job.get("status") == "resolved":
                raise IdentityEnrichmentError("IDENTITY_JOB_ALREADY_RESOLVED")
            if job.get("status") == "blocked":
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if job.get("status") != "review_required":
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_REVIEWABLE")
            if not identity_job_key_matches(job):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            network_scope_id = (
                str(job.get("network_scope_id") or "")
                if is_strong_network_scope_id(job.get("network_scope_id"))
                else None
            )
            physical_mac = normalized_physical_mac(job.get("physical_mac"))
            evidence = job.get("evidence") or {}
            if blocked_binding_reason(
                network_scope_id,
                physical_mac,
                evidence,
                device_id=job.get("device_id"),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if not evidence_signature_matches(evidence, job.get("evidence_signature")):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            current_signature = str(job.get("evidence_signature") or "")
            if expected_evidence_signature is not None and not hmac.compare_digest(
                current_signature,
                str(expected_evidence_signature),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            current_job_key = str(job.get("job_key") or "")
            if expected_job_key is not None and not hmac.compare_digest(
                current_job_key,
                str(expected_job_key),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")

            from ..services.identity_research import (
                _eligible_job,
                _requires_device_scoped_resolution,
            )

            eligible_job = _eligible_job(job)
            has_authenticated_self_evidence = any(
                isinstance(proof, Mapping)
                and str(proof.get("source") or "").strip().casefold()
                == "authenticated-self-android"
                for proof in evidence.get("structured_provenance") or []
            )
            eligible_requires_device_scope = (
                eligible_job is not None
                and _requires_device_scoped_resolution(eligible_job)
            )
            if has_authenticated_self_evidence != _device_scoped or (
                _device_scoped and not eligible_requires_device_scope
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if _device_scoped:
                safe_evidence = eligible_job.get("evidence") or {}

                def normalized(value: object) -> str:
                    return " ".join(str(value or "").strip().casefold().split())

                exact_hints = {
                    "manufacturer": {
                        normalized(value)
                        for value in safe_evidence.get("manufacturer_hints") or []
                    },
                    "model": {
                        normalized(value)
                        for value in safe_evidence.get("model_hints") or []
                    },
                    "device_type": {
                        normalized(value)
                        for value in safe_evidence.get("device_type_hints") or []
                    },
                }
                if any(
                    normalized(validated[field]) not in exact_hints[field]
                    for field in ("manufacturer", "model", "device_type")
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
                authenticated_proofs = {
                    (
                        str(proof.get("kind") or "").strip().casefold(),
                        normalized(proof.get("value")),
                    )
                    for proof in eligible_job.get("corroboration") or []
                    if isinstance(proof, Mapping)
                    and str(proof.get("source") or "").strip().casefold()
                    == "authenticated-self-android"
                }
                if any(
                    (field, normalized(validated[field])) not in authenticated_proofs
                    for field in ("manufacturer", "model", "device_type")
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")

            if is_automated_identity_resolution_provenance(resolution_provenance):
                normalized_model = " ".join(validated["model"].casefold().split())
                advertised_models = {
                    " ".join(str(value or "").casefold().split())
                    for value in evidence.get("model_hints") or []
                }
                if normalized_model not in advertised_models or not (
                    source_matches_registered_official_domain(
                        validated["source_reference"],
                        validated["manufacturer"],
                    )
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")

            now = utc_now()
            resolution_id = (
                f"identity-auto-{uuid4()}"
                if is_automated_identity_resolution_provenance(resolution_provenance)
                else f"identity-review-{uuid4()}"
            )
            resolution = {
                **{key: validated[key] for key in ("manufacturer", "device_type", "model", "canonical_name")},
                "history_resolution_id": resolution_id,
                "resolution_provenance": resolution_provenance,
            }
            if _catalog_reuse:
                resolution["catalog_reused"] = True
            if _device_scoped:
                resolution["device_scoped"] = True
            resolution_signature = build_resolution_signature(
                job_key=current_job_key,
                evidence_signature=current_signature,
                resolution=resolution,
                source_reference=validated["source_reference"],
                resolution_provenance=resolution_provenance,
            )
            if not _device_scoped:
                self._register_verified_product_catalog(
                    conn,
                    validated=validated,
                    provenance=resolution_provenance,
                    verified_at=now,
                )
            updated = conn.execute(
                update(identity_enrichment_jobs_table)
                .where(
                    identity_enrichment_jobs_table.c.job_id == job_id,
                    identity_enrichment_jobs_table.c.status == "review_required",
                    identity_enrichment_jobs_table.c.evidence_signature == current_signature,
                    identity_enrichment_jobs_table.c.job_key == current_job_key,
                )
                .values(
                    status="resolved",
                    blocked_reason=None,
                    resolution_json=json.dumps(resolution, ensure_ascii=False, sort_keys=True),
                    source_reference=validated["source_reference"],
                    resolution_provenance=resolution_provenance,
                    resolution_signature=resolution_signature,
                    resolved_at=now,
                    updated_at=now,
                )
            )
            if updated.rowcount != 1:
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            conn.execute(
                insert(device_identity_history_table).values(
                    resolution_id=resolution_id,
                    home_id=job["home_id"],
                    device_id=job["device_id"],
                    network_scope_id=network_scope_id,
                    physical_mac=physical_mac,
                    observed_at=now,
                    identity_status="manual_resolved",
                    manufacturer=validated["manufacturer"],
                    device_type=validated["device_type"],
                    model=validated["model"],
                    canonical_name=validated["canonical_name"],
                    confidence=1.0,
                    evidence_json=json.dumps(
                        [
                            *resolution_history_evidence(job_id, resolution_provenance),
                            *(["verified-product-catalog-reuse"] if _catalog_reuse else []),
                            *(
                                ["device-scoped:authenticated-self-android"]
                                if _device_scoped
                                else []
                            ),
                        ],
                        ensure_ascii=False,
                    ),
                    candidates_json="[]",
                    note=(
                        "서버의 서명된 제품 카탈로그와 현재 장치의 구조화 단서가 정확히 일치한 재확인 결과입니다."
                        if _catalog_reuse
                        else "공식 제조사 웹 인용과 수집 단서가 정확히 일치한 자동 확인 결과입니다."
                        if is_automated_identity_resolution_provenance(
                            resolution_provenance
                        )
                        else "공식 출처를 확인한 운영자 검토 결과입니다."
                    ),
                    resolver_version=IDENTITY_ENRICHMENT_RESOLVER_VERSION,
                )
            )
            resolved_row = conn.execute(
                select(identity_enrichment_jobs_table).where(
                    identity_enrichment_jobs_table.c.job_id == job_id
                )
            ).first()
            resolved = self._identity_enrichment_job_from_row(resolved_row)
            assert resolved is not None
        if _propagate_catalog:
            self.reconcile_verified_product_catalog_jobs()
        return resolved

    def resolve_device_scoped_identity_job(
        self,
        job_id: str,
        *,
        manufacturer: str,
        device_type: str,
        model: str,
        source_reference: str,
        resolution_provenance: str = IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
        expected_evidence_signature: str | None = None,
        expected_job_key: str | None = None,
    ) -> dict[str, Any]:
        """Resolve one L2-attested Android self job without catalog promotion."""

        return self.resolve_identity_enrichment_job(
            job_id,
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=source_reference,
            resolution_provenance=resolution_provenance,
            expected_evidence_signature=expected_evidence_signature,
            expected_job_key=expected_job_key,
            _propagate_catalog=False,
            _catalog_reuse=False,
            _device_scoped=True,
        )

    def reconcile_verified_product_catalog_jobs(
        self,
        *,
        limit: int = 200,
        should_stop: Callable[[], bool] | None = None,
    ) -> int:
        """Boundedly resolve independently bound observations from signed facts."""

        from .sqlite_repository import (
            verified_catalog_reconcile_version,
            verified_catalog_resolution_for_job,
        )

        catalog_entries = self.verified_product_catalog_entries()
        catalog_version = verified_catalog_reconcile_version(catalog_entries)
        if not catalog_entries or catalog_version is None:
            return 0
        bounded_limit = max(1, min(int(limit), 2000))
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(identity_enrichment_jobs_table)
                .where(
                    identity_enrichment_jobs_table.c.status == "review_required",
                    func.coalesce(
                        identity_enrichment_jobs_table.c.catalog_reconcile_version,
                        "",
                    )
                    != catalog_version,
                )
                .order_by(
                    identity_enrichment_jobs_table.c.first_seen_at,
                    identity_enrichment_jobs_table.c.job_id,
                )
                .limit(bounded_limit)
            ).all()
        resolved_count = 0
        checked_without_match: list[tuple[str, str, str]] = []
        for row in rows:
            if should_stop is not None and should_stop():
                break
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                continue
            resolution = verified_catalog_resolution_for_job(job, catalog_entries)
            if resolution is None:
                checked_without_match.append(
                    (
                        str(job.get("job_id") or ""),
                        str(job.get("evidence_signature") or ""),
                        str(job.get("job_key") or ""),
                    )
                )
                continue
            try:
                self.resolve_identity_enrichment_job(
                    str(job["job_id"]),
                    manufacturer=resolution["manufacturer"],
                    device_type=resolution["device_type"],
                    model=resolution["model"],
                    source_reference=resolution["source_reference"],
                    resolution_provenance=resolution["resolution_provenance"],
                    expected_evidence_signature=str(job.get("evidence_signature") or ""),
                    expected_job_key=str(job.get("job_key") or ""),
                    _propagate_catalog=False,
                    _catalog_reuse=True,
                )
            except IdentityEnrichmentError:
                continue
            resolved_count += 1
        if checked_without_match:
            with self.engine.begin() as conn:
                for job_id, evidence_signature, job_key in checked_without_match:
                    conn.execute(
                        update(identity_enrichment_jobs_table)
                        .where(
                            identity_enrichment_jobs_table.c.job_id == job_id,
                            identity_enrichment_jobs_table.c.status == "review_required",
                            identity_enrichment_jobs_table.c.evidence_signature
                            == evidence_signature,
                            identity_enrichment_jobs_table.c.job_key == job_key,
                            func.coalesce(
                                identity_enrichment_jobs_table.c.catalog_reconcile_version,
                                "",
                            )
                            != catalog_version,
                        )
                        .values(catalog_reconcile_version=catalog_version)
                    )
        return resolved_count

    def reset_identity_research_backoff_for_version(self, version: str) -> int:
        """Clear only the future retry time once per valid job/policy version."""

        normalized_version = str(version or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{5,127}", normalized_version):
            raise ValueError("invalid identity research policy version")
        now = utc_now()
        updated_count = 0
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(identity_enrichment_jobs_table).where(
                    identity_enrichment_jobs_table.c.status == "review_required",
                    func.coalesce(
                        identity_enrichment_jobs_table.c.research_policy_version,
                        "",
                    )
                    != normalized_version,
                )
            ).all()
            for row in rows:
                job = self._identity_enrichment_job_from_row(row)
                evidence = (job or {}).get("evidence")
                if not isinstance(job, Mapping) or not isinstance(evidence, Mapping):
                    continue
                if (
                    blocked_binding_reason(
                        str(job.get("network_scope_id") or "") or None,
                        str(job.get("physical_mac") or "") or None,
                        evidence,
                        device_id=job.get("device_id"),
                    )
                    is not None
                    or not identity_job_key_matches(job)
                    or not evidence_signature_matches(
                        evidence, job.get("evidence_signature")
                    )
                ):
                    continue
                updated = conn.execute(
                    update(identity_enrichment_jobs_table)
                    .where(
                        identity_enrichment_jobs_table.c.job_id == job["job_id"],
                        identity_enrichment_jobs_table.c.status == "review_required",
                        identity_enrichment_jobs_table.c.evidence_signature
                        == job["evidence_signature"],
                        identity_enrichment_jobs_table.c.job_key == job["job_key"],
                        func.coalesce(
                            identity_enrichment_jobs_table.c.research_policy_version,
                            "",
                        )
                        != normalized_version,
                    )
                    .values(
                        research_next_attempt_at=None,
                        research_policy_version=normalized_version,
                        updated_at=now,
                    )
                )
                updated_count += int(updated.rowcount == 1)
        return updated_count

    def claim_identity_research_jobs(
        self,
        *,
        home_id: str,
        limit: int = 8,
        job_ids: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fairly claim due jobs and persist exponential backoff before I/O."""

        bounded_limit = max(1, min(int(limit), 8))
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat().replace("+00:00", "Z")
        selected_ids = tuple(
            dict.fromkeys(
                str(value or "").strip()
                for value in (job_ids or ())
                if str(value or "").strip()
            )
        )[:200]
        if job_ids is not None and not selected_ids:
            return []
        claimed: list[dict[str, Any]] = []
        with self.engine.begin() as conn:
            selection_conditions = []
            if selected_ids:
                selection_conditions.append(
                    identity_enrichment_jobs_table.c.job_id.in_(selected_ids)
                )
            rows = conn.execute(
                select(identity_enrichment_jobs_table)
                .where(
                    identity_enrichment_jobs_table.c.home_id == home_id,
                    identity_enrichment_jobs_table.c.status == "review_required",
                    or_(
                        identity_enrichment_jobs_table.c.research_next_attempt_at.is_(None),
                        identity_enrichment_jobs_table.c.research_next_attempt_at <= now,
                    ),
                    *selection_conditions,
                )
                .order_by(
                    func.coalesce(
                        identity_enrichment_jobs_table.c.research_last_attempt_at,
                        identity_enrichment_jobs_table.c.first_seen_at,
                    ).asc(),
                    identity_enrichment_jobs_table.c.first_seen_at.asc(),
                    identity_enrichment_jobs_table.c.job_id.asc(),
                )
                .limit(bounded_limit)
            ).all()
            for row in rows:
                data = row_to_dict(row) or {}
                attempts = max(0, int(data.get("research_attempt_count") or 0)) + 1
                delay_seconds = min(6 * 60 * 60, 60 * (2 ** min(attempts - 1, 8)))
                next_attempt = (now_dt + timedelta(seconds=delay_seconds)).isoformat().replace(
                    "+00:00", "Z"
                )
                updated = conn.execute(
                    update(identity_enrichment_jobs_table)
                    .where(
                        identity_enrichment_jobs_table.c.job_id == data.get("job_id"),
                        identity_enrichment_jobs_table.c.home_id == home_id,
                        identity_enrichment_jobs_table.c.status == "review_required",
                        or_(
                            identity_enrichment_jobs_table.c.research_next_attempt_at.is_(None),
                            identity_enrichment_jobs_table.c.research_next_attempt_at <= now,
                        ),
                    )
                    .values(
                        research_attempt_count=attempts,
                        research_last_attempt_at=now,
                        research_next_attempt_at=next_attempt,
                        updated_at=now,
                    )
                )
                if updated.rowcount != 1:
                    continue
                claimed_row = conn.execute(
                    select(identity_enrichment_jobs_table).where(
                        identity_enrichment_jobs_table.c.job_id == data.get("job_id")
                    )
                ).first()
                job = self._identity_enrichment_job_from_row(claimed_row)
                if job is not None:
                    claimed.append(job)
        return claimed

    def reject_identity_enrichment_job(self, job_id: str, *, reason: str) -> dict[str, Any]:
        normalized_reason = str(reason or "").strip().upper()
        if normalized_reason not in IDENTITY_ENRICHMENT_REJECT_REASONS:
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        with self.engine.begin() as conn:
            row = conn.execute(
                select(identity_enrichment_jobs_table).where(
                    identity_enrichment_jobs_table.c.job_id == job_id
                )
            ).first()
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_FOUND")
            if job.get("status") == "resolved":
                raise IdentityEnrichmentError("IDENTITY_JOB_ALREADY_RESOLVED")
            conn.execute(
                update(identity_enrichment_jobs_table)
                .where(identity_enrichment_jobs_table.c.job_id == job_id)
                .values(
                    status="rejected",
                    blocked_reason=f"REJECTED_{normalized_reason}",
                    updated_at=utc_now(),
                )
            )
            rejected_row = conn.execute(
                select(identity_enrichment_jobs_table).where(
                    identity_enrichment_jobs_table.c.job_id == job_id
                )
            ).first()
            rejected = self._identity_enrichment_job_from_row(rejected_row)
            assert rejected is not None
            return rejected

    def _apply_approved_manual_identities(
        self,
        devices: list[dict[str, Any]],
        *,
        home_id: str,
        network_scope_id: str | None,
        conn=None,
    ) -> list[dict[str, Any]]:
        if not devices or not is_strong_network_scope_id(network_scope_id):
            return devices
        ambiguous_macs = _ambiguous_physical_macs(devices)
        macs = sorted(
            {
                mac
                for device in devices
                if (mac := normalized_physical_mac(device.get("mac_address"))) is not None
                and mac not in ambiguous_macs
            }
        )
        evidence_bindings = sorted(
            {
                signature
                for device in devices
                if (
                    signature := stable_identity_evidence_signature(
                        structured_identity_evidence(device),
                        device_id=device.get("device_id"),
                    )
                )
                is not None
            }
        )
        if not macs and not evidence_bindings:
            return devices

        def load(
            connection,
        ) -> tuple[
            dict[str, dict[str, str]],
            dict[tuple[str, str], dict[str, str]],
        ]:
            binding_conditions = []
            if macs:
                binding_conditions.append(
                    func.upper(identity_enrichment_jobs_table.c.physical_mac).in_(macs)
                )
            if evidence_bindings:
                binding_conditions.append(
                    identity_enrichment_jobs_table.c.evidence_binding_signature.in_(
                        evidence_bindings
                    )
                )
            rows = connection.execute(
                select(identity_enrichment_jobs_table)
                .where(
                    identity_enrichment_jobs_table.c.home_id == home_id,
                    identity_enrichment_jobs_table.c.network_scope_id == network_scope_id,
                    identity_enrichment_jobs_table.c.status == "resolved",
                    or_(*binding_conditions),
                )
                .order_by(identity_enrichment_jobs_table.c.resolved_at.desc())
            ).all()
            approved_by_mac: dict[str, dict[str, str]] = {}
            approved_by_evidence: dict[tuple[str, str], dict[str, str]] = {}
            for row in rows:
                job = self._identity_enrichment_job_from_row(row)
                if job is None or not evidence_signature_matches(job.get("evidence") or {}, job.get("evidence_signature")):
                    continue
                resolution = job.get("resolution") or {}
                history_id = str(resolution.get("history_resolution_id") or "")
                history_row = connection.execute(
                    select(device_identity_history_table).where(
                        device_identity_history_table.c.resolution_id == history_id,
                        device_identity_history_table.c.home_id == home_id,
                    )
                ).first()
                history = row_to_dict(history_row)
                if history is None:
                    continue
                try:
                    history["identity_evidence"] = json.loads(history.get("evidence_json") or "[]")
                except (TypeError, ValueError, json.JSONDecodeError):
                    history["identity_evidence"] = []
                trusted = trusted_identity_resolution(history, job)
                mac = normalized_physical_mac(job.get("physical_mac"))
                evidence_binding = str(job.get("evidence_binding_signature") or "")
                if trusted is None:
                    continue
                approved_identity = {
                    **trusted,
                    "_resolution_provenance": str(
                        job.get("resolution_provenance")
                        or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
                    ),
                    "_device_scoped": resolution.get("device_scoped") is True,
                }
                if mac is not None:
                    approved_by_mac.setdefault(mac, approved_identity)
                elif evidence_binding and not approved_identity["_device_scoped"]:
                    approved_by_evidence.setdefault(
                        (evidence_binding, str(job.get("device_id") or "")),
                        approved_identity,
                    )
            return approved_by_mac, approved_by_evidence

        if conn is None:
            with self.engine.begin() as local_conn:
                approved_by_mac, approved_by_evidence = load(local_conn)
        else:
            approved_by_mac, approved_by_evidence = load(conn)

        result: list[dict[str, Any]] = []
        for device in devices:
            # A trusted resolution is identity evidence, never current
            # liveness evidence. Preserve the latest phantom classification.
            if bool(device.get("is_phantom")):
                result.append(device)
                continue
            physical_mac = normalized_physical_mac(device.get("mac_address"))
            if physical_mac in ambiguous_macs:
                physical_mac = None
            current_evidence_binding = stable_identity_evidence_signature(
                structured_identity_evidence(device),
                device_id=device.get("device_id"),
            )
            approved_identity = approved_by_mac.get(physical_mac or "")
            if (
                approved_identity is None
                and physical_mac is None
                and current_evidence_binding
            ):
                approved_identity = approved_by_evidence.get(
                    (
                        current_evidence_binding,
                        str(device.get("device_id") or ""),
                    )
                )
            if approved_identity is None:
                result.append(device)
                continue
            provenance = str(
                approved_identity.get("_resolution_provenance")
                or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
            )
            device_scoped = approved_identity.get("_device_scoped") is True
            trusted_fields = {
                key: value
                for key, value in approved_identity.items()
                if key not in {"_resolution_provenance", "_device_scoped"}
            }
            enriched = {
                **device,
                **trusted_fields,
                "identity_status": "manual_resolved",
                "identity_resolver_version": IDENTITY_ENRICHMENT_RESOLVER_VERSION,
                "identity_evidence": [f"official-source:{provenance}"],
                "identity_candidates": [],
                "identity_note": "공식 제조사 출처로 실제 제품을 확인했어요.",
                "identity_confidence": 1.0,
                "identity_family_verified": True,
                "is_resolved": True,
                "is_unresolved": False,
                "is_phantom": False,
            }
            if device_scoped:
                enriched = strip_untrusted_self_claims(enriched)
            enriched = bind_trusted_manual_identity(enriched)
            enriched.update(normalized_storage_fields(enriched))
            enriched = scoring_with_cve(enriched)
            scored = score_device(enriched)
            enriched.update(
                security_score=scored["score"],
                risk_level=scored["risk_level"],
                risk_summary=scored["summary"],
                recommended_actions=scored["recommended_actions"],
            )
            result.append(enriched)
        return result

    def _resolve_stored_device_id(self, device_id: str, home_id: str) -> str | None:
        """Resolve a public-safe or legacy device ID to the stored key.

        The SQLite and PostgreSQL repository implementations deliberately use
        the same compatibility rule, so a historic address-derived ID remains
        usable for a detail/alias request without becoming public again.
        """
        latest = self._latest_observed_scan_devices(home_id=home_id)
        if latest is not None:
            for item in latest:
                raw_id = str(item.get("device_id") or "")
                if raw_id == device_id or public_device_id(raw_id, home_id) == device_id:
                    return raw_id
            legacy_ip = legacy_device_id_ip_address(device_id)
            if legacy_ip is not None:
                from .sqlite_repository import make_device_id, scoped_device_id

                opaque_id = scoped_device_id(home_id, make_device_id(legacy_ip, ""))
                if any(str(item.get("device_id") or "") == opaque_id for item in latest):
                    return opaque_id
            return None

        return None

    def device(self, device_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        latest = self._latest_observed_scan_devices(home_id=home_id)
        if latest is not None:
            stored_id = self._resolve_stored_device_id(device_id, home_id)
            return next(
                (
                    d
                    for d in self._public_devices(self._apply_aliases(latest, home_id))
                    if d["device_id"] == device_id
                    or (stored_id is not None and str(d.get("device_id") or "") == public_device_id(stored_id, home_id))
                ),
                None,
            )
        return None

    def _device_alias_map(self, home_id: str = HOME["home_id"]) -> dict[str, str]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(device_aliases_table.c.device_id, device_aliases_table.c.alias)
                .where(device_aliases_table.c.home_id == home_id)
            ).all()
        aliases = {str(row[0]): str(row[1]) for row in rows}
        from .sqlite_repository import make_device_id, scoped_device_id

        for stored_id, alias in tuple(aliases.items()):
            legacy_ip = legacy_device_id_ip_address(stored_id)
            if legacy_ip is not None:
                aliases.setdefault(scoped_device_id(home_id, make_device_id(legacy_ip, "")), alias)
        return aliases

    def _device_alias_records(self, home_id: str) -> list[dict[str, Any]]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(
                    device_aliases_table.c.device_id,
                    device_aliases_table.c.network_scope_id,
                    device_aliases_table.c.physical_mac,
                    device_aliases_table.c.alias,
                ).where(device_aliases_table.c.home_id == home_id)
            ).mappings().all()
        return [dict(row) for row in rows]

    def _latest_valid_network_scope(self, home_id: str) -> tuple[bool, str | None]:
        with self.engine.begin() as conn:
            scans = conn.execute(
                select(
                    scans_table.c.scan_id,
                    scans_table.c.network_context_json,
                    scans_table.c.network_scope_id,
                )
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .order_by(scans_table.c.created_at.desc())
            ).mappings().all()
            for scan in scans:
                rows = conn.execute(
                    select(scan_devices_table.c.device_snapshot_json)
                    .where(scan_devices_table.c.scan_id == scan.get("scan_id"))
                    .order_by(scan_devices_table.c.id.asc())
                ).all()
                devices = [json.loads(row[0]) for row in rows]
                bounded = _validated_authoritative_snapshot(
                    json.loads(scan.get("network_context_json") or "{}"),
                    devices,
                )
                if bounded is None:
                    continue
                return True, scan.get("network_scope_id")
        return False, None

    def _apply_aliases(
        self,
        devices: list[dict[str, Any]],
        home_id: str,
        *,
        network_scope_id: str | None = None,
        observed_scope_supplied: bool = False,
    ) -> list[dict[str, Any]]:
        records = self._device_alias_records(home_id)
        if not records:
            return devices
        if observed_scope_supplied:
            has_observed_scan = True
            active_scope = network_scope_id
        else:
            has_observed_scan, active_scope = self._latest_valid_network_scope(home_id)

        result: list[dict[str, Any]] = []
        for device in devices:
            device_id = str(device.get("device_id") or "")
            device_mac = normalized_physical_mac(device.get("mac_address"))
            alias = None
            for record in records:
                bound_scope = record.get("network_scope_id")
                bound_mac = normalized_physical_mac(record.get("physical_mac"))
                if is_strong_network_scope_id(bound_scope) and bound_mac:
                    if active_scope == bound_scope and device_mac == bound_mac:
                        alias = str(record.get("alias") or "") or None
                        break
            result.append(
                {**device, "alias": alias, "name": alias}
                if alias
                else device
            )
        return result

    def set_device_alias(self, device_id: str, alias: str | None, home_id: str = HOME["home_id"]) -> None:
        if alias and not is_safe_device_alias(alias):
            raise ValueError("기기 별칭에는 확인된 제품 이름만 사용할 수 있습니다.")
        stored_id = self._resolve_stored_device_id(device_id, home_id) or device_id
        has_observed_scan, network_scope_id = self._latest_valid_network_scope(home_id)
        physical_mac = None
        if has_observed_scan and is_strong_network_scope_id(network_scope_id):
            current = self._latest_observed_scan_devices(home_id) or []
            matched = next(
                (item for item in current if str(item.get("device_id") or "") == stored_id),
                None,
            )
            physical_mac = normalized_physical_mac((matched or {}).get("mac_address"))
        with self.engine.begin() as conn:
            if alias:
                if physical_mac:
                    conn.execute(
                        delete(device_aliases_table).where(
                            device_aliases_table.c.home_id == home_id,
                            device_aliases_table.c.network_scope_id == network_scope_id,
                            func.upper(device_aliases_table.c.physical_mac) == physical_mac,
                        )
                    )
                self._upsert(
                    conn,
                    device_aliases_table,
                    {
                        "home_id": home_id,
                        "device_id": stored_id,
                        "network_scope_id": network_scope_id if physical_mac else None,
                        "physical_mac": physical_mac,
                        "alias": alias,
                        "updated_at": utc_now(),
                    },
                    index_elements=["home_id", "device_id"],
                )
            else:
                predicate = device_aliases_table.c.device_id == stored_id
                if physical_mac:
                    predicate = or_(
                        predicate,
                        and_(
                            device_aliases_table.c.network_scope_id == network_scope_id,
                            func.upper(device_aliases_table.c.physical_mac) == physical_mac,
                        ),
                    )
                conn.execute(
                    delete(device_aliases_table).where(
                        device_aliases_table.c.home_id == home_id,
                        predicate,
                    )
                )

    @staticmethod
    def _public_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            presented
            for device in devices
            if not is_self_observation(device)
            and (
                presented := apply_device_presentation(
                    score_device_with_current_cve(device)
                )
            ) is not None
        ]

    def security_score(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        latest_context = self.latest_scan_context(home_id=home_id)
        has_scan = latest_context is not None
        partial_scan = scan_is_partial(latest_context)
        coverage_complete = None if not has_scan else not partial_scan
        _, summary = summarize_public_security(
            self._stored_devices(home_id),
            coverage_complete=coverage_complete,
        )
        pending_findings = visible_identity_findings(
            self.identity_findings(home_id=home_id)
        )
        if pending_findings and has_scan:
            summary = _hold_identity_incomplete_security(summary, pending_findings)
        if partial_scan:
            summary = project_partial_security(summary)
        return {
            "home_id": home_id,
            "score": summary["score"],
            "score_status": public_score_status(summary, coverage_complete=coverage_complete),
            "risk_level": summary["risk_level"],
            "summary": summary["summary"],
            "device_scores": summary["device_scores"],
            "identity_incomplete": bool(pending_findings),
            "identity_pending_count": len(pending_findings),
            "identity_findings": pending_findings,
            "scan_complete": coverage_complete is True,
            "coverage_complete": coverage_complete,
        }

    def security_events(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        observations = [
            *self.devices(home_id=home_id),
            *visible_identity_findings(self.identity_findings(home_id=home_id)),
        ]
        return _project_security_events(home_id, observations)

    # ---------------- 스캔 ----------------

    def create_scan(
        self,
        scan_profile: str = "quick",
        scan_source: str = "android-native",
        network_context: dict[str, Any] | None = None,
        discovered_devices: list[dict[str, Any]] | None = None,
        home_id: str = HOME["home_id"],
    ) -> dict[str, Any]:
        if scan_source != _AUTHORITATIVE_SCAN_SOURCE:
            raise ValueError("unsupported scan source")
        return self._record_scan(
            scan_profile=scan_profile,
            scan_source=scan_source,
            network_context=network_context,
            discovered_devices=discovered_devices,
            home_id=home_id,
        )

    def record_windows_port_probe(
        self,
        *,
        network_context: dict[str, Any] | None,
        discovered_devices: list[dict[str, Any]],
        home_id: str,
        scan_profile: str = "internal-probe",
    ) -> dict[str, Any]:
        """Persist an internal host probe without entering mobile/public state."""

        return self._record_scan(
            scan_profile=scan_profile,
            scan_source="windows-port-probe",
            network_context=network_context,
            discovered_devices=discovered_devices,
            home_id=home_id,
        )

    def _record_scan(
        self,
        *,
        scan_profile: str,
        scan_source: str,
        network_context: dict[str, Any] | None,
        discovered_devices: list[dict[str, Any]] | None,
        home_id: str,
    ) -> dict[str, Any]:
        if discovered_devices is None:
            raise ValueError("discovered_devices is required")
        with self.engine.begin() as conn:
            owner = conn.execute(
                select(users_table.c.user_id)
                .join(homes_table, homes_table.c.home_id == users_table.c.home_id)
                .where(homes_table.c.home_id == home_id)
                .limit(1)
            ).first()
        if owner is None:
            raise ValueError("authenticated home does not exist")
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            rejection_reasons = actual_android_scan_rejection_reasons(
                network_context,
                discovered_devices,
            )
            if rejection_reasons:
                raise ValueError("actual Android scan evidence is required")
        network_scope_id = derive_network_scope_id(
            home_id=home_id,
            network_context=network_context,
            discovered_devices=discovered_devices,
        )
        strong_scope_candidates = (
            derive_strong_network_scope_ids(
                home_id=home_id,
                network_context=network_context,
                discovered_devices=discovered_devices,
            )
            if scan_source == _AUTHORITATIVE_SCAN_SOURCE
            else ()
        )
        stored_network_context = normalize_stored_network_context(network_context)
        public_network_context = sanitize_public_network_context(stored_network_context)
        stored_devices, attested_self_job_devices = self._store_discovered_devices(
            discovered_devices,
            scan_source=scan_source,
            home_id=home_id,
            network_scope_id=network_scope_id,
        )
        history_self_job_devices = (
            self._authenticated_self_history_job_devices(
                stored_devices,
                home_id=home_id,
                current_scope_candidates=strong_scope_candidates,
            )
            if scan_source == _AUTHORITATIVE_SCAN_SOURCE
            else []
        )
        history_self_macs = {
            mac
            for device in history_self_job_devices
            if (mac := normalized_physical_mac(device.get("mac_address"))) is not None
        }
        attested_self_job_devices.extend(history_self_job_devices)
        projected_devices = self._apply_approved_manual_identities(
            stored_devices,
            home_id=home_id,
            network_scope_id=network_scope_id,
        )
        aliased_devices = self._apply_aliases(
            [device for device in projected_devices if not is_self_observation(device)],
            home_id,
            network_scope_id=network_scope_id,
            observed_scope_supplied=True,
        )
        partial_scan = scan_is_partial(stored_network_context)
        public_devices, summary = summarize_public_security(
            aliased_devices,
            coverage_complete=not partial_scan,
        )
        raw_identity_findings = build_public_identity_findings(
            aliased_devices,
            public_devices,
        )
        identity_findings = visible_identity_findings(raw_identity_findings)
        identity_incomplete = bool(identity_findings)
        incomplete_scan = partial_scan
        if partial_scan:
            summary = project_partial_security(summary)
        elif identity_findings:
            summary = _hold_identity_incomplete_security(summary, identity_findings)
        security_score_payload = {
            "home_id": home_id,
            "score": summary["score"],
            "score_status": public_score_status(summary, coverage_complete=not partial_scan),
            "risk_level": summary["risk_level"],
            "summary": summary["summary"],
            "device_scores": summary["device_scores"],
            "identity_incomplete": bool(identity_findings),
            "identity_pending_count": len(identity_findings),
            "scan_complete": not incomplete_scan,
            "coverage_complete": not partial_scan,
        }
        # devices_found·high_risk_devices·알림(FCM/저장값)은 phantom 제외 실기기 기준(sqlite_repository 동일).
        real_devices = public_devices
        high_risk_devices = confirmed_public_red_count(real_devices, identity_findings)
        scan_id = f"scan-{uuid4()}"
        created_at = utc_now()
        with self.engine.begin() as conn:
            conn.execute(
                insert(scans_table).values(
                    scan_id=scan_id,
                    home_id=home_id,
                    status="partial" if incomplete_scan else "completed",
                    progress=100,
                    scan_profile=scan_profile,
                    scan_source=scan_source,
                    network_context_json=json.dumps(stored_network_context, ensure_ascii=False),
                    network_scope_id=network_scope_id,
                    current_step=(
                        PARTIAL_SCAN_STEP
                        if partial_scan
                        else IDENTITY_PENDING_STEP
                        if identity_incomplete
                        else "점검 완료"
                    ),
                    devices_found=len(real_devices) + len(identity_findings),
                    high_risk_devices=high_risk_devices,
                    security_score_json=json.dumps(security_score_payload, ensure_ascii=False),
                    created_at=created_at,
                )
            )
            # Persist private observations for merge/re-identification only.  They
            # are never returned through the public scan result or used in counts.
            for device in stored_devices:
                conn.execute(
                    insert(scan_devices_table).values(
                        scan_id=scan_id,
                        device_snapshot_json=json.dumps(device, ensure_ascii=False),
                    )
                )
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            finding_ids = {
                str(finding.get("device_id") or "")
                for finding in raw_identity_findings
            }
            unresolved_job_devices = [
                device
                for device in stored_devices
                if public_device_id(device.get("device_id"), home_id) in finding_ids
                and normalized_physical_mac(device.get("mac_address"))
                not in history_self_macs
            ]
            self._upsert_identity_enrichment_jobs(
                [
                    *unresolved_job_devices,
                    *attested_self_job_devices,
                ],
                home_id=home_id,
                network_scope_id=network_scope_id,
                ambiguity_devices=stored_devices,
            )
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            self._create_notification(
                notification_type="scan_completed",
                title="보안 점검 일부 완료" if partial_scan else "보안 점검 완료",
                message=(
                    PARTIAL_SCAN_NOTIFICATION
                    if partial_scan
                    else scan_completed_message(real_devices, identity_findings, security_score_payload)
                ),
                home_id=home_id,
                scan_id=scan_id,
                scan_source=scan_source,
            )
        return {
            "scan_id": scan_id,
            "home_id": home_id,
            "status": "partial" if incomplete_scan else "completed",
            "progress": 100,
            "scan_profile": scan_profile,
            "scan_source": scan_source,
            "network_context": public_network_context,
            "current_step": (
                PARTIAL_SCAN_STEP
                if partial_scan
                else IDENTITY_PENDING_STEP
                if identity_incomplete
                else "점검 완료"
            ),
            "devices_found": len(real_devices) + len(identity_findings),
            "identified_count": len(real_devices),
            "identity_pending_count": len(identity_findings),
            "high_risk_devices": high_risk_devices,
            "devices": public_devices,
            # Keep resolver evidence for the authenticated HTTP projection
            # boundary. Aggregate fields above use only resident-visible rows.
            "identity_findings": raw_identity_findings,
            "events": _project_security_events(home_id, [*real_devices, *identity_findings]),
            "security_score": security_score_payload,
            "created_at": created_at,
        }

    def _validated_scan_row_snapshot(
        self,
        data: dict[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Revalidate one exact stored Android row before public projection."""

        try:
            network_context = json.loads(data.get("network_context_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            network_context = {}
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(scan_devices_table.c.device_snapshot_json)
                .where(scan_devices_table.c.scan_id == data.get("scan_id"))
                .order_by(scan_devices_table.c.id.asc())
            ).all()
        devices: list[dict[str, Any]] = []
        for row in rows:
            try:
                snapshot = json.loads(row[0])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(snapshot, dict):
                devices.append(snapshot)
        return _validated_authoritative_snapshot(network_context, devices)

    def scan_status(self, scan_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(scans_table).where(
                    scans_table.c.scan_id == scan_id,
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
            ).first()
        data = row_to_dict(row)
        if data is None:
            return None
        if data["scan_source"] == _AUTHORITATIVE_SCAN_SOURCE:
            bounded = self._validated_scan_row_snapshot(data)
            if bounded is None:
                return None
            network_context, snapshots = bounded
            from .sqlite_repository import apply_verified_product_catalog_projection

            snapshots = apply_verified_product_catalog_projection(
                snapshots,
                self.verified_product_catalog_entries(),
            )
            snapshots = self._apply_approved_manual_identities(
                snapshots,
                home_id=home_id,
                network_scope_id=data.get("network_scope_id"),
            )
            aliased_snapshots = self._apply_aliases(
                [device for device in snapshots if not is_self_observation(device)],
                home_id,
                network_scope_id=data.get("network_scope_id"),
                observed_scope_supplied=True,
            )
            partial_scan = scan_is_partial(network_context)
            public_devices, summary = summarize_public_security(
                aliased_snapshots,
                coverage_complete=not partial_scan,
            )
            if partial_scan:
                summary = project_partial_security(summary)
            raw_findings = build_public_identity_findings(
                aliased_snapshots,
                public_devices,
            )
            findings = visible_identity_findings(raw_findings)
            incomplete_scan = partial_scan
            return {
                "scan_id": data["scan_id"],
                "status": "partial" if incomplete_scan else "completed",
                "progress": data["progress"],
                "scan_source": data["scan_source"],
                "current_step": (
                    PARTIAL_SCAN_STEP
                    if partial_scan
                    else IDENTITY_PENDING_STEP
                    if findings
                    else "점검 완료"
                ),
                "scan_complete": not incomplete_scan,
                "coverage_complete": not partial_scan,
                "identity_pending_count": len(findings),
                "score_status": public_score_status(summary, coverage_complete=not partial_scan),
                "devices_found": len(public_devices) + len(findings),
                "high_risk_devices": confirmed_public_red_count(public_devices, findings),
                "created_at": data["created_at"],
            }
        return None

    def scan_result(self, scan_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(scans_table).where(
                    scans_table.c.scan_id == scan_id,
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
            ).first()
            data = row_to_dict(row)
            if data is None:
                return None

        # Real scan consumers share one current-membership view.  This mirrors
        # SQLite: latest membership, with identity/firmware enrichment only
        # from the same strong network scope and physical MAC.
        if data["scan_source"] == _AUTHORITATIVE_SCAN_SOURCE:
            requested_snapshot = self._validated_scan_row_snapshot(data)
            if requested_snapshot is None:
                return None
            requested_context, _requested_devices = requested_snapshot
            stored_current = self._stored_devices(home_id)
            current_context = self.latest_scan_context(home_id) or requested_context
            requested_partial = scan_is_partial(requested_context)
            current_partial = scan_is_partial(current_context)
            partial_scan = requested_partial or current_partial
            current_devices, summary = summarize_public_security(
                stored_current,
                coverage_complete=not partial_scan,
            )
            stored_context = requested_context if requested_partial else current_context
            latest_observed = self._latest_scan_devices_only(home_id)
            finding_source = stored_current if latest_observed is None else latest_observed
            raw_current_findings = build_public_identity_findings(
                finding_source,
                current_devices,
            )
            current_findings = visible_identity_findings(raw_current_findings)
            if partial_scan:
                summary = project_partial_security(summary)
            elif current_findings:
                summary = _hold_identity_incomplete_security(summary, current_findings)
            incomplete_scan = partial_scan
            return {
                "scan_id": data["scan_id"],
                "home_id": data["home_id"],
                "status": "partial" if incomplete_scan else "completed",
                "progress": data["progress"],
                "scan_profile": data["scan_profile"],
                "scan_source": data["scan_source"],
                "network_context": sanitize_public_network_context(stored_context),
                "current_step": (
                    PARTIAL_SCAN_STEP
                    if partial_scan
                    else IDENTITY_PENDING_STEP
                    if current_findings
                    else "점검 완료"
                ),
                "devices_found": len(current_devices) + len(current_findings),
                "identified_count": len(current_devices),
                "identity_pending_count": len(current_findings),
                "high_risk_devices": confirmed_public_red_count(current_devices, current_findings),
                "devices": current_devices,
                # The HTTP boundary projects this raw resolver evidence list;
                # counters, scores and events above use only visible findings.
                "identity_findings": raw_current_findings,
                "events": self.security_events(home_id=home_id),
                "security_score": {
                    "home_id": home_id,
                    "score": summary["score"],
                    "risk_level": summary["risk_level"],
                    "summary": summary["summary"],
                    "device_scores": summary["device_scores"],
                    "score_status": public_score_status(summary, coverage_complete=not partial_scan),
                    "identity_incomplete": bool(current_findings),
                    "identity_pending_count": len(current_findings),
                    "scan_complete": not incomplete_scan,
                    "coverage_complete": not partial_scan,
                },
                "created_at": data["created_at"],
            }

        return None

    def finalize_identity_researched_scan(
        self,
        scan_id: str,
        *,
        home_id: str = HOME["home_id"],
    ) -> bool:
        """Refresh a completed projection after research without duplicating alerts."""

        result = self.scan_result(scan_id, home_id=home_id)
        if result is None or result.get("status") != "completed":
            return False
        if max(0, int(result.get("identity_pending_count") or 0)):
            return False
        score = result.get("security_score")
        if (
            not isinstance(score, Mapping)
            or score.get("scan_complete") is not True
            or score.get("coverage_complete") is not True
        ):
            return False

        notification = sanitize_public_notification(
            {
                "title": "보안 점검 완료",
                "message": scan_completed_message(list(result.get("devices") or []), [], score),
            }
        )
        notification_id = "scan-complete-" + hashlib.sha256(
            f"{home_id}\0{scan_id}".encode("utf-8")
        ).hexdigest()[:32]
        now = utc_now()
        with self.engine.begin() as conn:
            updated = conn.execute(
                update(scans_table)
                .where(
                    scans_table.c.scan_id == scan_id,
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .values(
                    status="completed",
                    current_step="점검 완료",
                    devices_found=int(result.get("devices_found") or 0),
                    high_risk_devices=int(result.get("high_risk_devices") or 0),
                    security_score_json=json.dumps(dict(score), ensure_ascii=False),
                )
            )
            if updated.rowcount != 1:
                return False
            existing = conn.execute(
                select(notifications_table.c.notification_id)
                .where(
                    notifications_table.c.home_id == home_id,
                    notifications_table.c.scan_id == scan_id,
                    notifications_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                    notifications_table.c.type == "scan_completed",
                )
                .limit(1)
            ).first()
            if existing is None:
                conn.execute(
                    text(
                        """
                        INSERT INTO notifications (
                            notification_id, home_id, type, title, message,
                            scan_id, scan_source, read, created_at
                        ) VALUES (
                            :notification_id, :home_id, 'scan_completed', :title, :message,
                            :scan_id, :scan_source, 0, :created_at
                        ) ON CONFLICT(notification_id) DO NOTHING
                        """
                    ),
                    {
                        "notification_id": notification_id,
                        "home_id": home_id,
                        "title": notification["title"],
                        "message": notification["message"],
                        "scan_id": scan_id,
                        "scan_source": _AUTHORITATIVE_SCAN_SOURCE,
                        "created_at": now,
                    },
                )
            else:
                conn.execute(
                    update(notifications_table)
                    .where(
                        notifications_table.c.home_id == home_id,
                        notifications_table.c.scan_id == scan_id,
                        notifications_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                        notifications_table.c.type == "scan_completed",
                    )
                    .values(
                        title=notification["title"],
                        message=notification["message"],
                    )
                )
        return True

    # ---------------- 보호자 ----------------

    def _next_guardian_short_code(self) -> str:
        with self.engine.begin() as conn:
            rows = conn.execute(select(guardian_invites_table.c.short_code).where(guardian_invites_table.c.short_code.is_not(None))).all()
        existing_codes = {str(row[0]).strip().upper() for row in rows if row[0]}
        return generate_short_code(existing_codes)

    def create_guardian_invite(
        self,
        email: str,
        relation: str,
        ward_account_name: str | None = None,
        home_id: str = HOME["home_id"],
    ) -> dict[str, Any]:
        created_at = utc_now()
        short_code = self._next_guardian_short_code()
        invite = {
            "invite_id": f"invite-{uuid4()}",
            "home_id": home_id,
            "email": email,
            "relation": relation,
            "display_name": default_display_name(email, relation),
            "ward_account_name": clean_optional_name(ward_account_name),
            "short_code": short_code,
            "deep_link": build_deep_link(short_code),
            "status": "pending",
            "message": "보호자 초대 링크와 짧은 코드를 만들었어요.",
            "created_at": created_at,
            "expires_at": invite_expires_at(created_at),
            "accepted_at": None,
            "revoked_at": None,
            "last_viewed_at": None,
            "guardian_token_hash": None,
            "session_created_at": None,
            "session_last_used_at": None,
        }
        with self.engine.begin() as conn:
            home_exists = conn.execute(
                select(homes_table.c.home_id)
                .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                .where(homes_table.c.home_id == home_id)
                .limit(1)
            ).first()
            if not str(home_id or "").strip() or home_exists is None:
                raise ValueError("authenticated home does not exist")
            invite["ward_account_name"] = invite["ward_account_name"] or self._fallback_ward_account_name(conn, home_id)
            conn.execute(insert(guardian_invites_table).values(**invite))
        self._create_notification(
            notification_type="guardian_invite",
            title="보호자 초대 전송",
            message=f"{email} 보호자에게 링크와 짧은 코드 초대를 만들었어요.",
            home_id=home_id,
        )
        return deepcopy(normalize_guardian_invite(invite))

    def guardians(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(guardian_invites_table)
                .join(homes_table, homes_table.c.home_id == guardian_invites_table.c.home_id)
                .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                .where(guardian_invites_table.c.home_id == home_id)
                .order_by(desc(guardian_invites_table.c.created_at))
            ).all()
        return [normalize_guardian_invite(row_to_dict(r) or {}) for r in rows if r]

    def guardian_invite_summary(self, home_id: str = HOME["home_id"]) -> dict[str, int]:
        return guardian_invite_summary(self.guardians(home_id=home_id))

    def guardian_count(self, home_id: str = HOME["home_id"]) -> int:
        return self.guardian_invite_summary(home_id=home_id)["accepted"]

    def upsert_guardian_account(
        self,
        guardian_id: str,
        email: str,
        display_name: str | None = None,
        provider: str = "google",
    ) -> dict[str, Any]:
        now = utc_now()
        values = {
            "guardian_id": guardian_id.strip(),
            "email": email.strip().lower(),
            "display_name": (display_name or email).strip(),
            "provider": provider.strip().lower(),
            "created_at": now,
            "last_login_at": now,
        }
        if (
            not values["guardian_id"]
            or not values["email"]
            or not values["display_name"]
            or values["provider"] != "google"
        ):
            raise ValueError("verified Google guardian account is required")
        with self.engine.begin() as conn:
            self._upsert(conn, guardian_accounts_table, values, index_elements=["guardian_id"])
        return self.guardian_account_by_id(values["guardian_id"]) or values

    def guardian_account_by_id(self, guardian_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(select(guardian_accounts_table).where(guardian_accounts_table.c.guardian_id == guardian_id)).first()
        return row_to_dict(row)

    def accept_guardian_invite_for_account(self, invite_lookup: str, guardian: dict[str, Any]) -> dict[str, Any]:
        lookup = normalize_invite_lookup(invite_lookup)
        if not lookup:
            return {
                "ok": False,
                "status_code": 400,
                "code": "GUARDIAN_INVITE_REQUIRED",
                "message": "초대 링크 또는 짧은 코드를 입력해 주세요.",
            }

        guardian_id = str(guardian.get("guardian_id") or "").strip()
        guardian_email = str(guardian.get("guardian_email") or guardian.get("email") or "").strip().lower()
        guardian_name = str(guardian.get("guardian_name") or guardian.get("display_name") or guardian_email).strip()
        if not guardian_id or not guardian_email:
            return {
                "ok": False,
                "status_code": 400,
                "code": "GUARDIAN_ACCOUNT_REQUIRED",
                "message": "보호자 Google 로그인이 먼저 필요합니다.",
            }

        accepted_at = utc_now()
        with self.engine.begin() as conn:
            invite_row = conn.execute(
                select(guardian_invites_table).where(
                    (guardian_invites_table.c.invite_id == lookup) | (guardian_invites_table.c.short_code == lookup.upper())
                )
            ).first()
            if invite_row is None:
                return {
                    "ok": False,
                    "status_code": 404,
                    "code": "GUARDIAN_INVITE_404",
                    "message": "초대 코드를 찾을 수 없어요. 코드를 다시 확인해 주세요.",
                }
            invite_data = normalize_guardian_invite(row_to_dict(invite_row) or {})
            invite_home_id = str(invite_data.get("home_id") or "").strip()
            home_exists = bool(
                invite_home_id
                and conn.execute(
                    select(homes_table.c.home_id)
                    .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                    .where(homes_table.c.home_id == invite_home_id)
                    .limit(1)
                ).first()
            )
            if not home_exists:
                return {
                    "ok": False,
                    "status_code": 409,
                    "code": "GUARDIAN_INVITE_HOME_INVALID",
                    "message": "초대의 피보호자 집 정보를 확인하지 못했어요. 사용자에게 새 초대를 요청해 주세요.",
                }
            if invite_data.get("status") == "revoked":
                return {
                    "ok": False,
                    "status_code": 410,
                    "code": "GUARDIAN_INVITE_REVOKED",
                    "message": "취소된 보호자 초대입니다. 새 초대를 요청해 주세요.",
                }
            if invite_data.get("status") == "expired":
                return {
                    "ok": False,
                    "status_code": 410,
                    "code": "GUARDIAN_INVITE_EXPIRED",
                    "message": "만료된 보호자 초대입니다. 새 초대를 요청해 주세요.",
                }

            existing_link = conn.execute(
                select(guardian_ward_links_table).where(
                    guardian_ward_links_table.c.invite_id == invite_data["invite_id"],
                    guardian_ward_links_table.c.status == "active",
                )
            ).first()
            if existing_link is not None:
                existing_link_data = row_to_dict(existing_link) or {}
                if str(existing_link_data.get("home_id") or "").strip() != invite_home_id:
                    return {
                        "ok": False,
                        "status_code": 409,
                        "code": "GUARDIAN_LINK_HOME_MISMATCH",
                        "message": "보호자 연결의 집 정보가 일치하지 않아요. 사용자에게 새 초대를 요청해 주세요.",
                    }
                if existing_link_data.get("guardian_id") != guardian_id:
                    return {
                        "ok": False,
                        "status_code": 409,
                        "code": "GUARDIAN_INVITE_ALREADY_ACCEPTED",
                        "message": "이미 다른 보호자 계정에 추가된 초대입니다. 사용자에게 새 초대를 요청해 주세요.",
                    }
                account_values = {
                    "guardian_id": guardian_id,
                    "email": guardian_email,
                    "display_name": guardian_name or guardian_email,
                    "provider": str(guardian.get("provider") or "google"),
                    "created_at": accepted_at,
                    "last_login_at": accepted_at,
                }
                self._upsert(conn, guardian_accounts_table, account_values, index_elements=["guardian_id"])
                conn.execute(
                    update(guardian_ward_links_table)
                    .where(guardian_ward_links_table.c.link_id == existing_link_data["link_id"])
                    .values(last_viewed_at=accepted_at)
                )
                conn.execute(
                    update(guardian_invites_table)
                    .where(guardian_invites_table.c.invite_id == invite_data["invite_id"])
                    .values(last_viewed_at=accepted_at)
                )
                account_row = conn.execute(select(guardian_accounts_table).where(guardian_accounts_table.c.guardian_id == guardian_id)).first()
                link_row = conn.execute(select(guardian_ward_links_table).where(guardian_ward_links_table.c.link_id == existing_link_data["link_id"])).first()
                invite_row = conn.execute(select(guardian_invites_table).where(guardian_invites_table.c.invite_id == invite_data["invite_id"])).first()
                return {
                    "ok": True,
                    "guardian": row_to_dict(account_row) or account_values,
                    "ward": _guardian_ward_from_row(row_to_dict(link_row)),
                    "invite": normalize_guardian_invite(row_to_dict(invite_row) or invite_data),
                }

            any_existing_link = conn.execute(
                select(guardian_ward_links_table).where(guardian_ward_links_table.c.invite_id == invite_data["invite_id"]).limit(1)
            ).first()
            if invite_data.get("status") == "accepted" and any_existing_link is not None:
                return {
                    "ok": False,
                    "status_code": 409,
                    "code": "GUARDIAN_INVITE_ALREADY_ACCEPTED",
                    "message": "이미 사용된 초대입니다. 다시 연결하려면 사용자에게 새 초대를 요청해 주세요.",
                }

            account_values = {
                "guardian_id": guardian_id,
                "email": guardian_email,
                "display_name": guardian_name or guardian_email,
                "provider": str(guardian.get("provider") or "google"),
                "created_at": accepted_at,
                "last_login_at": accepted_at,
            }
            self._upsert(conn, guardian_accounts_table, account_values, index_elements=["guardian_id"])

            ward_account_name = clean_optional_name(invite_data.get("ward_account_name")) or self._fallback_ward_account_name(conn, invite_home_id)
            link_values = {
                "link_id": f"ward-link-{uuid4()}",
                "guardian_id": guardian_id,
                "invite_id": invite_data["invite_id"],
                "home_id": invite_home_id,
                "ward_account_name": ward_account_name,
                "ward_alias": None,
                "ward_display_name": ward_account_name,
                "status": "active",
                "accepted_at": accepted_at,
                "revoked_at": None,
                "last_viewed_at": accepted_at,
            }
            conn.execute(insert(guardian_ward_links_table).values(**link_values))
            conn.execute(
                update(guardian_invites_table)
                .where(guardian_invites_table.c.invite_id == invite_data["invite_id"])
                .where(guardian_invites_table.c.revoked_at.is_(None))
                .values(
                    last_viewed_at=accepted_at,
                    accepted_at=func.coalesce(guardian_invites_table.c.accepted_at, accepted_at),
                    ward_account_name=func.coalesce(guardian_invites_table.c.ward_account_name, ward_account_name),
                    status="accepted",
                    message="보호자 계정에 연결됐어요.",
                )
            )
            account_row = conn.execute(select(guardian_accounts_table).where(guardian_accounts_table.c.guardian_id == guardian_id)).first()
            link_row = conn.execute(select(guardian_ward_links_table).where(guardian_ward_links_table.c.link_id == link_values["link_id"])).first()
            invite_row = conn.execute(select(guardian_invites_table).where(guardian_invites_table.c.invite_id == invite_data["invite_id"])).first()

        return {
            "ok": True,
            "guardian": row_to_dict(account_row) or account_values,
            "ward": _guardian_ward_from_row(row_to_dict(link_row)),
            "invite": normalize_guardian_invite(row_to_dict(invite_row) or invite_data),
        }

    def guardian_wards(self, guardian_id: str) -> list[dict[str, Any]]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(guardian_ward_links_table)
                .join(
                    guardian_invites_table,
                    and_(
                        guardian_invites_table.c.invite_id == guardian_ward_links_table.c.invite_id,
                        guardian_invites_table.c.home_id == guardian_ward_links_table.c.home_id,
                    ),
                )
                .join(
                    guardian_accounts_table,
                    guardian_accounts_table.c.guardian_id == guardian_ward_links_table.c.guardian_id,
                )
                .join(homes_table, homes_table.c.home_id == guardian_ward_links_table.c.home_id)
                .join(users_table, users_table.c.home_id == guardian_ward_links_table.c.home_id)
                .where(
                    guardian_ward_links_table.c.guardian_id == guardian_id,
                    guardian_ward_links_table.c.status == "active",
                    guardian_ward_links_table.c.revoked_at.is_(None),
                    guardian_invites_table.c.revoked_at.is_(None),
                    or_(
                        guardian_invites_table.c.accepted_at.is_not(None),
                        func.lower(guardian_invites_table.c.status) == "accepted",
                    ),
                    func.lower(func.trim(guardian_accounts_table.c.provider)) == "google",
                    func.trim(func.coalesce(guardian_accounts_table.c.email, "")) != "",
                    func.trim(func.coalesce(guardian_accounts_table.c.display_name, "")) != "",
                    users_table.c.role == "user",
                    func.trim(func.coalesce(users_table.c.email, "")) != "",
                    func.trim(func.coalesce(users_table.c.nickname, "")) != "",
                )
                .order_by(desc(guardian_ward_links_table.c.accepted_at))
            ).all()
        return [_guardian_ward_from_row(row_to_dict(row)) for row in rows]

    def guardian_ward_link_by_id(self, link_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(guardian_ward_links_table)
                .join(
                    guardian_invites_table,
                    and_(
                        guardian_invites_table.c.invite_id == guardian_ward_links_table.c.invite_id,
                        guardian_invites_table.c.home_id == guardian_ward_links_table.c.home_id,
                    ),
                )
                .join(
                    guardian_accounts_table,
                    guardian_accounts_table.c.guardian_id == guardian_ward_links_table.c.guardian_id,
                )
                .join(homes_table, homes_table.c.home_id == guardian_ward_links_table.c.home_id)
                .join(users_table, users_table.c.home_id == guardian_ward_links_table.c.home_id)
                .where(
                    guardian_ward_links_table.c.link_id == link_id,
                    or_(
                        and_(
                            guardian_ward_links_table.c.status == "active",
                            guardian_ward_links_table.c.revoked_at.is_(None),
                            guardian_invites_table.c.revoked_at.is_(None),
                            or_(
                                guardian_invites_table.c.accepted_at.is_not(None),
                                func.lower(guardian_invites_table.c.status) == "accepted",
                            ),
                        ),
                        guardian_ward_links_table.c.status == "revoked",
                    ),
                    func.lower(func.trim(guardian_accounts_table.c.provider)) == "google",
                    func.trim(func.coalesce(guardian_accounts_table.c.email, "")) != "",
                    func.trim(func.coalesce(guardian_accounts_table.c.display_name, "")) != "",
                    users_table.c.role == "user",
                    func.trim(func.coalesce(users_table.c.email, "")) != "",
                    func.trim(func.coalesce(users_table.c.nickname, "")) != "",
                )
            ).first()
        return _guardian_ward_from_row(row_to_dict(row)) if row else None

    def update_guardian_ward_alias(self, link_id: str, ward_alias: str | None) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        alias = clean_optional_name(ward_alias)
        with self.engine.begin() as conn:
            row = conn.execute(select(guardian_ward_links_table).where(guardian_ward_links_table.c.link_id == link_id)).first()
            data = row_to_dict(row)
            if data is None:
                return None
            home_id = str(data.get("home_id") or "").strip()
            if not home_id:
                return None
            ward_account_name = clean_optional_name(data.get("ward_account_name")) or self._fallback_ward_account_name(conn, home_id)
            conn.execute(
                update(guardian_ward_links_table)
                .where(guardian_ward_links_table.c.link_id == link_id)
                .values(
                    ward_account_name=ward_account_name,
                    ward_alias=alias,
                    ward_display_name=alias or ward_account_name,
                )
            )
            updated = conn.execute(select(guardian_ward_links_table).where(guardian_ward_links_table.c.link_id == link_id)).first()
        return _guardian_ward_from_row(row_to_dict(updated))

    def mark_guardian_ward_viewed(self, link_id: str) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        viewed_at = utc_now()
        with self.engine.begin() as conn:
            conn.execute(
                update(guardian_ward_links_table)
                .where(guardian_ward_links_table.c.link_id == link_id)
                .values(last_viewed_at=viewed_at)
            )
        return self.guardian_ward_link_by_id(link_id)

    def revoke_guardian_ward_link(self, link_id: str) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        revoked_at = utc_now()
        with self.engine.begin() as conn:
            conn.execute(
                update(guardian_ward_links_table)
                .where(guardian_ward_links_table.c.link_id == link_id)
                .values(status="revoked", revoked_at=func.coalesce(guardian_ward_links_table.c.revoked_at, revoked_at))
            )
            updated = conn.execute(
                select(guardian_ward_links_table).where(
                    guardian_ward_links_table.c.link_id == link_id
                )
            ).first()
        return _guardian_ward_from_row(row_to_dict(updated)) if updated else None

    def guardian_invite_by_id(self, invite_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(guardian_invites_table)
                .join(homes_table, homes_table.c.home_id == guardian_invites_table.c.home_id)
                .join(users_table, users_table.c.home_id == guardian_invites_table.c.home_id)
                .where(guardian_invites_table.c.invite_id == invite_id)
            ).first()
        data = row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def guardian_invite_by_lookup(self, invite_lookup: str) -> dict[str, Any] | None:
        lookup = normalize_invite_lookup(invite_lookup)
        if not lookup:
            return None
        with self.engine.begin() as conn:
            row = conn.execute(
                select(guardian_invites_table)
                .join(homes_table, homes_table.c.home_id == guardian_invites_table.c.home_id)
                .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                .where(
                    (guardian_invites_table.c.invite_id == lookup) | (guardian_invites_table.c.short_code == lookup.upper())
                )
            ).first()
        data = row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def guardian_invite_by_session_token(self, session_token: str) -> dict[str, Any] | None:
        token_hash = hash_guardian_session_token(session_token)
        if not token_hash:
            return None
        with self.engine.begin() as conn:
            row = conn.execute(
                select(guardian_invites_table)
                .join(homes_table, homes_table.c.home_id == guardian_invites_table.c.home_id)
                .join(users_table, users_table.c.home_id == homes_table.c.home_id)
                .where(guardian_invites_table.c.guardian_token_hash == token_hash)
            ).first()
        data = row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def mark_guardian_invite_viewed(self, invite_id: str, guardian_token_hash: str | None = None) -> dict[str, Any] | None:
        if self.guardian_invite_by_id(invite_id) is None:
            return None
        viewed_at = utc_now()
        values = {
            "last_viewed_at": viewed_at,
            "accepted_at": func.coalesce(guardian_invites_table.c.accepted_at, viewed_at),
            "status": case(
                (guardian_invites_table.c.status.in_(["pending", "sent"]), "accepted"),
                else_=guardian_invites_table.c.status,
            ),
        }
        if guardian_token_hash:
            values["guardian_token_hash"] = guardian_token_hash
            values["session_created_at"] = func.coalesce(guardian_invites_table.c.session_created_at, viewed_at)
            values["session_last_used_at"] = viewed_at
        with self.engine.begin() as conn:
            conn.execute(
                update(guardian_invites_table)
                .where(guardian_invites_table.c.invite_id == invite_id)
                .where(guardian_invites_table.c.revoked_at.is_(None))
                .values(**values)
            )
        return self.guardian_invite_by_id(invite_id)

    def mark_guardian_session_used(self, invite_id: str) -> dict[str, Any] | None:
        if self.guardian_invite_by_id(invite_id) is None:
            return None
        viewed_at = utc_now()
        with self.engine.begin() as conn:
            conn.execute(
                update(guardian_invites_table)
                .where(guardian_invites_table.c.invite_id == invite_id)
                .where(guardian_invites_table.c.revoked_at.is_(None))
                .values(last_viewed_at=viewed_at, session_last_used_at=viewed_at)
            )
        return self.guardian_invite_by_id(invite_id)

    def revoke_guardian_invite(self, invite_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        revoked_at = utc_now()
        with self.engine.begin() as conn:
            conn.execute(
                update(guardian_invites_table)
                .where(guardian_invites_table.c.invite_id == invite_id, guardian_invites_table.c.home_id == home_id)
                .values(status="revoked", revoked_at=revoked_at, message="보호자 초대를 취소했어요.")
            )
            conn.execute(
                update(guardian_ward_links_table)
                .where(guardian_ward_links_table.c.invite_id == invite_id, guardian_ward_links_table.c.home_id == home_id)
                .values(status="revoked", revoked_at=revoked_at)
            )
        invite = self.guardian_invite_by_id(invite_id)
        if not invite or invite.get("home_id") != home_id:
            return None
        return invite

    def delete_guardian_invite(self, invite_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        """보호자 초대를 '실제로' 삭제한다(revoke=상태표시와 달리 행 자체 제거). 연결된 ward_link 도 함께 지운다."""
        invite = self.guardian_invite_by_id(invite_id)
        if not invite or invite.get("home_id") != home_id:
            return None
        with self.engine.begin() as conn:
            conn.execute(
                delete(guardian_ward_links_table).where(
                    guardian_ward_links_table.c.invite_id == invite_id,
                    guardian_ward_links_table.c.home_id == home_id,
                )
            )
            conn.execute(
                delete(guardian_invites_table).where(
                    guardian_invites_table.c.invite_id == invite_id,
                    guardian_invites_table.c.home_id == home_id,
                )
            )
        return invite

    def purge_stale_guardian_invites(self, home_id: str = HOME["home_id"], older_than_days: int = 90) -> int:
        """오래된 '만료/취소' 초대 행을 정리한다(누적 방지). pending·accepted 는 보존. 삭제 개수 반환."""
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(guardian_invites_table).where(guardian_invites_table.c.home_id == home_id)
            ).all()
            purge_ids: list[str] = []
            for row in rows:
                invite = row_to_dict(row) or {}
                status = effective_invite_status(invite)
                if status == "revoked":
                    stamp = parse_utc_text(invite.get("revoked_at")) or parse_utc_text(invite.get("created_at"))
                elif status == "expired":
                    stamp = parse_utc_text(invite.get("expires_at")) or parse_utc_text(invite.get("created_at"))
                else:
                    continue
                if stamp is not None and stamp < cutoff:
                    invite_id = invite.get("invite_id")
                    if invite_id:
                        purge_ids.append(str(invite_id))
            if not purge_ids:
                return 0
            conn.execute(delete(guardian_ward_links_table).where(guardian_ward_links_table.c.invite_id.in_(purge_ids)))
            conn.execute(delete(guardian_invites_table).where(guardian_invites_table.c.invite_id.in_(purge_ids)))
        return len(purge_ids)

    # ---------------- 알림 ----------------

    def notifications(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(notifications_table)
                .where(notifications_table.c.home_id == home_id)
                .order_by(desc(notifications_table.c.id))
            ).all()
        notifications: list[dict[str, Any]] = []
        seen_scan_cards: set[tuple[str, str, str]] = set()
        for row in rows:
            row_data = row_to_dict(row) or {}
            if not row_data or not self._notification_is_public(row_data, home_id):
                continue
            if str(row_data.get("type") or "") == "scan_completed":
                key = (
                    str(row_data.get("home_id") or ""),
                    str(row_data.get("scan_id") or ""),
                    str(row_data.get("scan_source") or ""),
                )
                if key in seen_scan_cards:
                    continue
                seen_scan_cards.add(key)
            notifications.append(
                sanitize_public_notification(_notification_from_row(row_data))
            )
        return notifications

    def _notification_is_public(self, row: dict[str, Any], home_id: str) -> bool:
        if str(row.get("type") or "") != "scan_completed":
            return True
        scan_id = str(row.get("scan_id") or "").strip()
        if str(row.get("scan_source") or "") != _AUTHORITATIVE_SCAN_SOURCE or not scan_id:
            return False
        with self.engine.begin() as conn:
            stored = conn.execute(
                select(
                    scans_table.c.status,
                    scans_table.c.scan_source,
                    scans_table.c.security_score_json,
                ).where(
                    scans_table.c.scan_id == scan_id,
                    scans_table.c.home_id == home_id,
                )
            ).first()
        if stored is None or str(stored.scan_source or "") != _AUTHORITATIVE_SCAN_SOURCE:
            return False
        try:
            score = json.loads(stored.security_score_json or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(score, Mapping):
            return False
        if str(stored.status or "") == "partial":
            return str(row.get("title") or "") == "보안 점검 일부 완료"
        return (
            str(stored.status or "") == "completed"
            and str(row.get("title") or "") == "보안 점검 완료"
            and score.get("scan_complete") is True
            and score.get("coverage_complete") is True
        )

    def mark_notification_read(self, notification_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(notifications_table).where(
                    notifications_table.c.notification_id == notification_id,
                    notifications_table.c.home_id == home_id,
                )
            ).first()
            existing_data = row_to_dict(existing)
            if existing_data is None or not self._notification_is_public(existing_data, home_id):
                return None
            conn.execute(
                update(notifications_table)
                .where(notifications_table.c.notification_id == notification_id, notifications_table.c.home_id == home_id)
                .values(read=1)
            )
            row = conn.execute(
                select(notifications_table).where(
                    notifications_table.c.notification_id == notification_id,
                    notifications_table.c.home_id == home_id,
                )
            ).first()
        data = row_to_dict(row)
        return sanitize_public_notification(_notification_from_row(data)) if data else None

    def _create_notification(
        self,
        notification_type: str,
        title: str,
        message: str,
        home_id: str = HOME["home_id"],
        scan_id: str | None = None,
        scan_source: str | None = None,
    ) -> None:
        if notification_type == "scan_completed" and (
            scan_source != _AUTHORITATIVE_SCAN_SOURCE or not str(scan_id or "").strip()
        ):
            raise ValueError("scan notification requires authoritative provenance")
        notification = sanitize_public_notification({"title": title, "message": message})
        with self.engine.begin() as conn:
            conn.execute(
                insert(notifications_table).values(
                    notification_id=f"notification-{uuid4()}",
                    home_id=home_id,
                    type=notification_type,
                    title=notification["title"],
                    message=notification["message"],
                    scan_id=scan_id,
                    scan_source=scan_source,
                    read=0,
                    created_at=utc_now(),
                )
            )

    # ---------------- FCM ----------------

    def register_fcm_token(self, fcm_token: str, platform: str, user_id: str) -> dict[str, Any]:
        updated_at = utc_now()
        with self.engine.begin() as conn:
            self._upsert(
                conn,
                fcm_tokens_table,
                {"fcm_token": fcm_token, "platform": platform, "user_id": user_id, "updated_at": updated_at},
                index_elements=["fcm_token"],
            )
        return {"registered": True, "platform": platform, "updated_at": updated_at}

    def delete_fcm_token(self, fcm_token: str, user_id: str) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(delete(fcm_tokens_table).where(fcm_tokens_table.c.fcm_token == fcm_token, fcm_tokens_table.c.user_id == user_id))
            return (result.rowcount or 0) > 0

    def list_fcm_tokens(self, user_id: str | None = None) -> list[str]:
        with self.engine.begin() as conn:
            stmt = select(fcm_tokens_table.c.fcm_token)
            if user_id:
                stmt = stmt.where(fcm_tokens_table.c.user_id == user_id)
            rows = conn.execute(stmt).all()
        return [r[0] for r in rows]

    # ---------------- 인증 세션 ----------------

    def create_auth_session(
        self,
        *,
        session_id: str,
        user_id: str,
        home_id: str,
        role: str,
        refresh_token_hash: str,
        expires_at: str,
        superseded_refresh_token_hash: str | None = None,
        activation_state: str = "active",
        handoff_predecessor_session_id: str | None = None,
        handoff_predecessor_refresh_token_hash: str | None = None,
        handoff_id_hash: str | None = None,
        handoff_expires_at: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        values = {
            "session_id": session_id,
            "user_id": user_id,
            "home_id": home_id,
            "role": role,
            "refresh_token_hash": refresh_token_hash,
            "previous_refresh_token_hash": None,
            "refresh_retry_id": None,
            "refresh_retry_until": None,
            "activation_state": activation_state,
            "handoff_predecessor_session_id": handoff_predecessor_session_id,
            "handoff_predecessor_refresh_token_hash": handoff_predecessor_refresh_token_hash,
            "handoff_id_hash": handoff_id_hash,
            "handoff_expires_at": handoff_expires_at,
            "handoff_completed_at": None,
            "created_at": now,
            "last_used_at": now,
            "expires_at": expires_at,
            "revoked_at": None,
        }
        with self.engine.begin() as conn:
            conn.execute(insert(auth_sessions_table).values(**values))
            # Legacy/internal callers can still use explicit supersession. The
            # public Google callback stages replacements and activates them via
            # complete_auth_handoff, so a lost callback response keeps the old
            # role fully usable.
            if superseded_refresh_token_hash:
                conn.execute(
                    update(auth_sessions_table)
                    .where(
                        or_(
                            auth_sessions_table.c.refresh_token_hash == superseded_refresh_token_hash,
                            auth_sessions_table.c.previous_refresh_token_hash == superseded_refresh_token_hash,
                        ),
                        auth_sessions_table.c.session_id != session_id,
                        auth_sessions_table.c.revoked_at.is_(None),
                    )
                    .values(revoked_at=now, last_used_at=now)
                )
        return values

    def auth_session_by_id(self, session_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(auth_sessions_table).where(auth_sessions_table.c.session_id == session_id)
            ).first()
        return row_to_dict(row)

    def auth_session_by_refresh_hash(self, refresh_token_hash: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(auth_sessions_table).where(auth_sessions_table.c.refresh_token_hash == refresh_token_hash)
            ).first()
        return row_to_dict(row)

    def auth_session_by_previous_refresh_hash(self, refresh_token_hash: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(auth_sessions_table).where(auth_sessions_table.c.previous_refresh_token_hash == refresh_token_hash)
            ).first()
        return row_to_dict(row)

    def complete_auth_handoff(
        self,
        *,
        predecessor_refresh_token_hash: str,
        successor_refresh_token_hash: str,
        handoff_id_hash: str,
    ) -> dict[str, Any] | None:
        """Activate a staged role successor and retire its predecessor.

        The transaction consumes only HMAC values, never plaintext refresh
        tokens. A fully matching completed handoff is returned unchanged so a
        client can retry safely after losing the completion response.
        """
        now = utc_now()
        with self.engine.begin() as conn:
            candidate_row = conn.execute(
                select(auth_sessions_table)
                .where(auth_sessions_table.c.refresh_token_hash == successor_refresh_token_hash)
                .with_for_update()
            ).first()
            candidate = row_to_dict(candidate_row)
            if candidate is None or candidate.get("revoked_at"):
                return None
            if not (
                hmac.compare_digest(
                    str(candidate.get("handoff_predecessor_refresh_token_hash") or ""),
                    predecessor_refresh_token_hash,
                )
                and hmac.compare_digest(str(candidate.get("handoff_id_hash") or ""), handoff_id_hash)
                and candidate.get("handoff_predecessor_session_id")
            ):
                return None

            activation_state = str(candidate.get("activation_state") or "active")
            if activation_state == "active" and candidate.get("handoff_completed_at"):
                return candidate
            if activation_state != "pending":
                return None
            expires_at = parse_utc_text(candidate.get("handoff_expires_at"))
            if expires_at is None or expires_at <= datetime.now(UTC):
                return None

            retired = conn.execute(
                update(auth_sessions_table)
                .where(
                    auth_sessions_table.c.session_id == str(candidate["handoff_predecessor_session_id"]),
                    auth_sessions_table.c.refresh_token_hash == predecessor_refresh_token_hash,
                    auth_sessions_table.c.activation_state == "active",
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(revoked_at=now, last_used_at=now)
            )
            if (retired.rowcount or 0) != 1:
                return None
            activated = conn.execute(
                update(auth_sessions_table)
                .where(
                    auth_sessions_table.c.session_id == str(candidate["session_id"]),
                    auth_sessions_table.c.refresh_token_hash == successor_refresh_token_hash,
                    auth_sessions_table.c.activation_state == "pending",
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(activation_state="active", handoff_completed_at=now, last_used_at=now)
            )
            if (activated.rowcount or 0) != 1:
                raise RuntimeError("auth handoff activation race")
            return row_to_dict(
                conn.execute(
                    select(auth_sessions_table).where(auth_sessions_table.c.session_id == str(candidate["session_id"]))
                ).first()
            )

    def rotate_auth_session(
        self,
        *,
        session_id: str,
        previous_refresh_token_hash: str,
        refresh_token_hash: str,
        expires_at: str,
        refresh_retry_id: str | None = None,
        refresh_retry_until: str | None = None,
    ) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                update(auth_sessions_table)
                .where(
                    auth_sessions_table.c.session_id == session_id,
                    auth_sessions_table.c.refresh_token_hash == previous_refresh_token_hash,
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(
                    refresh_token_hash=refresh_token_hash,
                    previous_refresh_token_hash=previous_refresh_token_hash if refresh_retry_id else None,
                    refresh_retry_id=refresh_retry_id,
                    refresh_retry_until=refresh_retry_until,
                    last_used_at=utc_now(),
                    expires_at=expires_at,
                )
            )
        return (result.rowcount or 0) == 1

    def recover_auth_session_rotation(
        self,
        *,
        session_id: str,
        previous_refresh_token_hash: str,
        refresh_retry_id: str,
        refresh_token_hash: str,
    ) -> bool:
        """Atomically attest that a pending rotation is still recoverable."""
        now = utc_now()
        with self.engine.begin() as conn:
            result = conn.execute(
                update(auth_sessions_table)
                .where(
                    auth_sessions_table.c.session_id == session_id,
                    auth_sessions_table.c.previous_refresh_token_hash == previous_refresh_token_hash,
                    auth_sessions_table.c.refresh_retry_id == refresh_retry_id,
                    auth_sessions_table.c.refresh_token_hash == refresh_token_hash,
                    auth_sessions_table.c.refresh_retry_until > now,
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(last_used_at=now)
            )
        return (result.rowcount or 0) == 1

    def revoke_auth_session_by_refresh_hash(self, refresh_token_hash: str) -> bool:
        now = utc_now()
        with self.engine.begin() as conn:
            result = conn.execute(
                update(auth_sessions_table)
                .where(
                    or_(
                        auth_sessions_table.c.refresh_token_hash == refresh_token_hash,
                        auth_sessions_table.c.previous_refresh_token_hash == refresh_token_hash,
                    ),
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(revoked_at=now, last_used_at=now)
            )
        return (result.rowcount or 0) == 1

    def revoke_auth_session_by_id(self, session_id: str) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                update(auth_sessions_table)
                .where(
                    auth_sessions_table.c.session_id == session_id,
                    auth_sessions_table.c.revoked_at.is_(None),
                )
                .values(revoked_at=utc_now(), last_used_at=utc_now())
            )
        return (result.rowcount or 0) == 1

    # ---------------- 내부 헬퍼 ----------------

    def _verified_identity_for_mac(
        self,
        conn,
        mac_address: str | None,
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, str] | None:
        """Find catalog identity evidence bound to one strong scope and MAC."""
        from ..services.device_identity import verified_catalog_marker_identity

        mac = normalized_physical_mac(mac_address)
        if mac is None or not is_strong_network_scope_id(network_scope_id):
            return None

        history_rows = conn.execute(
            select(device_identity_history_table)
            .where(
                device_identity_history_table.c.home_id == home_id,
                device_identity_history_table.c.network_scope_id == network_scope_id,
                func.upper(device_identity_history_table.c.physical_mac) == mac,
                device_identity_history_table.c.identity_status.in_(("resolved", "manual_resolved")),
                device_identity_history_table.c.confidence >= 0.9,
            )
            .order_by(
                device_identity_history_table.c.confidence.desc(),
                device_identity_history_table.c.observed_at.desc(),
            )
            .limit(50)
        ).mappings().all()
        for row in history_rows:
            if row.get("identity_status") == "manual_resolved":
                history = dict(row)
                try:
                    history["identity_evidence"] = json.loads(history.get("evidence_json") or "[]")
                except (TypeError, ValueError, json.JSONDecodeError):
                    history["identity_evidence"] = []
                job_rows = conn.execute(
                    select(identity_enrichment_jobs_table)
                    .where(
                        identity_enrichment_jobs_table.c.home_id == home_id,
                        identity_enrichment_jobs_table.c.network_scope_id == network_scope_id,
                        func.upper(identity_enrichment_jobs_table.c.physical_mac) == mac,
                        identity_enrichment_jobs_table.c.status == "resolved",
                    )
                    .order_by(identity_enrichment_jobs_table.c.resolved_at.desc())
                ).all()
                for job_row in job_rows:
                    job = self._identity_enrichment_job_from_row(job_row)
                    if (
                        job is not None
                        and evidence_signature_matches(
                            job.get("evidence") or {}, job.get("evidence_signature")
                        )
                        and (trusted := trusted_identity_resolution(history, job)) is not None
                    ):
                        return trusted
                continue
            record = {
                **dict(row),
                "mac_address": mac,
                "identity_confidence": row.get("confidence"),
                "is_unresolved": 0,
                "is_phantom": 0,
                "scan_source": "android-native",
            }
            identity = verified_catalog_marker_identity(record)
            if identity:
                return identity

        legacy_rows = conn.execute(
            select(scan_devices_table.c.device_snapshot_json)
            .join(scans_table, scans_table.c.scan_id == scan_devices_table.c.scan_id)
            .where(
                scans_table.c.home_id == home_id,
                scans_table.c.network_scope_id == network_scope_id,
                scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
            )
            .order_by(scans_table.c.created_at.desc(), scan_devices_table.c.id.asc())
            .limit(200)
        ).all()
        for row in legacy_rows:
            try:
                snapshot = json.loads(row[0])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict) or normalized_physical_mac(snapshot.get("mac_address")) != mac:
                continue
            if snapshot.get("identity_status") == "manual_resolved":
                continue
            identity = verified_catalog_marker_identity(snapshot)
            if identity:
                return identity
        return None

    def _verified_appliance_family_identity_for_mac(
        self,
        conn,
        mac_address: str | None,
        current_snapshot: Mapping[str, Any],
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, Any] | None:
        """Recover only device-advertised Family Hub family history.

        This is the SQLAlchemy counterpart of SQLite's bounded recovery path:
        current strong scope, same real MAC, authoritative Android snapshot,
        and a prior structured Spotify ``getInfo`` response are all required.
        """

        mac = normalized_physical_mac(mac_address)
        if mac is None or not is_strong_network_scope_id(network_scope_id):
            return None

        if self.dialect == "postgresql":
            candidate_query = text(
                """
                SELECT s.network_scope_id, s.created_at, sd.device_snapshot_json
                FROM scans AS s
                JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
                WHERE s.home_id = :home_id
                  AND s.scan_source = :scan_source
                  AND upper(replace(trim(COALESCE(
                        CAST(sd.device_snapshot_json AS jsonb) ->> 'mac_address', ''
                      )), '-', ':')) = :physical_mac
                ORDER BY s.created_at DESC, sd.id ASC
                LIMIT 400
                """
            )
        else:
            candidate_query = text(
                """
                SELECT s.network_scope_id, s.created_at, sd.device_snapshot_json
                FROM scans AS s
                JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
                WHERE s.home_id = :home_id
                  AND s.scan_source = :scan_source
                  AND CASE
                        WHEN json_valid(sd.device_snapshot_json)
                        THEN upper(replace(trim(json_extract(
                            sd.device_snapshot_json, '$.mac_address'
                        )), '-', ':'))
                        ELSE ''
                      END = :physical_mac
                ORDER BY s.created_at DESC, sd.id ASC
                LIMIT 400
                """
            )
        rows = conn.execute(
            candidate_query,
            {
                "home_id": home_id,
                "scan_source": _AUTHORITATIVE_SCAN_SOURCE,
                "physical_mac": mac,
            },
        ).mappings().all()
        for row in rows:
            identity = verified_family_hub_snapshot_identity(
                row.get("device_snapshot_json"),
                historical_scope_id=row.get("network_scope_id"),
                current_scope_id=network_scope_id,
                current_physical_mac=mac,
                current_snapshot_payload=current_snapshot,
            )
            if identity is not None:
                return identity
        return None

    def _verified_appliance_family_identity_for_advertised_token(
        self,
        conn,
        current_snapshot: Mapping[str, Any],
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, Any] | None:
        """Recover bounded Family Hub identity without creating a MAC binding.

        The shared verifier accepts the current MAC-shaped mDNS token only
        when a prior authoritative snapshot bound that exact self-advertised
        token to its matching real physical MAC and captured structured
        Samsung Family Hub ``getInfo`` evidence.  IP, device id, OUI and open
        ports do not participate in this path.
        """

        if not is_strong_network_scope_id(network_scope_id):
            return None
        advertised_token = exact_spotify_mdns_mac_token(current_snapshot)
        if advertised_token is None:
            return None
        if self.dialect == "postgresql":
            candidate_query = text(
                """
                SELECT s.network_scope_id, sd.device_snapshot_json
                FROM scans AS s
                JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
                WHERE s.home_id = :home_id
                  AND s.scan_source = :scan_source
                  AND EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements_text(
                          CASE
                            WHEN jsonb_typeof(
                              CAST(sd.device_snapshot_json AS jsonb) -> 'fingerprints'
                            ) = 'array'
                            THEN CAST(sd.device_snapshot_json AS jsonb) -> 'fingerprints'
                            ELSE '[]'::jsonb
                          END
                        ) AS fingerprint(value)
                        WHERE strpos(fingerprint.value, ':') > 0
                          AND lower(trim(split_part(
                                fingerprint.value, ':', 1
                              ))) = 'mdns-name'
                          AND upper(trim(substr(
                                fingerprint.value,
                                strpos(fingerprint.value, ':') + 1
                              ))) = :advertised_token
                      )
                ORDER BY s.created_at DESC, sd.id ASC
                LIMIT 400
                """
            )
        else:
            candidate_query = text(
                """
                SELECT s.network_scope_id, sd.device_snapshot_json
                FROM scans AS s
                JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
                WHERE s.home_id = :home_id
                  AND s.scan_source = :scan_source
                  AND EXISTS (
                        SELECT 1
                        FROM json_each(
                            CASE
                              WHEN json_valid(sd.device_snapshot_json)
                              THEN sd.device_snapshot_json
                              ELSE '{}'
                            END,
                            '$.fingerprints'
                        ) AS fingerprint
                        WHERE fingerprint.type = 'text'
                          AND instr(CAST(fingerprint.value AS TEXT), ':') > 0
                          AND lower(trim(substr(
                                CAST(fingerprint.value AS TEXT),
                                1,
                                instr(CAST(fingerprint.value AS TEXT), ':') - 1
                              ))) = 'mdns-name'
                          AND upper(trim(substr(
                                CAST(fingerprint.value AS TEXT),
                                instr(CAST(fingerprint.value AS TEXT), ':') + 1
                              ))) = :advertised_token
                      )
                ORDER BY s.created_at DESC, sd.id ASC
                LIMIT 400
                """
            )
        rows = conn.execute(
            candidate_query,
            {
                "home_id": home_id,
                "scan_source": _AUTHORITATIVE_SCAN_SOURCE,
                "advertised_token": advertised_token,
            },
        ).mappings().all()
        for row in rows:
            identity = verified_family_hub_advertised_token_identity(
                row.get("device_snapshot_json"),
                current_snapshot,
                historical_scope_id=row.get("network_scope_id"),
                current_scope_id=network_scope_id,
                # Let the shared verifier distinguish the explicit UNKNOWN-*
                # scanner placeholder from arbitrary malformed MAC claims.
                current_physical_mac=None,
            )
            if identity is not None:
                return identity
        return None

    def _authenticated_self_history_job_devices(
        self,
        current_devices: list[dict[str, Any]],
        *,
        home_id: str,
        current_scope_candidates: Sequence[str],
    ) -> list[dict[str, Any]]:
        bssid_scopes = tuple(
            dict.fromkeys(
                str(scope or "").strip().casefold()
                for scope in current_scope_candidates
                if str(scope or "").strip().casefold().startswith("hgns1b-")
                and is_strong_network_scope_id(scope)
            )
        )
        if not current_devices or not bssid_scopes:
            return []

        with self.engine.begin() as conn:
            rows = conn.execute(
                select(
                    scans_table.c.scan_id,
                    scans_table.c.home_id,
                    scans_table.c.network_scope_id,
                    scans_table.c.scan_source,
                    scan_devices_table.c.device_snapshot_json,
                )
                .join(
                    scan_devices_table,
                    scan_devices_table.c.scan_id == scans_table.c.scan_id,
                )
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                    scans_table.c.network_scope_id.in_(bssid_scopes),
                )
                .order_by(
                    scans_table.c.created_at.desc(),
                    scan_devices_table.c.id.asc(),
                )
                .limit(800)
            ).mappings().all()
        records_by_ip: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            try:
                snapshot = json.loads(row.get("device_snapshot_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict) or not is_self_observation(snapshot):
                continue
            ip_address = str(snapshot.get("ip_address") or "").strip()
            if not ip_address:
                continue
            records_by_ip.setdefault(ip_address, []).append(
                {
                    "scan_id": str(row.get("scan_id") or ""),
                    "home_id": str(row.get("home_id") or ""),
                    "network_scope_id": str(row.get("network_scope_id") or ""),
                    "scan_source": str(row.get("scan_source") or ""),
                    "snapshot_payload": snapshot,
                }
            )
        if not records_by_ip:
            return []

        ambiguous_macs = _ambiguous_physical_macs(current_devices)
        claimed_macs: set[str] = set()
        job_devices: list[dict[str, Any]] = []
        for current in current_devices:
            if is_self_observation(current) or bool(current.get("is_phantom")):
                continue
            physical_mac = normalized_physical_mac(current.get("mac_address"))
            if (
                physical_mac is None
                or physical_mac in ambiguous_macs
                or physical_mac in claimed_macs
            ):
                continue
            ip_address = str(current.get("ip_address") or "").strip()
            identity = verified_authenticated_self_android_history_identity(
                records_by_ip.get(ip_address),
                current,
                home_id=home_id,
                current_scope_candidates=bssid_scopes,
                current_physical_mac=physical_mac,
            )
            if identity is None:
                continue
            manufacturer = str(identity.get("manufacturer") or "").strip()
            model = str(identity.get("model") or "").strip()
            device_type = str(identity.get("device_type") or "").strip().casefold()
            claim = {
                "device_id": current.get("device_id"),
                "name": "",
                "device_type": device_type,
                "manufacturer": manufacturer,
                "model": model,
                "ip_address": ip_address,
                "mac_address": physical_mac,
                "online": bool(current.get("online", True)),
                "open_ports": [],
                "services": ["self-device"],
                "discovery_sources": ["self"],
                "fingerprints": [
                    "self-android",
                    f"self-manufacturer:{manufacturer}",
                    f"self-model:{model}",
                ],
                "risk_signals": ["self_device"],
                "vulnerabilities": [],
                "confidence": 1.0,
                "scan_source": _AUTHORITATIVE_SCAN_SOURCE,
            }
            marked = bind_authenticated_self_android_claim(claim)
            if marked is None:
                continue
            claimed_macs.add(physical_mac)
            job_devices.append(marked)
        return job_devices

    def _store_discovered_devices(
        self,
        discovered_devices: list[dict[str, Any]],
        scan_source: str,
        home_id: str = HOME["home_id"],
        network_scope_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        from .sqlite_repository import (  # 동일 normalization 재사용
            normalize_observed_device,
            phantom_port_echo_mask,
        )

        raw_self_bindings = [
            binding
            for raw in discovered_devices
            if (binding := authenticated_self_android_binding(raw)) is not None
        ]
        self_binding = (
            raw_self_bindings[0]
            if len(raw_self_bindings) == 1
            and is_strong_network_scope_id(network_scope_id)
            else None
        )
        cleaned_devices = [
            strip_untrusted_authenticated_self_android(raw)
            for raw in discovered_devices
        ]
        stored: list[dict[str, Any]] = []
        attested_self_job_devices: list[dict[str, Any]] = []
        phantom_mask = phantom_port_echo_mask(cleaned_devices)
        catalog_entries = self.verified_product_catalog_entries()
        ambiguous_macs = _ambiguous_physical_macs(cleaned_devices)
        if self_binding is not None and self_binding[1] in ambiguous_macs:
            self_binding = None
        with self.engine.begin() as conn:
            for index, raw in enumerate(cleaned_devices):
                observed_mac = normalized_physical_mac(raw.get("mac_address"))
                binding_mac = None if observed_mac in ambiguous_macs else observed_mac
                historical_identity = self._verified_identity_for_mac(
                    conn,
                    binding_mac,
                    home_id,
                    network_scope_id,
                )
                if historical_identity is None:
                    historical_identity = self._verified_appliance_family_identity_for_mac(
                        conn,
                        binding_mac,
                        raw,
                        home_id,
                        network_scope_id,
                    )
                if (
                    historical_identity is None
                    and scan_source == _AUTHORITATIVE_SCAN_SOURCE
                    and observed_mac is None
                ):
                    historical_identity = (
                        self._verified_appliance_family_identity_for_advertised_token(
                            conn,
                            raw,
                            home_id,
                            network_scope_id,
                        )
                    )
                if historical_identity is not None:
                    if historical_identity.get("_history_kind") == "appliance_family":
                        historical_identity = bind_verified_appliance_family_history(
                            historical_identity
                        )
                    else:
                        historical_identity = bind_verified_catalog_history(
                            historical_identity
                        )
                device = normalize_observed_device(
                    raw,
                    scan_source=scan_source,
                    home_id=home_id,
                    verified_identity=historical_identity,
                    phantom_port_echo=phantom_mask[index],
                    catalog_entries=catalog_entries,
                )
                device = scoring_with_cve(device)
                scored = score_device(device)
                device.update(
                    {
                        "security_score": scored["score"],
                        "risk_level": scored["risk_level"],
                        "risk_summary": scored["summary"],
                        "recommended_actions": scored["recommended_actions"],
                    }
                )
                if scan_source == _AUTHORITATIVE_SCAN_SOURCE and not bool(
                    device.get("is_phantom")
                ):
                    # Non-authoritative probes remain available through their
                    # own frozen scan result, but must not replace the Android
                    # current row or contribute resolver history.
                    values = _device_row_values_dict(device)
                    self._upsert(conn, devices_table, values, index_elements=["device_id"])
                    conn.execute(
                        insert(device_identity_history_table).values(
                            resolution_id=f"identity-{uuid4()}",
                            home_id=home_id,
                            device_id=device["device_id"],
                            network_scope_id=(
                                network_scope_id
                                if is_strong_network_scope_id(network_scope_id)
                                else None
                            ),
                            physical_mac=(
                                None
                                if normalized_physical_mac(device.get("mac_address"))
                                in ambiguous_macs
                                else normalized_physical_mac(device.get("mac_address"))
                            ),
                            observed_at=device.get("last_seen") or utc_now(),
                            identity_status=device.get("identity_status")
                            or ("resolved" if device.get("is_resolved") else "unresolved"),
                            manufacturer=str(device.get("manufacturer") or ""),
                            device_type=str(device.get("device_type") or ""),
                            model=str(device.get("model") or ""),
                            canonical_name=str(device.get("canonical_name") or ""),
                            confidence=float(device.get("identity_confidence", device.get("confidence", 0.2)) or 0.2),
                            evidence_json=json.dumps(device.get("identity_evidence") or [], ensure_ascii=False),
                            candidates_json=json.dumps(device.get("identity_candidates") or [], ensure_ascii=False),
                            note=str(device.get("identity_note") or ""),
                            resolver_version=str(device.get("identity_resolver_version") or "server-identity-1.0.0"),
                        )
                    )
                stored.append(deepcopy(device))
        if self_binding is not None:
            matching_self = [
                device
                for device in stored
                if is_self_observation(device)
                and (
                    str(device.get("ip_address") or "").strip(),
                    normalized_physical_mac(device.get("mac_address")),
                    str(device.get("manufacturer") or "").strip(),
                    str(device.get("model") or "").strip(),
                    str(device.get("device_type") or "").strip().casefold(),
                )
                == self_binding
            ]
            if len(matching_self) == 1:
                marked = bind_authenticated_self_android_claim(matching_self[0])
                if marked is not None:
                    attested_self_job_devices.append(marked)
        return stored, attested_self_job_devices

    def _latest_observed_scan_devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]] | None:
        from .sqlite_repository import (
            apply_verified_product_catalog_projection,
            merge_latest_observed_scans,
        )

        catalog_entries = self.verified_product_catalog_entries()
        with self.engine.begin() as conn:
            scans = conn.execute(
                select(scans_table)
                .where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
                .order_by(desc(scans_table.c.created_at))
            ).all()
            valid: list[
                tuple[str, str | None, dict[str, Any], list[dict[str, Any]]]
            ] = []
            for scan_row in scans:
                scan = row_to_dict(scan_row) or {}
                device_rows = conn.execute(
                    select(scan_devices_table.c.device_snapshot_json).where(scan_devices_table.c.scan_id == scan["scan_id"]).order_by(scan_devices_table.c.id.asc())
                ).all()
                devices = [json.loads(r[0]) for r in device_rows]
                bounded = _validated_authoritative_snapshot(
                    json.loads(scan.get("network_context_json") or "{}"),
                    devices,
                )
                if bounded is None:
                    continue
                network_context, devices = bounded
                valid.append(
                    (
                        str(scan.get("created_at") or ""),
                        scan.get("network_scope_id"),
                        network_context,
                        devices,
                    )
                )
        merged = merge_latest_observed_scans(valid)
        if merged is None:
            return None
        merged = apply_verified_product_catalog_projection(
            merged,
            catalog_entries,
        )
        return self._apply_approved_manual_identities(
            merged,
            home_id=home_id,
            network_scope_id=valid[0][1],
        )

    def _observed_scan_exists(self, home_id: str = HOME["home_id"]) -> bool:
        with self.engine.begin() as conn:
            scans = conn.execute(
                select(scans_table).where(
                    scans_table.c.home_id == home_id,
                    scans_table.c.scan_source == _AUTHORITATIVE_SCAN_SOURCE,
                )
            ).all()
            for scan_row in scans:
                scan = row_to_dict(scan_row) or {}
                device_rows = conn.execute(
                    select(scan_devices_table.c.device_snapshot_json).where(scan_devices_table.c.scan_id == scan["scan_id"])
                ).all()
                devices = [json.loads(r[0]) for r in device_rows]
                bounded = _validated_authoritative_snapshot(
                    json.loads(scan.get("network_context_json") or "{}"),
                    devices,
                )
                if bounded is None:
                    continue
                return True
        return False


def _device_row_values_dict(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": device["device_id"],
        "home_id": device.get("home_id", HOME["home_id"]),
        "name": device["name"],
        "device_type": device["device_type"],
        "manufacturer": device["manufacturer"],
        "model": device["model"],
        "ip_address": device["ip_address"],
        "mac_address": device["mac_address"],
        "online": int(device["online"]),
        "last_seen": device["last_seen"],
        "open_ports_json": json.dumps(device["open_ports"], ensure_ascii=False),
        "services_json": json.dumps(device.get("services", []), ensure_ascii=False),
        "default_credentials": int(device["default_credentials"]),
        "encryption": device["encryption"],
        "firmware": device.get("firmware", "unknown"),
        "vulnerabilities_json": json.dumps(device["vulnerabilities"], ensure_ascii=False),
        "discovery_sources_json": json.dumps(device.get("discovery_sources", []), ensure_ascii=False),
        "fingerprints_json": json.dumps(device.get("fingerprints", []), ensure_ascii=False),
        "risk_signals_json": json.dumps(device.get("risk_signals", []), ensure_ascii=False),
        "scan_source": device["scan_source"],
            "confidence": float(device.get("confidence", 0.85)),
            "is_unresolved": int(bool(device.get("is_unresolved", False))),
            "is_phantom": int(bool(device.get("is_phantom", False))),
            "security_score": int(device["security_score"]),
        "risk_level": device["risk_level"],
        "risk_summary": device["risk_summary"],
        "recommended_actions_json": json.dumps(device["recommended_actions"], ensure_ascii=False),
        "risk_rank": {"red": 0, "yellow": 1, "green": 2}.get(device["risk_level"], 3),
    }


def _user_from_row(data: dict[str, Any] | None) -> dict[str, Any]:
    if data is None:
        raise ValueError("user row is required")
    return {
        "user_id": data["user_id"],
        "email": data["email"],
        "nickname": data["nickname"],
        "role": data["role"],
        "email_verified": bool(data["email_verified"]),
        "home_id": data["home_id"],
    }


def _device_from_row(data: dict[str, Any] | None) -> dict[str, Any]:
    if data is None:
        return {}
    return {
        "device_id": data["device_id"],
        "home_id": data.get("home_id", HOME["home_id"]),
        "name": data["name"],
        "device_type": data["device_type"],
        "manufacturer": data["manufacturer"],
        "model": data["model"],
        "ip_address": data["ip_address"],
        "mac_address": data["mac_address"],
        "online": bool(data["online"]),
        "last_seen": data["last_seen"],
        "open_ports": json.loads(data["open_ports_json"]),
        "services": json.loads(data["services_json"]),
        "default_credentials": bool(data["default_credentials"]),
        "encryption": data["encryption"],
        "firmware": data["firmware"],
        "vulnerabilities": json.loads(data["vulnerabilities_json"]),
        "discovery_sources": json.loads(data["discovery_sources_json"]),
        "fingerprints": json.loads(data["fingerprints_json"]),
        "risk_signals": json.loads(data["risk_signals_json"]),
        "scan_source": data["scan_source"],
        "confidence": float(data["confidence"]),
        "is_unresolved": bool(data.get("is_unresolved", False)),
        "is_phantom": bool(data.get("is_phantom", False)),
        "security_score": int(data["security_score"]),
        "risk_level": data["risk_level"],
        "risk_summary": data["risk_summary"],
        "recommended_actions": json.loads(data["recommended_actions_json"]),
    }


def _notification_from_row(data: dict[str, Any] | None) -> dict[str, Any] | None:
    if data is None:
        return None
    return {
        "notification_id": data["notification_id"],
        "home_id": data["home_id"],
        "type": data["type"],
        "title": data["title"],
        "message": data["message"],
        "read": bool(data["read"]),
        "created_at": data["created_at"],
    }


def _guardian_ward_from_row(data: dict[str, Any] | None) -> dict[str, Any]:
    if data is None:
        return {}
    ward_account_name = clean_optional_name(data.get("ward_account_name")) or ""
    ward_alias = clean_optional_name(data.get("ward_alias"))
    ward_display_name = clean_optional_name(data.get("ward_display_name")) or ward_alias or ward_account_name
    return {
        "link_id": data["link_id"],
        "guardian_id": data["guardian_id"],
        "invite_id": data["invite_id"],
        "home_id": data["home_id"],
        "ward_account_name": ward_account_name,
        "ward_alias": ward_alias,
        "ward_display_name": ward_display_name,
        "status": data["status"],
        "accepted_at": data["accepted_at"],
        "revoked_at": data.get("revoked_at"),
        "last_viewed_at": data.get("last_viewed_at"),
    }
