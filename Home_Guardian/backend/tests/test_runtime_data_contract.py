from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from app.main import ScanRequest
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import SQLiteRepository


HOME_ID = "home-0001"
NETWORK_CONTEXT = {
    "ssid": "Resident Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.66.20",
    "gateway_ip": "192.168.66.1",
    "subnet_cidr": "192.168.66.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}
RED_CAMERA = {
    "name": "Hikvision 카메라",
    "device_type": "camera",
    "manufacturer": "Hikvision",
    "model": "DS-2CD2042",
    "ip_address": "192.168.66.21",
    "mac_address": "AA:BB:CC:66:00:21",
    "open_ports": [23, 80, 554, 3702],
    "services": ["telnet", "http", "rtsp", "onvif"],
    "discovery_sources": ["ssdp", "onvif"],
    "fingerprints": [
        "upnp-manufacturer:Hikvision",
        "upnp-model:DS-2CD2042",
        "onvif-device",
    ],
    "risk_signals": ["rtsp_open", "default_credentials_possible"],
    "vulnerabilities": [{"cve_id": "CVE-2021-36260", "severity": "critical"}],
}


def _repository(tmp_path: Path, kind: str):
    path = tmp_path / f"runtime-contract-{kind}.sqlite3"
    if kind == "sqlite":
        return SQLiteRepository(db_path=str(path)), path
    return SqlAlchemyRepository(f"sqlite+pysqlite:///{path.as_posix()}"), path


def _reopen(path: Path, kind: str):
    if kind == "sqlite":
        return SQLiteRepository(db_path=str(path))
    return SqlAlchemyRepository(f"sqlite+pysqlite:///{path.as_posix()}")


def _close(repository) -> None:
    if isinstance(repository, SqlAlchemyRepository):
        repository.close()


def _raw_rows(repository, statement: str, params: dict[str, object] | None = None) -> list[dict[str, object]]:
    values = params or {}
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            return [dict(row) for row in conn.execute(statement, values).fetchall()]
    with repository.engine.begin() as conn:
        return [dict(row) for row in conn.execute(text(statement), values).mappings().all()]


def _raw_execute(repository, statement: str, params: dict[str, object] | None = None) -> None:
    values = params or {}
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(statement, values)
        return
    with repository.engine.begin() as conn:
        conn.execute(text(statement), values)


def _count(repository, table: str, where: str = "1 = 1", params: dict[str, object] | None = None) -> int:
    return int(_raw_rows(repository, f"SELECT COUNT(*) AS count FROM {table} WHERE {where}", params)[0]["count"])


def _provision_owner(repository, home_id: str = HOME_ID) -> None:
    repository.upsert_user(
        {
            "user_id": "real-resident-owner",
            "email": "resident-owner@example.invalid",
            "nickname": "실제 거주자",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )


def _insert_legacy_rows(repository, actual_scan_id: str) -> None:
    now = "2026-08-20T00:00:00Z"
    expires = "2099-08-20T00:00:00Z"
    _raw_execute(
        repository,
        """
        INSERT INTO users (user_id, email, nickname, role, email_verified, home_id)
        VALUES ('user-0001', 'tester@homeguardian.local', 'Legacy fixture', 'user', 1, :home_id)
        """,
        {"home_id": HOME_ID},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO auth_sessions (
            session_id, user_id, home_id, role, refresh_token_hash,
            activation_state, created_at, last_used_at, expires_at
        ) VALUES (
            'legacy-user-session', 'user-0001', :home_id, 'user',
            'legacy-user-refresh-hash', 'active', :now, :now, :expires
        )
        """,
        {"home_id": HOME_ID, "now": now, "expires": expires},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO fcm_tokens (fcm_token, platform, user_id, updated_at)
        VALUES ('legacy-fcm-token', 'android', 'user-0001', :now)
        """,
        {"now": now},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO guardian_accounts (
            guardian_id, email, display_name, provider, created_at, last_login_at
        ) VALUES (
            'legacy-test-guardian', 'legacy-guardian@example.invalid',
            'Legacy guardian', 'test', :now, :now
        )
        """,
        {"now": now},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO auth_sessions (
            session_id, user_id, home_id, role, refresh_token_hash,
            activation_state, created_at, last_used_at, expires_at
        ) VALUES (
            'legacy-guardian-session', 'legacy-test-guardian', '', 'guardian',
            'legacy-guardian-refresh-hash', 'active', :now, :now, :expires
        )
        """,
        {"now": now, "expires": expires},
    )
    for invite_id, short_code in (
        ("legacy-linked-invite", "LEGACY01"),
        ("legacy-orphan-invite", "LEGACY02"),
    ):
        _raw_execute(
            repository,
            """
            INSERT INTO guardian_invites (
                invite_id, home_id, email, relation, display_name,
                ward_account_name, short_code, deep_link, status, message,
                created_at, expires_at, accepted_at, last_viewed_at,
                guardian_token_hash, session_created_at, session_last_used_at
            ) VALUES (
                :invite_id, :home_id, 'guardian@example.invalid', '가족', '보호자',
                '실제 거주자', :short_code, :deep_link, 'accepted', '연결됨',
                :now, :expires, :now, :now, :token_hash, :now, :now
            )
            """,
            {
                "invite_id": invite_id,
                "home_id": HOME_ID,
                "short_code": short_code,
                "deep_link": f"homeguardian://guardian/{short_code}",
                "now": now,
                "expires": expires,
                "token_hash": f"token-{invite_id}",
            },
        )
    _raw_execute(
        repository,
        """
        INSERT INTO guardian_ward_links (
            link_id, guardian_id, invite_id, home_id, ward_account_name,
            ward_alias, ward_display_name, status, accepted_at, revoked_at, last_viewed_at
        ) VALUES (
            'legacy-test-link', 'legacy-test-guardian', 'legacy-linked-invite',
            :home_id, '실제 거주자', NULL, '실제 거주자', 'active', :now, NULL, :now
        )
        """,
        {"home_id": HOME_ID, "now": now},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO scans (
            scan_id, home_id, status, progress, scan_profile, scan_source,
            network_context_json, network_scope_id, current_step,
            devices_found, high_risk_devices, security_score_json, created_at
        ) VALUES (
            'legacy-non-authoritative-scan', :home_id, 'completed', 100,
            'legacy', 'mock-api', :context, NULL, '완료', 1, 0, :score, :now
        )
        """,
        {
            "home_id": HOME_ID,
            "context": json.dumps(NETWORK_CONTEXT, ensure_ascii=False),
            "score": json.dumps({"home_id": HOME_ID, "score": 100, "risk_level": "green"}),
            "now": now,
        },
    )
    _raw_execute(
        repository,
        """
        INSERT INTO scan_devices (scan_id, device_snapshot_json)
        VALUES ('legacy-non-authoritative-scan', :snapshot)
        """,
        {"snapshot": json.dumps(RED_CAMERA, ensure_ascii=False)},
    )
    _raw_execute(
        repository,
        """
        INSERT INTO devices (
            device_id, home_id, name, device_type, manufacturer, model,
            ip_address, mac_address, online, last_seen, open_ports_json,
            services_json, default_credentials, encryption, firmware,
            vulnerabilities_json, discovery_sources_json, fingerprints_json,
            risk_signals_json, scan_source, confidence, is_unresolved,
            is_phantom, security_score, risk_level, risk_summary,
            recommended_actions_json, risk_rank
        )
        SELECT
            'legacy-seed-labelled-device', home_id, name, device_type,
            manufacturer, model, ip_address, mac_address, online, last_seen,
            open_ports_json, services_json, default_credentials, encryption,
            firmware, vulnerabilities_json, discovery_sources_json,
            fingerprints_json, risk_signals_json, 'seed', confidence,
            is_unresolved, is_phantom, security_score, risk_level, risk_summary,
            recommended_actions_json, risk_rank
        FROM devices
        WHERE home_id = :home_id
        LIMIT 1
        """,
        {"home_id": HOME_ID},
    )
    assert _count(repository, "scan_devices", "scan_id = :scan_id", {"scan_id": actual_scan_id}) == 1


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_repository_initialization_has_no_implicit_user_or_home(tmp_path, kind):
    repository, _path = _repository(tmp_path, kind)
    try:
        assert _count(repository, "users") == 0
        assert _count(repository, "homes") == 0
        assert _count(repository, "scans") == 0
        assert _count(repository, "devices") == 0
    finally:
        _close(repository)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_startup_cleanup_removes_reserved_principals_resets_ghost_links_and_preserves_evidence(
    tmp_path,
    kind,
):
    repository, path = _repository(tmp_path, kind)
    _provision_owner(repository)
    actual = repository.create_scan(
        scan_source="android-native",
        network_context=NETWORK_CONTEXT,
        discovered_devices=[RED_CAMERA],
        home_id=HOME_ID,
    )
    _insert_legacy_rows(repository, actual["scan_id"])
    _close(repository)

    reopened = _reopen(path, kind)
    try:
        assert _count(reopened, "users", "user_id = 'user-0001'") == 0
        assert _count(reopened, "auth_sessions", "user_id IN ('user-0001', 'legacy-test-guardian')") == 0
        assert _count(reopened, "fcm_tokens", "user_id = 'user-0001'") == 0
        assert _count(reopened, "guardian_accounts", "guardian_id = 'legacy-test-guardian'") == 0
        assert _count(reopened, "guardian_ward_links", "link_id = 'legacy-test-link'") == 0

        invites = {
            str(row["invite_id"]): row
            for row in _raw_rows(
                reopened,
                "SELECT * FROM guardian_invites WHERE invite_id LIKE 'legacy-%-invite'",
            )
        }
        assert set(invites) == {"legacy-linked-invite", "legacy-orphan-invite"}
        for invite in invites.values():
            assert invite["status"] == "pending"
            assert invite["accepted_at"] is None
            assert invite["guardian_token_hash"] is None
            assert invite["session_created_at"] is None
            assert invite["session_last_used_at"] is None
        assert reopened.guardian_count(home_id=HOME_ID) == 0

        # The reserved principal is removed, but its old shared home and real
        # Android observation are retained because a genuine owner still owns it.
        assert reopened.user_by_id("real-resident-owner") is not None
        assert reopened.home(home_id=HOME_ID)["home_id"] == HOME_ID
        assert reopened.scan_status(actual["scan_id"], home_id=HOME_ID) is not None
        assert reopened.scan_result(actual["scan_id"], home_id=HOME_ID) is not None
        assert len(reopened.devices(home_id=HOME_ID)) == 1

        # Old source labels are not trustworthy deletion provenance. Keep the
        # rows private for recovery, but never expose them as current results.
        assert _count(reopened, "scans", "scan_id = 'legacy-non-authoritative-scan'") == 1
        assert _count(reopened, "devices", "device_id = 'legacy-seed-labelled-device'") == 1
        assert reopened.scan_status("legacy-non-authoritative-scan", home_id=HOME_ID) is None
        assert reopened.scan_result("legacy-non-authoritative-scan", home_id=HOME_ID) is None
    finally:
        _close(reopened)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_notifications_and_security_events_require_authoritative_android_provenance(tmp_path, kind):
    repository, _path = _repository(tmp_path, kind)
    _provision_owner(repository)
    try:
        actual = repository.create_scan(
            scan_source="android-native",
            network_context=NETWORK_CONTEXT,
            discovered_devices=[RED_CAMERA],
            home_id=HOME_ID,
        )
        _raw_execute(
            repository,
            """
            INSERT INTO notifications (
                notification_id, home_id, type, title, message,
                scan_id, scan_source, read, created_at
            ) VALUES (
                'legacy-scan-notification', :home_id, 'scan_completed',
                '과거 점검 완료', '과거 결과', NULL, NULL, 0, '2026-08-20T00:00:00Z'
            )
            """,
            {"home_id": HOME_ID},
        )
        _raw_execute(
            repository,
            """
            INSERT INTO notifications (
                notification_id, home_id, type, title, message,
                scan_id, scan_source, read, created_at
            ) VALUES (
                'real-general-notification', :home_id, 'guardian_invite',
                '보호자 연결 안내', '보호자 연결 상태를 확인해 주세요.',
                NULL, NULL, 0, '2026-08-20T00:00:00Z'
            )
            """,
            {"home_id": HOME_ID},
        )
        _raw_execute(
            repository,
            """
            INSERT INTO security_events (
                event_id, home_id, severity, title, description,
                device_id, created_at, action_guide
            ) VALUES (
                'legacy-unproven-event', :home_id, 'red', '과거 위험',
                '출처 없는 과거 이벤트', 'legacy-device',
                '2026-08-20T00:00:00Z', '과거 조치'
            )
            """,
            {"home_id": HOME_ID},
        )

        notification_ids = {
            item["notification_id"] for item in repository.notifications(home_id=HOME_ID)
        }
        assert "legacy-scan-notification" not in notification_ids
        assert "real-general-notification" in notification_ids
        assert any(item.get("type") == "scan_completed" for item in repository.notifications(home_id=HOME_ID))

        events = repository.security_events(home_id=HOME_ID)
        assert events
        assert all(item["event_id"] != "legacy-unproven-event" for item in events)
        assert any(item["severity"] == "red" for item in events)
        assert actual["events"] and actual["events"][0]["severity"] == "red"

        before = len(repository.notifications(home_id=HOME_ID))
        internal = repository.record_windows_port_probe(
            network_context=NETWORK_CONTEXT,
            discovered_devices=[RED_CAMERA],
            home_id=HOME_ID,
        )
        assert repository.scan_status(internal["scan_id"], home_id=HOME_ID) is None
        assert repository.scan_result(internal["scan_id"], home_id=HOME_ID) is None
        assert len(repository.notifications(home_id=HOME_ID)) == before
        with pytest.raises(ValueError, match="unsupported scan source"):
            repository.create_scan(
                scan_source="windows-port-probe",
                network_context=NETWORK_CONTEXT,
                discovered_devices=[RED_CAMERA],
                home_id=HOME_ID,
            )
    finally:
        _close(repository)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_missing_or_ownerless_home_never_autocreates_scan_state(tmp_path, kind):
    repository, _path = _repository(tmp_path, kind)
    try:
        with pytest.raises(KeyError):
            repository.home(home_id="missing-home")
        with pytest.raises(ValueError, match="authenticated home"):
            repository.create_scan(
                scan_source="android-native",
                network_context=NETWORK_CONTEXT,
                discovered_devices=[],
                home_id="missing-home",
            )
        with pytest.raises(ValueError, match="authenticated home"):
            repository.record_windows_port_probe(
                network_context=NETWORK_CONTEXT,
                discovered_devices=[],
                home_id="missing-home",
            )
        assert _count(repository, "homes") == 0
        assert _count(repository, "scans") == 0
        assert _count(repository, "notifications") == 0
    finally:
        _close(repository)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_active_link_with_revocation_timestamp_is_quarantined_on_startup(tmp_path, kind):
    repository, path = _repository(tmp_path, kind)
    _provision_owner(repository)
    invite = repository.create_guardian_invite(
        email="stale-link-guardian@example.invalid",
        relation="가족",
        home_id=HOME_ID,
    )
    accepted = repository.accept_guardian_invite_for_account(
        invite["short_code"],
        {
            "guardian_id": "stale-link-guardian",
            "email": "stale-link-guardian@example.invalid",
            "display_name": "정상 보호자",
            "provider": "google",
        },
    )
    link_id = accepted["ward"]["link_id"]
    _raw_execute(
        repository,
        """
        UPDATE guardian_ward_links
        SET status = 'active', revoked_at = '2026-08-20T00:00:00Z'
        WHERE link_id = :link_id
        """,
        {"link_id": link_id},
    )
    _close(repository)

    reopened = _reopen(path, kind)
    try:
        raw_link = _raw_rows(
            reopened,
            "SELECT status, revoked_at FROM guardian_ward_links WHERE link_id = :link_id",
            {"link_id": link_id},
        )[0]
        raw_invite = _raw_rows(
            reopened,
            "SELECT status, accepted_at FROM guardian_invites WHERE invite_id = :invite_id",
            {"invite_id": invite["invite_id"]},
        )[0]

        assert raw_link["status"] == "revoked"
        assert raw_link["revoked_at"] is not None
        assert raw_invite["status"] == "pending"
        assert raw_invite["accepted_at"] is None
        assert reopened.guardian_ward_link_by_id(link_id)["status"] == "revoked"
        assert reopened.guardian_wards("stale-link-guardian") == []
    finally:
        _close(reopened)


def test_runtime_source_contains_no_fake_auth_or_data_entrypoint():
    backend_root = Path(__file__).resolve().parents[1]
    app_root = backend_root / "app"
    python_sources = {
        path: path.read_text(encoding="utf-8")
        for path in app_root.rglob("*.py")
    }
    combined = "\n".join(python_sources.values())
    for forbidden in (
        "TEST_USER",
        "/auth/test-login",
        "x-home-guardian-user-id",
        "x-home-guardian-home-id",
        "HG_ALLOW_TEST_LOGIN",
        "HG_ALLOW_TEST_SCOPE",
        "ALLOW_DEV_GOOGLE_OAUTH",
        "HG_ALLOW_EPHEMERAL_AUTH_SECRET",
        "mock-api",
        "home-0001",
    ):
        assert forbidden.lower() not in combined.lower()

    assert re.search(r"scan_source\s*[,=:][^\n]*['\"]seed['\"]", combined, re.IGNORECASE) is None

    # Exact pre-v1 identifiers are migration input only. They must not appear
    # in defaults, public getters, API scopes or write fallbacks.
    for filename in ("sqlite_repository.py", "sa_repository.py"):
        source = (app_root / "storage" / filename).read_text(encoding="utf-8")
        start = source.index("def _purge_legacy_synthetic_state")
        next_method = source.find("\n    def ", start + 8)
        cleanup = source[start:] if next_method < 0 else source[start:next_method]
        outside_cleanup = source[:start] + ("" if next_method < 0 else source[next_method:])
        assert "user-0001" in cleanup
        assert "tester@homeguardian.local" in cleanup
        assert "user-0001" not in outside_cleanup
        assert "tester@homeguardian.local" not in outside_cleanup

    ddl = (app_root / "storage" / "postgres_schema.sql").read_text(encoding="utf-8")
    cleanup_start = ddl.index("-- Remove unsafe defaults")
    cleanup_end = ddl.index("-- v1.0.0 role-handoff migration")
    ddl_cleanup = ddl[cleanup_start:cleanup_end]
    ddl_outside_cleanup = ddl[:cleanup_start] + ddl[cleanup_end:]
    assert "user-0001" in ddl_cleanup
    assert "tester@homeguardian.local" in ddl_cleanup
    assert "user-0001" not in ddl_outside_cleanup
    assert "tester@homeguardian.local" not in ddl_outside_cleanup
    assert re.search(r"DEFAULT\s+['\"](?:seed|mock-api|home-0001)['\"]", ddl, re.IGNORECASE) is None


def test_public_scan_request_accepts_only_explicit_android_evidence():
    request = ScanRequest.model_validate(
        {
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": NETWORK_CONTEXT,
            "devices": [],
        }
    )
    assert request.scan_source == "android-native"
    assert request.devices == []

    for rejected_source in ("windows-port-probe", "mock-api"):
        with pytest.raises(ValidationError):
            ScanRequest.model_validate(
                {
                    "scan_profile": "quick",
                    "scan_source": rejected_source,
                    "network_context": NETWORK_CONTEXT,
                    "devices": [],
                }
            )
    with pytest.raises(ValidationError):
        ScanRequest.model_validate(
            {
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": NETWORK_CONTEXT,
            }
        )
