import json
import hashlib
import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

TEST_DB_PATH = Path(__file__).resolve().parents[2] / ".tmp" / "home_guardian_test.sqlite3"
# The shared test environment is configured before application imports in
# backend/tests/conftest.py so test collection order cannot select a developer
# database or production-like credentials.

from app.main import app, issue_token_pair, repository
from app.services.cve_matcher import CveMatcher
from app.services.google_oauth import GoogleOAuthResult


_USER_SESSION_HEADERS: dict[str, dict[str, str]] = {}
_GUARDIAN_SESSION_HEADERS: dict[str, dict[str, str]] = {}


@contextmanager
def sqlite_test_connection() -> Iterator[sqlite3.Connection]:
    """Keep direct fixture writes transactional and explicitly close them."""
    conn = sqlite3.connect(TEST_DB_PATH)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def scoped_headers(user_id: str) -> dict[str, str]:
    cached = _USER_SESSION_HEADERS.get(user_id)
    if cached is not None:
        return dict(cached)
    email_key = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:20]
    user = repository.upsert_user(
        {
            "user_id": user_id,
            "email": f"{email_key}@backend-test.invalid",
            "nickname": f"테스트 사용자 {email_key[:6]}",
            "role": "user",
            "email_verified": True,
            "home_id": f"home-{user_id}",
        }
    )
    session = issue_token_pair(user)
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    _USER_SESSION_HEADERS[user_id] = headers
    return dict(headers)


def issue_test_session(email: str, nickname: str, *, user_id: str | None = None) -> dict[str, object]:
    stable_user_id = user_id or f"fixture-user-{hashlib.sha256(email.encode('utf-8')).hexdigest()[:20]}"
    user = repository.upsert_user(
        {
            "user_id": stable_user_id,
            "email": email,
            "nickname": nickname,
            "role": "user",
            "email_verified": True,
            "home_id": f"home-{stable_user_id}",
        }
    )
    return {
        "user": user,
        **issue_token_pair(user),
        "auth_mode": "test-fixture",
    }


def guardian_headers(guardian_id: str) -> dict[str, str]:
    cached = _GUARDIAN_SESSION_HEADERS.get(guardian_id)
    if cached is not None:
        return dict(cached)
    email_key = hashlib.sha256(guardian_id.encode("utf-8")).hexdigest()[:20]
    email = f"{email_key}@test.homeguardian.invalid"
    repository.upsert_guardian_account(
        guardian_id=guardian_id,
        email=email,
        display_name=f"테스트 보호자 {email_key[:6]}",
    )
    session = issue_token_pair(
        {
            "user_id": guardian_id,
            "email": email,
            "nickname": f"테스트 보호자 {email_key[:6]}",
            "role": "guardian",
            "home_id": "",
        }
    )
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    _GUARDIAN_SESSION_HEADERS[guardian_id] = headers
    return dict(headers)


class AuthenticatedTestClient(TestClient):
    """Attach one real signed fixture session to owner API calls only."""

    def request(self, method, url, **kwargs):
        path = str(url).split("?", 1)[0]
        public_auth_paths = {
            "/api/v1/auth/google/callback",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/handoff/complete",
        }
        protected_owner_api = (
            path.startswith("/api/v1/")
            and path not in public_auth_paths
            and not path.startswith(
                (
                    "/api/v1/internal/",
                    "/api/v1/ml/",
                    "/api/v1/guardian-mode/",
                )
            )
        )
        if protected_owner_api and kwargs.get("headers") is None:
            kwargs["headers"] = scoped_headers("default-api-owner")
        elif path.startswith("/api/v1/guardian-mode/") and kwargs.get("headers") is None:
            body = kwargs.get("json") if isinstance(kwargs.get("json"), dict) else {}
            params = kwargs.get("params") if isinstance(kwargs.get("params"), dict) else {}
            guardian_id = str(body.get("guardian_id") or params.get("guardian_id") or "").strip()
            if guardian_id:
                kwargs["headers"] = guardian_headers(guardian_id)
        return super().request(method, url, **kwargs)


client = AuthenticatedTestClient(app)


def actual_empty_scan_payload() -> dict[str, object]:
    return {
        "scan_profile": "quick",
        "scan_source": "android-native",
        "network_context": {
            "local_ip": "192.168.240.50",
            "gateway_ip": "192.168.240.1",
            "subnet_cidr": "192.168.240.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
            "is_emulator": False,
            "is_virtual_network": False,
        },
        "devices": [],
    }


def provision_repository_owner(repository, home_id: str) -> str:
    owner_key = hashlib.sha256(home_id.encode("utf-8")).hexdigest()[:16]
    repository.upsert_user(
        {
            "user_id": f"repository-owner-{owner_key}",
            "email": f"{owner_key}@repository-test.invalid",
            "nickname": f"저장소 테스트 사용자 {owner_key[:6]}",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )
    return home_id


def mark_sqlite_release_migration_pending(repository) -> None:
    """Model a database created by the previous application release."""

    from app.storage.sqlite_repository import _SQLITE_SCHEMA_MIGRATION_ID

    with repository._connect() as conn:
        conn.execute(
            "DELETE FROM repository_migrations WHERE migration_id = ?",
            (_SQLITE_SCHEMA_MIGRATION_ID,),
        )


def unwrap(response):
    body = response.json()
    assert body["success"] is True
    assert body["error"] is None
    return body["data"]


def assert_no_forbidden_public_device_text(value):
    forbidden = (
        "웹 관리 기기",
        "제조사 미확인",
        "정체불명",
        "알 수 없는",
        "기기 후보",
        "realtek",
        "espressif",
        "esp32",
        "chipset",
        "ieee",
        "oui",
        "private",
        "registration authority",
        "ma-m",
        "ma-s",
        "iana",
        "등록기관",
    )
    if isinstance(value, str):
        assert not any(term in value.lower() for term in forbidden), value
    elif isinstance(value, dict):
        for item in value.values():
            assert_no_forbidden_public_device_text(item)
    elif isinstance(value, list):
        for item in value:
            assert_no_forbidden_public_device_text(item)


def assert_safe_validation_error(response, *sensitive_values: str) -> None:
    """422 public responses must never include raw rejected request values."""
    assert response.status_code == 422
    body = response.json()
    assert body["success"] is False
    assert body["data"] is None
    assert body["error"]["code"] == "INPUT_CHECK_REQUIRED"
    assert body["error"]["details"] == {}
    assert body["error"]["message"]

    public_text = json.dumps(body, ensure_ascii=False)
    for sensitive_value in sensitive_values:
        assert sensitive_value not in public_text


def test_health_returns_8010_service():
    data = unwrap(client.get("/health"))
    assert data["status"] == "healthy"
    assert data["port"] == 8010


def test_health_requires_google_client_id_without_exposing_configuration(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AUTH_CONFIGURATION_REQUIRED"
    assert "GOOGLE_CLIENT_ID" not in json.dumps(response.json(), ensure_ascii=False)


def test_health_rejects_malformed_google_client_id(monkeypatch):
    malformed = "not a google oauth client id"
    monkeypatch.setenv("GOOGLE_CLIENT_ID", malformed)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AUTH_CONFIGURATION_REQUIRED"
    assert malformed not in json.dumps(response.json(), ensure_ascii=False)


def test_test_fixture_issues_named_user_session_without_runtime_endpoint():
    login_data = issue_test_session("fixture-login@example.com", "테스트")
    assert login_data["auth_mode"] == "test-fixture"
    assert login_data["user"]["email"] == "fixture-login@example.com"


def test_request_validation_error_never_reflects_scan_payload_values():
    raw_device_name = "\uc6f9 \uad00\ub9ac \uae30\uae30 Realtek OUI " + ("x" * 600)
    raw_ipv4 = "192.168.77.201-" * 20
    raw_ipv6 = "fe80::abcd-" * 40
    raw_mac = "AA:BB:CC:DD:EE:FF-" * 20

    response = client.post(
        "/api/v1/security/scan",
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "devices": [
                {
                    "name": raw_device_name,
                    "ip_address": raw_ipv4,
                    "mac_address": raw_mac,
                    "firmware": raw_ipv6,
                }
            ],
        },
    )

    assert_safe_validation_error(
        response,
        raw_device_name,
        raw_ipv4,
        raw_ipv6,
        raw_mac,
        "\uc6f9 \uad00\ub9ac \uae30\uae30",
        "Realtek",
        "OUI",
        "192.168.77.201",
        "fe80::abcd",
        "AA:BB:CC:DD:EE:FF",
    )


def test_request_validation_error_never_reflects_auth_secrets():
    requests = (
        (
            "/api/v1/auth/refresh",
            {"refresh_token": "raw-refresh-secret"},
            ("raw-refresh-secret",),
        ),
        (
            "/api/v1/auth/logout",
            {"refresh_token": "raw-logout-secret"},
            ("raw-logout-secret",),
        ),
        (
            "/api/v1/auth/handoff/complete",
            {
                "previous_refresh_token": "raw-previous-secret",
                "successor_refresh_token": "raw-successor-secret",
                "handoff_id": "raw-handoff-secret",
            },
            ("raw-previous-secret", "raw-successor-secret", "raw-handoff-secret"),
        ),
    )

    for path, payload, secrets_to_redact in requests:
        assert_safe_validation_error(client.post(path, json=payload), *secrets_to_redact)


def test_auth_refresh_rotates_and_logout_revokes_session():
    login = issue_test_session("session@example.com", "세션 사용자")
    initial_refresh = login["refresh_token"]
    initial_access = login["access_token"]

    session = unwrap(client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {initial_access}"}))
    assert session["role"] == "user"

    refreshed = unwrap(client.post("/api/v1/auth/refresh", json={"refresh_token": initial_refresh}))
    assert refreshed["refresh_token"] != initial_refresh
    assert refreshed["access_token"] != initial_access
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": initial_refresh})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "AUTH_SESSION_INVALID"

    assert unwrap(client.post("/api/v1/auth/logout", json={"refresh_token": refreshed["refresh_token"]}))["revoked"] is True
    revoked_access = client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {refreshed['access_token']}"})
    assert revoked_access.status_code == 401


def test_deleted_user_principal_invalidates_access_and_refresh_tokens():
    login = issue_test_session(
        "deleted-principal-user@example.com",
        "삭제된 사용자 계정",
        user_id="deleted-principal-user",
    )
    with sqlite_test_connection() as conn:
        conn.execute("DELETE FROM users WHERE user_id = ?", ("deleted-principal-user",))

    access = client.get(
        "/api/v1/dashboard",
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )
    refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["refresh_token"]},
    )

    assert access.status_code == 401
    assert refresh.status_code == 401


def test_deleted_guardian_principal_invalidates_access_and_refresh_tokens():
    guardian_id = "deleted-principal-guardian"
    guardian = repository.upsert_guardian_account(
        guardian_id=guardian_id,
        email="deleted-principal-guardian@example.com",
        display_name="삭제된 보호자 계정",
    )
    login = issue_token_pair(
        {
            "user_id": guardian["guardian_id"],
            "email": guardian["email"],
            "nickname": guardian["display_name"],
            "role": "guardian",
            "home_id": "",
        }
    )
    with sqlite_test_connection() as conn:
        conn.execute("DELETE FROM guardian_accounts WHERE guardian_id = ?", (guardian_id,))

    access = client.get(
        "/api/v1/guardian-mode/wards",
        params={"guardian_id": guardian_id},
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )
    refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["refresh_token"]},
    )

    assert access.status_code == 401
    assert refresh.status_code == 401


def test_auth_session_rejects_a_tampered_access_signature():
    """A signed token must not become usable when only its signature is changed."""
    login = issue_test_session("tampered-access@example.com", "서명 변조 확인")
    access_token = login["access_token"]
    replacement = "A" if access_token[-1] != "A" else "B"
    tampered_access_token = f"{access_token[:-1]}{replacement}"

    response = client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {tampered_access_token}"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_SESSION_INVALID"
    assert client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {access_token}"},
    ).status_code == 200


def test_auth_refresh_recovers_lost_response_after_relaunch():
    """A persisted attempt id recovers a committed rotation after response loss."""
    from app.storage.sqlite_repository import SQLiteRepository

    login = issue_test_session("refresh-recovery@example.com", "Refresh recovery")
    original_refresh = login["refresh_token"]
    attempt_id = "refresh-recovery-attempt-0001"

    # Simulate a server commit followed by a lost HTTP response: the client
    # still has only original_refresh and the previously stored attempt id.
    committed = unwrap(
        client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh, "refresh_attempt_id": attempt_id},
        )
    )
    with sqlite_test_connection() as conn:
        row = conn.execute(
            """
            SELECT refresh_token_hash, previous_refresh_token_hash, refresh_retry_id
            FROM auth_sessions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (login["user"]["user_id"],),
        ).fetchone()
    assert row is not None
    assert original_refresh not in row[0]
    assert original_refresh not in row[1]
    assert committed["refresh_token"] not in row[0]
    assert row[2] == attempt_id

    # Re-opening the repository covers a relaunch/process reconnect against the
    # same persisted state. A different id must not recover the successor.
    SQLiteRepository(db_path=TEST_DB_PATH)
    wrong_attempt = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh, "refresh_attempt_id": "refresh-recovery-attempt-other"},
    )
    assert wrong_attempt.status_code == 401

    recovered = unwrap(
        client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh, "refresh_attempt_id": attempt_id},
        )
    )
    assert recovered["refresh_token"] == committed["refresh_token"]
    assert recovered["user"]["user_id"] == login["user"]["user_id"]
    assert unwrap(
        client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {recovered['access_token']}"})
    )["user"]["email"] == "refresh-recovery@example.com"


def test_auth_logout_with_response_loss_predecessor_revokes_successor_session():
    """Logout must retire the active successor addressed by its retry predecessor."""
    login = issue_test_session("refresh-logout@example.com", "Refresh logout")
    predecessor_refresh = login["refresh_token"]
    attempt_id = "refresh-logout-attempt-0001"
    successor = unwrap(
        client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": predecessor_refresh, "refresh_attempt_id": attempt_id},
        )
    )

    assert unwrap(
        client.post("/api/v1/auth/logout", json={"refresh_token": predecessor_refresh})
    )["revoked"] is True
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": successor["refresh_token"]},
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": predecessor_refresh, "refresh_attempt_id": attempt_id},
    ).status_code == 401
    assert client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {successor['access_token']}"},
    ).status_code == 401


def test_auth_session_survives_repository_reinitialization():
    """A repository re-open is the storage-level part of a process restart test."""
    from app.storage.sqlite_repository import SQLiteRepository

    login = issue_test_session("restart@example.com", "재시작 사용자")
    SQLiteRepository(db_path=TEST_DB_PATH)
    refreshed = unwrap(client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]}))
    restored = unwrap(client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {refreshed['access_token']}"}))
    assert restored["user"]["email"] == "restart@example.com"


def test_sqlalchemy_auth_rotation_persists_retryable_hash_state(tmp_path, request):
    from app.storage.sa_repository import SqlAlchemyRepository

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-auth-rotation.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    expiry = "2099-01-01T00:00:00Z"
    retry_until = "2099-01-01T00:10:00Z"
    repository.create_auth_session(
        session_id="session-sa-refresh-recovery",
        user_id="user-sa-refresh-recovery",
        home_id="home-user-sa-refresh-recovery",
        role="user",
        refresh_token_hash="old-refresh-hmac",
        expires_at=expiry,
    )

    assert repository.rotate_auth_session(
        session_id="session-sa-refresh-recovery",
        previous_refresh_token_hash="old-refresh-hmac",
        refresh_token_hash="successor-refresh-hmac",
        expires_at=expiry,
        refresh_retry_id="refresh-recovery-attempt-0001",
        refresh_retry_until=retry_until,
    )

    reopened = SqlAlchemyRepository(database_url)
    request.addfinalizer(reopened.close)
    pending = reopened.auth_session_by_previous_refresh_hash("old-refresh-hmac")
    assert pending is not None
    assert pending["refresh_token_hash"] == "successor-refresh-hmac"
    assert pending["refresh_retry_id"] == "refresh-recovery-attempt-0001"
    assert reopened.recover_auth_session_rotation(
        session_id="session-sa-refresh-recovery",
        previous_refresh_token_hash="old-refresh-hmac",
        refresh_retry_id="refresh-recovery-attempt-0001",
        refresh_token_hash="successor-refresh-hmac",
    )
    assert not reopened.recover_auth_session_rotation(
        session_id="session-sa-refresh-recovery",
        previous_refresh_token_hash="old-refresh-hmac",
        refresh_retry_id="refresh-recovery-attempt-other",
        refresh_token_hash="successor-refresh-hmac",
    )


def test_sqlalchemy_previous_refresh_hash_revokes_retryable_successors(tmp_path, request):
    """Logout and role supersession both retire a response-loss successor by its old hash."""
    from app.storage.sa_repository import SqlAlchemyRepository

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-auth-predecessor-revoke.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    expiry = "2099-01-01T00:00:00Z"
    retry_until = "2099-01-01T00:10:00Z"

    repository.create_auth_session(
        session_id="session-sa-predecessor-logout",
        user_id="user-sa-predecessor-logout",
        home_id="home-user-sa-predecessor-logout",
        role="user",
        refresh_token_hash="old-refresh-hmac-logout",
        expires_at=expiry,
    )
    assert repository.rotate_auth_session(
        session_id="session-sa-predecessor-logout",
        previous_refresh_token_hash="old-refresh-hmac-logout",
        refresh_token_hash="successor-refresh-hmac-logout",
        expires_at=expiry,
        refresh_retry_id="refresh-logout-attempt-0001",
        refresh_retry_until=retry_until,
    )
    assert repository.revoke_auth_session_by_refresh_hash("old-refresh-hmac-logout")
    revoked = repository.auth_session_by_id("session-sa-predecessor-logout")
    assert revoked is not None
    assert revoked["revoked_at"] is not None
    assert not repository.recover_auth_session_rotation(
        session_id="session-sa-predecessor-logout",
        previous_refresh_token_hash="old-refresh-hmac-logout",
        refresh_retry_id="refresh-logout-attempt-0001",
        refresh_token_hash="successor-refresh-hmac-logout",
    )

    repository.create_auth_session(
        session_id="session-sa-predecessor-switch",
        user_id="user-sa-predecessor-switch",
        home_id="home-user-sa-predecessor-switch",
        role="user",
        refresh_token_hash="old-refresh-hmac-switch",
        expires_at=expiry,
    )
    assert repository.rotate_auth_session(
        session_id="session-sa-predecessor-switch",
        previous_refresh_token_hash="old-refresh-hmac-switch",
        refresh_token_hash="successor-refresh-hmac-switch",
        expires_at=expiry,
        refresh_retry_id="refresh-switch-attempt-0001",
        refresh_retry_until=retry_until,
    )
    replacement = repository.create_auth_session(
        session_id="session-sa-replacement-role",
        user_id="guardian-sa-predecessor-switch",
        home_id="",
        role="guardian",
        refresh_token_hash="replacement-refresh-hmac-switch",
        expires_at=expiry,
        superseded_refresh_token_hash="old-refresh-hmac-switch",
    )
    superseded = repository.auth_session_by_id("session-sa-predecessor-switch")
    active_replacement = repository.auth_session_by_id("session-sa-replacement-role")
    assert superseded is not None
    assert superseded["revoked_at"] is not None
    assert replacement["revoked_at"] is None
    assert active_replacement is not None
    assert active_replacement["revoked_at"] is None


def test_sqlalchemy_auth_handoff_is_atomic_and_idempotent(tmp_path, request):
    """SQLite-via-SQLAlchemy follows the same staged handoff contract."""
    from app.storage.sa_repository import SqlAlchemyRepository

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-auth-handoff.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    expiry = "2099-01-01T00:00:00Z"
    handoff_expiry = "2099-01-01T00:10:00Z"
    repository.create_auth_session(
        session_id="session-sa-handoff-old",
        user_id="user-sa-handoff-old",
        home_id="home-sa-handoff-old",
        role="user",
        refresh_token_hash="old-handoff-refresh-hmac",
        expires_at=expiry,
    )
    repository.create_auth_session(
        session_id="session-sa-handoff-new",
        user_id="guardian-sa-handoff-new",
        home_id="",
        role="guardian",
        refresh_token_hash="new-handoff-refresh-hmac",
        expires_at=expiry,
        activation_state="pending",
        handoff_predecessor_session_id="session-sa-handoff-old",
        handoff_predecessor_refresh_token_hash="old-handoff-refresh-hmac",
        handoff_id_hash="handoff-id-hmac",
        handoff_expires_at=handoff_expiry,
    )

    assert repository.complete_auth_handoff(
        predecessor_refresh_token_hash="wrong-old-handoff-refresh-hmac",
        successor_refresh_token_hash="new-handoff-refresh-hmac",
        handoff_id_hash="handoff-id-hmac",
    ) is None
    old_before = repository.auth_session_by_id("session-sa-handoff-old")
    new_before = repository.auth_session_by_id("session-sa-handoff-new")
    assert old_before is not None and old_before["revoked_at"] is None
    assert new_before is not None and new_before["activation_state"] == "pending"

    completed = repository.complete_auth_handoff(
        predecessor_refresh_token_hash="old-handoff-refresh-hmac",
        successor_refresh_token_hash="new-handoff-refresh-hmac",
        handoff_id_hash="handoff-id-hmac",
    )
    assert completed is not None and completed["activation_state"] == "active"
    assert repository.auth_session_by_id("session-sa-handoff-old")["revoked_at"] is not None
    # Response-loss retry returns the same successor without needing the old
    # session to still be active.
    assert repository.complete_auth_handoff(
        predecessor_refresh_token_hash="old-handoff-refresh-hmac",
        successor_refresh_token_hash="new-handoff-refresh-hmac",
        handoff_id_hash="handoff-id-hmac",
    )["session_id"] == "session-sa-handoff-new"


def test_persistent_auth_secret_survives_fresh_app_and_repository_processes(tmp_path):
    """A fixed signing secret keeps user and guardian sessions valid after a real process restart."""
    import subprocess
    import sys
    import textwrap

    backend_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "persistent-auth-restart.sqlite3"
    persistent_secret = "fixed-auth-token-secret-for-restart-test-at-least-32-characters"
    phase_environment = os.environ.copy()
    phase_environment.update(
        {
            "DATABASE_URL": "",
            "HOME_GUARDIAN_DB_PATH": str(database_path),
            "HG_AUTH_TOKEN_SECRET": persistent_secret,
        }
    )
    existing_python_path = phase_environment.get("PYTHONPATH", "")
    phase_environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(backend_root), existing_python_path) if part
    )

    def run_restart_phase(source: str, environment: dict[str, str]) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(source)],
            cwd=backend_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, (
            "isolated auth restart phase failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
        return json.loads(completed.stdout.strip().splitlines()[-1])

    issued = run_restart_phase(
        """
        import json

        from app.main import issue_token_pair, repository

        user = repository.upsert_user({
            "user_id": "persistent-restart-user",
            "email": "persistent-user@example.com",
            "nickname": "Persistent User",
            "role": "user",
            "email_verified": True,
            "home_id": "home-persistent-restart-user",
        })
        user_tokens = issue_token_pair(user)
        guardian = {
            "user_id": "guardian-persistent-restart",
            "email": "persistent-guardian@example.com",
            "nickname": "Persistent Guardian",
            "role": "guardian",
            "home_id": "",
        }
        repository.upsert_guardian_account(
            guardian_id=guardian["user_id"],
            email=guardian["email"],
            display_name=guardian["nickname"],
        )
        guardian_tokens = issue_token_pair(guardian)
        print(json.dumps({
            "user_id": user["user_id"],
            "user_refresh": user_tokens["refresh_token"],
            "guardian_id": guardian["user_id"],
            "guardian_refresh": guardian_tokens["refresh_token"],
        }, sort_keys=True))
        """,
        phase_environment,
    )

    refreshed_environment = phase_environment.copy()
    refreshed_environment["HG_TEST_RESTART_TOKENS"] = json.dumps(issued)
    verified = run_restart_phase(
        """
        import json
        import os

        from fastapi.testclient import TestClient
        from app.main import app

        api = TestClient(app)
        issued = json.loads(os.environ["HG_TEST_RESTART_TOKENS"])
        verified = {}
        for role, expected_id, original_refresh in (
            ("user", issued["user_id"], issued["user_refresh"]),
            ("guardian", issued["guardian_id"], issued["guardian_refresh"]),
        ):
            refreshed_response = api.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": original_refresh},
            )
            assert refreshed_response.status_code == 200, refreshed_response.text
            refreshed = refreshed_response.json()["data"]
            assert refreshed["refresh_token"] != original_refresh
            session_response = api.get(
                "/api/v1/auth/session",
                headers={"Authorization": f"Bearer {refreshed['access_token']}"},
            )
            assert session_response.status_code == 200, session_response.text
            session = session_response.json()["data"]
            assert session["role"] == role
            assert session["user"]["user_id"] == expected_id
            verified[role] = session["role"]
        print(json.dumps(verified, sort_keys=True))
        """,
        refreshed_environment,
    )

    assert verified == {"guardian": "guardian", "user": "user"}


def test_auth_secret_is_required_in_every_runtime(monkeypatch):
    from app.main import auth_token_secret

    monkeypatch.delenv("HG_AUTH_TOKEN_SECRET", raising=False)
    import pytest

    with pytest.raises(RuntimeError, match="HG_AUTH_TOKEN_SECRET"):
        auth_token_secret()


def test_runtime_has_no_test_auth_endpoint_or_header_bypass(monkeypatch):
    """Runtime exposes neither a test login route nor header-only identity."""
    from app.main import auth_token_secret
    import pytest

    monkeypatch.delenv("HG_AUTH_TOKEN_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="HG_AUTH_TOKEN_SECRET"):
        auth_token_secret()
    health = client.get("/health")
    assert health.status_code == 503
    assert health.json()["error"]["code"] == "AUTH_CONFIGURATION_REQUIRED"
    assert client.post(
        "/api/v1/auth/test-login",
        json={"email": "production-closed@example.com", "nickname": "운영 차단 확인"},
    ).status_code == 404
    assert client.get(
        "/api/v1/devices",
        headers={
            "X-Home-Guardian-User-Id": "header-bypass",
            "X-Home-Guardian-Home-Id": "home-header-bypass",
        },
    ).status_code == 401


def test_google_role_handoff_keeps_predecessor_until_durable_completion(monkeypatch):
    """A lost callback response cannot discard the working predecessor role."""

    def fake_authenticate(code, id_token_value, redirect_uri):
        assert code is None
        assert id_token_value == "role-switch-id-token"
        assert redirect_uri == "homeguardian://auth/google"
        return GoogleOAuthResult(
            user={
                "user_id": "google-role-switch",
                "email": "role-switch@example.com",
                "nickname": "역할 전환 사용자",
                "role": "user",
                "email_verified": True,
                "home_id": "operator-home",
            },
            provider="google",
            mode="oauth",
            raw_claims={"sub": "google-role-switch"},
        )

    monkeypatch.setattr("app.main.google_oauth_service.authenticate", fake_authenticate)
    previous = issue_test_session("previous-role@example.com", "이전 역할")
    previous_refresh = previous["refresh_token"]
    previous_attempt_id = "role-switch-refresh-attempt-0001"
    rotated_previous = unwrap(
        client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": previous_refresh, "refresh_attempt_id": previous_attempt_id},
        )
    )
    staged = unwrap(
        client.post(
            "/api/v1/auth/google/callback",
            json={
                "id_token": "role-switch-id-token",
                "redirect_uri": "homeguardian://auth/google",
                "role": "guardian",
                "previous_refresh_token": rotated_previous["refresh_token"],
            },
        )
    )

    assert staged["user"]["role"] == "guardian"
    assert staged["handoff"]["id"]
    # Simulate losing the callback HTTP response: the predecessor access token
    # still works and the staged successor cannot be used as a refresh session.
    assert client.post(
        "/api/v1/auth/refresh", json={"refresh_token": staged["refresh_token"]}
    ).status_code == 401
    assert unwrap(
        client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {rotated_previous['access_token']}"})
    )["role"] == "user"

    # Possession of either refresh token alone, or a forged handoff id, must
    # never activate the candidate or revoke the prior role.
    assert client.post(
        "/api/v1/auth/handoff/complete",
        json={
            "previous_refresh_token": rotated_previous["refresh_token"],
            "successor_refresh_token": staged["refresh_token"],
            "handoff_id": "forged-handoff-id-value-that-is-long-enough",
        },
    ).status_code == 401
    assert client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {rotated_previous['access_token']}"},
    ).status_code == 200

    completed = unwrap(
        client.post(
            "/api/v1/auth/handoff/complete",
            json={
                "previous_refresh_token": rotated_previous["refresh_token"],
                "successor_refresh_token": staged["refresh_token"],
                "handoff_id": staged["handoff"]["id"],
            },
        )
    )
    assert completed["user"]["role"] == "guardian"
    assert completed["refresh_token"] == staged["refresh_token"]
    assert client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {rotated_previous['access_token']}"},
    ).status_code == 401
    # Completion response loss is idempotently recovered after relaunch.
    recovered = unwrap(
        client.post(
            "/api/v1/auth/handoff/complete",
            json={
                "previous_refresh_token": rotated_previous["refresh_token"],
                "successor_refresh_token": staged["refresh_token"],
                "handoff_id": staged["handoff"]["id"],
            },
        )
    )
    assert recovered["refresh_token"] == staged["refresh_token"]
    assert unwrap(
        client.post("/api/v1/auth/refresh", json={"refresh_token": staged["refresh_token"]})
    )["user"]["role"] == "guardian"


def test_test_login_route_does_not_exist():
    response = client.post("/api/v1/auth/test-login", json={"email": "closed@example.com", "nickname": "차단 확인"})
    assert response.status_code == 404


def test_google_callback_without_client_id_returns_401(monkeypatch):
    """GOOGLE_CLIENT_ID가 없으면 비검증 응답을 절대 만들지 않는다."""
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    response = client.post(
        "/api/v1/auth/google/callback",
        json={"code": "code-x", "redirect_uri": "homeguardian://auth/google"},
    )
    assert response.status_code == 401
    payload = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "AUTH_GOOGLE_FAILED"


def test_google_callback_has_no_development_fallback(monkeypatch):
    """환경 표식과 관계없이 client id 없는 요청은 검증 실패한다."""
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    response = client.post(
        "/api/v1/auth/google/callback",
        json={"code": "code-y", "redirect_uri": "homeguardian://auth/google"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_GOOGLE_FAILED"


def test_google_callback_guardian_role_returns_guardian_account(monkeypatch):
    """보호자 Google 로그인은 사용자 홈 세션과 섞이지 않는 guardian 계정으로 반환한다."""

    def fake_authenticate(code, id_token_value, redirect_uri):
        assert code is None
        assert id_token_value == "verified-id-token"
        assert redirect_uri == "homeguardian://auth/google"
        return GoogleOAuthResult(
            user={
                "user_id": "google-sub-guardian-role",
                "email": "guardian.role@example.com",
                "nickname": "보호자 역할",
                "role": "user",
                "email_verified": True,
                "home_id": "operator-home",
            },
            provider="google",
            mode="oauth",
            raw_claims={"sub": "google-sub-guardian-role"},
        )

    monkeypatch.setattr("app.main.google_oauth_service.authenticate", fake_authenticate)

    data = unwrap(
        client.post(
            "/api/v1/auth/google/callback",
            json={
                "id_token": "verified-id-token",
                "redirect_uri": "homeguardian://auth/google",
                "role": "guardian",
            },
        )
    )

    assert data["provider"] == "google"
    assert data["auth_mode"] == "oauth"
    assert data["user"]["user_id"] == "guardian-google-sub-guardian-role"
    assert data["user"]["role"] == "guardian"
    assert data["user"]["home_id"] == ""


def test_dashboard_empty_state_when_no_scan_yet():
    """첫 배포/스캔 전 상태에서 dashboard/devices/score가 빈 상태로 일관되게 반환되는지 확인한다."""
    dashboard = unwrap(client.get("/api/v1/dashboard"))
    devices = unwrap(client.get("/api/v1/devices"))
    score = unwrap(client.get("/api/v1/security/score"))

    assert dashboard["home"]["mode"] == "basic"
    assert dashboard["home"]["device_count"] == 0
    assert devices["total"] == 0
    assert devices["items"] == []
    assert dashboard["guardian_status"]["connected_guardians"] == 0
    assert dashboard["top_risks"] == []
    assert dashboard["summary"]["online_devices"] == 0
    assert dashboard["summary"]["high_risk_devices"] == 0
    assert dashboard["summary"]["score_status"] == "not_started"
    assert dashboard["summary"]["scan_complete"] is False
    assert dashboard["summary"]["coverage_complete"] is None
    assert score["score"] == dashboard["summary"]["score"]
    assert score["device_scores"] == []
    assert score["score"] is None
    assert score["score_status"] == "not_started"
    assert score["risk_level"] == "unknown"
    assert score["scan_complete"] is False
    assert score["coverage_complete"] is None


def test_security_scan_on_empty_home_returns_empty_result():
    """실제 Android 점검이 0대를 관측해도 빈 결과를 일관되게 저장/조회한다."""
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.90.50",
                    "gateway_ip": "192.168.90.1",
                    "subnet_cidr": "192.168.90.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [],
            },
        )
    )
    status_data = unwrap(client.get(f"/api/v1/security/scan/{scan['scan_id']}/status"))
    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}"))
    score = unwrap(client.get("/api/v1/security/score"))
    dashboard = unwrap(client.get("/api/v1/dashboard"))
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "no-targets-guardian@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-no-targets",
        "guardian_email": "no-targets-guardian@example.com",
        "guardian_name": "빈 점검 확인 보호자",
    }
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    guardian_dashboard = unwrap(
        client.get(
            f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )

    assert status_data["status"] == "completed"
    assert status_data["progress"] == 100
    assert scan["push_result"] == {"sent": 0, "failed": 0}
    assert result["devices_found"] == 0
    assert result["devices"] == []
    assert result["high_risk_devices"] == 0
    assert result["security_score"]["device_scores"] == []
    assert scan["scan_complete"] is True and scan["coverage_complete"] is True
    assert status_data["score_status"] == "no_targets"
    assert dashboard["summary"]["score_status"] == "no_targets"
    assert dashboard["summary"]["score"] is None
    assert dashboard["summary"]["scan_complete"] is True
    assert dashboard["summary"]["coverage_complete"] is True
    assert guardian_dashboard["ward_summary"]["score"] is None
    assert guardian_dashboard["ward_summary"]["risk_level"] == "unknown"
    assert guardian_dashboard["ward_summary"]["score_status"] == "no_targets"
    assert guardian_dashboard["ward_summary"]["scan_complete"] is True
    assert guardian_dashboard["ward_summary"]["coverage_complete"] is True
    for public_score in (result["security_score"], score):
        assert public_score["score"] is None
        assert public_score["risk_level"] == "unknown"
        assert public_score["score_status"] == "no_targets"
        assert public_score["scan_complete"] is True
        assert public_score["coverage_complete"] is True
        assert public_score["summary"] == "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."


def test_unresolved_scan_returns_only_scan_level_research_status():
    """android-native 스캔으로 카메라 후보를 저장한 뒤, device 상세 안내가 한국어로 반환되는지 확인한다."""
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.10.50",
                    "gateway_ip": "192.168.10.1",
                    "subnet_cidr": "192.168.10.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "dev-192-168-10-21",
                        "name": "카메라 후보 192.168.10.21",
                        "device_type": "camera",
                        "ip_address": "192.168.10.21",
                        "mac_address": "UNKNOWN-192.168.10.21",
                        "open_ports": [23, 80, 554],
                        "services": ["telnet", "http", "rtsp"],
                        "vulnerabilities": [],
                        "discovery_sources": ["ws-discovery"],
                        "risk_signals": [
                            "camera_candidate",
                            "rtsp_open",
                            "telnet_open",
                            "default_credentials_possible",
                        ],
                    }
                ],
            },
        )
    )
    listed = unwrap(client.get("/api/v1/devices"))
    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}"))
    assert listed["items"] == []
    assert listed["identity_pending_count"] == 1
    assert listed["identity_research_status"] == "review_required"
    assert listed["identity_findings"] == []
    assert result["identity_pending_count"] == 1
    assert result["high_risk_devices"] == 1
    public_finding_text = json.dumps(listed, ensure_ascii=False)
    for temporary_label in (
        "품번 확인 중",
        "제품 정보 확인 중",
        "제품 정보 확인 필요",
        "제조사 미확인",
        "알 수 없는 기기",
    ):
        assert temporary_label not in public_finding_text
    # An address-derived legacy id has no strong scope+MAC continuity proof and
    # therefore cannot be used to recover private history or a current finding.
    legacy_response = client.get("/api/v1/devices/dev-192-168-10-21")
    assert legacy_response.status_code == 404


def test_cve_matcher_does_not_attach_product_cve_on_vendor_only_match():
    matcher = CveMatcher()

    matches = matcher.match_device(
        manufacturer="Samsung Electronics",
        model="SM-F956N",
        firmware="unknown",
        risk_signals=[],
    )

    assert not any(item.get("source") == "catalog" for item in matches)
    assert not any(item.get("matched_on") == "vendor-only" for item in matches)


def test_cve_matcher_keeps_catalog_cve_when_product_matches():
    matcher = CveMatcher()

    # 검증된 실제 CVE(CVE-2020-7847 = ipTIME *NAS* 파일업로드 RCE, CWE-434, 8.0 HIGH, NVD 확인)로 product
    # 매칭 시 카탈로그 CVE 유지를 검증. (이전엔 CVE-2018-15399=Cisco ASA 환각이라 제거했고, 한때 이 CVE 를
    # 'router/인증우회' 로 오귀속했으나 NVD 재확인 결과 ipTIME NAS 의 파일업로드 RCE 라 nas 로 정정.)
    matches = matcher.match_device(
        manufacturer="EFM Networks",
        model="ipTIME NAS2dual",
        firmware="unknown",
        risk_signals=[],
        device_type="nas",
    )

    assert any(item.get("cve_id") == "CVE-2020-7847" for item in matches)
    # 회귀: ipTIME *공유기* 는 이 NAS CVE 를 받지 않는다(오귀속 정정으로 오탐 제거)
    router_matches = matcher.match_device(
        manufacturer="EFM Networks", model="ipTIME BE3600QCA", device_type="router")
    assert not any(item.get("cve_id") == "CVE-2020-7847" for item in router_matches)
    assert all(item.get("matched_on") != "vendor-only" for item in matches)


def test_self_device_skips_cve_enrichment():
    """본인 휴대폰(self_device)은 검사 대상이 아니므로 CVE enrich 를 건너뛴다.
    (scoring 이 100/green·'검사 대상 아님'으로 고정하는 것과 모순되지 않게, 불필요한 NVD 조회도 회피.)"""
    from app.main import _enrich_with_cve

    phone = {
        "manufacturer": "samsung",
        "model": "SM-F956N",
        "firmware": "unknown",
        "device_type": "phone",
        "risk_signals": ["self_device"],
        "vulnerabilities": [],
    }
    enriched = _enrich_with_cve(phone)
    assert enriched.get("vulnerabilities") == []
    assert "risk_explanations" not in enriched  # self 는 어떤 CVE/신호도 부착하지 않는다


def test_android_native_scan_payload_is_stored_and_scored():
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.0.50",
                    "gateway_ip": "192.168.0.1",
                    "subnet_cidr": "192.168.0.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "dev-192-168-0-21",
                        "name": "카메라 후보 192.168.0.21",
                        "device_type": "camera",
                        "manufacturer": "Hikvision",
                        "model": "DS-2CD2042",
                        "ip_address": "192.168.0.21",
                        "mac_address": "AA:BB:CC:00:00:21",
                        "open_ports": [23, 80, 554, 3702],
                        "services": ["telnet", "http", "rtsp", "onvif"],
                        "vulnerabilities": [{"cve_id": "CVE-2024-TEST", "severity": "high"}],
                        "discovery_sources": ["tcp-port-probe", "ws-discovery"],
                        "fingerprints": [
                            "upnp-manufacturer:Hikvision",
                            "upnp-model:DS-2CD2042",
                            "upnp-type:camera",
                        ],
                        "risk_signals": ["camera_candidate", "rtsp_open", "onvif_discovery", "default_credentials_possible"],
                    }
                ],
            },
        )
    )
    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}"))
    devices = unwrap(client.get("/api/v1/devices"))
    assert len(devices["items"]) == 1
    assert devices["identified_count"] == 1
    assert devices["identity_pending_count"] == 0
    assert devices["identity_findings"] == []
    public_device_id = devices["items"][0]["device_id"]
    detail = unwrap(client.get(f"/api/v1/devices/{public_device_id}"))
    dashboard = unwrap(client.get("/api/v1/dashboard"))
    events = unwrap(client.get("/api/v1/security/events"))
    notifications = unwrap(client.get("/api/v1/notifications"))

    assert scan["scan_source"] == "android-native"
    assert result["network_context"] == {
        "interface_type": "wifi",
        "is_private_network": True,
    }
    assert "192.168.0.0/24" not in json.dumps(result, ensure_ascii=False)
    assert result["devices_found"] == 1
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 0
    assert result["identity_incomplete"] is False
    assert result["security_score"]["identity_pending_count"] == 0
    assert result["security_score"]["identity_incomplete"] is False
    assert result["security_score"]["identity_research_status"] == "complete"
    assert devices["total"] == 1
    assert "192-168-0-21" not in public_device_id
    assert devices["items"][0]["scan_source"] == "android-native"
    assert dashboard["home"]["device_count"] == 1
    assert events["total"] == 1
    assert events["items"][0]["severity"] == "red"
    assert events["items"][0]["device_id"] == public_device_id
    assert all("샘플" not in item["title"] for item in notifications["items"])
    assert detail["risk_level"] == "red"
    assert "risk_signals" not in detail
    assert detail["canonical_name"] == "하이크비전 카메라 (DS-2CD2042)"
    assert "is_identity_finding" not in detail


def test_spotify_service_only_responses_stay_private_without_inflating_public_counts():
    devices = [
        {
            "device_id": f"spotify-response-{index}",
            "name": "",
            "device_type": "unknown",
            "ip_address": f"192.168.62.{index + 20}",
            "mac_address": f"UNKNOWN-192.168.62.{index + 20}",
            "open_ports": [17654],
            "services": ["spotify-connect"],
            "discovery_sources": ["tcp-port-probe", "spotify-getinfo"],
            "fingerprints": ["spotify-probe:17654", "spotify-getinfo-done"],
        }
        for index in range(18)
    ]
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.62.10",
                    "gateway_ip": "192.168.62.1",
                    "subnet_cidr": "192.168.62.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": devices,
            },
        )
    )
    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}"))
    notifications = unwrap(client.get("/api/v1/notifications"))

    for payload in (scan, result):
        assert payload["devices_found"] == 0
        assert payload["identified_count"] == 0
        assert payload["identity_pending_count"] == 0
        assert payload["detected_connections"] == []
        assert payload["identity_findings"] == []
    assert result["security_score"]["score_status"] == "no_targets"

    private_jobs = repository.identity_enrichment_jobs(
        home_id="home-default-api-owner",
        limit=200,
    )
    spotify_jobs = [
        item
        for item in private_jobs
        if "spotify-connect" in (item.get("evidence") or {}).get("service_hints", [])
    ]
    assert len(spotify_jobs) == 18
    assert all(item["status"] in {"review_required", "blocked"} for item in spotify_jobs)
    raw_findings = [
        item
        for item in repository.identity_findings(home_id="home-default-api-owner")
        if item.get("observed_service") == "spotify-connect"
    ]
    assert len(raw_findings) == 18
    raw_snapshot = repository._latest_scan_devices_only("home-default-api-owner")
    assert len(raw_snapshot) == 18
    assert all("spotify-connect" in (item.get("services") or []) for item in raw_snapshot)
    assert any(
        "평가할 네트워크 기기는 확인되지 않았어요" in item["message"]
        for item in notifications["items"]
    )
    assert all("기기 18대" not in item["message"] for item in notifications["items"])


def test_public_api_and_guardian_dashboard_never_return_forbidden_device_text():
    user_headers = scoped_headers("public-presentation-v1")
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=user_headers,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.61.50",
                    "gateway_ip": "192.168.61.1",
                    "subnet_cidr": "192.168.61.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "public-router",
                        "name": "ipTIME 공유기 (A3004NS-M)",
                        "device_type": "router",
                        "manufacturer": "EFM Networks",
                        "model": "A3004NS-M",
                        "ip_address": "192.168.61.1",
                        "mac_address": "AA:BB:CC:61:00:01",
                        "open_ports": [23],
                        "services": ["telnet"],
                        "discovery_sources": ["ssdp"],
                        "risk_signals": ["default_credentials_possible"],
                    },
                    {
                        "device_id": "public-weak-signal",
                        "name": "웹 관리 기기",
                        "device_type": "web-device",
                        "manufacturer": "Realtek",
                        "model": "RTL8197F",
                        "ip_address": "192.168.61.99",
                        "mac_address": "UNKNOWN-192.168.61.99",
                        "open_ports": [80],
                        "services": ["http"],
                        "discovery_sources": ["tcp-port-probe"],
                    },
                ],
            },
        )
    )
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=user_headers,
            json={"email": "public-presentation-guardian@example.com", "relation": "가족"},
        )
    )
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "guardian_id": "guardian-public-presentation",
                "guardian_email": "public-presentation-guardian@example.com",
                "guardian_name": "표시 확인 보호자",
                "invite": invite["short_code"],
            },
        )
    )
    public_payloads = [
        scan,
        unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=user_headers)),
        unwrap(client.get("/api/v1/devices", headers=user_headers)),
        unwrap(client.get("/api/v1/dashboard", headers=user_headers)),
        unwrap(client.get("/api/v1/security/score", headers=user_headers)),
        unwrap(client.get("/api/v1/security/events", headers=user_headers)),
        unwrap(client.get("/api/v1/notifications", headers=user_headers)),
        unwrap(client.get("/api/v1/guardians", headers=user_headers)),
        unwrap(
            client.get(
                f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
                params={"guardian_id": "guardian-public-presentation"},
            )
        ),
    ]

    for payload in public_payloads:
        assert_no_forbidden_public_device_text(payload)


def test_public_api_and_notifications_redact_registration_authority_text():
    from app.storage import repository

    user_id = "registration-authority-public"
    headers = scoped_headers(user_id)
    home_id = f"home-{user_id}"
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=headers,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.63.50",
                    "gateway_ip": "192.168.63.1",
                    "subnet_cidr": "192.168.63.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "registration-authority-router",
                        "name": "IEEE Registration Authority 공유기",
                        "device_type": "router",
                        "manufacturer": "IEEE Registration Authority",
                        "model": "MA-S OUI",
                        "ip_address": "192.168.63.1",
                        "mac_address": "AA:BB:CC:63:00:01",
                        "open_ports": [80],
                        "services": ["http"],
                        "fingerprints": ["ssdp:InternetGatewayDevice"],
                        "risk_signals": ["IANA registry signal"],
                        "vulnerabilities": [
                            {
                                "cve_id": "CVE-2026-0001",
                                "summary_ko": "Private 등록기관 신호를 찾았습니다.",
                                "remediation_ko": "OUI 값을 확인하세요.",
                            }
                        ],
                    }
                ],
            },
        )
    )
    repository._create_notification(
        "registration-authority",
        "IEEE Registration Authority 기기 안내",
        "OUI Private MA-M IANA 등록기관 값은 공개하면 안 됩니다.",
        home_id=home_id,
    )

    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=headers))
    devices = unwrap(client.get("/api/v1/devices", headers=headers))
    notifications = unwrap(client.get("/api/v1/notifications", headers=headers))

    assert_no_forbidden_public_device_text(result)
    assert_no_forbidden_public_device_text(devices)
    assert_no_forbidden_public_device_text(notifications)


def test_user_scoped_scan_devices_and_notifications_do_not_cross_accounts():
    user_a = scoped_headers("user-isolation-a")
    user_b = scoped_headers("user-isolation-b")

    scan_a = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=user_a,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.10.50",
                    "gateway_ip": "192.168.10.1",
                    "subnet_cidr": "192.168.10.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "same-lan-device",
                        "name": "A집 카메라",
                        "device_type": "camera",
                        "ip_address": "192.168.10.21",
                        "mac_address": "AA:AA:AA:AA:AA:AA",
                        "open_ports": [80, 554],
                        "services": ["http", "rtsp"],
                            "risk_signals": ["camera_candidate", "rtsp_open"],
                            "discovery_sources": ["ws-discovery"],
                    }
                ],
            },
        )
    )
    scan_b = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=user_b,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.20.50",
                    "gateway_ip": "192.168.20.1",
                    "subnet_cidr": "192.168.20.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "same-lan-device",
                        "name": "B집 카메라",
                        "device_type": "camera",
                        "ip_address": "192.168.20.21",
                        "mac_address": "AA:AA:AA:AA:AA:AA",
                        "open_ports": [80, 554],
                        "services": ["http", "rtsp"],
                            "risk_signals": ["camera_candidate", "rtsp_open"],
                            "discovery_sources": ["ws-discovery"],
                    }
                ],
            },
        )
    )
    invite_a = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=user_a,
            json={"email": "isolation-a-guardian@example.com", "relation": "가족"},
        )
    )
    invite_b = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=user_b,
            json={"email": "isolation-b-guardian@example.com", "relation": "가족"},
        )
    )

    devices_a = unwrap(client.get("/api/v1/devices", headers=user_a))
    devices_b = unwrap(client.get("/api/v1/devices", headers=user_b))
    notifications_a = unwrap(client.get("/api/v1/notifications", headers=user_a))
    notifications_b = unwrap(client.get("/api/v1/notifications", headers=user_b))
    wrong_scan_lookup = client.get(f"/api/v1/security/scans/{scan_b['scan_id']}", headers=user_a)

    assert scan_a["scan_id"] != scan_b["scan_id"]
    assert devices_a["items"] == []
    assert devices_b["items"] == []
    assert devices_a["identity_pending_count"] == 1
    assert devices_b["identity_pending_count"] == 1
    assert any(invite_a["email"] in item["message"] for item in notifications_a["items"])
    assert all(invite_b["email"] not in item["message"] for item in notifications_a["items"])
    assert any(invite_b["email"] in item["message"] for item in notifications_b["items"])
    assert all(invite_a["email"] not in item["message"] for item in notifications_b["items"])
    assert wrong_scan_lookup.status_code == 404


def test_guardian_ward_dashboard_uses_selected_ward_home_scope():
    user_a = scoped_headers("user-ward-scope-a")
    user_b = scoped_headers("user-ward-scope-b")
    guardian = {
        "guardian_id": "guardian-ward-scope-owner",
        "guardian_email": "ward.scope.guardian@example.com",
        "guardian_name": "범위 확인 보호자",
    }

    invite_a = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=user_a,
            json={"email": "ward-scope-a@example.com", "relation": "가족", "ward_name": "A 사용자"},
        )
    )
    unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=user_a,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.30.50",
                    "gateway_ip": "192.168.30.1",
                    "subnet_cidr": "192.168.30.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "ward-scope-camera",
                        "name": "A 사용자 카메라",
                        "device_type": "camera",
                        "manufacturer": "Hikvision",
                        "model": "DS-2CD2042",
                        "fingerprints": ["upnp-manufacturer:Hikvision", "upnp-model:DS-2CD2042", "onvif-device"],
                        "ip_address": "192.168.30.21",
                        "mac_address": "UNKNOWN-192.168.30.21",
                        "open_ports": [23, 80, 554],
                        "services": ["telnet", "http", "rtsp"],
                        "vulnerabilities": [{"cve_id": "CVE-2026-A-SCOPE", "severity": "high"}],
                            "risk_signals": ["camera_candidate", "default_credentials_possible", "rtsp_open"],
                            "discovery_sources": ["ws-discovery"],
                    }
                ],
            },
        )
    )
    accepted_a = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite_a["short_code"]},
        )
    )

    invite_b = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=user_b,
            json={"email": "ward-scope-b@example.com", "relation": "가족", "ward_name": "B 사용자"},
        )
    )
    unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=user_b,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.40.50",
                    "gateway_ip": "192.168.40.1",
                    "subnet_cidr": "192.168.40.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "device_id": "ward-scope-camera",
                        "name": "B 사용자 카메라",
                        "device_type": "camera",
                        "manufacturer": "Hikvision",
                        "model": "DS-2CD2042",
                        "fingerprints": ["upnp-manufacturer:Hikvision", "upnp-model:DS-2CD2042", "onvif-device"],
                        "ip_address": "192.168.40.21",
                        "mac_address": "UNKNOWN-192.168.40.21",
                        "open_ports": [23, 80, 554],
                        "services": ["telnet", "http", "rtsp"],
                        "vulnerabilities": [{"cve_id": "CVE-2026-B-SCOPE", "severity": "high"}],
                            "risk_signals": ["camera_candidate", "default_credentials_possible", "rtsp_open"],
                            "discovery_sources": ["ws-discovery"],
                    }
                ],
            },
        )
    )
    unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite_b["short_code"]},
        )
    )

    dashboard_a = unwrap(
        client.get(
            f"/api/v1/guardian-mode/wards/{accepted_a['active_ward']['link_id']}/dashboard",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )

    assert dashboard_a["ward"]["ward_display_name"] == "A 사용자"
    assert dashboard_a["ward_summary"]["device_count"] == 1
    assert len(dashboard_a["high_risk_devices"]) == 1
    assert dashboard_a["high_risk_devices"][0]["canonical_name"] == "하이크비전 카메라 (DS-2CD2042)"
    assert dashboard_a["identity_findings"] == []


def test_android_native_scan_rejects_emulator_virtual_network():
    response = client.post(
        "/api/v1/security/scan",
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": {
                "local_ip": "10.0.2.15",
                "gateway_ip": "10.0.2.2",
                "subnet_cidr": "10.0.2.0/24",
                "is_private_network": True,
                "interface_type": "wifi",
                "is_emulator": True,
                "is_virtual_network": True,
            },
            "devices": [
                {
                    "device_id": "emulator-router",
                    "name": "Emulator NAT 후보",
                    "device_type": "router",
                    "ip_address": "10.0.2.3",
                    "open_ports": [53, 80],
                    "services": ["dns", "http"],
                }
            ],
        },
    )
    body = response.json()

    assert response.status_code == 400
    assert body["success"] is False
    assert body["error"]["code"] == "SCAN_ACTUAL_DEVICE_REQUIRED"
    assert "실기기" in body["error"]["message"]
    assert "Android Emulator" in body["error"]["details"]["reasons"]


def test_stale_emulator_scan_snapshot_is_hidden_from_device_list():
    stale_device = {
        "device_id": "local-10-0-2-3",
        "name": "Emulator NAT 후보",
        "device_type": "unknown",
        "manufacturer": "OUI 확인 필요",
        "model": "LAN fingerprint",
        "ip_address": "10.0.2.3",
        "mac_address": "UNKNOWN-10.0.2.3",
        "online": True,
        "last_seen": "2026-05-06T00:00:00Z",
        "open_ports": [53],
        "services": ["dns"],
        "default_credentials": False,
        "encryption": "unknown",
        "firmware": "unknown",
        "vulnerabilities": [],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": [],
        "risk_signals": [],
        "scan_source": "android-native",
        "confidence": 0.75,
        "security_score": 100,
        "risk_level": "green",
        "risk_summary": "현재 큰 위험은 보이지 않아요.",
        "recommended_actions": ["정기 점검 때 다시 확인하면 충분해요."],
    }
    with sqlite_test_connection() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                scan_id, home_id, status, progress, scan_profile, current_step,
                scan_source, network_context_json, devices_found, high_risk_devices,
                security_score_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-stale-emulator",
                "home-0001",
                "completed",
                100,
                "quick",
                "점검 완료",
                "android-native",
                json.dumps(
                    {
                        "local_ip": "10.0.2.15",
                        "gateway_ip": "10.0.2.2",
                        "subnet_cidr": "10.0.2.0/24",
                        "is_private_network": True,
                        "interface_type": "wifi",
                        "is_emulator": True,
                        "is_virtual_network": True,
                    },
                    ensure_ascii=False,
                ),
                1,
                0,
                json.dumps({"score": 100, "risk_level": "green", "summary": "stale emulator"}, ensure_ascii=False),
                "2099-01-01T00:00:00Z",
            ),
        )
        conn.execute(
            "INSERT INTO scan_devices (scan_id, device_snapshot_json) VALUES (?, ?)",
            ("scan-stale-emulator", json.dumps(stale_device, ensure_ascii=False)),
        )

    devices = unwrap(client.get("/api/v1/devices"))

    assert all(
        "ip_address" not in item and "mac_address" not in item
        for item in devices["items"]
    )


def test_guardian_invite_adds_notification():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "guardian@example.com", "relation": "가족"},
        )
    )
    notifications = unwrap(client.get("/api/v1/notifications"))

    assert invite["status"] == "pending"
    assert invite["status_label"] == "초대 대기"
    assert re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", invite["short_code"])
    assert invite["deep_link"] == f"homeguardian://join?invite={invite['short_code']}"
    assert invite["expires_at"] > invite["created_at"]
    assert notifications["unread_count"] >= 1
    assert notifications["items"][0]["type"] == "guardian_invite"


def test_guardian_list_and_notification_read_are_persistent():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "persist-guardian@example.com", "relation": "가족"},
        )
    )
    guardians = unwrap(client.get("/api/v1/guardians"))
    notifications = unwrap(client.get("/api/v1/notifications"))
    notification_id = notifications["items"][0]["notification_id"]
    read_notification = unwrap(client.patch(f"/api/v1/notifications/{notification_id}/read"))

    assert any(item["invite_id"] == invite["invite_id"] for item in guardians["items"])
    assert any(item["short_code"] == invite["short_code"] for item in guardians["items"])
    assert read_notification["notification_id"] == notification_id
    assert read_notification["read"] is True


def test_guardian_invite_delete_removes_row_and_404_on_repeat():
    headers = scoped_headers("delete-invite-user")
    invite = unwrap(
        client.post("/api/v1/guardians/invite", headers=headers, json={"email": "del@example.com", "relation": "가족"})
    )
    invite_id = invite["invite_id"]
    before = unwrap(client.get("/api/v1/guardians", headers=headers))
    assert any(i["invite_id"] == invite_id for i in before["items"])
    # 삭제(취소=상태표시와 달리 행 제거) → 목록에서 사라진다
    deleted = unwrap(client.delete(f"/api/v1/guardians/{invite_id}", headers=headers))
    assert deleted["invite_id"] == invite_id
    after = unwrap(client.get("/api/v1/guardians", headers=headers))
    assert all(i["invite_id"] != invite_id for i in after["items"])
    # 이미 삭제된 초대를 다시 삭제하면 404
    assert client.delete(f"/api/v1/guardians/{invite_id}", headers=headers).status_code == 404


def test_purge_stale_guardian_invites_keeps_active_removes_old(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    repo = SQLiteRepository(db_path=str(tmp_path / "invites.db"))
    home = "home-purge-test"
    repo.upsert_user(
        {
            "user_id": "purge-owner",
            "email": "purge-owner@example.invalid",
            "nickname": "초대 정리 소유자",
            "role": "user",
            "email_verified": True,
            "home_id": home,
        }
    )
    pending = repo.create_guardian_invite(email="pending@example.com", relation="가족", home_id=home)
    revoked = repo.create_guardian_invite(email="revoked@example.com", relation="이웃", home_id=home)
    repo.revoke_guardian_invite(revoked["invite_id"], home_id=home)
    # older_than_days=-1 → cutoff 가 미래 → 만료/취소는 정리 대상, pending(유효)은 보존
    removed = repo.purge_stale_guardian_invites(home_id=home, older_than_days=-1)
    assert removed == 1
    remaining = {i["invite_id"] for i in repo.guardians(home_id=home)}
    assert pending["invite_id"] in remaining          # 유효 초대 보존
    assert revoked["invite_id"] not in remaining       # 오래된 취소 초대 삭제
    # 기본값(90일)으로는 방금 취소한 최근 초대는 보존(누적만 정리, 활성/최근 보존)
    fresh = repo.create_guardian_invite(email="fresh@example.com", relation="가족", home_id=home)
    repo.revoke_guardian_invite(fresh["invite_id"], home_id=home)
    assert repo.purge_stale_guardian_invites(home_id=home, older_than_days=90) == 0


def test_guardian_safe_device_strips_personal_identifiers():
    """보호자에게 가는 기기 객체에서 MAC/IP/fingerprint 가 제거되고, MAC 을 담은 device_id 가 마스킹된다.
    위험 판단에 필요한 이름/종류/포트/위험도/취약점은 보존(보호자 화면 회귀 방지)."""
    from app.main import _guardian_safe_device

    dev = {
        "device_id": "device-AA-BB-CC-DD-EE-FF", "name": "카메라 후보", "device_type": "camera",
        "manufacturer": "Hikvision", "model": "DS-2CD", "mac_address": "AA:BB:CC:DD:EE:FF",
        "ip_address": "192.168.0.5", "discovery_sources": ["ws-discovery"],
        "fingerprints": ["netbios-name:PC", "mdns-name:cam", "upnp-manufacturer:Hikvision", "upnp-model:DS-2CD"],
        "open_ports": [80, 23], "services": ["http", "telnet"], "risk_level": "red",
        "vulnerabilities": [{"cve_id": "CVE-2021-36260"}],
    }
    safe = _guardian_safe_device(dev)
    assert "mac_address" not in safe and "ip_address" not in safe and "fingerprints" not in safe
    assert safe["device_id"].startswith("ward-")
    assert "AA" not in safe["device_id"] and "EE-FF" not in safe["device_id"]  # MAC 미노출
    # 보호자 화면이 쓰는 필드는 보존
    assert safe["name"] == "하이크비전 카메라 (DS-2CD)" and safe["canonical_name"] == "하이크비전 카메라 (DS-2CD)"
    assert safe["device_type"] == "camera"
    assert safe["open_ports"] == [] and safe["services"] == [] and safe["risk_level"] == "red"
    assert safe["vulnerabilities"] == [{"cve_id": "CVE-2021-36260"}]


def test_guardian_ward_list_and_dashboard_include_same_safe_complete_device_snapshot(monkeypatch):
    """List preview and detail expose every real risk class without leaking LAN identifiers."""
    owner_id = "guardian-complete-device-snapshot-owner"
    owner_headers = scoped_headers(owner_id)
    home_id = f"home-{owner_id}"
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=owner_headers,
            json={
                "email": "complete.snapshot.guardian@example.com",
                "relation": "가족",
                "ward_name": "전체 기기 피보호자",
            },
        )
    )
    guardian = {
        "guardian_id": "guardian-complete-device-snapshot",
        "guardian_email": "complete.snapshot.guardian@example.com",
        "guardian_name": "전체 기기 보호자",
    }
    risk_levels = ("red", "yellow", "green", "unknown")
    household_devices = [
        {
            "device_id": f"device-AA-BB-CC-DD-EE-0{index}",
            "home_id": home_id,
            "name": f"검증 기기 {index}",
            "canonical_name": f"검증 기기 {index}",
            "device_type": "computer",
            "manufacturer": "ASRock",
            "model": f"MODEL-{index}",
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "recommended_actions": [],
            "risk_level": risk_level,
            "security_score": 25 * index,
            "online": True,
            "is_resolved": True,
            "is_phantom": False,
        }
        for index, risk_level in enumerate(risk_levels, start=1)
    ]
    household_devices.append(
        {
            **household_devices[0],
            "device_id": "device-AA-BB-CC-DD-EE-99",
            "name": "phantom must stay hidden",
            "is_phantom": True,
        }
    )
    queried_home_ids: list[str] = []

    def scoped_devices(*, home_id: str):
        queried_home_ids.append(home_id)
        if home_id != f"home-{owner_id}":
            return [
                {
                    **household_devices[0],
                    "device_id": "foreign-device-must-not-leak",
                    "home_id": home_id,
                }
            ]
        return [dict(device) for device in household_devices]

    monkeypatch.setattr(repository, "devices", scoped_devices)
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    link_id = accepted["active_ward"]["link_id"]
    detail = unwrap(
        client.get(
            f"/api/v1/guardian-mode/wards/{link_id}/dashboard",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )
    ward_list = unwrap(
        client.get(
            "/api/v1/guardian-mode/wards",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )
    ward_preview = next(item for item in ward_list["items"] if item["link_id"] == link_id)

    assert set(queried_home_ids) == {home_id}
    assert len(detail["devices"]) == len(risk_levels)
    assert detail["devices"] == detail["ward"]["devices"] == ward_preview["devices"]
    assert {device["risk_level"] for device in detail["devices"]} == set(risk_levels)
    assert detail["ward_summary"]["device_count"] == len(risk_levels)
    assert detail["ward_summary"]["high_risk_devices"] == 1
    assert detail["ward_summary"]["caution_devices"] == 1
    assert ward_preview["summary"]["device_count"] == len(risk_levels)
    assert ward_preview["summary"]["high_risk_devices"] == 1
    assert ward_preview["summary"]["caution_devices"] == 1
    assert all(device["name"] != "phantom must stay hidden" for device in detail["devices"])
    for original, safe in zip(household_devices[:-1], detail["devices"], strict=True):
        assert safe["device_id"].startswith("ward-")
        assert safe["device_id"] != original["device_id"]
        assert "mac_address" not in safe
        assert "ip_address" not in safe
        assert "fingerprints" not in safe


def test_guardian_legacy_dashboard_is_retired_for_invite_and_session():
    """No invite code or legacy session header can return household data in v1."""
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "viewer@example.com", "relation": "가족"},
        )
    )

    responses = (
        client.get(f"/api/v1/guardian-mode/dashboard?invite={invite['short_code']}"),
        client.get(
            "/api/v1/guardian-mode/dashboard",
            headers={"X-Guardian-Session": "retired-session-token-must-not-grant-data"},
        ),
    )
    for response in responses:
        payload = response.json()
        assert response.status_code == 410
        assert payload["success"] is False
        assert payload["error"]["code"] == "GUARDIAN_LEGACY_SESSION_RETIRED"
        assert payload.get("data") is None


def test_guardian_legacy_dashboard_returns_retirement_before_invite_validation():
    response = client.get("/api/v1/guardian-mode/dashboard?invite=NOPE-1234")
    payload = response.json()

    assert response.status_code == 410
    assert payload["success"] is False
    assert payload["error"]["code"] == "GUARDIAN_LEGACY_SESSION_RETIRED"
    assert payload.get("data") is None


def test_expired_guardian_invite_blocks_google_guardian_link():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "expired-viewer@example.com", "relation": "가족"},
        )
    )
    # 최근 만료(2일 전): 만료 상태로 대시보드는 차단하되, 90일 보존창 안이라 정리(purge) 대상은 아니다.
    # (과거엔 서기 2000년 같은 고대 날짜를 썼는데, 그건 누적정리 purge 가 마땅히 지우는 대상이라 충돌한다.)
    from datetime import UTC, datetime, timedelta

    recently_expired = (datetime.now(UTC) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    with sqlite_test_connection() as conn:
        conn.execute(
            "UPDATE guardian_invites SET expires_at = ?, status = 'pending' WHERE invite_id = ?",
            (recently_expired, invite["invite_id"]),
        )

    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": invite["short_code"],
            "guardian_id": "guardian-expired-link",
            "guardian_email": "expired.link.guardian@example.com",
            "guardian_name": "Expired Link Guardian",
        },
    )
    guardians = unwrap(client.get("/api/v1/guardians"))

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "GUARDIAN_INVITE_EXPIRED"
    assert any(item["invite_id"] == invite["invite_id"] and item["status"] == "expired" for item in guardians["items"])


def test_revoked_guardian_invite_cannot_be_linked():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "session-revoke@example.com", "relation": "가족"},
        )
    )

    unwrap(client.patch(f"/api/v1/guardians/{invite['invite_id']}/revoke"))
    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": invite["short_code"],
            "guardian_id": "guardian-revoked-link",
            "guardian_email": "revoked.link.guardian@example.com",
            "guardian_name": "Revoked Link Guardian",
        },
    )

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "GUARDIAN_INVITE_REVOKED"


def test_google_guardian_link_and_dashboard_require_matching_bearer_session(monkeypatch):
    """Only the verified Google guardian who owns a link can read that ward."""
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            headers=scoped_headers("guardian-google-bearer-ward"),
            json={"email": "google-guardian-owner@example.com", "relation": "family"},
        )
    )
    profiles = {
        "google-guardian-owner-token": {
            "user_id": "google-guardian-owner",
            "email": "google.guardian.owner@example.com",
            "nickname": "Google Guardian Owner",
            "role": "user",
            "email_verified": True,
            "home_id": "ignored-by-guardian-role",
        },
        "google-guardian-other-token": {
            "user_id": "google-guardian-other",
            "email": "google.guardian.other@example.com",
            "nickname": "Google Guardian Other",
            "role": "user",
            "email_verified": True,
            "home_id": "ignored-by-guardian-role",
        },
    }

    def fake_authenticate(code, id_token_value, redirect_uri):
        assert code is None
        assert redirect_uri == "homeguardian://auth/google"
        return GoogleOAuthResult(
            user=profiles[id_token_value],
            provider="google",
            mode="oauth",
            raw_claims={"sub": profiles[id_token_value]["user_id"]},
        )

    monkeypatch.setattr("app.main.google_oauth_service.authenticate", fake_authenticate)
    owner_session = unwrap(
        client.post(
            "/api/v1/auth/google/callback",
            json={
                "id_token": "google-guardian-owner-token",
                "redirect_uri": "homeguardian://auth/google",
                "role": "guardian",
            },
        )
    )
    other_session = unwrap(
        client.post(
            "/api/v1/auth/google/callback",
            json={
                "id_token": "google-guardian-other-token",
                "redirect_uri": "homeguardian://auth/google",
                "role": "guardian",
            },
        )
    )

    guardian_id = owner_session["user"]["user_id"]
    owner_headers = {"Authorization": f"Bearer {owner_session['access_token']}"}
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            headers=owner_headers,
            json={
                "invite": invite["short_code"],
                "guardian_id": guardian_id,
                # These legacy body fields must not override the verified
                # Google guardian account bound to owner_headers.
                "guardian_email": "forged-guardian@example.test",
                "guardian_name": "Forged guardian name",
            },
        )
    )
    link_id = accepted["active_ward"]["link_id"]
    dashboard = unwrap(
        client.get(
            f"/api/v1/guardian-mode/wards/{link_id}/dashboard",
            headers=owner_headers,
            params={"guardian_id": guardian_id},
        )
    )
    other_response = client.get(
        f"/api/v1/guardian-mode/wards/{link_id}/dashboard",
        headers={"Authorization": f"Bearer {other_session['access_token']}"},
        params={"guardian_id": guardian_id},
    )

    assert accepted["guardian"]["guardian_id"] == guardian_id
    assert accepted["guardian"]["email"] == owner_session["user"]["email"]
    assert accepted["guardian"]["display_name"] == owner_session["user"]["nickname"]
    assert dashboard["read_only"] is True
    assert dashboard["scope"] == "guardian-read-only"
    assert other_response.status_code == 401
    assert other_response.json()["error"]["code"] == "GUARDIAN_AUTH_REQUIRED"


def test_guardian_account_accepts_two_wards_and_lists_them():
    first_invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "multi-ward-a@example.com", "relation": "이웃"},
        )
    )
    second_invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "multi-ward-b@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-google-multi-ward",
        "guardian_email": "multi.guardian@example.com",
        "guardian_name": "여러 집 보호자",
    }

    first_accept = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": first_invite["short_code"]},
        )
    )
    second_accept = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": second_invite["short_code"]},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))

    assert first_accept["guardian"]["guardian_id"] == guardian["guardian_id"]
    assert second_accept["guardian"]["email"].endswith("@test.homeguardian.invalid")
    assert ward_list["total"] == 2
    assert {item["invite_id"] for item in ward_list["items"]} == {
        first_invite["invite_id"],
        second_invite["invite_id"],
    }
    assert all(item["status"] == "active" for item in ward_list["items"])
    assert "guardian_session_token" not in first_accept["dashboard"]


def test_guardian_link_defaults_to_ward_account_name():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={
                "email": "account-name-default@example.com",
                "relation": "보호자",
                "ward_name": "김사용자",
            },
        )
    )
    guardian = {
        "guardian_id": "guardian-account-name-default",
        "guardian_email": "account.name.default.guardian@example.com",
        "guardian_name": "계정명 확인 보호자",
    }

    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))
    active_ward = accepted["active_ward"]

    assert invite["ward_account_name"] == "김사용자"
    assert active_ward["ward_account_name"] == "김사용자"
    assert active_ward["ward_alias"] is None
    assert active_ward["ward_display_name"] == "김사용자"
    assert ward_list["items"][0]["ward_display_name"] == "김사용자"
    assert ward_list["items"][0]["ward_display_name"] != "보호자"


def test_guardian_can_edit_and_clear_owned_ward_alias():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={
                "email": "alias-edit@example.com",
                "relation": "가족",
                "ward_name": "박사용자",
            },
        )
    )
    guardian = {
        "guardian_id": "guardian-alias-owner",
        "guardian_email": "alias.owner@example.com",
        "guardian_name": "별칭 보호자",
    }
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    link_id = accepted["active_ward"]["link_id"]

    renamed = unwrap(
        client.patch(
            f"/api/v1/guardian-mode/wards/{link_id}",
            json={"guardian_id": guardian["guardian_id"], "ward_alias": "엄마 집"},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))
    cleared = unwrap(
        client.patch(
            f"/api/v1/guardian-mode/wards/{link_id}",
            json={"guardian_id": guardian["guardian_id"], "ward_alias": ""},
        )
    )

    assert renamed["ward_account_name"] == "박사용자"
    assert renamed["ward_alias"] == "엄마 집"
    assert renamed["ward_display_name"] == "엄마 집"
    assert ward_list["items"][0]["ward_display_name"] == "엄마 집"
    assert cleared["ward_account_name"] == "박사용자"
    assert cleared["ward_alias"] is None
    assert cleared["ward_display_name"] == "박사용자"


def test_guardian_cannot_edit_other_guardian_ward_alias():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={
                "email": "alias-forbidden@example.com",
                "relation": "가족",
                "ward_name": "이사용자",
            },
        )
    )
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "invite": invite["short_code"],
                "guardian_id": "guardian-alias-owner-only",
                "guardian_email": "alias.owner.only@example.com",
                "guardian_name": "소유 보호자",
            },
        )
    )

    response = client.patch(
        f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}",
        json={"guardian_id": "guardian-alias-attacker", "ward_alias": "볼 수 없는 이름"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "GUARDIAN_LINK_FORBIDDEN"


def test_guardian_mode_wards_requires_guardian_account():
    response = client.get("/api/v1/guardian-mode/wards")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "GUARDIAN_ACCOUNT_REQUIRED"


def test_guardian_link_accept_unknown_code_never_returns_home_data():
    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": "NOPE-4040",
            "guardian_id": "guardian-unknown-code",
            "guardian_email": "unknown.guardian@example.com",
            "guardian_name": "없는 코드 보호자",
        },
    )
    payload = response.json()

    assert response.status_code == 404
    assert payload["success"] is False
    assert payload["error"]["code"] == "GUARDIAN_INVITE_404"
    assert "data" not in payload or payload.get("data") is None


def test_guardian_link_accept_requires_valid_guardian_account_payload():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "invalid-guardian-account@example.com", "relation": "가족"},
        )
    )

    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": invite["short_code"],
            "guardian_id": "",
            "guardian_email": "invalid.guardian@example.com",
        },
    )

    assert response.status_code == 422


def test_guardian_mode_ward_dashboard_requires_guardian_account():
    response = client.get("/api/v1/guardian-mode/wards/link-missing-guardian/dashboard")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "GUARDIAN_ACCOUNT_REQUIRED"


def test_guardian_link_dashboard_allows_owner_read_only_view():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "owner-dashboard@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-link-dashboard-owner",
        "guardian_email": "dashboard.owner@example.com",
        "guardian_name": "대시보드 보호자",
    }
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )

    dashboard = unwrap(
        client.get(
            f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )

    assert dashboard["read_only"] is True
    assert dashboard["scope"] == "guardian-read-only"
    assert dashboard["ward"]["link_id"] == accepted["active_ward"]["link_id"]
    assert "guardian_session_token" not in dashboard


def test_guardian_link_dashboard_rejects_other_guardian():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "owner-only@example.com", "relation": "가족"},
        )
    )
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "invite": invite["short_code"],
                "guardian_id": "guardian-link-owner",
                "guardian_email": "owner.guardian@example.com",
                "guardian_name": "권한 있는 보호자",
            },
        )
    )

    response = client.get(
        f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
        params={"guardian_id": "guardian-link-attacker"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "GUARDIAN_LINK_FORBIDDEN"


def test_guardian_link_revoke_blocks_dashboard():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "linked-revoke@example.com", "relation": "가족"},
        )
    )
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "invite": invite["short_code"],
                "guardian_id": "guardian-link-revoke",
                "guardian_email": "revoke.guardian@example.com",
                "guardian_name": "취소 테스트 보호자",
            },
        )
    )

    unwrap(client.patch(f"/api/v1/guardians/{invite['invite_id']}/revoke"))
    response = client.get(
        f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
        params={"guardian_id": "guardian-link-revoke"},
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": "guardian-link-revoke"}))

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "GUARDIAN_LINK_REVOKED"
    assert ward_list["total"] == 0


def test_guardian_can_remove_ward_link_without_revoking_invite():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "remove-ward@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-remove-ward",
        "guardian_email": "remove.ward.guardian@example.com",
        "guardian_name": "삭제 테스트 보호자",
    }
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    link_id = accepted["active_ward"]["link_id"]

    removed = unwrap(
        client.delete(
            f"/api/v1/guardian-mode/wards/{link_id}",
            params={"guardian_id": guardian["guardian_id"]},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))
    dashboard_after_remove = client.get(
        f"/api/v1/guardian-mode/wards/{link_id}/dashboard",
        params={"guardian_id": guardian["guardian_id"]},
    )
    reaccepted = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={**guardian, "invite": invite["short_code"]},
    )

    assert removed["link_id"] == link_id
    assert removed["status"] == "revoked"
    assert ward_list["total"] == 0
    assert dashboard_after_remove.status_code == 410
    assert dashboard_after_remove.json()["error"]["code"] == "GUARDIAN_LINK_REVOKED"
    assert reaccepted.status_code == 409
    assert reaccepted.json()["error"]["code"] == "GUARDIAN_INVITE_ALREADY_ACCEPTED"


def test_guardian_cannot_remove_other_guardian_ward_link():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "remove-other-ward@example.com", "relation": "가족"},
        )
    )
    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "invite": invite["short_code"],
                "guardian_id": "guardian-remove-owner",
                "guardian_email": "remove.owner@example.com",
                "guardian_name": "연결 소유자",
            },
        )
    )

    response = client.delete(
        f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}",
        params={"guardian_id": "guardian-remove-attacker"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "GUARDIAN_LINK_FORBIDDEN"


def test_guardian_invite_cannot_be_claimed_by_second_guardian():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "claim-once@example.com", "relation": "가족"},
        )
    )
    unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={
                "invite": invite["short_code"],
                "guardian_id": "guardian-first-claim",
                "guardian_email": "first.guardian@example.com",
                "guardian_name": "첫 보호자",
            },
        )
    )

    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": invite["short_code"],
            "guardian_id": "guardian-second-claim",
            "guardian_email": "second.guardian@example.com",
            "guardian_name": "두 번째 보호자",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "GUARDIAN_INVITE_ALREADY_ACCEPTED"


def test_guardian_invite_reentry_for_same_guardian_restores_existing_link():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "same-guardian-reentry@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-same-reentry",
        "guardian_email": "same.guardian@example.com",
        "guardian_name": "같은 보호자",
    }
    first_accept = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )

    second_accept = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))

    assert second_accept["active_ward"]["link_id"] == first_accept["active_ward"]["link_id"]
    assert second_accept["total"] == 1
    assert ward_list["total"] == 1
    assert "guardian_session_token" not in second_accept["dashboard"]


def test_guardian_account_claims_pending_invite_via_link():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "legacy-accepted-link@example.com", "relation": "가족"},
        )
    )
    guardian = {
        "guardian_id": "guardian-legacy-accepted-link",
        "guardian_email": "legacy.accepted.guardian@example.com",
        "guardian_name": "기존 초대 보호자",
    }

    accepted = unwrap(
        client.post(
            "/api/v1/guardian-mode/links/accept",
            json={**guardian, "invite": invite["short_code"]},
        )
    )
    ward_list = unwrap(client.get("/api/v1/guardian-mode/wards", params={"guardian_id": guardian["guardian_id"]}))

    assert accepted["active_ward"]["invite_id"] == invite["invite_id"]
    assert accepted["total"] == 1
    assert ward_list["total"] == 1
    assert ward_list["items"][0]["invite_id"] == invite["invite_id"]
    assert "guardian_session_token" not in accepted["dashboard"]


def test_revoked_guardian_invite_blocks_google_guardian_link():
    invite = unwrap(
        client.post(
            "/api/v1/guardians/invite",
            json={"email": "revoke-me@example.com", "relation": "가족"},
        )
    )

    revoked = unwrap(client.patch(f"/api/v1/guardians/{invite['invite_id']}/revoke"))
    response = client.post(
        "/api/v1/guardian-mode/links/accept",
        json={
            "invite": invite["short_code"],
            "guardian_id": "guardian-revoked-before-link",
            "guardian_email": "revoked.before.link@example.com",
            "guardian_name": "Revoked Before Link Guardian",
        },
    )
    guardians = unwrap(client.get("/api/v1/guardians"))

    assert revoked["status"] == "revoked"
    assert revoked["status_label"] == "초대 취소"
    assert revoked["revoked_at"]
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "GUARDIAN_INVITE_REVOKED"
    assert any(item["invite_id"] == invite["invite_id"] and item["status"] == "revoked" for item in guardians["items"])


def test_fcm_token_register_and_delete_flow():
    token = "dev-fcm-token-for-tests"
    registered = unwrap(
        client.post(
            "/api/v1/auth/fcm-token",
            json={"fcm_token": token, "platform": "android"},
        )
    )
    deleted = client.request("DELETE", "/api/v1/auth/fcm-token", json={"fcm_token": token})

    assert registered["registered"] is True
    assert registered["platform"] == "android"
    assert deleted.status_code == 204


def test_security_scan_with_registered_fcm_token_falls_back_without_credentials(monkeypatch):
    monkeypatch.delenv("FIREBASE_CREDENTIALS", raising=False)
    token = "dev-fcm-token-without-credentials"
    unwrap(
        client.post(
            "/api/v1/auth/fcm-token",
            json={"fcm_token": token, "platform": "android"},
        )
    )

    scan = unwrap(client.post("/api/v1/security/scan", json=actual_empty_scan_payload()))
    client.request("DELETE", "/api/v1/auth/fcm-token", json={"fcm_token": token})

    assert scan["push_result"] == {"sent": 0, "failed": 1}


def test_security_scan_removes_permanently_invalid_fcm_token(monkeypatch):
    from app import main as main_module

    token = "permanently-unregistered-fcm-token"
    unwrap(
        client.post(
            "/api/v1/auth/fcm-token",
            json={"fcm_token": token, "platform": "android"},
        )
    )

    def fake_broadcast(*, tokens, title, body, data, on_invalid_token):
        assert tokens == [token]
        on_invalid_token(token)
        return {"sent": 0, "failed": 1}

    monkeypatch.setattr(main_module.fcm_service, "broadcast", fake_broadcast)

    scan = unwrap(client.post("/api/v1/security/scan", json=actual_empty_scan_payload()))
    deleted_again = client.request("DELETE", "/api/v1/auth/fcm-token", json={"fcm_token": token})

    assert scan["push_result"] == {"sent": 0, "failed": 1}
    assert deleted_again.status_code == 404


def test_security_scan_projects_push_result_to_counts_only(monkeypatch):
    from app import main as main_module

    secret_token = "fcm-secret-token-should-never-reach-the-scan-response"
    monkeypatch.setattr(
        main_module,
        "_broadcast_scan_completed_push",
        lambda _scan_result, user_id=None: {
            "ok": False,
            "mode": "firebase-admin",
            "sent": 0,
            "failed": 1,
            "pending": 1,
            "message_id": "provider-message-id",
            "failures": [{"token": secret_token[-12:], "error": f"provider rejected {secret_token}"}],
        },
    )

    scan = unwrap(client.post("/api/v1/security/scan", json=actual_empty_scan_payload()))

    assert scan["push_result"] == {"sent": 0, "failed": 1}
    serialized = json.dumps(scan, ensure_ascii=False)
    for private_value in (secret_token, secret_token[-12:], "firebase-admin", "provider-message-id", "provider rejected"):
        assert private_value not in serialized


def test_fcm_token_delete_unknown_token_is_404():
    response = client.request(
        "DELETE",
        "/api/v1/auth/fcm-token",
        json={"fcm_token": "never-registered-token"},
    )

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"]


def test_notification_read_unknown_id_is_404():
    response = client.patch("/api/v1/notifications/notification-does-not-exist/read")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOTIFICATION_404"


def test_device_detail_unknown_id_is_404():
    response = client.get("/api/v1/devices/device-does-not-exist")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DEVICE_404"


def test_scan_status_and_scan_result_return_404_for_unknown_id():
    status_response = client.get("/api/v1/security/scan/scan-does-not-exist/status")
    result_response = client.get("/api/v1/security/scans/scan-does-not-exist")

    assert status_response.status_code == 404
    assert result_response.status_code == 404


def test_security_score_and_events_endpoints_return_consistent_shape():
    score = unwrap(client.get("/api/v1/security/score"))
    events = unwrap(client.get("/api/v1/security/events"))

    assert "score" in score and "risk_level" in score and "device_scores" in score
    assert "items" in events and events["total"] == len(events["items"])


def test_ml_metrics_and_predict_endpoints_return_safe_shape():
    metrics = unwrap(client.get("/api/v1/ml/metrics"))
    prediction = unwrap(
        client.post(
            "/api/v1/ml/predict",
            json={
                "open_ports": [23, 80, 554],
                "services": ["telnet", "http", "rtsp"],
                "risk_signals": ["camera_candidate", "default_credentials_possible"],
                "device_type": "camera",
                "default_credentials": True,
                "encryption": "unknown",
            },
        )
    )

    assert "available" in metrics
    assert "available" in prediction
    assert 0.0 <= prediction["attack_probability"] <= 1.0
    assert isinstance(prediction["feature_vector"], list)
    assert metrics["available"] is True
    inference_metrics = metrics["metrics"]["inference"]
    assert inference_metrics["source"]["datasets"] == [
        "CIC-IoT-2023 (selected LAN-related attack-category proxy rows)",
        "UNSW-NB15 (selected LAN-related attack-category proxy rows)",
    ]
    assert "semantic proxy features" in inference_metrics["description"]
    assert "not field accuracy" in inference_metrics["description"]
    assert "not field accuracy" in inference_metrics["source"]["note"]
    exposed_metadata = json.dumps(inference_metrics, ensure_ascii=False)
    assert "LAN-detectable" not in exposed_metadata
    assert "LAN-relevant" not in exposed_metadata
    assert "detectable from LAN scan signals" not in exposed_metadata


def test_guardian_invite_rejects_invalid_email():
    response = client.post(
        "/api/v1/guardians/invite",
        json={"email": "no-at-sign-here", "relation": "친구"},
    )

    assert response.status_code in {400, 422}
    body = response.json()
    if response.status_code == 400:
        assert body["success"] is False


def test_scan_source_rejects_unknown_value():
    response = client.post(
        "/api/v1/security/scan",
        json={"scan_profile": "quick", "scan_source": "demo-fallback"},
    )

    assert response.status_code == 422, "demo-fallback 옵션은 제거되어 더 이상 허용되지 않는다"


def test_auth_me_returns_signed_fixture_user():
    user = unwrap(client.get("/api/v1/auth/me"))

    assert user["user_id"] == "default-api-owner"
    assert user["home_id"] == "home-default-api-owner"
    assert "@" in user["email"]


def test_android_native_scan_rejects_documentation_ip():
    """문서용 IP(192.0.2.x, 198.51.100.x, 203.0.113.x) payload도 거부되어야 한다."""
    response = client.post(
        "/api/v1/security/scan",
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": {
                "local_ip": "192.168.1.50",
                "gateway_ip": "192.168.1.1",
                "subnet_cidr": "192.168.1.0/24",
                "is_private_network": True,
                "interface_type": "wifi",
            },
            "devices": [
                {
                    "device_id": "doc-ip-camera",
                    "name": "문서용 IP 카메라",
                    "device_type": "camera",
                    "ip_address": "192.0.2.10",
                    "mac_address": "UNKNOWN-192.0.2.10",
                    "open_ports": [554],
                    "services": ["rtsp"],
                }
            ],
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "SCAN_ACTUAL_DEVICE_REQUIRED"


def test_scan_push_surfaces_caution_devices_not_just_red():
    """스캔 완료 FCM 푸시가 '위험(red)' 0대여도 '주의(yellow)' 기기를 알린다.
    (앱 내 알림과 동일 기준 — 라우터 CVE 등 yellow 기기를 '안전 검사를 마쳤어요'로 숨기지 않게.)"""
    from app.main import _scan_push_title_body

    # 위험 0, 주의 3(사용자 홈 패턴: 공유기 CVE·냉장고·RPi)
    yellow_home = {
        "high_risk_devices": 0, "devices_found": 6,
        "security_score": {"device_scores": [{"risk_level": l} for l in ["green", "yellow", "yellow", "yellow", "green", "green"]]},
    }
    title, body, caution = _scan_push_title_body(yellow_home)
    assert caution == 3
    assert title != "안전 검사를 마쳤어요"      # yellow 가 있는데 "안전" 이라 하지 않는다
    assert "주의 3대" in body

    # 위험이 있으면 위험 우선
    red_home = {"high_risk_devices": 1, "devices_found": 4, "security_score": {"device_scores": [{"risk_level": "red"}, {"risk_level": "yellow"}]}}
    t2, b2, _ = _scan_push_title_body(red_home)
    assert t2 == "위험한 기기가 발견됐어요" and "위험 1대" in b2

    # 모두 안전할 때만 "안전 검사를 마쳤어요"
    safe_home = {"high_risk_devices": 0, "devices_found": 3, "security_score": {"device_scores": [{"risk_level": "green"}] * 3}}
    t3, _, c3 = _scan_push_title_body(safe_home)
    assert t3 == "안전 검사를 마쳤어요" and c3 == 0

    # 완료했지만 평가 대상 0대인 경우는 안전 또는 재시도 오류로 표현하지 않는다.
    t4, b4, c4 = _scan_push_title_body(
        {"status": "completed", "scan_complete": True, "devices_found": 0, "security_score": {"score_status": "no_targets", "device_scores": []}}
    )
    assert t4 == "보안 점검을 마쳤어요" and c4 == 0
    assert b4 == "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."
    assert "안전" not in t4 + b4 and "다시" not in t4 + b4

    # 관측 대상은 있지만 모든 scorer가 실패한 경우 0/red fail-closed 집계와
    # 푸시 문구가 모순되게 "안전" 또는 "위험 없음"을 말하지 않는다.
    t5, b5, c5 = _scan_push_title_body(
        {
            "status": "completed",
            "scan_complete": True,
            "devices_found": 1,
            "high_risk_devices": 0,
            "security_score": {
                "score": 0,
                "risk_level": "red",
                "score_status": "final",
                "device_scores": [{"device_id": "dev-1", "score": None, "risk_level": "unknown"}],
            },
        }
    )
    assert t5 == "보안 점수를 계산하지 못했어요" and c5 == 0
    assert b5 == "점검은 완료됐지만 기기 점수를 계산하지 못했어요. 기기별 실패 안내를 확인해 주세요."
    assert "안전" not in t5 + b5 and "위험·주의 기기 없음" not in b5

def test_scan_request_input_bounds_reject_oversized_payload():
    """입력 경계(보안): 인증된 악의적 앱/MITM 이 거대 스캔 페이로드로 메모리/저장을 망가뜨리지 못하게
    DiscoveredDeviceRequest/ScanRequest 가 문자열·리스트 길이를 제한한다. 한도는 네이티브 실출력
    (/24 최대 254 기기)보다 넉넉해 정상 스캔은 거부되지 않는다.
    """
    from pydantic import ValidationError
    from app.main import ScanRequest, DiscoveredDeviceRequest

    # 정상 규모(254 기기 × 30 fingerprint)는 통과 — 회귀 방지
    ok = ScanRequest(
        scan_source="android-native",
        network_context={
            "local_ip": "192.168.0.50",
            "gateway_ip": "192.168.0.1",
            "subnet_cidr": "192.168.0.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
        },
        devices=[{"ip_address": f"192.168.0.{i}", "name": f"기기 {i}",
                  "fingerprints": [f"mdns-type:._x{j}._tcp" for j in range(30)], "open_ports": [80, 443]}
                 for i in range(1, 255)],
    )
    assert len(ok.devices) == 254

    # 악의적 거대 입력은 거부
    import pytest
    with pytest.raises(ValidationError):
        ScanRequest(
            scan_source="android-native",
            network_context={
                "local_ip": "10.0.0.50",
                "gateway_ip": "10.0.0.1",
                "subnet_cidr": "10.0.0.0/24",
                "is_private_network": True,
                "interface_type": "wifi",
            },
            devices=[{"ip_address": "10.0.0.1"}] * 1000,
        )
    with pytest.raises(ValidationError):
        DiscoveredDeviceRequest(ip_address="192.168.0.1", name="A" * 5000)
    with pytest.raises(ValidationError):
        DiscoveredDeviceRequest(ip_address="192.168.0.1", fingerprints=["x"] * 2000)

def test_all_request_models_bound_oversized_input():
    """입력 경계(보안) 전수: scan 외에도 이메일·OAuth·ml-predict 요청이 거대 입력을 거부한다.
    guardian/FCM 모델은 이미 max_length 보유. 정상 값은 통과(회귀 방지).
    """
    import pytest
    from pydantic import ValidationError
    from app.main import (
        AuthHandoffCompleteRequest, GoogleCallbackRequest, GuardianInviteRequest, MlPredictRequest, validate_email_text,
    )

    # 이메일: RFC 254 초과 거부, 정상 통과
    with pytest.raises(ValueError):
        validate_email_text("a" * 300 + "@x.com")
    assert validate_email_text("user@example.com") == "user@example.com"
    assert GuardianInviteRequest(email="guardian@example.com", ward_name="할머니").email

    # OAuth: 거대 id_token 거부, 정상(2KB) 통과
    with pytest.raises(ValidationError):
        GoogleCallbackRequest(id_token="A" * 9000)
    assert GoogleCallbackRequest(id_token="A" * 2000).id_token

    # Handoff proof: short secrets and non-URL-safe ids are rejected before
    # they can reach a storage query.
    with pytest.raises(ValidationError):
        AuthHandoffCompleteRequest(
            previous_refresh_token="A" * 31,
            successor_refresh_token="B" * 32,
            handoff_id="C" * 32,
        )
    with pytest.raises(ValidationError):
        AuthHandoffCompleteRequest(
            previous_refresh_token="A" * 32,
            successor_refresh_token="B" * 32,
            handoff_id="not a valid handoff id because it has spaces",
        )

    # ml-predict: 거대 리스트 거부, 정상 통과
    with pytest.raises(ValidationError):
        MlPredictRequest(open_ports=list(range(1000)))
    assert len(MlPredictRequest(open_ports=list(range(50))).open_ports) == 50

def test_enrich_device_isolates_per_device_failure():
    """한 기기의 이상 데이터로 enrich 가 터져도 전체 기기 목록(컴프리헨션으로 enrich)이 사라지면 안 된다.
    보안 도구에서 '이상한 기기 1대 -> 아무것도 안 보임'은 나쁜 실패다. 실패 기기는 원본 반환(우아한 강등).
    """
    import logging
    from app.main import _enrich_device

    logging.disable(logging.CRITICAL)
    try:
        class _Weird(dict):
            def get(self, key, default=None):
                if key == "vulnerabilities":
                    raise RuntimeError("강제 크래시")
                return super().get(key, default)

        devices = [
            {"ip_address": "192.168.0.6", "device_type": "camera", "manufacturer": "Hikvision",
             "model": "DS-2CD2042", "open_ports": [80, 554], "risk_signals": ["camera_candidate"],
             "fingerprints": ["upnp-manufacturer:Hikvision", "upnp-model:DS-2CD2042", "onvif-device"],
             "discovery_sources": ["onvif"], "vulnerabilities": [], "name": "카메라"},
            _Weird({"ip_address": "192.168.0.99", "name": "이상한 기기"}),  # enrich 중 예외
            {"ip_address": "192.168.0.7", "device_type": "router", "manufacturer": "TP-Link",
             "open_ports": [80], "risk_signals": [],
             "fingerprints": ["upnp-manufacturer:TP-Link", "upnp-model:Archer C7", "ssdp:InternetGatewayDevice"],
             "discovery_sources": ["ssdp"], "vulnerabilities": [], "name": "공유기", "model": "Archer C7"},
        ]
        out = [_enrich_device(d) for d in devices]
        assert len(out) == 3  # 전체 유지
        assert len(out[0].get("vulnerabilities", [])) >= 1  # 정상 기기는 enrich
        assert out[1].get("is_unresolved") is True  # 실패 기기는 공개 목록에서 제외될 내부 상태
        assert len(out[2].get("vulnerabilities", [])) >= 1
    finally:
        logging.disable(logging.NOTSET)

def test_home_security_score_includes_cve_critical_gate():
    """홈 보안 점수(메인 화면 신호등)는 CVE enrich 를 포함해 산정돼야 한다. 과거 repository.security_score
    가 summarize_home_security 를 CVE 미포함 self.devices() 로 불러, critical CVE 카메라가 있는 집이
    red 가 아니라 yellow 로 과소보고됐다(_scoring_with_cve 미적용). 회귀로 고정한다.
    """
    import os, tempfile, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ml"))
    from app.storage.sqlite_repository import SQLiteRepository

    nc = {"local_ip": "192.168.0.5", "gateway_ip": "192.168.0.1", "subnet_cidr": "192.168.0.0/24",
          "is_private_network": True, "interface_type": "wifi"}
    repo = SQLiteRepository(db_path=os.path.join(tempfile.mkdtemp(), "hs.db"))
    home_id = provision_repository_owner(repo, "home-score-critical-gate")
    repo.create_scan(scan_source="android-native", home_id=home_id, network_context=nc, discovered_devices=[
        {"name": "카메라", "device_type": "camera", "ip_address": "192.168.0.20", "mac_address": "UNKNOWN-20",
         "manufacturer": "Hikvision", "model": "DS-2CD2042", "open_ports": [80, 554],
         "services": ["http", "rtsp"], "risk_signals": ["camera_candidate"],
         "fingerprints": ["upnp-manufacturer:Hikvision", "upnp-model:DS-2CD2042", "onvif-device"],
         "discovery_sources": ["onvif"]}])
    ss = repo.security_score(home_id=home_id)
    # critical CVE(CVE-2017-7921/2021-36260) 카메라가 있으면 집 전체는 red 여야 한다(과소보고 금지)
    assert ss["risk_level"] == "red", f"홈 점수 과소보고: {ss['risk_level']}"


def test_public_score_keeps_private_port_penalty_without_exposing_observation():
    headers = scoped_headers("private-score-projection")
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=headers,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.91.50",
                    "gateway_ip": "192.168.91.1",
                    "subnet_cidr": "192.168.91.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                },
                "devices": [
                    {
                        "name": "ipTIME 공유기",
                        "device_type": "router",
                        "manufacturer": "EFM Networks",
                        "model": "A3004NS-M",
                        "ip_address": "192.168.91.1",
                        "mac_address": "AA:BB:CC:91:00:01",
                        "open_ports": [23],
                        "services": ["telnet"],
                        "discovery_sources": ["ssdp"],
                        "fingerprints": [
                            "upnp-manufacturer:EFM Networks",
                            "upnp-model:A3004NS-M",
                            "ssdp:InternetGatewayDevice",
                        ],
                    }
                ],
            },
        )
    )

    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=headers))
    score = unwrap(client.get("/api/v1/security/score", headers=headers))

    assert result["security_score"]["risk_level"] == "yellow"
    assert score["risk_level"] == "yellow"
    assert result["devices"][0]["risk_level"] == "yellow"
    assert result["devices"][0]["open_ports"] == []
    assert "risk_signals" not in result["devices"][0]


def test_guardian_dashboard_excludes_phantom_from_device_count():
    """보호자 dashboard도 refusal-only 주소를 실제 기기로 세지 않는다."""
    user = scoped_headers("guardian-phantom-exclude")
    guardian = {
        "guardian_id": "guardian-phantom-owner",
        "guardian_email": "phantom.guardian@example.com",
        "guardian_name": "유령 제외 보호자",
    }
    invite = unwrap(client.post("/api/v1/guardians/invite", headers=user,
        json={"email": "phantom-ward@example.com", "relation": "가족", "ward_name": "유령 사용자"}))
    unwrap(client.post("/api/v1/security/scan", headers=user, json={
        "scan_profile": "quick", "scan_source": "android-native",
        "network_context": {"local_ip": "192.168.77.50", "gateway_ip": "192.168.77.1",
                            "subnet_cidr": "192.168.77.0/24", "is_private_network": True, "interface_type": "wifi"},
        "devices": [
                {"name": "공유기", "device_type": "router", "ip_address": "192.168.77.1",
                 "mac_address": "AA:BB:CC:77:00:01", "open_ports": [80], "services": ["http"],
                 "manufacturer": "ASUS", "model": "RT-AX58U", "discovery_sources": ["ssdp"],
                 "fingerprints": ["upnp-manufacturer:ASUS", "upnp-model:RT-AX58U"], "risk_signals": []},
            *[
                {"name": "", "device_type": "web-device",
                 "ip_address": f"192.168.77.{last}", "mac_address": f"UNKNOWN-192.168.77.{last}",
                 "open_ports": [], "services": [],
                 "discovery_sources": ["tcp-refused-presence"],
                 "fingerprints": [], "risk_signals": []}
                for last in range(200, 208)
            ],  # 주소별 실제 응답 없이 refusal만 반복된 전송 진단
        ],
    }))
    # 사용자 화면: refusal-only 텔레메트리는 내부 증거로만 보존하고 기기나
    # 식별 대기 항목으로 가장하지 않는다.
    ward_devices = unwrap(client.get("/api/v1/devices", headers=user))
    assert ward_devices["total"] == 1
    assert ward_devices["identity_pending_count"] == 0
    assert "unverified_count" not in ward_devices
    # 보호자 dashboard도 같은 공개 경계를 사용한다.
    accepted = unwrap(client.post("/api/v1/guardian-mode/links/accept",
        json={**guardian, "invite": invite["short_code"]}))
    dashboard = unwrap(client.get(
        f"/api/v1/guardian-mode/wards/{accepted['active_ward']['link_id']}/dashboard",
        params={"guardian_id": guardian["guardian_id"]}))
    assert dashboard["ward_summary"]["device_count"] == 1, dashboard["ward_summary"]
    assert dashboard["identity_findings"] == []


def test_reopen_normalizes_legacy_device_rows_snapshots_notifications_and_aliases(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    network_context = {
        "local_ip": "192.168.70.50",
        "gateway_ip": "192.168.70.1",
        "subnet_cidr": "192.168.70.0/24",
        "is_private_network": True,
        "interface_type": "wifi",
    }
    db_path = tmp_path / "legacy-device-presentation.db"
    repository = SQLiteRepository(db_path=str(db_path))
    home_id = provision_repository_owner(repository, "home-legacy-device-presentation")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context=network_context,
        discovered_devices=[
            {
                "device_id": "legacy-router",
                "name": "ipTIME 공유기 (A3004NS-M)",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "ip_address": "192.168.70.1",
                "mac_address": "AA:BB:CC:70:00:01",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["ssdp"],
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004NS-M"],
            },
            {
                "device_id": "legacy-weak-signal",
                "name": "웹 관리 기기",
                "device_type": "web-device",
                "manufacturer": "Realtek",
                "model": "RTL8197F",
                "ip_address": "192.168.70.99",
                "mac_address": "UNKNOWN-192.168.70.99",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["tcp-port-probe"],
            },
        ],
    )
    with repository._connect() as conn:
        conn.execute("UPDATE devices SET name = ? WHERE device_id = ?", ("제조사 미확인 기기", "legacy-router"))
        rows = conn.execute(
            "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ?", (scan["scan_id"],)
        ).fetchall()
        for row in rows:
            snapshot = json.loads(row["device_snapshot_json"])
            snapshot["name"] = "정체불명 기기" if snapshot["device_id"] == "legacy-router" else "웹 관리 기기"
            conn.execute(
                "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
                (json.dumps(snapshot, ensure_ascii=False), row["id"]),
            )
        conn.execute(
            "INSERT INTO device_aliases (home_id, device_id, alias, updated_at) VALUES (?, ?, ?, ?)",
            (home_id, "legacy-router", "기기 후보", "2026-08-13T00:00:00Z"),
        )
    repository._create_notification(
        "legacy", "정체불명 기기 안내", "Realtek chipset 신호를 찾았습니다.", home_id=home_id
    )
    mark_sqlite_release_migration_pending(repository)

    reopened = SQLiteRepository(db_path=str(db_path))

    assert [device["name"] for device in reopened.devices(home_id=home_id)] == ["ipTIME 공유기 (A3004NS-M)"]
    assert reopened._device_alias_map(home_id=home_id) == {}
    for payload in [
        reopened.devices(home_id=home_id),
        reopened.scan_result(scan["scan_id"], home_id=home_id),
        reopened.dashboard(home_id=home_id),
        reopened.notifications(home_id=home_id),
    ]:
        assert_no_forbidden_public_device_text(payload)


def test_reopen_normalizes_confirmation_needed_device_label(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    label = "\uD655\uC778 \uD544\uC694 \uAE30\uAE30"
    network_context = {
        "local_ip": "192.168.74.50",
        "gateway_ip": "192.168.74.1",
        "subnet_cidr": "192.168.74.0/24",
        "is_private_network": True,
        "interface_type": "wifi",
    }
    db_path = tmp_path / "legacy-confirmation-needed-device.db"
    repository = SQLiteRepository(db_path=str(db_path))
    home_id = provision_repository_owner(repository, "home-legacy-confirmation-label")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context=network_context,
        discovered_devices=[
            {
                "device_id": "legacy-confirmation-router",
                "name": "Router",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004",
                "ip_address": "192.168.74.1",
                "mac_address": "AA:BB:CC:74:00:01",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["ssdp"],
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004"],
            }
        ],
    )
    with repository._connect() as conn:
        conn.execute("UPDATE devices SET name = ? WHERE device_id = ?", (label, "legacy-confirmation-router"))
        snapshot_row = conn.execute(
            "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ?", (scan["scan_id"],)
        ).fetchone()
        snapshot = json.loads(snapshot_row["device_snapshot_json"])
        snapshot["name"] = label
        conn.execute(
            "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
            (json.dumps(snapshot, ensure_ascii=False), snapshot_row["id"]),
        )
        conn.execute(
            "INSERT INTO device_aliases (home_id, device_id, alias, updated_at) VALUES (?, ?, ?, ?)",
            (home_id, "legacy-confirmation-router", label, "2026-08-13T00:00:00Z"),
        )
    repository._create_notification(
        "legacy", f"{label} notice", f"{label} needs another check.", home_id=home_id
    )
    mark_sqlite_release_migration_pending(repository)

    reopened = SQLiteRepository(db_path=str(db_path))

    assert reopened._device_alias_map(home_id=home_id) == {}
    for payload in [
        reopened.devices(home_id=home_id),
        reopened.scan_result(scan["scan_id"], home_id=home_id),
        reopened.notifications(home_id=home_id),
    ]:
        assert label not in str(payload)
    with reopened._connect() as conn:
        stored_rows = conn.execute("SELECT name FROM devices").fetchall()
        snapshot_rows = conn.execute("SELECT device_snapshot_json FROM scan_devices").fetchall()
        notification_rows = conn.execute("SELECT title, message FROM notifications").fetchall()
        alias_rows = conn.execute("SELECT alias FROM device_aliases").fetchall()
    assert label not in str(stored_rows)
    assert label not in str(snapshot_rows)
    assert label not in str(notification_rows)
    assert alias_rows == []


def test_notification_write_never_persists_confirmation_needed_label(tmp_path, request):
    from sqlalchemy import select

    from app.storage.sa_repository import SqlAlchemyRepository, notifications_table
    from app.storage.sqlite_repository import SQLiteRepository

    label = "\uD655\uC778 \uD544\uC694 \uAE30\uAE30"
    sqlite_repository = SQLiteRepository(db_path=str(tmp_path / "notification-write.sqlite3"))
    sqlite_repository._create_notification("device-check", f"{label} notice", f"{label} needs another check.")
    with sqlite_repository._connect() as conn:
        sqlite_row = conn.execute("SELECT title, message FROM notifications").fetchone()
    assert label not in str(dict(sqlite_row))

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'notification-write-sa.sqlite3').as_posix()}"
    sqlalchemy_repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(sqlalchemy_repository.close)
    sqlalchemy_repository._create_notification("device-check", f"{label} notice", f"{label} needs another check.")
    with sqlalchemy_repository.engine.begin() as conn:
        sqlalchemy_row = conn.execute(select(notifications_table.c.title, notifications_table.c.message)).first()
    assert label not in str(tuple(sqlalchemy_row))


def test_reopen_normalizes_legacy_registration_authority_text(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    network_context = {
        "local_ip": "192.168.73.50",
        "gateway_ip": "192.168.73.1",
        "subnet_cidr": "192.168.73.0/24",
        "is_private_network": True,
        "interface_type": "wifi",
    }
    db_path = tmp_path / "legacy-registration-authority.db"
    repository = SQLiteRepository(db_path=str(db_path))
    home_id = provision_repository_owner(repository, "home-legacy-registration-authority")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context=network_context,
        discovered_devices=[
            {
                "device_id": "legacy-registration-router",
                "name": "SafeHome Router",
                "device_type": "router",
                "manufacturer": "SafeHome",
                "model": "R-1",
                "ip_address": "192.168.73.1",
                "mac_address": "AA:BB:CC:73:00:01",
                "open_ports": [80],
                "services": ["http"],
                "fingerprints": ["ssdp:InternetGatewayDevice"],
                "discovery_sources": ["ssdp"],
            }
        ],
    )
    with repository._connect() as conn:
        conn.execute(
            "UPDATE devices SET name = ?, manufacturer = ?, model = ? WHERE device_id = ?",
            (
                "IEEE Registration Authority 공유기",
                "IEEE Registration Authority",
                "MA-S OUI",
                "legacy-registration-router",
            ),
        )
        snapshot_row = conn.execute(
            "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ?",
            (scan["scan_id"],),
        ).fetchone()
        snapshot = json.loads(snapshot_row["device_snapshot_json"])
        snapshot.update(
            {
                "name": "Private 등록기관 공유기",
                "manufacturer": "IEEE Registration Authority",
                "model": "MA-M",
                "recommended_actions": ["IANA 등록기관을 확인하세요."],
                "risk_summary": "OUI 등록기관 신호를 찾았습니다.",
            }
        )
        conn.execute(
            "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
            (json.dumps(snapshot, ensure_ascii=False), snapshot_row["id"]),
        )
        conn.execute(
            "INSERT INTO device_aliases (home_id, device_id, alias, updated_at) VALUES (?, ?, ?, ?)",
            (home_id, "legacy-registration-router", "IEEE Registration Authority 공유기", "2026-08-13T00:00:00Z"),
        )
        conn.execute(
            """
            INSERT INTO security_events (event_id, home_id, severity, title, description, device_id, created_at, action_guide)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-registration-event",
                home_id,
                "yellow",
                "IEEE Registration Authority 안내",
                "Private OUI 등록기관 신호를 찾았습니다.",
                "legacy-registration-router",
                "2026-08-13T00:00:00Z",
                "MA-S 값을 확인하세요.",
            ),
        )
    repository._create_notification(
        "legacy-registration-authority",
        "IANA Registration Authority 안내",
        "OUI Private 등록기관 신호를 찾았습니다.",
        home_id=home_id,
    )
    mark_sqlite_release_migration_pending(repository)

    reopened = SQLiteRepository(db_path=str(db_path))

    reopened_devices = reopened.devices(home_id=home_id)
    assert len(reopened_devices) == 0
    assert reopened._device_alias_map(home_id=home_id) == {}
    for payload in [
        reopened.devices(home_id=home_id),
        reopened.scan_result(scan["scan_id"], home_id=home_id),
        reopened.dashboard(home_id=home_id),
        reopened.notifications(home_id=home_id),
    ]:
        assert_no_forbidden_public_device_text(payload)
    with reopened._connect() as conn:
        event = conn.execute(
            "SELECT title, description, action_guide FROM security_events WHERE event_id = ?",
            ("legacy-registration-event",),
        ).fetchone()
    assert_no_forbidden_public_device_text(dict(event))


def test_legacy_address_derived_device_id_is_hidden_and_still_accepts_alias_updates(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    db_path = tmp_path / "legacy-device-id.db"
    repository = SQLiteRepository(db_path=str(db_path))
    home_id = "home-legacy-device-id"
    provision_repository_owner(repository, home_id)
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context={
            "bssid": "10:20:30:77:00:01",
            "local_ip": "192.168.77.50",
            "gateway_ip": "192.168.77.1",
            "subnet_cidr": "192.168.77.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
        },
        discovered_devices=[
            {
                "name": "ipTIME 공유기 (A3004NS-M)",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "ip_address": "192.168.77.2",
                "mac_address": "AA:BB:CC:77:00:02",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["ssdp"],
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004NS-M"],
            }
        ],
    )
    legacy_id = "dev-192-168-77-2"
    with repository._connect() as conn:
        snapshot_row = conn.execute(
            "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ?",
            (scan["scan_id"],),
        ).fetchone()
        snapshot = json.loads(snapshot_row["device_snapshot_json"])
        snapshot["device_id"] = legacy_id
        conn.execute(
            "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
            (json.dumps(snapshot, ensure_ascii=False), snapshot_row["id"]),
        )

    reopened = SQLiteRepository(db_path=str(db_path))
    public_device = reopened.devices(home_id=home_id)[0]
    public_id = public_device["device_id"]

    assert public_id != legacy_id
    assert "192-168-77-2" not in public_id
    assert reopened.device(public_id, home_id=home_id)["device_id"] == public_id
    # Legacy app caches remain readable, but no response revives the old ID.
    assert reopened.device(legacy_id, home_id=home_id)["device_id"] == public_id

    reopened.set_device_alias(public_id, "우리 집 공유기", home_id=home_id)
    assert reopened.device(public_id, home_id=home_id)["name"] == "우리 집 공유기"


def test_sqlalchemy_repository_uses_the_same_public_presentation_boundary(tmp_path, request):
    from app.storage.sa_repository import SqlAlchemyRepository

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-presentation.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    home_id = provision_repository_owner(repository, "home-sa-presentation")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context={
            "local_ip": "192.168.71.50",
            "gateway_ip": "192.168.71.1",
            "subnet_cidr": "192.168.71.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
        },
        discovered_devices=[
            {
                "device_id": "sa-router",
                "name": "ipTIME 공유기 (A3004NS-M)",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "ip_address": "192.168.71.2",
                "mac_address": "AA:BB:CC:71:00:02",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["ssdp"],
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004NS-M"],
            },
            {
                "device_id": "sa-weak",
                "name": "웹 관리 기기",
                "device_type": "web-device",
                "manufacturer": "Realtek",
                "model": "RTL8197F",
                "ip_address": "192.168.71.98",
                "mac_address": "UNKNOWN-192.168.71.98",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["tcp-port-probe"],
            },
        ],
    )

    reopened = SqlAlchemyRepository(database_url)
    request.addfinalizer(reopened.close)

    assert [device["name"] for device in reopened.devices(home_id=home_id)] == ["ipTIME 공유기 (A3004NS-M)"]
    for payload in [
        reopened.devices(home_id=home_id),
        reopened.scan_result(scan["scan_id"], home_id=home_id),
        reopened.dashboard(home_id=home_id),
    ]:
        assert_no_forbidden_public_device_text(payload)


def test_sqlalchemy_repository_hides_legacy_address_derived_id_and_resolves_public_alias(tmp_path, request):
    from sqlalchemy import select, update

    from app.storage.sa_repository import SqlAlchemyRepository, scan_devices_table

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-legacy-device-id.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    home_id = "home-sa-legacy-device-id"
    provision_repository_owner(repository, home_id)
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context={
            "bssid": "10:20:30:78:00:01",
            "local_ip": "192.168.78.50",
            "gateway_ip": "192.168.78.1",
            "subnet_cidr": "192.168.78.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
        },
        discovered_devices=[
            {
                "name": "ipTIME 공유기 (A3004NS-M)",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "ip_address": "192.168.78.2",
                "mac_address": "AA:BB:CC:78:00:02",
                "open_ports": [80],
                "services": ["http"],
                "discovery_sources": ["ssdp"],
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004NS-M"],
            }
        ],
    )
    legacy_id = "dev-192-168-78-2"
    with repository.engine.begin() as conn:
        row = conn.execute(
            select(scan_devices_table.c.id, scan_devices_table.c.device_snapshot_json)
            .where(scan_devices_table.c.scan_id == scan["scan_id"])
        ).first()
        snapshot = json.loads(row[1])
        snapshot["device_id"] = legacy_id
        conn.execute(
            update(scan_devices_table)
            .where(scan_devices_table.c.id == row[0])
            .values(device_snapshot_json=json.dumps(snapshot, ensure_ascii=False))
        )

    reopened = SqlAlchemyRepository(database_url)
    request.addfinalizer(reopened.close)
    public_id = reopened.devices(home_id=home_id)[0]["device_id"]

    assert public_id != legacy_id
    assert "192-168-78-2" not in public_id
    assert reopened.device(public_id, home_id=home_id)["device_id"] == public_id
    assert reopened.device(legacy_id, home_id=home_id)["device_id"] == public_id
    reopened.set_device_alias(public_id, "우리 집 공유기", home_id=home_id)
    assert reopened.device(public_id, home_id=home_id)["name"] == "우리 집 공유기"


def test_sqlalchemy_score_uses_private_observation_and_persists_alias(tmp_path, request):
    from app.storage.sa_repository import SqlAlchemyRepository

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-score.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    home_id = provision_repository_owner(repository, "home-sa-score")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context={
            "local_ip": "192.168.92.50",
            "gateway_ip": "192.168.92.1",
            "subnet_cidr": "192.168.92.0/24",
            "is_private_network": True,
            "interface_type": "wifi",
        },
        discovered_devices=[
            {
                "name": "ipTIME 공유기",
                "device_type": "router",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "ip_address": "192.168.92.1",
                "mac_address": "AA:BB:CC:92:00:01",
                "open_ports": [23],
                "services": ["telnet"],
                "discovery_sources": ["ssdp"],
                "fingerprints": [
                    "upnp-manufacturer:EFM Networks",
                    "upnp-model:A3004NS-M",
                    "ssdp:InternetGatewayDevice",
                ],
            }
        ],
    )
    device_id = scan["devices"][0]["device_id"]
    repository.set_device_alias(device_id, "거실 공유기", home_id=home_id)

    reopened = SqlAlchemyRepository(database_url)
    request.addfinalizer(reopened.close)
    result = reopened.scan_result(scan["scan_id"], home_id=home_id)
    score = reopened.security_score(home_id=home_id)

    assert reopened.device(device_id, home_id=home_id)["name"] == "거실 공유기"
    assert result["security_score"]["risk_level"] == "yellow"
    assert score["risk_level"] == "yellow"
    assert result["devices"][0]["open_ports"] == []
    assert "risk_signals" not in result["devices"][0]


def _safe_network_context() -> dict[str, object]:
    return {
        "local_ip": "192.168.96.50",
        "gateway_ip": "192.168.96.1",
        "subnet_cidr": "192.168.96.0/24",
        "interface_type": "wifi",
        "is_private_network": True,
        "is_emulator": False,
        "is_virtual_network": False,
    }


def _public_network_context() -> dict[str, object]:
    return {
        "interface_type": "wifi",
        "is_private_network": True,
        "is_emulator": False,
        "is_virtual_network": False,
    }


def _legacy_public_network_context() -> dict[str, object]:
    return {
        "is_private_network": True,
        "is_emulator": False,
        "is_virtual_network": False,
    }


def _network_context_with_discovery_text() -> dict[str, object]:
    return {
        **_safe_network_context(),
        "scanner_note": "Realtek IEEE Registration Authority web-device",
        "nested_diagnostics": {"candidate": "OUI MA-S"},
        "device_banner": "ESP32 temporary device",
        "unexpected_boolean": "true",
    }


def _legacy_network_context_with_discovery_text() -> dict[str, object]:
    return {
        **_network_context_with_discovery_text(),
        "local_ip": "not-an-ip OUI",
        "interface_type": "wifi Realtek",
    }


def test_scan_result_api_projects_network_context_to_safe_allowlist():
    headers = scoped_headers("network-context-public-projection")
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=headers,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": _network_context_with_discovery_text(),
                "devices": [],
            },
        )
    )

    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=headers))

    assert result["network_context"] == _public_network_context()
    serialized = json.dumps(result, ensure_ascii=False)
    for raw_address in ("192.168.96.50", "192.168.96.1", "192.168.96.0/24"):
        assert raw_address not in serialized
    assert_no_forbidden_public_device_text(result)


def test_scan_result_preserves_collection_counters_without_network_identifiers():
    headers = scoped_headers("scan-diagnostics-public-contract")
    scan = unwrap(
        client.post(
            "/api/v1/security/scan",
            headers=headers,
            json={
                "scan_profile": "quick",
                "scan_source": "android-native",
                "network_context": {
                    "local_ip": "192.168.97.50",
                    "gateway_ip": "192.168.97.1",
                    "subnet_cidr": "192.168.97.0/24",
                    "is_private_network": True,
                    "interface_type": "wifi",
                    "scan_diagnostics": {
                        "candidate_host_count": 254,
                        "arp_entries_before_probe": 8,
                        "mdns_hosts": 3,
                        "ssdp_hosts": 2,
                        "onvif_hosts": 1,
                        "tcp_hosts": 12,
                        "raw_observation_count": 16,
                        "unsafe_text": "192.168.97.50 Realtek",
                    },
                },
                "devices": [],
            },
        )
    )

    assert scan["network_context"] == {
        "interface_type": "wifi",
        "is_private_network": True,
        "scan_diagnostics": {
            "candidate_host_count": 254,
            "arp_entries_before_probe": 8,
            "mdns_hosts": 3,
            "ssdp_hosts": 2,
            "onvif_hosts": 1,
            "tcp_hosts": 12,
            "raw_observation_count": 16,
        },
    }
    result = unwrap(client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=headers))
    assert result["network_context"] == scan["network_context"]
    serialized = json.dumps(result, ensure_ascii=False)
    for raw in ("192.168.97.50", "192.168.97.1", "192.168.97.0/24", "Realtek"):
        assert raw not in serialized


def test_sqlite_invalid_legacy_android_scan_is_preserved_but_not_public(tmp_path):
    from app.storage.sqlite_repository import SQLiteRepository

    repository = SQLiteRepository(db_path=str(tmp_path / "legacy-network-context.sqlite3"))
    home_id = provision_repository_owner(repository, "home-sqlite-legacy-network")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context=_safe_network_context(),
        discovered_devices=[],
    )
    with repository._connect() as conn:
        conn.execute(
            "UPDATE scans SET network_context_json = ? WHERE scan_id = ?",
            (json.dumps(_legacy_network_context_with_discovery_text(), ensure_ascii=False), scan["scan_id"]),
        )

    result = repository.scan_result(scan["scan_id"], home_id=home_id)

    assert result is None
    with repository._connect() as conn:
        assert conn.execute(
            "SELECT 1 FROM scans WHERE scan_id = ?",
            (scan["scan_id"],),
        ).fetchone() is not None


def test_sqlalchemy_invalid_legacy_android_scan_is_preserved_but_not_public(tmp_path, request):
    from app.storage.sa_repository import SqlAlchemyRepository, scans_table

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'sa-legacy-network-context.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    request.addfinalizer(repository.close)
    home_id = provision_repository_owner(repository, "home-sa-legacy-network")
    scan = repository.create_scan(
        scan_source="android-native",
        home_id=home_id,
        network_context=_safe_network_context(),
        discovered_devices=[],
    )
    with repository.engine.begin() as conn:
        conn.execute(
            scans_table.update()
            .where(scans_table.c.scan_id == scan["scan_id"])
            .values(network_context_json=json.dumps(_legacy_network_context_with_discovery_text(), ensure_ascii=False))
        )

    result = repository.scan_result(scan["scan_id"], home_id=home_id)

    assert result is None
    with repository.engine.begin() as conn:
        assert conn.execute(
            scans_table.select().where(scans_table.c.scan_id == scan["scan_id"])
        ).first() is not None


def test_public_endpoints_project_legacy_ipv6_and_forged_device_text(monkeypatch):
    from app import main as main_module

    home_id = "home-public-boundary"
    raw_device_id = "device-2001:db8::1"
    raw_notification_id = "device-::1"
    monkeypatch.setattr(
        main_module.repository,
        "devices",
        lambda *, home_id: [
            {
                "device_id": raw_device_id,
                "home_id": home_id,
                "device_type": "router",
                "manufacturer": "iptime(EFM)",
                "model": "A3004",
                "identity_status": "resolved",
                "identity_confidence": 0.96,
                "identity_resolver_version": "server-identity-1.0.0",
                "identity_candidates": [
                    {
                        "label": "ipTIME 공유기 (A3004)",
                        "kind": "서버 카탈로그 확정",
                        "catalog_id": "iptime-router",
                    }
                ],
                "discovery_sources": ["ssdp"],
                "location": "거실",
                "serial_hint": "serial-1234",
            }
        ],
    )
    monkeypatch.setattr(
        main_module.repository,
        "notifications",
        lambda *, home_id: [
            {
                "notification_id": "notification-public-boundary",
                "home_id": home_id,
                "type": "legacy",
                "title": "SafeHome camera (R-1) 보안 안내",
                "message": "SafeHome camera (R-1)의 설정을 확인해 주세요.",
                "device_id": raw_notification_id,
                "read": False,
                "created_at": "2026-08-13T00:00:00Z",
            }
        ],
    )

    headers = scoped_headers("public-boundary")
    devices = unwrap(client.get("/api/v1/devices", headers=headers))
    notifications = unwrap(client.get("/api/v1/notifications", headers=headers))

    device = devices["items"][0]
    notification = notifications["items"][0]
    assert device["device_id"].startswith("device-")
    assert device["device_id"] != raw_device_id
    assert "2001:db8::1" not in str(device)
    assert "location" not in device and "serial_hint" not in device
    assert notification["title"] == "기기 확인 안내"
    assert notification["device_id"].startswith("device-")
    assert raw_notification_id not in str(notification)
    assert "SafeHome" not in str(notification)


def test_identity_history_endpoint_projects_explicit_safe_dto(monkeypatch):
    from app import main as main_module

    home_id = "home-history-public-boundary"
    raw_device_id = "dev-192-168-50-44"
    malicious_values = (
        "192.168.50.44",
        "AA:BB:CC:DD:EE:FF",
        "IEEE OUI",
        "알 수 없는 기기",
        "ssdp-location:http://device.local/root.xml",
    )
    monkeypatch.setattr(
        main_module.repository,
        "identity_history",
        lambda **_kwargs: [
            {
                "resolution_id": "resolution-192.168.50.44",
                "home_id": home_id,
                "device_id": raw_device_id,
                "observed_at": "2026-08-21T08:30:00Z 192.168.50.44",
                "identity_status": "resolved",
                "manufacturer": "IEEE OUI",
                "device_type": "router",
                "model": "AA:BB:CC:DD:EE:FF",
                "canonical_name": "알 수 없는 기기 192.168.50.44",
                "confidence": 0.99,
                "identity_evidence": ["ssdp-location:http://device.local/root.xml"],
                "identity_candidates": [{"label": "IEEE OUI", "raw": "192.168.50.44"}],
                "identity_note": "AA:BB:CC:DD:EE:FF 제품 확인",
                "resolver_version": "raw-resolver/OUI",
            },
            {
                "resolution_id": "resolution-safe",
                "home_id": home_id,
                "device_id": "dev-0123456789abcdef01234567",
                "observed_at": "2026-08-21T08:31:00Z",
                "identity_status": "resolved",
                "manufacturer": "Samsung",
                "device_type": "fridge",
                "model": "RF85C90",
                "canonical_name": "삼성 냉장고 (RF85C90)",
                "confidence": 0.96,
                "identity_evidence": ["private structured evidence"],
                "identity_candidates": [
                    {
                        "label": "삼성 냉장고 (RF85C90)",
                        "kind": "서버 카탈로그 확정",
                        "catalog_id": "samsung-familyhub-refrigerator",
                    }
                ],
                "identity_note": "private resolver note",
                "resolver_version": "server-identity-1.0.0",
            },
        ],
    )

    response = client.get(
        "/api/v1/devices/device-requested/identity-history",
        headers=scoped_headers("history-public-boundary"),
    )
    history = unwrap(response)

    assert history["total"] == 2
    malicious, resolved = history["items"]
    assert set(malicious) == {"device_id", "identity_status", "resolved", "message", "confidence"}
    assert malicious["identity_status"] == "unresolved"
    assert malicious["resolved"] is False
    assert malicious["device_id"] != raw_device_id
    assert set(resolved) == {
        "device_id",
        "observed_at",
        "identity_status",
        "resolved",
        "message",
        "confidence",
        "canonical_name",
        "manufacturer",
        "model",
        "device_type",
    }
    assert resolved["canonical_name"] == "삼성 냉장고 (RF85C90)"
    assert resolved["manufacturer"] == "삼성"
    assert resolved["model"] == "RF85C90"
    assert resolved["device_type"] == "fridge"

    public_text = json.dumps(history, ensure_ascii=False)
    for value in malicious_values:
        assert value not in public_text
    for private_key in (
        "resolution_id",
        "home_id",
        "identity_evidence",
        "identity_candidates",
        "identity_note",
        "resolver_version",
    ):
        assert private_key not in public_text

