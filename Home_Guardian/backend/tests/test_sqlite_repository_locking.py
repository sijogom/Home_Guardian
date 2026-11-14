from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from app.storage.sqlite_repository import (
    SQLiteRepository,
    _SQLITE_BUSY_TIMEOUT_MS,
    _SQLITE_SCHEMA_MIGRATION_ID,
)


def _provision_owner(repository: SQLiteRepository, home_id: str) -> None:
    repository.upsert_user(
        {
            "user_id": "sqlite-lock-owner",
            "email": "sqlite-lock-owner@test.homeguardian.invalid",
            "nickname": "SQLite 잠금 테스트 사용자",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )


def test_release_migration_runs_once_and_missing_marker_rearms_it(tmp_path):
    class CountingRepository(SQLiteRepository):
        migration_calls = 0

        def _migrate_schema(self, conn: sqlite3.Connection) -> None:
            type(self).migration_calls += 1
            super()._migrate_schema(conn)

    db_path = tmp_path / "migration-once.sqlite3"

    first = CountingRepository(db_path=db_path)
    assert CountingRepository.migration_calls == 1

    # A worker process constructing its own repository for a claimed=0 pass
    # must not replay the release-wide data normalization.
    CountingRepository(db_path=db_path)
    assert CountingRepository.migration_calls == 1

    with first._connect() as conn:
        marker = conn.execute(
            "SELECT applied_at FROM repository_migrations WHERE migration_id = ?",
            (_SQLITE_SCHEMA_MIGRATION_ID,),
        ).fetchone()
        assert marker is not None
        conn.execute(
            "DELETE FROM repository_migrations WHERE migration_id = ?",
            (_SQLITE_SCHEMA_MIGRATION_ID,),
        )

    # A later release can re-arm migrations by using a new marker id.  Removing
    # the current marker models that upgrade without weakening normal starts.
    CountingRepository(db_path=db_path)
    assert CountingRepository.migration_calls == 2


def test_failed_release_migration_is_retried_instead_of_marked_complete(tmp_path):
    class FailingRepository(SQLiteRepository):
        def _migrate_schema(self, conn: sqlite3.Connection) -> None:
            raise RuntimeError("deliberate migration failure")

    db_path = tmp_path / "migration-retry.sqlite3"
    with pytest.raises(RuntimeError, match="deliberate migration failure"):
        FailingRepository(db_path=db_path)

    recovered = SQLiteRepository(db_path=db_path)
    with recovered._connect() as conn:
        marker = conn.execute(
            "SELECT 1 FROM repository_migrations WHERE migration_id = ?",
            (_SQLITE_SCHEMA_MIGRATION_ID,),
        ).fetchone()
    assert marker is not None


def test_request_connections_do_not_reconfigure_journal_mode(tmp_path, monkeypatch):
    statements: list[str] = []
    original_connect = sqlite3.connect

    class TracedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            statements.append(str(sql))
            return super().execute(sql, parameters)

    def traced_connect(*args, **kwargs):
        kwargs["factory"] = TracedConnection
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    repository = SQLiteRepository(db_path=tmp_path / "journal-once.sqlite3")

    statements.clear()
    with repository._connect() as conn:
        conn.execute("SELECT 1").fetchone()

    normalized = [statement.strip().lower() for statement in statements]
    assert f"pragma busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}" in normalized
    assert "pragma foreign_keys=on" in normalized
    assert "pragma journal_mode=wal" not in normalized


def test_scan_auth_and_notification_writes_wait_past_five_second_lock(tmp_path):
    db_path = tmp_path / "concurrent-writes.sqlite3"
    bootstrap = SQLiteRepository(db_path=db_path)
    home_id = "home-sqlite-concurrent-writes"
    _provision_owner(bootstrap, home_id)

    scan_repository = SQLiteRepository(db_path=db_path)
    auth_repository = SQLiteRepository(db_path=db_path)
    notification_repository = SQLiteRepository(db_path=db_path)
    with bootstrap._connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == _SQLITE_BUSY_TIMEOUT_MS

    blocker = sqlite3.connect(db_path, timeout=30.0)
    blocker.execute("PRAGMA busy_timeout=30000")
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute("UPDATE homes SET name = name WHERE home_id = ?", (home_id,))

    start = Barrier(4)

    def run_after_barrier(operation):
        start.wait()
        return operation()

    operations = (
        lambda: scan_repository.create_scan(
            scan_profile="quick",
            scan_source="android-native",
            network_context={
                "local_ip": "192.168.120.50",
                "gateway_ip": "192.168.120.1",
                "subnet_cidr": "192.168.120.0/24",
                "is_private_network": True,
                "interface_type": "wifi",
                "is_emulator": False,
                "is_virtual_network": False,
            },
            discovered_devices=[],
            home_id=home_id,
        ),
        lambda: auth_repository.create_auth_session(
            session_id="session-concurrent-write",
            user_id="sqlite-lock-owner",
            home_id=home_id,
            role="user",
            refresh_token_hash="refresh-concurrent-write",
            expires_at="2099-01-01T00:00:00Z",
        ),
        lambda: notification_repository._create_notification(
            "concurrent-write",
            "동시 쓰기 점검",
            "SQLite 잠금 대기 회귀 테스트",
            home_id=home_id,
        ),
    )

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(run_after_barrier, operation)
                for operation in operations
            ]
            start.wait()
            # The former 5-second timeout raised database-is-locked here.
            time.sleep(5.25)
            blocker.commit()
            results = [future.result(timeout=10) for future in futures]
    finally:
        blocker.close()

    assert results[0]["scan_id"]
    assert results[1]["session_id"] == "session-concurrent-write"
    assert results[2]["notification_id"]
