from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from app.services.device_presentation import build_public_detected_connections
from app.services.identity_enrichment import (
    IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
    IdentityEnrichmentError,
    build_verified_product_catalog_entry,
)
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import SQLiteRepository, _SQLITE_SCHEMA_MIGRATION_ID


CONTEXT = {
    "ssid": "Private Academy Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.77.10",
    "gateway_ip": "192.168.77.1",
    "subnet_cidr": "192.168.77.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}
SOURCE_URL = "https://www.samsung.com/sec/support/model/XYZ-9000/"
CATALOG_COLUMNS = {
    "manufacturer",
    "manufacturer_key",
    "exact_model",
    "model_key",
    "device_type",
    "source_url",
    "provenance",
    "verified_at",
    "catalog_signature",
}


@pytest.fixture(params=("sqlite", "sqlalchemy"))
def repository_case(request, tmp_path):
    db_path = tmp_path / f"catalog-{request.param}.sqlite3"
    if request.param == "sqlite":
        repo = SQLiteRepository(db_path=db_path)
    else:
        repo = SqlAlchemyRepository(f"sqlite+pysqlite:///{db_path.as_posix()}")
    try:
        yield request.param, db_path, repo
    finally:
        close = getattr(repo, "close", None)
        if close:
            close()


def _provision_home(repo, home_id: str) -> None:
    token = home_id.replace("-", "")
    repo.upsert_user(
        {
            "user_id": f"owner-{token}",
            "email": f"{token}@catalog.invalid",
            "nickname": f"카탈로그 사용자 {token}",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )


def _unresolved_device(*, ip: str, mac: str, name: str = "academy-pc") -> dict:
    return {
        "name": name,
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http", "upnp"],
        "discovery_sources": ["tcp-port-probe", "upnp"],
        "fingerprints": ["upnp-manufacturer:Samsung"],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _create_review_job(repo, *, home_id: str, ip: str, mac: str) -> dict:
    _provision_home(repo, home_id)
    repo.create_scan(
        scan_source="android-native",
        network_context=CONTEXT,
        discovered_devices=[_unresolved_device(ip=ip, mac=mac)],
        home_id=home_id,
    )
    jobs = repo.identity_enrichment_jobs(
        status_filter="review_required",
        home_id=home_id,
    )
    assert len(jobs) == 1
    return jobs[0]


def _resolve(
    repo,
    job: dict,
    *,
    device_type: str = "fridge",
    model: str = "XYZ-9000",
) -> dict:
    return repo.resolve_identity_enrichment_job(
        job["job_id"],
        manufacturer="Samsung",
        device_type=device_type,
        model=model,
        source_reference=SOURCE_URL,
        expected_evidence_signature=job["evidence_signature"],
        expected_job_key=job["job_key"],
    )


def _execute(repository, sql: str, values: dict[str, object] | None = None):
    values = values or {}
    if isinstance(repository, SQLiteRepository):
        query = sql
        ordered_values: tuple[object, ...] = ()
        for key, value in values.items():
            query = query.replace(f":{key}", "?")
            ordered_values += (value,)
        with repository._connect() as conn:
            return conn.execute(query, ordered_values).fetchall()
    with repository.engine.begin() as conn:
        result = conn.execute(text(sql), values)
        return result.all() if result.returns_rows else []


def _reopen(kind: str, db_path: Path):
    if kind == "sqlite":
        return SQLiteRepository(db_path=db_path)
    return SqlAlchemyRepository(f"sqlite+pysqlite:///{db_path.as_posix()}")


def test_catalog_persists_across_homes_and_repository_reopen(repository_case):
    kind, db_path, repo = repository_case
    first = _create_review_job(
        repo,
        home_id="home-catalog-a",
        ip="192.168.77.21",
        mac="00:11:22:33:44:21",
    )
    _resolve(repo, first)
    _provision_home(repo, "home-catalog-b")

    entries = repo.verified_product_catalog_entries()
    assert len(entries) == 1
    assert entries[0]["manufacturer_key"] == "samsung"
    assert entries[0]["model_key"] == "xyz-9000"
    assert set(entries[0]) == CATALOG_COLUMNS

    close = getattr(repo, "close", None)
    if close:
        close()
    reopened = _reopen(kind, db_path)
    try:
        assert reopened.verified_product_catalog_entries() == entries
    finally:
        reopened_close = getattr(reopened, "close", None)
        if reopened_close:
            reopened_close()


def test_signed_resolution_backfills_missing_catalog_on_reopen(repository_case):
    kind, db_path, repo = repository_case
    job = _create_review_job(
        repo,
        home_id="home-backfill",
        ip="192.168.77.25",
        mac="00:11:22:33:44:25",
    )
    _resolve(repo, job)
    _execute(repo, "DELETE FROM verified_product_catalog")
    assert repo.verified_product_catalog_entries() == []
    if kind == "sqlite":
        _execute(
            repo,
            "DELETE FROM repository_migrations WHERE migration_id = :migration_id",
            {"migration_id": _SQLITE_SCHEMA_MIGRATION_ID},
        )

    close = getattr(repo, "close", None)
    if close:
        close()
    reopened = _reopen(kind, db_path)
    try:
        entries = reopened.verified_product_catalog_entries()
        assert len(entries) == 1
        assert entries[0]["model_key"] == "xyz-9000"
    finally:
        reopened_close = getattr(reopened, "close", None)
        if reopened_close:
            reopened_close()


def test_tampered_resolution_is_not_backfilled(repository_case):
    kind, db_path, repo = repository_case
    job = _create_review_job(
        repo,
        home_id="home-invalid-backfill",
        ip="192.168.77.26",
        mac="00:11:22:33:44:26",
    )
    resolved = _resolve(repo, job)
    _execute(repo, "DELETE FROM verified_product_catalog")
    _execute(
        repo,
        "UPDATE identity_enrichment_jobs SET resolution_signature = :signature "
        "WHERE job_id = :job_id",
        {"signature": "tampered", "job_id": resolved["job_id"]},
    )

    close = getattr(repo, "close", None)
    if close:
        close()
    reopened = _reopen(kind, db_path)
    try:
        assert reopened.verified_product_catalog_entries() == []
    finally:
        reopened_close = getattr(reopened, "close", None)
        if reopened_close:
            reopened_close()


def test_duplicate_product_is_idempotent_across_distinct_home_jobs(repository_case):
    _kind, _db_path, repo = repository_case
    first = _create_review_job(
        repo,
        home_id="home-duplicate-a",
        ip="192.168.77.31",
        mac="00:11:22:33:44:31",
    )
    second = _create_review_job(
        repo,
        home_id="home-duplicate-b",
        ip="192.168.77.32",
        mac="00:11:22:33:44:32",
    )
    _resolve(repo, first)
    _resolve(repo, second)

    assert len(repo.verified_product_catalog_entries()) == 1
    assert len(
        _execute(
            repo,
            "SELECT * FROM device_identity_history "
            "WHERE identity_status = 'manual_resolved'",
        )
    ) == 2
    resolved = repo.identity_enrichment_jobs(status_filter="resolved")
    assert {job["home_id"] for job in resolved} == {
        "home-duplicate-a",
        "home-duplicate-b",
    }


def test_type_conflict_rolls_back_catalog_job_and_history_atomically(repository_case):
    _kind, _db_path, repo = repository_case
    first = _create_review_job(
        repo,
        home_id="home-conflict-a",
        ip="192.168.77.41",
        mac="00:11:22:33:44:41",
    )
    _resolve(repo, first, device_type="fridge")
    conflicting = _create_review_job(
        repo,
        home_id="home-conflict-b",
        ip="192.168.77.42",
        mac="00:11:22:33:44:42",
    )

    with pytest.raises(IdentityEnrichmentError, match="IDENTITY_CATALOG_CONFLICT"):
        _resolve(repo, conflicting, device_type="tv")

    entries = repo.verified_product_catalog_entries()
    assert len(entries) == 1
    assert entries[0]["device_type"] == "fridge"
    assert len(
        _execute(
            repo,
            "SELECT * FROM device_identity_history "
            "WHERE identity_status = 'manual_resolved'",
        )
    ) == 1
    pending = repo.identity_enrichment_jobs(
        status_filter="review_required",
        home_id="home-conflict-b",
    )
    assert [job["job_id"] for job in pending] == [conflicting["job_id"]]


def test_tampered_catalog_signature_is_ignored_and_private_columns_do_not_exist(
    repository_case,
):
    _kind, _db_path, repo = repository_case
    job = _create_review_job(
        repo,
        home_id="home-tamper",
        ip="192.168.77.51",
        mac="00:11:22:33:44:51",
    )
    _resolve(repo, job)

    columns = {
        str(row[1])
        for row in _execute(repo, "PRAGMA table_info(verified_product_catalog)")
    }
    assert columns == CATALOG_COLUMNS
    assert not columns & {
        "home_id",
        "device_id",
        "network_scope_id",
        "ip_address",
        "mac_address",
        "ssid",
        "bssid",
        "hostname",
        "evidence_json",
        "job_id",
        "alias",
        "open_ports_json",
    }
    _execute(
        repo,
        "UPDATE verified_product_catalog SET catalog_signature = :signature",
        {"signature": "tampered"},
    )
    assert repo.verified_product_catalog_entries() == []


def test_same_named_academy_physical_endpoints_remain_distinct_in_public_inventory(
    repository_case,
):
    _kind, _db_path, repo = repository_case
    home_id = "home-academy"
    _provision_home(repo, home_id)
    result = repo.create_scan(
        scan_source="android-native",
        network_context=CONTEXT,
        discovered_devices=[
            _unresolved_device(
                ip="192.168.77.61",
                mac="00:11:22:33:44:61",
                name="academy-shared-name",
            ),
            _unresolved_device(
                ip="192.168.77.62",
                mac="00:11:22:33:44:62",
                name="academy-shared-name",
            ),
        ],
        home_id=home_id,
    )

    # The hostname is not identity, but each distinct concrete physical MAC is
    # current endpoint evidence. Both remain separate public pending cards and
    # separate research jobs even though an academy can reuse one host label.
    assert result["devices_found"] == 2
    assert result["identity_pending_count"] == 2
    assert len(result["identity_findings"]) == 2
    cards = build_public_detected_connections(result["identity_findings"])
    assert len(cards) == 2
    assert len({card["name"] for card in cards}) == 2
    assert all("academy-shared-name" not in card["name"] for card in cards)
    assert len({card["device_id"] for card in cards}) == 2
    assert len(result["security_score"]["device_scores"]) == 2
    assert repo.devices(home_id=home_id) == []
    jobs = repo.identity_enrichment_jobs(home_id=home_id)
    assert len(jobs) == 2
    assert len({job["device_id"] for job in jobs}) == 2


def test_postgresql_catalog_schema_has_parity_and_no_household_columns():
    schema_path = Path(__file__).resolve().parents[1] / "app" / "storage" / "postgres_schema.sql"
    schema = schema_path.read_text(encoding="utf-8")
    match = re.search(
        r"CREATE TABLE IF NOT EXISTS verified_product_catalog \((.*?)\n\);",
        schema,
        flags=re.DOTALL,
    )
    assert match is not None
    table_sql = match.group(1)
    for column in CATALOG_COLUMNS:
        assert re.search(rf"\b{re.escape(column)}\b", table_sql)
    for forbidden in (
        "home_id",
        "device_id",
        "network_scope_id",
        "ip_address",
        "mac_address",
        "ssid",
        "bssid",
        "hostname",
        "evidence_json",
        "job_id",
        "alias",
        "port",
    ):
        assert not re.search(rf"\b{forbidden}\b", table_sql)
    assert "UNIQUE (manufacturer_key, model_key)" in table_sql
    assert "automated-official-http" in table_sql
    assert "idx_verified_product_catalog_model" in schema


def test_automated_http_catalog_requires_registered_official_domain():
    entry = build_verified_product_catalog_entry(
        manufacturer="Samsung",
        device_type="fridge",
        exact_model="XYZ-9000",
        source_url=SOURCE_URL,
        provenance=IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
        verified_at="2026-08-28T00:00:00Z",
    )
    assert entry["provenance"] == "automated-official-http"

    with pytest.raises(IdentityEnrichmentError, match="IDENTITY_MODEL_NOT_SPECIFIC"):
        build_verified_product_catalog_entry(
            manufacturer="Acme",
            device_type="router",
            exact_model="ACME-9000",
            source_url="https://acme.com/products/ACME-9000/",
            provenance=IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
            verified_at="2026-08-28T00:00:00Z",
        )
