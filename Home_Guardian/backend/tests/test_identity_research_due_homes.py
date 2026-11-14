from __future__ import annotations

import pytest
from sqlalchemy import text

from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import SQLiteRepository


@pytest.fixture(params=("sqlite", "sqlalchemy"))
def repository(request, tmp_path):
    path = tmp_path / f"due-homes-{request.param}.sqlite3"
    if request.param == "sqlite":
        repo = SQLiteRepository(db_path=path)
    else:
        repo = SqlAlchemyRepository(f"sqlite+pysqlite:///{path.as_posix()}")
    try:
        yield repo
    finally:
        close = getattr(repo, "close", None)
        if close:
            close()


def _provision(repo, home_id: str) -> None:
    token = home_id.replace("-", "")
    repo.upsert_user(
        {
            "user_id": f"owner-{token}",
            "email": f"{token}@due.invalid",
            "nickname": token,
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )


def _context() -> dict[str, object]:
    return {
        "ssid": "Research fairness",
        "bssid": "10:20:30:40:50:60",
        "local_ip": "192.168.77.10",
        "gateway_ip": "192.168.77.1",
        "subnet_cidr": "192.168.77.0/24",
        "is_private_network": True,
        "interface_type": "wifi",
    }


def _device(index: int) -> dict[str, object]:
    return {
        "name": "",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": f"192.168.77.{index + 2}",
        "mac_address": f"02:00:00:00:{index // 256:02X}:{index % 256:02X}",
        "open_ports": [80],
        "services": ["http"],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": ["http-server:embedded"],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _insert_queue_rows(repository, rows: list[dict[str, object]]) -> None:
    sql = """
        INSERT INTO identity_enrichment_jobs (
            job_id, job_key, home_id, device_id, status, blocked_reason,
            evidence_json, evidence_signature, seen_count, first_seen_at,
            last_seen_at, updated_at, research_attempt_count
        ) VALUES (
            :job_id, :job_key, :home_id, :device_id, 'review_required', NULL,
            '{}', :evidence_signature, 1, :first_seen_at,
            :first_seen_at, :first_seen_at, 0
        )
    """
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.executemany(
                sql.replace(":job_id", "?")
                .replace(":job_key", "?")
                .replace(":home_id", "?")
                .replace(":device_id", "?")
                .replace(":evidence_signature", "?")
                .replace(":first_seen_at", "?"),
                [
                    (
                        row["job_id"],
                        row["job_key"],
                        row["home_id"],
                        row["device_id"],
                        row["evidence_signature"],
                        row["first_seen_at"],
                        row["first_seen_at"],
                        row["first_seen_at"],
                    )
                    for row in rows
                ],
            )
        return
    with repository.engine.begin() as conn:
        conn.execute(text(sql), rows)


def _update_job(repository, job_id: str, **values: object) -> None:
    assignments = ", ".join(f"{key} = :{key}" for key in values)
    parameters = {"job_id": job_id, **values}
    if isinstance(repository, SQLiteRepository):
        query = f"UPDATE identity_enrichment_jobs SET {assignments} WHERE job_id = :job_id"
        ordered: list[object] = []
        for key, value in values.items():
            query = query.replace(f":{key}", "?")
            ordered.append(value)
        query = query.replace(":job_id", "?")
        ordered.append(job_id)
        with repository._connect() as conn:
            conn.execute(query, tuple(ordered))
        return
    with repository.engine.begin() as conn:
        conn.execute(
            text(f"UPDATE identity_enrichment_jobs SET {assignments} WHERE job_id = :job_id"),
            parameters,
        )


def test_due_home_query_is_not_truncated_by_two_hundred_job_window(repository) -> None:
    old_home = "home-old-single"
    noisy_home = "home-new-many"
    _provision(repository, old_home)
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(),
        # Keep a non-zero stable observation token.  The all-zero local MAC
        # is intentionally treated as non-bindable and would create a blocked
        # job rather than a due research job.
        discovered_devices=[_device(250)],
        home_id=old_home,
    )

    _provision(repository, noisy_home)
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(),
        discovered_devices=[_device(index) for index in range(201)],
        home_id=noisy_home,
    )

    truncated = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=200,
    )
    assert len(truncated) == 200
    assert {job["home_id"] for job in truncated} == {noisy_home}

    due_homes = repository.identity_research_due_home_ids(limit=200)
    assert due_homes[0] == old_home
    assert set(due_homes) == {old_home, noisy_home}


def test_nine_homes_with_eighty_four_jobs_rotate_after_first_eight(repository) -> None:
    homes = [f"home-fair-{index:02d}" for index in range(9)]
    rows: list[dict[str, object]] = []
    for home_index, home_id in enumerate(homes):
        _provision(repository, home_id)
        for job_index in range(84):
            token = f"{home_index:02d}-{job_index:03d}"
            rows.append(
                {
                    "job_id": f"identity-job-fair-{token}",
                    "job_key": f"job-key-fair-{token}",
                    "home_id": home_id,
                    "device_id": f"device-fair-{token}",
                    "evidence_signature": f"evidence-fair-{token}",
                    "first_seen_at": "2026-08-28T00:00:00Z",
                }
            )
    _insert_queue_rows(repository, rows)

    first_order = repository.identity_research_due_home_ids(limit=20)
    assert first_order == homes
    for home_id in first_order[:8]:
        assert len(repository.claim_identity_research_jobs(home_id=home_id, limit=1)) == 1

    second_order = repository.identity_research_due_home_ids(limit=20)
    assert second_order[0] == homes[8]
    assert set(second_order) == set(homes)


def test_selected_job_id_claim_does_not_advance_mixed_sibling(repository) -> None:
    home_id = "home-selected-claim"
    _provision(repository, home_id)
    rows = [
        {
            "job_id": f"identity-job-selected-{index}",
            "job_key": f"job-key-selected-{index}",
            "home_id": home_id,
            "device_id": f"device-selected-{index}",
            "evidence_signature": f"evidence-selected-{index}",
            "first_seen_at": f"2026-08-28T00:00:0{index}Z",
        }
        for index in range(2)
    ]
    _insert_queue_rows(repository, rows)

    claimed = repository.claim_identity_research_jobs(
        home_id=home_id,
        limit=2,
        job_ids=["identity-job-selected-1"],
    )

    assert [job["job_id"] for job in claimed] == ["identity-job-selected-1"]
    stored = {
        job["job_id"]: job for job in repository.identity_enrichment_jobs(home_id=home_id)
    }
    assert stored["identity-job-selected-0"]["research_attempt_count"] == 0
    assert stored["identity-job-selected-0"]["research_next_attempt_at"] is None
    assert stored["identity-job-selected-1"]["research_attempt_count"] == 1
    assert stored["identity-job-selected-1"]["research_next_attempt_at"] is not None


def test_policy_version_grants_one_retry_without_erasing_attempt_audit(repository) -> None:
    home_id = "home-policy-reset"
    _provision(repository, home_id)
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(),
        discovered_devices=[_device(33)],
        home_id=home_id,
    )
    job = repository.identity_enrichment_jobs(
        status_filter="review_required",
        home_id=home_id,
    )[0]
    last_attempt = "2026-08-28T01:00:00Z"
    future = "2099-08-28T07:00:00Z"
    _update_job(
        repository,
        job["job_id"],
        research_attempt_count=9,
        research_last_attempt_at=last_attempt,
        research_next_attempt_at=future,
        research_policy_version="identity-policy-old",
    )

    assert repository.reset_identity_research_backoff_for_version(
        "identity-policy-v1-aaaaaaaa"
    ) == 1
    reset = repository.identity_enrichment_jobs(home_id=home_id)[0]
    assert reset["research_attempt_count"] == 9
    assert reset["research_last_attempt_at"] == last_attempt
    assert reset["research_next_attempt_at"] is None
    assert reset["research_policy_version"] == "identity-policy-v1-aaaaaaaa"

    _update_job(repository, job["job_id"], research_next_attempt_at=future)
    assert repository.reset_identity_research_backoff_for_version(
        "identity-policy-v1-aaaaaaaa"
    ) == 0
    unchanged = repository.identity_enrichment_jobs(home_id=home_id)[0]
    assert unchanged["research_next_attempt_at"] == future
    assert repository.reset_identity_research_backoff_for_version(
        "identity-policy-v1-bbbbbbbb"
    ) == 1
    retried = repository.identity_enrichment_jobs(home_id=home_id)[0]
    assert retried["research_next_attempt_at"] is None
    assert retried["research_attempt_count"] == 9
