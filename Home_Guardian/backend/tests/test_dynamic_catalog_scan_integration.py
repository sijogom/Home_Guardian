from __future__ import annotations

from copy import deepcopy

import pytest
from sqlalchemy import text

from app.services.identity_enrichment import build_evidence_signature
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import (
    SQLiteRepository,
    verified_catalog_resolution_for_job,
)


@pytest.fixture(params=("sqlite", "sqlalchemy"))
def repository(request, tmp_path):
    path = tmp_path / f"catalog-scan-{request.param}.sqlite3"
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
            "email": f"{token}@scan-catalog.invalid",
            "nickname": token,
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )


def _context(*, bssid: str, subnet: str, gateway: str, local_ip: str) -> dict[str, object]:
    return {
        "ssid": "Catalog integration",
        "bssid": bssid,
        "local_ip": local_ip,
        "gateway_ip": gateway,
        "subnet_cidr": subnet,
        "is_private_network": True,
        "interface_type": "wifi",
    }


def _observation(
    *,
    ip: str,
    mac: str,
    manufacturer: str = "Samsung",
    model: str = "XYZ-9000",
    device_type: str = "fridge",
) -> dict[str, object]:
    return {
        "name": "",
        "device_type": device_type,
        "manufacturer": manufacturer,
        "model": model,
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http", "upnp"],
        "discovery_sources": ["http", "upnp"],
        "fingerprints": [
            f"http-manufacturer:{manufacturer}",
            f"http-model:{model}",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
    }


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


def test_verified_product_reprojects_an_existing_scan_in_another_home(repository) -> None:
    first_home = "home-catalog-source"
    second_home = "home-catalog-consumer"
    _provision(repository, first_home)
    _provision(repository, second_home)

    repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:50:61",
            subnet="192.168.61.0/24",
            gateway="192.168.61.1",
            local_ip="192.168.61.10",
        ),
        discovered_devices=[_observation(ip="192.168.61.21", mac="00:16:32:00:61:21")],
        home_id=first_home,
    )
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:50:62",
            subnet="192.168.62.0/24",
            gateway="192.168.62.1",
            local_ip="192.168.62.10",
        ),
        discovered_devices=[_observation(ip="192.168.62.22", mac="00:16:32:00:62:22")],
        home_id=second_home,
    )

    before_devices = repository.devices(home_id=second_home)
    before_findings = repository.identity_findings(home_id=second_home)
    # The unresolved observation remains visible in the public scan result as
    # an identity finding.  A later global catalog fact may move that same row
    # into the identified-device projection, but it must not create network
    # membership or change the public device identifier.
    assert before_devices == []
    assert len(before_findings) == 1
    before_device_id = before_findings[0]["device_id"]

    source_job = repository.identity_enrichment_jobs(
        status_filter="review_required",
        home_id=first_home,
    )[0]
    repository.resolve_identity_enrichment_job(
        source_job["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="XYZ-9000",
        source_reference="https://www.samsung.com/sec/support/model/XYZ-9000/",
        expected_evidence_signature=source_job["evidence_signature"],
        expected_job_key=source_job["job_key"],
    )

    after = repository.devices(home_id=second_home)
    assert len(after) == 1
    assert after[0]["device_id"] == before_device_id
    assert after[0]["manufacturer"] == "삼성"
    assert after[0]["model"] == "XYZ-9000"
    assert after[0]["device_type"] == "fridge"
    assert after[0]["name"] == "삼성 냉장고 (XYZ-9000)"
    assert repository.identity_findings(home_id=second_home) == []

    consumer_job = repository.identity_enrichment_jobs(home_id=second_home)[0]
    assert consumer_job["status"] == "resolved"
    assert consumer_job["resolution"]["catalog_reused"] is True
    assert second_home not in repository.identity_research_due_home_ids(limit=200)
    assert repository.claim_identity_research_jobs(home_id=second_home, limit=8) == []

    first_device = repository.devices(home_id=first_home)[0]
    assert first_device["device_id"] != after[0]["device_id"]


def test_one_catalog_fact_resolves_eighty_four_distinct_observations(repository) -> None:
    source_home = "home-catalog-source-84"
    consumer_home = "home-catalog-consumer-84"
    _provision(repository, source_home)
    _provision(repository, consumer_home)
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:84:01",
            subnet="192.168.84.0/24",
            gateway="192.168.84.1",
            local_ip="192.168.84.10",
        ),
        discovered_devices=[_observation(ip="192.168.84.11", mac="00:16:32:84:00:01")],
        home_id=source_home,
    )
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:84:02",
            subnet="192.168.85.0/24",
            gateway="192.168.85.1",
            local_ip="192.168.85.10",
        ),
        discovered_devices=[
            _observation(
                ip=f"192.168.85.{index + 20}",
                mac=f"00:16:32:85:{index // 256:02X}:{index % 256:02X}",
            )
            for index in range(84)
        ],
        home_id=consumer_home,
    )
    before_jobs = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=consumer_home, limit=200
    )
    assert len(before_jobs) == 84
    assert len(repository.identity_findings(home_id=consumer_home)) == 84

    source_job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=source_home
    )[0]
    repository.resolve_identity_enrichment_job(
        source_job["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="XYZ-9000",
        source_reference="https://www.samsung.com/sec/support/model/XYZ-9000/",
        expected_evidence_signature=source_job["evidence_signature"],
        expected_job_key=source_job["job_key"],
    )

    consumer_jobs = repository.identity_enrichment_jobs(home_id=consumer_home, limit=200)
    assert len(consumer_jobs) == 84
    assert {job["status"] for job in consumer_jobs} == {"resolved"}
    assert {job["resolution"]["catalog_reused"] for job in consumer_jobs} == {True}
    devices = repository.devices(home_id=consumer_home)
    assert len(devices) == 84
    assert len({device["device_id"] for device in devices}) == 84
    assert repository.identity_findings(home_id=consumer_home) == []
    assert consumer_home not in repository.identity_research_due_home_ids(limit=200)
    assert repository.claim_identity_research_jobs(home_id=consumer_home, limit=8) == []


def test_catalog_reconcile_is_bounded_deadline_aware_and_resumes(repository) -> None:
    source_home = "home-catalog-bounded-source"
    _provision(repository, source_home)
    repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:90:01",
            subnet="192.168.90.0/24",
            gateway="192.168.90.1",
            local_ip="192.168.90.10",
        ),
        discovered_devices=[_observation(ip="192.168.90.20", mac="00:16:32:90:00:01")],
        home_id=source_home,
    )

    queue_homes: list[str] = []
    for index in range(5):
        home_id = f"home-catalog-bounded-{index}"
        queue_homes.append(home_id)
        _provision(repository, home_id)
        repository.create_scan(
            scan_source="android-native",
            network_context=_context(
                bssid=f"10:20:30:40:91:{index + 1:02X}",
                subnet=f"192.168.{91 + index}.0/24",
                gateway=f"192.168.{91 + index}.1",
                local_ip=f"192.168.{91 + index}.10",
            ),
            discovered_devices=[
                _observation(
                    ip=f"192.168.{91 + index}.20",
                    mac=f"00:16:32:91:00:{index + 1:02X}",
                    model="XYZ-9000" if index == 4 else f"OTHER-{index:04d}",
                )
            ],
            home_id=home_id,
        )

    source_job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=source_home
    )[0]
    repository.resolve_identity_enrichment_job(
        source_job["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="XYZ-9000",
        source_reference="https://www.samsung.com/sec/support/model/XYZ-9000/",
        expected_evidence_signature=source_job["evidence_signature"],
        expected_job_key=source_job["job_key"],
        _propagate_catalog=False,
    )

    stop_ticks = iter((False, True))
    assert repository.reconcile_verified_product_catalog_jobs(
        limit=5, should_stop=lambda: next(stop_ticks)
    ) == 0
    queued = repository.identity_enrichment_jobs(status_filter="review_required", limit=200)
    assert sum(bool(job.get("catalog_reconcile_version")) for job in queued) == 1

    assert repository.reconcile_verified_product_catalog_jobs(limit=2) == 0
    queued = repository.identity_enrichment_jobs(status_filter="review_required", limit=200)
    assert sum(bool(job.get("catalog_reconcile_version")) for job in queued) == 3

    assert repository.reconcile_verified_product_catalog_jobs(limit=2) == 1
    resolved_tail = repository.identity_enrichment_jobs(home_id=queue_homes[-1])[0]
    assert resolved_tail["status"] == "resolved"
    assert repository.identity_findings(home_id=queue_homes[-1]) == []
    assert repository.reconcile_verified_product_catalog_jobs(limit=2) == 0


def test_catalog_reconcile_rejects_tampered_job_binding(repository) -> None:
    source_home = "home-catalog-tamper-source"
    consumer_home = "home-catalog-tamper-consumer"
    _provision(repository, source_home)
    _provision(repository, consumer_home)
    for home_id, octet in ((source_home, 101), (consumer_home, 102)):
        repository.create_scan(
            scan_source="android-native",
            network_context=_context(
                bssid=f"10:20:30:40:AA:{octet:02X}",
                subnet=f"192.168.{octet}.0/24",
                gateway=f"192.168.{octet}.1",
                local_ip=f"192.168.{octet}.10",
            ),
            discovered_devices=[
                _observation(
                    ip=f"192.168.{octet}.20",
                    mac=f"00:16:32:AA:00:{octet:02X}",
                )
            ],
            home_id=home_id,
        )
    source_job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=source_home
    )[0]
    repository.resolve_identity_enrichment_job(
        source_job["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="XYZ-9000",
        source_reference="https://www.samsung.com/sec/support/model/XYZ-9000/",
        expected_evidence_signature=source_job["evidence_signature"],
        expected_job_key=source_job["job_key"],
        _propagate_catalog=False,
    )
    consumer_job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=consumer_home
    )[0]
    _update_job(repository, consumer_job["job_id"], job_key="tampered-job-key")

    assert repository.reconcile_verified_product_catalog_jobs(limit=10) == 0
    after = repository.identity_enrichment_jobs(home_id=consumer_home)[0]
    assert after["status"] == "review_required"
    # The public scan projection can still use the independently signed global
    # product fact, but the tampered queue row itself must never be closed.
    assert repository.identity_findings(home_id=consumer_home) == []


def test_catalog_reuse_accepts_missing_type_but_rejects_conflicting_clues(repository) -> None:
    source_home = "home-catalog-conflict-source"
    consumer_home = "home-catalog-conflict-consumer"
    _provision(repository, source_home)
    _provision(repository, consumer_home)
    for home_id, octet in ((source_home, 106), (consumer_home, 107)):
        repository.create_scan(
            scan_source="android-native",
            network_context=_context(
                bssid=f"10:20:30:40:CC:{octet:02X}",
                subnet=f"192.168.{octet}.0/24",
                gateway=f"192.168.{octet}.1",
                local_ip=f"192.168.{octet}.10",
            ),
            discovered_devices=[
                _observation(
                    ip=f"192.168.{octet}.20",
                    mac=f"00:16:32:CC:00:{octet:02X}",
                )
            ],
            home_id=home_id,
        )
    source_job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=source_home
    )[0]
    repository.resolve_identity_enrichment_job(
        source_job["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="XYZ-9000",
        source_reference="https://www.samsung.com/sec/support/model/XYZ-9000/",
        expected_evidence_signature=source_job["evidence_signature"],
        expected_job_key=source_job["job_key"],
        _propagate_catalog=False,
    )
    job = repository.identity_enrichment_jobs(
        status_filter="review_required", home_id=consumer_home
    )[0]
    catalog = repository.verified_product_catalog_entries()
    assert verified_catalog_resolution_for_job(job, catalog) is not None

    conflicting_proofs = (
        [{"kind": "manufacturer", "source": "upnp", "value": "LG"}],
        [{"kind": "model", "source": "upnp", "value": "OTHER-9999"}],
        [
            {"kind": "device_type", "source": "upnp", "value": "fridge"},
            {"kind": "device_type", "source": "upnp", "value": "router"},
        ],
    )
    for additions in conflicting_proofs:
        candidate = deepcopy(job)
        evidence = deepcopy(job["evidence"])
        evidence["structured_provenance"] = [
            *evidence["structured_provenance"],
            *additions,
        ]
        candidate["evidence"] = evidence
        candidate["evidence_signature"] = build_evidence_signature(evidence)
        assert verified_catalog_resolution_for_job(candidate, catalog) is None


def test_completed_unresolved_scan_status_result_and_event_copy_match(repository) -> None:
    home_id = "home-completed-unresolved-parity"
    _provision(repository, home_id)
    observation = _observation(
        ip="192.168.111.20",
        mac="00:16:32:BB:00:01",
        model="XYZ-9000",
    )
    observation["open_ports"] = [23, 80]
    observation["default_credentials"] = True
    observation["risk_signals"] = ["default_credentials_possible", "telnet_open"]
    scan = repository.create_scan(
        scan_source="android-native",
        network_context=_context(
            bssid="10:20:30:40:BB:01",
            subnet="192.168.111.0/24",
            gateway="192.168.111.1",
            local_ip="192.168.111.10",
        ),
        discovered_devices=[observation],
        home_id=home_id,
    )

    status = repository.scan_status(scan["scan_id"], home_id=home_id)
    result = repository.scan_result(scan["scan_id"], home_id=home_id)
    assert scan["status"] == status["status"] == result["status"] == "completed"
    assert scan["current_step"] == status["current_step"] == result["current_step"] == "점검 완료"
    assert scan["identity_pending_count"] == status["identity_pending_count"] == result[
        "identity_pending_count"
    ] == 1
    assert result["security_score"]["score_status"] == "final"
    events = repository.security_events(home_id=home_id)
    assert events
    assert all("다시 점검" not in str(event.get("action_guide") or "") for event in events)
    assert {
        str(event.get("action_guide") or "") for event in events
    } == {"위험 안내를 확인하고 필요하면 해당 연결을 제한해 주세요."}
