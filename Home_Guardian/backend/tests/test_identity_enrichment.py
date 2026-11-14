from __future__ import annotations

import json
import inspect
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError as SqlAlchemyIntegrityError

import app.main as main_module
from app.main import IDENTITY_REVIEW_HEADER, app
from app.scan_validation import strip_untrusted_self_claims
from app.services.device_presentation import (
    build_public_detected_connections,
    is_self_observation,
)
from app.services.identity_enrichment import (
    IdentityEnrichmentError,
    bind_authenticated_self_android_claim,
    blocked_binding_reason,
    build_identity_job_key,
    project_identity_enrichment_job,
    stable_identity_evidence_signature,
    strip_untrusted_authenticated_self_android,
    structured_identity_evidence,
    validate_identity_resolution,
)
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import SQLiteRepository, _SQLITE_SCHEMA_MIGRATION_ID


REVIEW_SECRET = "identity-review-test-secret-with-at-least-32-characters"
HOME_ID = "home-0001"
BASE_CONTEXT = {
    "ssid": "Private Home Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.50.10",
    "gateway_ip": "192.168.50.1",
    "subnet_cidr": "192.168.50.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}


def _bind_test_home(repo, home_id: str) -> None:
    repo.upsert_user(
        {
            "user_id": "identity-enrichment-owner",
            "email": "identity-enrichment-owner@example.invalid",
            "nickname": "식별 테스트 사용자",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )
    for name in dir(repo):
        method = getattr(repo, name)
        if not callable(method):
            continue
        try:
            signature = inspect.signature(method)
            accepts_home = "home_id" in signature.parameters
        except (TypeError, ValueError):
            accepts_home = False
        if not accepts_home:
            continue

        def scoped(*args, __method=method, __signature=signature, **kwargs):
            bound = __signature.bind_partial(*args, **kwargs)
            if "home_id" not in bound.arguments:
                kwargs["home_id"] = home_id
            return __method(*args, **kwargs)

        setattr(repo, name, scoped)


def _weak_device(
    *,
    ip: str = "192.168.50.20",
    mac: str = "AA:BB:CC:00:00:20",
) -> dict:
    return {
        "name": "private-living-room.local",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http"],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": [
            "mdns-name:private-living-room.local",
            f"ssdp-location:http://{ip}:80/device.xml",
            "upnp-manufacturer:Samsung",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _macless_product_device(
    ip: str,
    *,
    mac: str | None = None,
) -> dict:
    return {
        "name": "",
        "device_type": "computer",
        "manufacturer": "Apple",
        "model": "A2991",
        "ip_address": ip,
        "mac_address": mac or f"UNKNOWN-{ip}",
        "open_ports": [5000],
        "services": ["mdns"],
        "discovery_sources": ["mdns"],
        "fingerprints": [
            "mdns-txt:manufacturer=Apple",
            "mdns-txt:model=A2991",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _self_android_device(
    *,
    ip: str = "192.168.50.10",
    mac: str = "DA:F5:1E:FE:00:0A",
    manufacturer: str = "Samsung",
    model: str = "SM-F956N",
    device_type: str = "phone",
) -> dict:
    return {
        "name": f"내 휴대폰 ({model})",
        "device_type": device_type,
        "manufacturer": manufacturer,
        "model": model,
        "ip_address": ip,
        "mac_address": mac,
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
    }


@pytest.fixture(params=("sqlite", "sqlalchemy"))
def repository(request, tmp_path):
    if request.param == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "identity.sqlite3"))
    else:
        repo = SqlAlchemyRepository(
            f"sqlite+pysqlite:///{(tmp_path / 'identity-sa.sqlite3').as_posix()}"
        )
    _bind_test_home(repo, HOME_ID)
    try:
        yield repo
    finally:
        close = getattr(repo, "close", None)
        if close:
            close()


def _scan(repository, device: dict, *, context: dict | None = None) -> dict:
    return repository.create_scan(
        scan_source="android-native",
        network_context=context or BASE_CONTEXT,
        discovered_devices=[device],
        home_id=HOME_ID,
    )


def _approve(repository, job_id: str) -> dict:
    return repository.resolve_identity_enrichment_job(
        job_id,
        manufacturer="Samsung",
        device_type="fridge",
        model="RF85C90N1AP",
        source_reference="https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
    )


def _replace_scan_snapshot(repository, scan_id: str, payload: dict) -> None:
    serialized = json.dumps(payload, ensure_ascii=False)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE scan_devices SET device_snapshot_json = ? WHERE scan_id = ?",
                (serialized, scan_id),
            )
        return
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scan_devices SET device_snapshot_json = :payload "
                "WHERE scan_id = :scan_id"
            ),
            {"payload": serialized, "scan_id": scan_id},
        )


def _stored_scan_snapshots(repository, scan_id: str) -> list[dict]:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            rows = conn.execute(
                "SELECT device_snapshot_json FROM scan_devices "
                "WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
    else:
        with repository.engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT device_snapshot_json FROM scan_devices "
                    "WHERE scan_id = :scan_id ORDER BY id"
                ),
                {"scan_id": scan_id},
            ).fetchall()
    return [json.loads(row[0]) for row in rows]


def test_authenticated_self_android_proof_requires_in_process_sentinel():
    raw = _self_android_device()
    forged = {
        **raw,
        "_authenticated_self_android_proof": "forged-json-value",
        "fingerprints": [*raw["fingerprints"], "authenticated-self-android"],
        "discovery_sources": ["self", "authenticated-self-android"],
    }

    assert not any(
        proof.get("source") == "authenticated-self-android"
        for proof in structured_identity_evidence(forged).get(
            "structured_provenance", []
        )
    )
    cleaned = strip_untrusted_authenticated_self_android(forged)
    assert "_authenticated_self_android_proof" not in cleaned
    assert "authenticated-self-android" not in cleaned["fingerprints"]
    assert "authenticated-self-android" not in cleaned["discovery_sources"]

    bound = bind_authenticated_self_android_claim(raw)
    assert bound is not None
    evidence = structured_identity_evidence(bound)
    assert evidence["manufacturer_hints"] == ["Samsung"]
    assert evidence["model_hints"] == ["SM-F956N"]
    assert evidence["device_type_hints"] == ["phone"]
    assert {
        (proof["kind"], proof["source"], proof["value"])
        for proof in evidence["structured_provenance"]
    } == {
        ("manufacturer", "authenticated-self-android", "Samsung"),
        ("model", "authenticated-self-android", "SM-F956N"),
        ("device_type", "authenticated-self-android", "phone"),
    }


@pytest.mark.parametrize(
    "overrides",
    (
        {"confidence": 0.99},
        {"mac_address": "본인-기기"},
        {"manufacturer": "LG"},
        {"device_type": "tablet"},
        {"fingerprints": ["self-android", "self-model:SM-F956N"]},
    ),
)
def test_authenticated_self_android_binding_rejects_spoofed_build_fields(overrides):
    assert bind_authenticated_self_android_claim(
        {**_self_android_device(), **overrides}
    ) is None


def test_attested_self_and_unresolved_jobs_are_upserted_once_and_stay_private(repository):
    marked_self = bind_authenticated_self_android_claim(_self_android_device())
    assert marked_self is not None
    unresolved = _weak_device(ip="192.168.50.20", mac="AA:BB:CC:00:00:20")

    scan = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[marked_self, unresolved],
        home_id=HOME_ID,
    )
    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)

    assert len(jobs) == 2
    assert all(job["status"] == "review_required" for job in jobs)
    self_jobs = [
        job
        for job in jobs
        if job["evidence"].get("model_hints") == ["SM-F956N"]
    ]
    assert len(self_jobs) == 1
    assert self_jobs[0]["physical_mac"] == "DA:F5:1E:FE:00:0A"
    assert any(
        proof.get("source") == "authenticated-self-android"
        for proof in self_jobs[0]["evidence"]["structured_provenance"]
    )
    # The scanner itself never becomes a resident product card or count.
    assert all(device.get("model") != "SM-F956N" for device in scan["devices"])

    stored_text = json.dumps(
        _stored_scan_snapshots(repository, scan["scan_id"]),
        ensure_ascii=False,
    ).casefold()
    assert "_authenticated_self_android" not in stored_text
    assert "authenticated-self-android" not in stored_text


def _resolve_scoped_android_self(repository, job: dict, *, device_type: str, model: str):
    return repository.resolve_device_scoped_identity_job(
        job["job_id"],
        manufacturer="Samsung",
        device_type=device_type,
        model=model,
        source_reference=f"https://www.samsung.com/sec/support/model/{model}/",
        resolution_provenance="automated-official-http",
        expected_evidence_signature=job["evidence_signature"],
        expected_job_key=job["job_key"],
    )


def test_scoped_authenticated_self_resolution_is_public_but_never_global(repository):
    model = "SM-T720"
    marked_self = bind_authenticated_self_android_claim(
        _self_android_device(model=model, device_type="tablet")
    )
    assert marked_self is not None
    scan = _scan(repository, marked_self)
    job = repository.identity_enrichment_jobs(home_id=HOME_ID)[0]

    assert scan["devices"] == []
    assert repository.devices(home_id=HOME_ID) == []

    # The general resolver must not turn an Android Build claim into a global
    # product fact, even when every ordinary exact-match argument is valid.
    with pytest.raises(IdentityEnrichmentError) as general_error:
        repository.resolve_identity_enrichment_job(
            job["job_id"],
            manufacturer="Samsung",
            device_type="tablet",
            model=model,
            source_reference=f"https://www.samsung.com/sec/support/model/{model}/",
            resolution_provenance="automated-official-http",
            expected_evidence_signature=job["evidence_signature"],
            expected_job_key=job["job_key"],
        )
    assert general_error.value.code == "IDENTITY_BINDING_REQUIRED"

    with pytest.raises(IdentityEnrichmentError) as wrong_type:
        _resolve_scoped_android_self(
            repository,
            job,
            device_type="phone",
            model=model,
        )
    assert wrong_type.value.code == "IDENTITY_MODEL_NOT_SPECIFIC"

    with pytest.raises(IdentityEnrichmentError) as stale_cas:
        repository.resolve_device_scoped_identity_job(
            job["job_id"],
            manufacturer="Samsung",
            device_type="tablet",
            model=model,
            source_reference=f"https://www.samsung.com/sec/support/model/{model}/",
            resolution_provenance="automated-official-http",
            expected_evidence_signature="stale-evidence-signature",
            expected_job_key=job["job_key"],
        )
    assert stale_cas.value.code == "IDENTITY_BINDING_REQUIRED"

    resolved = _resolve_scoped_android_self(
        repository,
        job,
        device_type="tablet",
        model=model,
    )
    assert resolved["status"] == "resolved"
    assert resolved["resolution"]["device_scoped"] is True
    assert repository.verified_product_catalog_entries() == []

    devices = repository.devices(home_id=HOME_ID)
    assert len(devices) == 1
    assert devices[0]["model"] == model
    assert devices[0]["device_type"] == "tablet"
    assert devices[0]["name"] == f"삼성 태블릿 ({model})"
    assert is_self_observation(devices[0]) is False
    public_text = json.dumps(devices, ensure_ascii=False).casefold()
    assert "self-device" not in public_text
    assert "self-android" not in public_text
    assert "authenticated-self-android" not in public_text

    scan_result = repository.scan_result(scan["scan_id"], home_id=HOME_ID)
    scan_status = repository.scan_status(scan["scan_id"], home_id=HOME_ID)
    security_score = repository.security_score(home_id=HOME_ID)
    assert scan_result is not None and scan_status is not None
    assert scan_result["devices_found"] == 1
    assert scan_result["identified_count"] == 1
    assert scan_status["devices_found"] == 1
    assert [item["device_id"] for item in security_score["device_scores"]] == [
        devices[0]["device_id"]
    ]


def test_scoped_self_identity_carries_only_by_home_scope_and_unique_physical_mac(
    repository,
):
    former_model = "SM-F956N"
    former_mac = "02:11:22:33:44:55"
    former_context = {**BASE_CONTEXT, "local_ip": "192.168.50.5"}
    former_self = bind_authenticated_self_android_claim(
        _self_android_device(
            ip="192.168.50.5",
            mac=former_mac,
            model=former_model,
            device_type="phone",
        )
    )
    assert former_self is not None
    _scan(repository, former_self, context=former_context)
    former_job = repository.identity_enrichment_jobs(home_id=HOME_ID)[0]
    _resolve_scoped_android_self(
        repository,
        former_job,
        device_type="phone",
        model=former_model,
    )

    current_model = "SM-T720"
    current_mac = "02:66:77:88:99:AA"
    current_context = {**BASE_CONTEXT, "local_ip": "192.168.50.9"}
    current_self = bind_authenticated_self_android_claim(
        _self_android_device(
            ip="192.168.50.9",
            mac=current_mac,
            model=current_model,
            device_type="tablet",
        )
    )
    assert current_self is not None
    former_now_household = strip_untrusted_self_claims(
        _self_android_device(
            ip="192.168.50.5",
            mac=former_mac,
            model=former_model,
            device_type="phone",
        )
    )
    current_scan = repository.create_scan(
        scan_source="android-native",
        network_context=current_context,
        discovered_devices=[current_self, former_now_household],
        home_id=HOME_ID,
    )

    # The old scanner is now an ordinary endpoint and inherits only its own
    # signed physical-MAC identity. The current unresolved scanner stays hidden.
    assert [device["model"] for device in current_scan["devices"]] == [former_model]
    current_job = next(
        job
        for job in repository.identity_enrichment_jobs(home_id=HOME_ID)
        if job["evidence"].get("model_hints") == [current_model]
    )
    _resolve_scoped_android_self(
        repository,
        current_job,
        device_type="tablet",
        model=current_model,
    )
    refreshed = repository.scan_result(current_scan["scan_id"], home_id=HOME_ID)
    assert refreshed is not None
    assert {device["model"] for device in refreshed["devices"]} == {
        former_model,
        current_model,
    }
    assert refreshed["devices_found"] == 2
    assert len(refreshed["security_score"]["device_scores"]) == 2
    assert repository.verified_product_catalog_entries() == []

    # Same IP is not identity. A changed strong scope and different MAC cannot
    # inherit either scoped resolution.
    foreign_context = {
        **current_context,
        "bssid": "20:30:40:50:60:70",
    }
    foreign_scan = _scan(
        repository,
        _weak_device(ip="192.168.50.5", mac="02:AA:BB:CC:DD:EE"),
        context=foreign_context,
    )
    assert all(
        device.get("model") not in {former_model, current_model}
        for device in foreign_scan["devices"]
    )


def test_repeated_historical_self_and_current_server_neighbor_mint_scoped_jobs(
    repository,
):
    former_model = "SM-F956N"
    former_mac = "02:12:34:56:78:9A"
    former_ip = "192.168.50.5"
    former_context = {**BASE_CONTEXT, "local_ip": former_ip}
    historical_self = _self_android_device(
        ip=former_ip,
        mac=former_mac,
        model=former_model,
        device_type="phone",
    )

    # These are serialized legacy snapshots, not a caller-supplied trust flag.
    # Two distinct scans are required by the repository-neutral verifier.
    _scan(repository, historical_self, context=former_context)
    _scan(repository, historical_self, context=former_context)
    assert repository.identity_enrichment_jobs(home_id=HOME_ID) == []

    current_model = "SM-T720"
    current_self = bind_authenticated_self_android_claim(
        _self_android_device(
            ip="192.168.50.9",
            mac="02:AA:10:20:30:40",
            model=current_model,
            device_type="tablet",
        )
    )
    assert current_self is not None
    former_neighbor = {
        **_weak_device(ip=former_ip, mac=former_mac),
        "name": "",
        "manufacturer": "",
        "model": "",
        "device_type": "unknown",
        "discovery_sources": ["server-neighbor", "tcp-port-probe"],
        "fingerprints": [],
    }
    scan = repository.create_scan(
        scan_source="android-native",
        network_context={**BASE_CONTEXT, "local_ip": "192.168.50.9"},
        discovered_devices=[current_self, former_neighbor],
        home_id=HOME_ID,
    )

    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)
    assert len(jobs) == 2
    by_model = {
        job["evidence"]["model_hints"][0]: job
        for job in jobs
        if len(job["evidence"].get("model_hints") or []) == 1
    }
    assert set(by_model) == {former_model, current_model}
    assert by_model[former_model]["physical_mac"] == former_mac
    assert any(
        proof.get("source") == "authenticated-self-android"
        for proof in by_model[former_model]["evidence"]["structured_provenance"]
    )

    stored = _stored_scan_snapshots(repository, scan["scan_id"])
    stored_former = next(item for item in stored if item["ip_address"] == former_ip)
    assert is_self_observation(stored_former) is False
    assert stored_former.get("model") != former_model
    assert "authenticated-self-android" not in json.dumps(
        stored_former, ensure_ascii=False
    ).casefold()

    _resolve_scoped_android_self(
        repository,
        by_model[former_model],
        device_type="phone",
        model=former_model,
    )
    _resolve_scoped_android_self(
        repository,
        by_model[current_model],
        device_type="tablet",
        model=current_model,
    )
    refreshed = repository.scan_result(scan["scan_id"], home_id=HOME_ID)
    assert refreshed is not None
    assert {device["model"] for device in refreshed["devices"]} == {
        former_model,
        current_model,
    }
    assert refreshed["devices_found"] == 2
    assert len(refreshed["security_score"]["device_scores"]) == 2
    assert repository.verified_product_catalog_entries() == []


def test_one_historical_self_scan_cannot_mint_a_scoped_neighbor_job(repository):
    former_model = "SM-F956N"
    former_mac = "02:12:34:56:78:9B"
    former_ip = "192.168.50.5"
    _scan(
        repository,
        _self_android_device(
            ip=former_ip,
            mac=former_mac,
            model=former_model,
            device_type="phone",
        ),
        context={**BASE_CONTEXT, "local_ip": former_ip},
    )
    former_neighbor = {
        **_weak_device(ip=former_ip, mac=former_mac),
        "name": "",
        "manufacturer": "",
        "model": "",
        "device_type": "unknown",
        "discovery_sources": ["server-neighbor", "tcp-port-probe"],
        "fingerprints": [],
    }
    _scan(
        repository,
        former_neighbor,
        context={**BASE_CONTEXT, "local_ip": "192.168.50.9"},
    )

    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)
    assert len(jobs) == 1
    assert jobs[0]["physical_mac"] == former_mac
    assert jobs[0]["evidence"].get("model_hints") in (None, [])
    assert not any(
        proof.get("source") == "authenticated-self-android"
        for proof in jobs[0]["evidence"].get("structured_provenance", [])
    )


def test_device_scoped_resolver_rejects_an_ordinary_identity_job(repository):
    _scan(repository, _weak_device())
    job = repository.identity_enrichment_jobs(home_id=HOME_ID)[0]

    with pytest.raises(IdentityEnrichmentError) as raised:
        repository.resolve_device_scoped_identity_job(
            job["job_id"],
            manufacturer="Samsung",
            device_type="fridge",
            model="RF85C90N1AP",
            source_reference="https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
            resolution_provenance="automated-official-http",
            expected_evidence_signature=job["evidence_signature"],
            expected_job_key=job["job_key"],
        )
    assert raised.value.code == "IDENTITY_BINDING_REQUIRED"
    assert repository.verified_product_catalog_entries() == []


def test_stripped_forged_self_remains_identity_candidate_in_both_repositories(repository):
    forged = {
        **_weak_device(ip="192.168.50.44", mac="AA:BB:CC:00:00:44"),
        "device_id": "self-device",
        "name": "내 휴대폰 (Unknown)",
        "services": ["self-device", "http"],
        "discovery_sources": ["self", "tcp-port-probe"],
        "fingerprints": [
            "self-android",
            "self-manufacturer:Unknown",
            "self-model:Unknown",
            "upnp-manufacturer:Samsung",
        ],
        "risk_signals": ["self_device"],
    }
    ordinary = strip_untrusted_self_claims(forged)

    scan = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[ordinary],
        home_id=HOME_ID,
    )
    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)
    snapshots = _stored_scan_snapshots(repository, scan["scan_id"])

    assert len(jobs) == 1
    assert jobs[0]["physical_mac"] == "AA:BB:CC:00:00:44"
    assert snapshots[0]["ip_address"] == "192.168.50.44"
    assert snapshots[0]["mac_address"] == "AA:BB:CC:00:00:44"
    assert is_self_observation(snapshots[0]) is False
    stored_text = json.dumps(snapshots, ensure_ascii=False).casefold()
    assert "self-device" not in stored_text
    assert "self-android" not in stored_text
    assert "내 휴대폰" not in stored_text


def test_forced_attested_self_with_ambiguous_mac_never_creates_self_job(repository):
    marked_self = bind_authenticated_self_android_claim(_self_android_device())
    assert marked_self is not None
    duplicate_mac = _weak_device(
        ip="192.168.50.20",
        mac="DA:F5:1E:FE:00:0A",
    )

    repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[marked_self, duplicate_mac],
        home_id=HOME_ID,
    )
    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)

    assert all(job["evidence"].get("model_hints") != ["SM-F956N"] for job in jobs)
    assert not any(
        proof.get("source") == "authenticated-self-android"
        for job in jobs
        for proof in job["evidence"].get("structured_provenance", [])
    )


def test_structured_evidence_accepts_safe_mdns_and_airplay_product_fields():
    evidence = structured_identity_evidence(
        {
            "fingerprints": [
                "mdns-txt:manufacturer=Samsung",
                "mdns-txt:model=RF85C90",
                "airplay-manufacturer:Apple",
                "mdns-txt:fn=private living room",
                "mdns-txt:location=bedroom",
            ]
        }
    )

    assert evidence["manufacturer_hints"] == ["Apple", "Samsung"]
    assert evidence["model_hints"] == ["RF85C90"]
    assert evidence["structured_provenance"] == [
        {"kind": "manufacturer", "source": "airplay", "value": "Apple"},
        {"kind": "manufacturer", "source": "mdns", "value": "Samsung"},
        {"kind": "model", "source": "mdns", "value": "RF85C90"},
    ]
    evidence_text = json.dumps(evidence, ensure_ascii=False)
    assert "private living room" not in evidence_text
    assert "bedroom" not in evidence_text


def test_stable_macless_binding_requires_structured_model_or_protocol_hostname():
    product_evidence = structured_identity_evidence(
        {
            "fingerprints": [
                "mdns-txt:manufacturer=Samsung",
                "mdns-txt:model=RF85C90",
            ],
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
        }
    )
    product_binding = stable_identity_evidence_signature(product_evidence)
    assert product_binding is not None
    assert product_binding.startswith("hges1-")

    apple_mac_evidence = structured_identity_evidence(
        {
            "fingerprints": [
                "mdns-txt:am=Mac15,6",
                "mdns-txt:model=Mac15,6",
            ],
            "services": ["airplay", "mdns"],
            "discovery_sources": ["mdns"],
        }
    )
    assert stable_identity_evidence_signature(apple_mac_evidence) is not None

    # An opaque internal board identifier without an independently proven
    # maker/type is an observation clue, not a stable retail-product binding.
    board_evidence = structured_identity_evidence(
        {
            "fingerprints": ["mdns-txt:model=J617AP"],
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
        }
    )
    assert stable_identity_evidence_signature(board_evidence) is None

    host_evidence = structured_identity_evidence(
        {
            "fingerprints": ["netbios-name:TESTPC-MAIN"],
            "services": ["smb", "netbios"],
            "discovery_sources": ["netbios"],
        }
    )
    assert stable_identity_evidence_signature(host_evidence) is None
    host_binding = stable_identity_evidence_signature(
        host_evidence,
        device_id="device-host-a",
    )
    assert host_binding is not None
    assert host_binding.startswith("hges1-")
    assert host_binding != stable_identity_evidence_signature(
        host_evidence,
        device_id="device-host-b",
    )
    assert "TESTPC" not in json.dumps(host_evidence, ensure_ascii=False)

    # A hostname-shaped string without a matching protocol observation and all
    # transport-only evidence remain ineligible for cross-scan binding.
    assert stable_identity_evidence_signature(
        structured_identity_evidence(
            {
                "fingerprints": ["mdns-name:TESTPC-MAIN"],
                "services": ["http"],
                "discovery_sources": ["tcp-port-probe"],
            }
        )
    ) is None
    assert stable_identity_evidence_signature(
        structured_identity_evidence(
            {
                "services": ["http"],
                "discovery_sources": ["tcp-port-probe"],
            }
        )
    ) is None


def test_strong_scope_accepts_signed_macless_structured_evidence_only():
    evidence = structured_identity_evidence(
        {
            "fingerprints": [
                "mdns-txt:manufacturer=Samsung",
                "mdns-txt:model=RF85C90",
            ],
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
        }
    )
    assert blocked_binding_reason("hgns1b-strong", None, evidence) is None
    assert blocked_binding_reason("hgns1s-weak", None, evidence) == "STRONG_SCOPE_REQUIRED"
    assert (
        blocked_binding_reason("hgns1b-strong", None, {})
        == "PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED"
    )


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_startup_creates_new_canonical_job_before_superseding_legacy_key(
    tmp_path,
    repository_kind,
):
    database_path = tmp_path / f"identity-startup-key-{repository_kind}.sqlite3"

    def open_repository():
        if repository_kind == "sqlite":
            return SQLiteRepository(db_path=str(database_path))
        return SqlAlchemyRepository(
            f"sqlite+pysqlite:///{database_path.as_posix()}"
        )

    repo = open_repository()
    _bind_test_home(repo, HOME_ID)
    scan = _scan(repo, _macless_product_device("192.168.50.91"))
    assert scan["identity_pending_count"] == 1
    original = repo.identity_enrichment_jobs(home_id=HOME_ID)[0]
    canonical_key = original["job_key"]
    assert original["status"] == "review_required"
    assert str(original["evidence_binding_signature"]).startswith("hges1-")
    legacy_key = build_identity_job_key(
        home_id=HOME_ID,
        device_id=original["device_id"],
        network_scope_id=original["network_scope_id"],
        physical_mac=None,
        evidence_binding_signature=None,
    )
    assert legacy_key != canonical_key

    if repository_kind == "sqlite":
        with repo._connect() as conn:
            conn.execute(
                "UPDATE identity_enrichment_jobs SET job_key = ?, "
                "evidence_binding_signature = NULL, status = 'blocked', "
                "blocked_reason = 'PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED' "
                "WHERE job_id = ?",
                (legacy_key, original["job_id"]),
            )
            conn.execute(
                "DELETE FROM repository_migrations WHERE migration_id = ?",
                (_SQLITE_SCHEMA_MIGRATION_ID,),
            )
    else:
        with repo.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE identity_enrichment_jobs SET job_key = :job_key, "
                    "evidence_binding_signature = NULL, status = 'blocked', "
                    "blocked_reason = 'PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED' "
                    "WHERE job_id = :job_id"
                ),
                {"job_key": legacy_key, "job_id": original["job_id"]},
            )
        repo.close()

    reopened = open_repository()
    first_reopen = reopened.identity_enrichment_jobs(home_id=HOME_ID)
    by_key = {job["job_key"]: job for job in first_reopen}
    assert set(by_key) == {canonical_key, legacy_key}
    assert by_key[canonical_key]["status"] == "review_required"
    assert by_key[canonical_key]["blocked_reason"] is None
    assert by_key[canonical_key]["seen_count"] == 1
    assert by_key[legacy_key]["status"] == "superseded"
    assert by_key[legacy_key]["blocked_reason"] == "NOT_IN_LATEST_SCAN"
    if repository_kind == "sqlalchemy":
        reopened.close()

    # Replaying the same stored scan during another process start is not a new
    # sighting and must not inflate seen_count.
    reopened_again = open_repository()
    second_reopen = {
        job["job_key"]: job
        for job in reopened_again.identity_enrichment_jobs(home_id=HOME_ID)
    }
    assert second_reopen[canonical_key]["status"] == "review_required"
    assert second_reopen[canonical_key]["seen_count"] == 1
    assert second_reopen[legacy_key]["status"] == "superseded"
    if repository_kind == "sqlalchemy":
        reopened_again.close()


def test_duplicate_physical_mac_is_not_shared_by_jobs_or_identity_history(repository):
    repeated_mac = "02:AA:BB:CC:DD:91"
    product = _macless_product_device(
        "192.168.50.92",
        mac=repeated_mac,
    )
    generic = _weak_device(
        ip="192.168.50.93",
        mac=repeated_mac,
    )
    scan = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[product, generic],
        home_id=HOME_ID,
    )
    # One physical MAC is one public endpoint. Prefer the structured Apple clue
    # while retaining both raw observations/jobs because the repeated binding
    # is ambiguous for automatic resolution.
    assert scan["identity_pending_count"] == 1
    assert scan["devices_found"] == 1
    assert len(scan["identity_findings"]) == 2
    public_cards = build_public_detected_connections(scan["identity_findings"])
    assert len(public_cards) == 1
    assert public_cards[0]["model"] == "A2991"
    assert len(scan["security_score"]["device_scores"]) == 1

    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)
    assert len(jobs) == 2
    assert len({job["device_id"] for job in jobs}) == 2
    assert len({job["job_key"] for job in jobs}) == 2
    assert all(job["physical_mac"] is None for job in jobs)
    reviewable = [job for job in jobs if job["status"] == "review_required"]
    blocked = [job for job in jobs if job["status"] == "blocked"]
    assert len(reviewable) == 1
    assert len(blocked) == 1
    assert blocked[0]["blocked_reason"] == "PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED"

    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            history_rows = conn.execute(
                "SELECT device_id, physical_mac FROM device_identity_history "
                "WHERE home_id = ? ORDER BY device_id",
                (HOME_ID,),
            ).fetchall()
    else:
        with repository.engine.begin() as conn:
            history_rows = conn.execute(
                text(
                    "SELECT device_id, physical_mac FROM device_identity_history "
                    "WHERE home_id = :home_id ORDER BY device_id"
                ),
                {"home_id": HOME_ID},
            ).mappings().all()
    assert len(history_rows) == 2
    assert all(row["physical_mac"] is None for row in history_rows)

    resolved = repository.resolve_identity_enrichment_job(
        reviewable[0]["job_id"],
        manufacturer="Apple",
        device_type="computer",
        model="A2991",
        source_reference="https://www.apple.com/mac/A2991/",
    )
    assert resolved["status"] == "resolved"
    assert len(repository.devices(home_id=HOME_ID)) == 1
    findings = repository.identity_findings(home_id=HOME_ID)
    assert len(findings) == 1
    assert findings[0]["device_id"] == blocked[0]["device_id"]


def test_unresolved_job_upsert_is_durable_and_publicly_pending(repository):
    device = _weak_device()
    first = _scan(repository, device)
    second = _scan(repository, device)

    assert first["identity_pending_count"] == 1
    assert second["identity_pending_count"] == 1
    assert first["devices_found"] == 1
    assert second["devices_found"] == 1
    assert len(build_public_detected_connections(first["identity_findings"])) == 1
    assert len(first["security_score"]["device_scores"]) == 1
    jobs = repository.identity_enrichment_jobs()
    assert len(jobs) == 1
    job = jobs[0]
    assert job["status"] == "review_required"
    assert job["seen_count"] == 2
    assert job["blocked_reason"] is None

    evidence_text = json.dumps(job["evidence"], ensure_ascii=False).casefold()
    for private_value in (
        device["ip_address"],
        device["mac_address"],
        BASE_CONTEXT["ssid"],
        BASE_CONTEXT["bssid"],
        "private-living-room.local",
        "ssdp-location",
    ):
        assert private_value.casefold() not in evidence_text
    assert job["evidence"]["manufacturer_hints"] == ["Samsung"]

    projected_text = json.dumps(
        project_identity_enrichment_job(job), ensure_ascii=False
    ).casefold()
    for private_value in (
        device["ip_address"],
        device["mac_address"],
        BASE_CONTEXT["ssid"],
        BASE_CONTEXT["bssid"],
        "private-living-room.local",
    ):
        assert private_value.casefold() not in projected_text


@pytest.mark.parametrize(
    ("context", "mac", "expected_reason"),
    (
        (
            {key: value for key, value in BASE_CONTEXT.items() if key != "bssid"},
            "AA:BB:CC:00:00:21",
            "STRONG_SCOPE_REQUIRED",
        ),
        (
            BASE_CONTEXT,
            "01:00:5E:00:00:01",
            "PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED",
        ),
    ),
)
def test_blocked_jobs_cannot_be_approved(
    repository, context: dict, mac: str, expected_reason: str
):
    _scan(repository, _weak_device(mac=mac), context=context)
    job = repository.identity_enrichment_jobs()[0]

    assert job["status"] == "blocked"
    assert job["blocked_reason"] == expected_reason
    with pytest.raises(IdentityEnrichmentError) as raised:
        _approve(repository, job["job_id"])
    assert raised.value.code == "IDENTITY_BINDING_REQUIRED"


def test_binding_validation_rejects_truthy_legacy_values():
    assert (
        blocked_binding_reason("hgns1s-not-strong", "AA:BB:CC:00:00:20")
        == "STRONG_SCOPE_REQUIRED"
    )
    assert (
        blocked_binding_reason("hgns1b-strong", "01:00:5E:00:00:01")
        == "PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED"
    )


def test_resolution_is_immediately_visible_and_next_scan_stays_consistent(repository):
    raw = _weak_device()
    first_scan = _scan(repository, raw)
    job = repository.identity_enrichment_jobs()[0]
    resolved = _approve(repository, job["job_id"])

    assert resolved["status"] == "resolved"
    assert repository.identity_findings(home_id=HOME_ID) == []
    devices = repository.devices(home_id=HOME_ID)
    assert len(devices) == 1
    assert devices[0]["model"] == "RF85C90N1AP"
    assert "RF85C90N1AP" in devices[0]["name"]

    old_result = repository.scan_result(first_scan["scan_id"], home_id=HOME_ID)
    assert old_result is not None
    assert old_result["identity_pending_count"] == 0
    assert old_result["devices"][0]["model"] == "RF85C90N1AP"
    dashboard = repository.dashboard(home_id=HOME_ID)
    assert dashboard["summary"]["identity_pending_count"] == 0
    assert dashboard["identity_findings"] == []

    next_scan = _scan(repository, raw)
    assert next_scan["identity_pending_count"] == 0
    assert next_scan["identified_count"] == 1
    assert next_scan["devices"][0]["model"] == "RF85C90N1AP"
    next_status = repository.scan_status(next_scan["scan_id"], home_id=HOME_ID)
    next_result = repository.scan_result(next_scan["scan_id"], home_id=HOME_ID)
    assert next_status is not None and next_result is not None
    assert next_status["devices_found"] == next_scan["devices_found"]
    assert next_status["high_risk_devices"] == next_scan["high_risk_devices"]
    assert next_result["identity_pending_count"] == 0
    assert next_result["high_risk_devices"] == next_scan["high_risk_devices"]
    newest_notification = repository.notifications(home_id=HOME_ID)[0]
    assert "기기 1대" in newest_notification["message"]
    assert "추가 연결" not in newest_notification["message"]


def test_macless_structured_product_fact_reuses_model_without_crossing_observation_id(
    repository,
):
    def observation(ip: str) -> dict:
        return {
            "name": "",
            "device_type": "computer",
            "manufacturer": "Apple",
            "model": "A2991",
            "ip_address": ip,
            "mac_address": f"UNKNOWN-{ip}",
            "open_ports": [5000],
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": [
                "mdns-txt:manufacturer=Apple",
                "mdns-txt:model=A2991",
            ],
            "risk_signals": [],
            "vulnerabilities": [],
        }

    first = _scan(repository, observation("192.168.50.41"))
    assert first["identified_count"] == 0
    assert first["identity_pending_count"] == 1
    job = repository.identity_enrichment_jobs()[0]
    assert job["status"] == "review_required"
    assert job["physical_mac"] is None
    assert str(job.get("evidence_binding_signature") or "").startswith("hges1-")
    assert job["blocked_reason"] is None

    resolved = repository.resolve_identity_enrichment_job(
        job["job_id"],
        manufacturer="Apple",
        device_type="computer",
        model="A2991",
        source_reference="https://www.apple.com/mac/A2991/",
    )
    assert resolved["status"] == "resolved"
    assert resolved["physical_mac"] is None
    assert resolved["evidence_binding_signature"] == job["evidence_binding_signature"]

    second = _scan(repository, observation("192.168.50.77"))
    assert second["identified_count"] == 1
    assert second["identity_pending_count"] == 0
    assert len(second["devices"]) == 1
    assert second["devices"][0]["model"] == "A2991"
    jobs = repository.identity_enrichment_jobs()
    assert len(jobs) == 1
    assert jobs[0]["status"] == "resolved"
    assert second["devices"][0]["device_id"] != job["device_id"]


def test_same_structured_model_macless_devices_share_product_fact_but_stay_distinct(
    repository,
):
    def observation(ip: str) -> dict:
        return {
            "name": "",
            "device_type": "computer",
            "manufacturer": "Apple",
            "model": "A2991",
            "ip_address": ip,
            "mac_address": f"UNKNOWN-{ip}",
            "open_ports": [5000],
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": [
                "mdns-txt:manufacturer=Apple",
                "mdns-txt:model=A2991",
            ],
            "risk_signals": [],
            "vulnerabilities": [],
        }

    first = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[
            observation("192.168.50.71"),
            observation("192.168.50.72"),
        ],
        home_id=HOME_ID,
    )
    assert first["identified_count"] == 0
    assert first["identity_pending_count"] == 2
    jobs = sorted(repository.identity_enrichment_jobs(), key=lambda item: item["device_id"])
    assert len(jobs) == 2
    assert len({job["device_id"] for job in jobs}) == 2
    assert len({job["job_key"] for job in jobs}) == 2
    # The product evidence can match while the physical observations remain
    # distinct.  One verified product fact may identify both rows, but it must
    # never merge their device IDs.
    assert len({job["evidence_binding_signature"] for job in jobs}) == 1

    target, untouched = jobs
    repository.resolve_identity_enrichment_job(
        target["job_id"],
        manufacturer="Apple",
        device_type="computer",
        model="A2991",
        source_reference="https://www.apple.com/mac/A2991/",
    )
    after = {job["device_id"]: job for job in repository.identity_enrichment_jobs()}
    assert after[target["device_id"]]["status"] == "resolved"
    # Queue reconciliation changes the sibling job to resolved once the same
    # signed maker/model/type fact is available locally.
    assert after[untouched["device_id"]]["status"] == "resolved"
    devices = repository.devices(home_id=HOME_ID)
    assert len(devices) == 2
    assert len({device["device_id"] for device in devices}) == 2
    assert {device["model"] for device in devices} == {"A2991"}
    assert repository.identity_findings(home_id=HOME_ID) == []


def test_same_hostname_macless_computers_keep_separate_jobs_and_resolution(repository):
    def computer(ip: str) -> dict:
        return {
            "name": "DESKTOP-SHARED",
            "device_type": "computer",
            "manufacturer": "",
            "model": "",
            "ip_address": ip,
            "mac_address": f"UNKNOWN-{ip}",
            "open_ports": [139, 445],
            "services": ["smb", "netbios"],
            "discovery_sources": ["netbios"],
            "fingerprints": ["netbios-name:DESKTOP-SHARED"],
            "risk_signals": [],
            "vulnerabilities": [],
        }

    first = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[
            computer("192.168.50.61"),
            computer("192.168.50.62"),
        ],
        home_id=HOME_ID,
    )
    assert first["identified_count"] == 0
    assert first["identity_pending_count"] == 2
    jobs = sorted(repository.identity_enrichment_jobs(), key=lambda item: item["device_id"])
    assert len(jobs) == 2
    assert len({job["device_id"] for job in jobs}) == 2
    assert len({job["job_key"] for job in jobs}) == 2
    assert len({job["evidence_binding_signature"] for job in jobs}) == 2
    assert all(job["status"] == "review_required" for job in jobs)

    target, untouched = jobs
    repository.resolve_identity_enrichment_job(
        target["job_id"],
        manufacturer="Apple",
        device_type="computer",
        model="A2991",
        source_reference="https://www.apple.com/mac/A2991/",
    )

    after = {job["device_id"]: job for job in repository.identity_enrichment_jobs()}
    assert after[target["device_id"]]["status"] == "resolved"
    assert after[untouched["device_id"]]["status"] == "review_required"
    assert len(repository.devices(home_id=HOME_ID)) == 1
    findings = repository.identity_findings(home_id=HOME_ID)
    assert len(findings) == 1
    assert findings[0]["device_id"] == untouched["device_id"]


def test_public_projection_keeps_tcp_private_but_projects_fresh_neighbor(repository):
    scan = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[
            {
                "name": "",
                "device_type": "unknown",
                "ip_address": "192.168.50.81",
                "mac_address": "UNKNOWN-192.168.50.81",
                "open_ports": [49153],
                "services": ["tcp-49153"],
                "discovery_sources": ["server-tcp-probe"],
                "fingerprints": [],
                "risk_signals": [],
            },
            {
                "name": "",
                "device_type": "unknown",
                "ip_address": "192.168.50.82",
                "mac_address": "02:10:20:30:40:50",
                "open_ports": [],
                "services": [],
                "discovery_sources": ["android-neighbor"],
                "fingerprints": [],
                "risk_signals": [],
            },
        ],
        home_id=HOME_ID,
    )

    projected = main_module._apply_public_identity_contract(scan)
    assert projected["identified_count"] == 0
    assert projected["identity_pending_count"] == 1
    assert projected["devices_found"] == 1
    assert len(projected["detected_connections"]) == 1
    assert projected["detected_connections"][0]["device_id"] == scan["identity_findings"][1]["device_id"]
    assert len(projected["security_score"]["device_scores"]) == 1
    assert "TCP 서비스 응답" not in str(projected)
    assert "현재 Wi-Fi 이웃 확인" not in str(projected)


def test_public_projection_drops_legacy_arp_only_count_without_freshness(repository):
    scan = repository.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[
            {
                "name": "",
                "device_type": "unknown",
                "ip_address": "192.168.50.83",
                "mac_address": "02:10:20:30:40:51",
                "open_ports": [],
                "services": [],
                "discovery_sources": ["android-arp"],
                "fingerprints": [],
                "risk_signals": [],
            }
        ],
        home_id=HOME_ID,
    )
    # Legacy ARP rows do not carry freshness proof, so they are rejected at the
    # repository boundary as well as at the public projection boundary.
    assert scan["devices_found"] == 0
    assert scan["identity_pending_count"] == 0

    projected = main_module._apply_public_identity_contract(scan)
    assert projected["detected_connections"] == []
    assert projected["identity_pending_count"] == 0
    assert projected["devices_found"] == 0
    notification = repository.notifications(home_id=HOME_ID)[0]
    assert "기기 1대" not in notification["message"]


def test_resolution_job_and_history_write_roll_back_together(repository):
    _scan(repository, _weak_device())
    job = repository.identity_enrichment_jobs()[0]
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                """
                CREATE TRIGGER reject_identity_history_insert
                BEFORE INSERT ON device_identity_history
                BEGIN
                    SELECT RAISE(ABORT, 'forced history failure');
                END
                """
            )
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TRIGGER reject_identity_history_insert
                    BEFORE INSERT ON device_identity_history
                    BEGIN
                        SELECT RAISE(ABORT, 'forced history failure');
                    END
                    """
                )
            )

    with pytest.raises((sqlite3.IntegrityError, SqlAlchemyIntegrityError)):
        _approve(repository, job["job_id"])
    after = repository.identity_enrichment_jobs()[0]
    assert after["status"] == "review_required"
    assert after["resolution"] is None


def test_approval_isolated_by_physical_mac_and_bssid(repository):
    original = _weak_device()
    _scan(repository, original)
    _approve(repository, repository.identity_enrichment_jobs()[0]["job_id"])

    different_mac = _weak_device(mac="AC:BB:CC:00:00:20")
    second = _scan(repository, different_mac)
    assert second["identified_count"] == 0
    assert second["identity_pending_count"] == 1
    assert second["devices_found"] == 1
    assert len(second["security_score"]["device_scores"]) == 1
    assert all(
        item.get("model") != "RF85C90N1AP"
        for item in (repository._latest_scan_devices_only(HOME_ID) or [])
    )

    other_ap = {**BASE_CONTEXT, "bssid": "10:20:30:40:50:61"}
    third = _scan(repository, original, context=other_ap)
    assert third["identified_count"] == 0
    assert third["identity_pending_count"] == 1
    assert third["devices_found"] == 1
    assert len(third["security_score"]["device_scores"]) == 1
    assert all(
        item.get("model") != "RF85C90N1AP"
        for item in (repository._latest_scan_devices_only(HOME_ID) or [])
    )
    jobs = repository.identity_enrichment_jobs()
    assert len(jobs) == 3
    assert sum(job["status"] == "resolved" for job in jobs) == 1


@pytest.mark.parametrize(
    ("manufacturer", "device_type", "model", "source_reference"),
    (
        ("Samsung", "fridge", "Family Hub", "https://www.samsung.com/sec/support/"),
        ("Samsung", "fridge", "Living Room", "https://www.samsung.com/sec/support/"),
        ("LG", "fridge", "RF85C90N1AP", "https://www.lge.co.kr/support/product/"),
        ("Samsung", "router", "RF85C90N1AP", "https://www.samsung.com/sec/support/"),
        ("Samsung", "fridge", "RF85C90N1AP", "https://www.lge.co.kr/support/product/"),
        ("Samsung", "fridge", "RF85C90N1AP", "https://example.com/products/RF85C90N1AP"),
    ),
)
def test_generic_family_and_conflicting_resolutions_are_rejected(
    repository,
    manufacturer: str,
    device_type: str,
    model: str,
    source_reference: str,
):
    _scan(repository, _weak_device())
    job = repository.identity_enrichment_jobs()[0]
    with pytest.raises(IdentityEnrichmentError) as raised:
        repository.resolve_identity_enrichment_job(
            job["job_id"],
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=source_reference,
        )
    assert raised.value.code == "IDENTITY_MODEL_NOT_SPECIFIC"
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"


@pytest.mark.parametrize(
    ("manufacturer", "device_type", "model", "source_reference"),
    (
        (
            "Samsung",
            "fridge",
            "RF85C90N1AP",
            "https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
        ),
        ("LG", "tv", "OLED55C4", "https://www.lge.co.kr/tvs/OLED55C4"),
        ("KT", "router", "KM08-708H", "https://product.kt.com/router/KM08-708H"),
        (
            "EFM Networks",
            "router",
            "A3004NS-M",
            "https://iptime.com/iptime/products/A3004NS-M",
        ),
        ("Sonos", "speaker", "Arc", "https://www.sonos.com/shop/arc"),
    ),
)
def test_specific_models_require_matching_official_manufacturer_sources(
    manufacturer: str,
    device_type: str,
    model: str,
    source_reference: str,
):
    resolved = validate_identity_resolution(
        manufacturer=manufacturer,
        device_type=device_type,
        model=model,
        source_reference=source_reference,
    )
    assert resolved["model"] == model
    assert resolved["source_reference"] == source_reference


def test_legacy_false_resolved_snapshot_does_not_reappear(repository):
    first = _scan(repository, _weak_device())
    snapshots = repository._latest_scan_devices_only(HOME_ID)
    assert snapshots
    false_manual = {
        **snapshots[0],
        "name": "Living Room",
        "manufacturer": "Samsung",
        "device_type": "fridge",
        "model": "Family",
        "canonical_name": "Living Room",
        "identity_status": "manual_resolved",
        "identity_confidence": 1.0,
        "is_resolved": True,
        "is_unresolved": False,
    }
    _replace_scan_snapshot(repository, first["scan_id"], false_manual)

    second = _scan(repository, _weak_device())
    assert second["identified_count"] == 0
    assert second["identity_pending_count"] == 1
    assert second["devices_found"] == 1
    assert len(second["security_score"]["device_scores"]) == 1
    current_text = json.dumps(
        repository._latest_observed_scan_devices(HOME_ID), ensure_ascii=False
    )
    assert "Living Room" not in current_text
    assert '"Family"' not in current_text


def test_internal_api_requires_local_secret_and_returns_private_dto(
    repository, monkeypatch
):
    raw = _weak_device()
    _scan(repository, raw)
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setenv("HG_IDENTITY_REVIEW_SECRET", REVIEW_SECRET)
    headers = {IDENTITY_REVIEW_HEADER: REVIEW_SECRET}

    remote = TestClient(app, client=("198.51.100.8", 50000))
    response = remote.get(
        "/api/v1/internal/identity-enrichment/jobs", headers=headers
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "IDENTITY_REVIEW_LOCAL_ONLY"
    response = remote.post(
        "/api/v1/internal/identity-enrichment/jobs/not-a-job/resolve",
        headers={**headers, "Content-Type": "application/json"},
        content="{",
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "IDENTITY_REVIEW_LOCAL_ONLY"

    local = TestClient(app, client=("127.0.0.1", 50000))
    response = local.get(
        "/api/v1/internal/identity-enrichment/jobs",
        headers={**headers, "X-Real-IP": "198.51.100.8"},
    )
    assert response.status_code == 403
    response = local.get(
        "/api/v1/internal/identity-enrichment/jobs",
        headers={**headers, "X-Forwarded-For": "127.0.0.1, 198.51.100.8"},
    )
    assert response.status_code == 403
    response = local.get(
        "/api/v1/internal/identity-enrichment/jobs",
        headers={IDENTITY_REVIEW_HEADER: "wrong-secret-value"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "IDENTITY_REVIEW_DISABLED"
    response = local.post(
        "/api/v1/internal/identity-enrichment/jobs/not-a-job/resolve",
        headers={**headers, "Content-Type": "application/json"},
        content="{",
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_MODEL_NOT_SPECIFIC"

    response = local.get(
        "/api/v1/internal/identity-enrichment/jobs", headers=headers
    )
    assert response.status_code == 200
    job = response.json()["data"]["jobs"][0]
    public_text = json.dumps(response.json(), ensure_ascii=False).casefold()
    for private_value in (
        raw["ip_address"],
        raw["mac_address"],
        BASE_CONTEXT["ssid"],
        BASE_CONTEXT["bssid"],
        "private-living-room.local",
        REVIEW_SECRET,
    ):
        assert private_value.casefold() not in public_text

    response = local.post(
        f"/api/v1/internal/identity-enrichment/jobs/{job['job_id']}/resolve",
        headers=headers,
        json={
            "manufacturer": "Samsung",
            "device_type": "fridge",
            "model": "RF85C90N1AP",
            "source_reference": "https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
        },
    )
    assert response.status_code == 200
    assert response.json()["data"]["resolution"]["model"] == "RF85C90N1AP"
    assert raw["mac_address"] not in json.dumps(response.json(), ensure_ascii=False)

    response = local.post(
        f"/api/v1/internal/identity-enrichment/jobs/{job['job_id']}/resolve",
        headers=headers,
        json={
            "manufacturer": "Samsung",
            "device_type": "fridge",
            "model": "RF85C90N1AP",
            "source_reference": "https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDENTITY_JOB_ALREADY_RESOLVED"

    _scan(repository, _weak_device(mac="AC:BB:CC:00:00:22"))
    pending_job = next(
        item
        for item in repository.identity_enrichment_jobs()
        if item["status"] == "review_required"
    )
    response = local.post(
        f"/api/v1/internal/identity-enrichment/jobs/{pending_job['job_id']}/reject",
        headers=headers,
        json={"reason": "INSUFFICIENT_EVIDENCE"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "rejected"

    monkeypatch.setenv("HG_IDENTITY_REVIEW_SECRET", "too-short")
    response = local.get(
        "/api/v1/internal/identity-enrichment/jobs",
        headers={IDENTITY_REVIEW_HEADER: "too-short"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "IDENTITY_REVIEW_DISABLED"


def test_postgres_schema_declares_enrichment_constraints_and_indexes():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "storage"
        / "postgres_schema.sql"
    )
    schema = schema_path.read_text(encoding="utf-8")
    jobs_marker = "CREATE TABLE IF NOT EXISTS identity_enrichment_jobs ("
    jobs_start = schema.index(jobs_marker)
    jobs_end = schema.index(
        "\n);\n\nALTER TABLE identity_enrichment_jobs",
        jobs_start,
    )
    jobs_create = schema[jobs_start:jobs_end]
    history_start = schema.index("CREATE TABLE IF NOT EXISTS device_identity_history (")
    history_end = schema.index(
        "\n);\n\nALTER TABLE device_identity_history",
        history_start,
    )
    history_create = schema[history_start:history_end]

    assert jobs_marker in jobs_create
    assert "REFERENCES homes(home_id) ON DELETE CASCADE" in schema
    assert "idx_identity_enrichment_jobs_status_updated" in schema
    assert "idx_identity_enrichment_jobs_home_status_seen" in schema
    assert "seen_count >= 1" in schema
    assert "physical_mac TEXT,\n    evidence_binding_signature TEXT," in jobs_create
    assert "evidence_binding_signature" not in history_create
    assert "ADD COLUMN IF NOT EXISTS evidence_binding_signature TEXT" in schema
    assert "(physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL)" in jobs_create
    quarantine_at = schema.index("UPDATE identity_enrichment_jobs\nSET status = 'review_required'")
    constraint_at = schema.index("ADD CONSTRAINT ck_identity_enrichment_jobs_resolved_binding")
    assert quarantine_at < constraint_at


def test_repository_enforces_job_home_foreign_key(repository):
    statement = """
        INSERT INTO identity_enrichment_jobs (
            job_id, job_key, home_id, device_id, status, evidence_json,
            evidence_signature, seen_count, first_seen_at, last_seen_at, updated_at
        ) VALUES ('job', 'key', 'missing-home', 'device', 'blocked', '{}', 'sig', 1, 't', 't', 't')
    """
    if isinstance(repository, SQLiteRepository):
        with pytest.raises(sqlite3.IntegrityError), repository._connect() as conn:
            conn.execute(statement)
        return
    with pytest.raises(SqlAlchemyIntegrityError), repository.engine.begin() as conn:
        conn.execute(text(statement))
