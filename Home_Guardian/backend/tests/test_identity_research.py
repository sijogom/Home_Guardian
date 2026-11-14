from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Mapping

import pytest
from sqlalchemy import text

import app.main as main_module
from app.main import _apply_public_identity_contract
from app.services.identity_enrichment import (
    build_evidence_signature,
    source_matches_registered_official_domain,
    structured_identity_evidence,
)
from app.services.identity_research import (
    IdentityResearchFailure,
    identity_research_readiness,
    research_pending_identities,
)
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.sqlite_repository import SQLiteRepository, _SQLITE_SCHEMA_MIGRATION_ID
from conftest import bind_repository_home


HOME_ID = "home-identity-research"
CONTEXT = {
    "ssid": "Private Research Wi-Fi",
    "bssid": "10:20:30:40:60:70",
    "local_ip": "192.168.60.10",
    "gateway_ip": "192.168.60.1",
    "subnet_cidr": "192.168.60.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}
OFFICIAL_URL = "https://www.samsung.com/sec/refrigerators/RF85C90N1AP/"


@pytest.fixture(params=("sqlite", "sqlalchemy"))
def repository(request, tmp_path):
    if request.param == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "research.sqlite3"))
    else:
        repo = SqlAlchemyRepository(
            f"sqlite+pysqlite:///{(tmp_path / 'research-sa.sqlite3').as_posix()}"
        )
    bind_repository_home(repo, HOME_ID)
    try:
        yield repo
    finally:
        close = getattr(repo, "close", None)
        if close:
            close()


def _device(
    *,
    model: str = "RF85C90N1AP",
    ip: str = "192.168.60.20",
    mac: str = "AA:BB:CC:00:60:20",
) -> dict[str, Any]:
    return {
        "device_id": "private-device-id-never-send",
        "name": "private-kitchen-host.local",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http", "upnp"],
        "discovery_sources": ["tcp-port-probe", "upnp"],
        "fingerprints": [
            "upnp-manufacturer:Samsung",
            f"ssdp-location:http://{ip}:80/device.xml",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _scan(
    repository,
    devices: list[dict[str, Any]] | None = None,
    *,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return repository.create_scan(
        scan_source="android-native",
        network_context=dict(context or CONTEXT),
        discovered_devices=devices or [_device()],
        home_id=HOME_ID,
    )


def _make_job_researchable(
    repository,
    job: Mapping[str, Any],
    *,
    model: str = "RF85C90N1AP",
    manufacturer: str = "Samsung",
    device_type: str = "fridge",
    structured_provenance: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    evidence = {
        "manufacturer_hints": [manufacturer],
        "model_hints": [model],
        "device_type_hints": [device_type],
        "service_hints": ["http", "upnp"],
        "structured_provenance": structured_provenance
        or [
            {"kind": "manufacturer", "source": "upnp", "value": manufacturer},
            {"kind": "model", "source": "upnp", "value": model},
            {"kind": "model", "source": "spotify", "value": model},
        ],
    }
    evidence_json = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    evidence_signature = build_evidence_signature(evidence)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE identity_enrichment_jobs SET evidence_json = ?, evidence_signature = ? "
                "WHERE job_id = ? AND status = 'review_required'",
                (evidence_json, evidence_signature, job["job_id"]),
            )
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE identity_enrichment_jobs "
                    "SET evidence_json = :evidence_json, evidence_signature = :signature "
                    "WHERE job_id = :job_id AND status = 'review_required'"
                ),
                {
                    "evidence_json": evidence_json,
                    "signature": evidence_signature,
                    "job_id": job["job_id"],
                },
            )
    return next(
        item
        for item in repository.identity_enrichment_jobs()
        if item["job_id"] == job["job_id"]
    )


def _update_job_column(repository, job_id: str, column: str, value: object) -> None:
    allowed = {
        "evidence_json",
        "evidence_signature",
        "job_key",
        "physical_mac",
        "status",
        "resolution_json",
        "source_reference",
        "resolution_provenance",
        "resolution_signature",
    }
    assert column in allowed
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                f"UPDATE identity_enrichment_jobs SET {column} = ? WHERE job_id = ?",
                (value, job_id),
            )
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    f"UPDATE identity_enrichment_jobs SET {column} = :value "
                    "WHERE job_id = :job_id"
                ),
                {"value": value, "job_id": job_id},
            )


def _response(results: list[dict[str, Any]], citations: list[str]) -> dict[str, Any]:
    output_text = json.dumps(
        {"results": results},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    annotations: list[dict[str, Any]] = []
    search_cursor = 0
    for url in citations:
        url_token = json.dumps(url, ensure_ascii=False)
        start_index = output_text.find(url_token, search_cursor)
        if start_index < 0:
            start_index, end_index = 0, 1
            title = "official product page"
        else:
            end_index = start_index + len(url_token)
            search_cursor = end_index
            matching_result = next(
                (
                    result
                    for result in results
                    if result.get("official_source_url") == url
                    and start_index
                    <= output_text.find(
                        json.dumps(result, ensure_ascii=False, separators=(",", ":"))
                    )
                    + len(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
                ),
                None,
            )
            title = (
                f"official product {matching_result.get('model')}"
                if matching_result is not None
                else "official product page"
            )
        annotations.append(
            {
                "type": "url_citation",
                "url": url,
                "title": title,
                "start_index": start_index,
                "end_index": end_index,
            }
        )
    return {
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": [
                    {
                        "type": "output_text",
                        "text": output_text,
                        "annotations": annotations,
                    }
                ],
            }
        ],
    }


def _matching_result(job_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "manufacturer": "Samsung",
        "device_type": "fridge",
        "model": "RF85C90N1AP",
        "official_source_url": OFFICIAL_URL,
        "matched": True,
        **overrides,
    }


def _enabled_config() -> dict[str, str]:
    return {
        "HG_IDENTITY_RESEARCH_ENABLED": "1",
        "OPENAI_API_KEY": "sk-test-key-never-sent-to-network-0000",
        "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
    }


def test_missing_config_is_fail_closed_without_transport(repository):
    scan = _scan(repository)
    _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    called = False

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ={},
    )

    assert called is False
    assert outcome.enabled is False
    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"
    assert scan["status"] == "completed"
    # A fresh L2 observation with a concrete physical MAC remains a public
    # endpoint even when optional AI research is not configured.
    assert scan["devices_found"] == 1
    assert scan["identity_pending_count"] == 1
    assert len(scan["identity_findings"]) == 1
    assert scan["security_score"]["scan_complete"] is True
    assert scan["security_score"]["coverage_complete"] is True
    assert scan["security_score"]["score"] == 88
    assert scan["security_score"]["score_status"] == "final"
    assert len(repository.notifications(home_id=HOME_ID)) == 1


def test_latest_authoritative_scan_supersedes_stale_identity_jobs(repository):
    first_scan = _scan(repository)
    first_jobs = repository.identity_enrichment_jobs()
    assert first_jobs
    assert first_jobs[0]["status"] in {"review_required", "blocked"}

    latest_scan = repository.create_scan(
        scan_source="android-native",
        network_context=dict(CONTEXT),
        discovered_devices=[],
        home_id=HOME_ID,
    )

    jobs = repository.identity_enrichment_jobs()
    stale = next(item for item in jobs if item["job_id"] == first_jobs[0]["job_id"])
    assert stale["status"] == "superseded"
    assert stale["blocked_reason"] == "NOT_IN_LATEST_SCAN"
    assert stale["research_next_attempt_at"] is None
    assert latest_scan["scan_id"] != first_scan["scan_id"]
    assert latest_scan["identity_pending_count"] == 0
    assert latest_scan["status"] == "completed"


def test_repository_reopen_reconciles_stale_active_identity_jobs(repository):
    _scan(repository)
    job = repository.identity_enrichment_jobs()[0]
    repository.create_scan(
        scan_source="android-native",
        network_context=dict(CONTEXT),
        discovered_devices=[],
        home_id=HOME_ID,
    )

    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE identity_enrichment_jobs SET status = 'review_required', "
                "blocked_reason = NULL WHERE job_id = ?",
                (job["job_id"],),
            )
            conn.execute(
                "DELETE FROM repository_migrations WHERE migration_id = ?",
                (_SQLITE_SCHEMA_MIGRATION_ID,),
            )
        reopened = SQLiteRepository(db_path=repository.db_path)
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE identity_enrichment_jobs SET status = 'review_required', "
                    "blocked_reason = NULL WHERE job_id = :job_id"
                ),
                {"job_id": job["job_id"]},
            )
        reopened = SqlAlchemyRepository(repository.database_url)

    try:
        stale = next(
            item
            for item in reopened.identity_enrichment_jobs()
            if item["job_id"] == job["job_id"]
        )
        assert stale["status"] == "superseded"
        assert stale["blocked_reason"] == "NOT_IN_LATEST_SCAN"
        assert stale["research_next_attempt_at"] is None
    finally:
        close = getattr(reopened, "close", None)
        if close:
            close()


def test_repository_reopen_skips_newer_invalid_android_scan_for_job_reconciliation(
    repository,
):
    _scan(repository)
    before = repository.identity_enrichment_jobs()[0]
    invalid_context = {
        "ssid": "AndroidWifi",
        "bssid": "02:00:00:00:00:00",
        "local_ip": "10.0.2.15",
        "gateway_ip": "10.0.2.2",
        "subnet_cidr": "10.0.2.0/24",
        "is_private_network": True,
        "interface_type": "wifi",
        "is_emulator": True,
    }
    invalid_score = json.dumps(
        {
            "score": 100,
            "risk_level": "green",
            "scan_complete": True,
            "coverage_complete": True,
        },
        ensure_ascii=False,
    )
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, home_id, status, progress, scan_profile, scan_source,
                    network_context_json, network_scope_id, current_step,
                    devices_found, high_risk_devices, security_score_json, created_at
                ) VALUES (?, ?, 'completed', 100, 'quick', 'android-native', ?, NULL,
                          '점검 완료', 0, 0, ?, '9999-12-31T23:59:59Z')
                """,
                (
                    "invalid-emulator-newest",
                    HOME_ID,
                    json.dumps(invalid_context, ensure_ascii=False),
                    invalid_score,
                ),
            )
        reopened = SQLiteRepository(db_path=repository.db_path)
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO scans (
                        scan_id, home_id, status, progress, scan_profile, scan_source,
                        network_context_json, network_scope_id, current_step,
                        devices_found, high_risk_devices, security_score_json, created_at
                    ) VALUES (
                        'invalid-emulator-newest', :home_id, 'completed', 100,
                        'quick', 'android-native', :context, NULL, '점검 완료',
                        0, 0, :score, '9999-12-31T23:59:59Z'
                    )
                    """
                ),
                {
                    "home_id": HOME_ID,
                    "context": json.dumps(invalid_context, ensure_ascii=False),
                    "score": invalid_score,
                },
            )
        reopened = SqlAlchemyRepository(repository.database_url)

    try:
        after = next(
            item
            for item in reopened.identity_enrichment_jobs()
            if item["job_id"] == before["job_id"]
        )
        assert after["status"] == before["status"]
        assert after["blocked_reason"] == before["blocked_reason"]
        assert after["seen_count"] == before["seen_count"]
        assert after["evidence_signature"] == before["evidence_signature"]
        assert after["research_next_attempt_at"] == before["research_next_attempt_at"]
    finally:
        close = getattr(reopened, "close", None)
        if close:
            close()


@pytest.mark.parametrize(
    "broken_config",
    (
        {"OPENAI_API_KEY": ""},
        {"OPENAI_API_KEY": "sk-too-short"},
        {"HG_IDENTITY_RESEARCH_MODEL": ""},
        {"HG_IDENTITY_RESEARCH_MODEL": "../unsafe/model"},
    ),
)
def test_health_stays_ready_when_optional_research_config_is_invalid(
    monkeypatch,
    broken_config,
):
    config = _enabled_config()
    config.update(broken_config)
    ready, code = identity_research_readiness(config)
    assert ready is False
    assert code != "ready"

    for key, value in config.items():
        monkeypatch.setenv(key, value)
    response = main_module.health()
    assert response["data"]["status"] == "healthy"


def test_health_stays_ready_when_optional_external_research_is_disabled(monkeypatch):
    for key in ("HG_IDENTITY_RESEARCH_ENABLED", "OPENAI_API_KEY", "HG_IDENTITY_RESEARCH_MODEL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HG_IDENTITY_RESEARCH_ENABLED", "0")

    ready, code = identity_research_readiness()
    assert (ready, code) == (False, "disabled")
    response = main_module.health()
    assert response["data"]["status"] == "healthy"


def test_health_is_ready_only_with_explicit_safe_research_config(monkeypatch):
    for key, value in _enabled_config().items():
        monkeypatch.setenv(key, value)
    ready, code = identity_research_readiness()
    assert (ready, code) == (True, "ready")
    response = main_module.health()
    assert response["data"]["status"] == "healthy"


def test_two_independent_model_sources_use_privacy_safe_payload_and_exact_official_match(repository):
    raw = _device()
    _scan(repository, [raw])
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    captured: dict[str, Any] = {}

    def transport(**kwargs: Any) -> Mapping[str, Any]:
        captured.update(kwargs)
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    assert outcome.resolved_count == 1
    assert outcome.pending_count == 0
    assert captured["url"] == "https://api.openai.com/v1/responses"
    assert captured["timeout_seconds"] <= 5
    payload = captured["payload"]
    assert payload["store"] is False
    assert payload["tools"] == [{"type": "web_search"}]
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    prompt_text = str(payload["input"])
    assert job["job_id"] in prompt_text
    assert "RF85C90N1AP" in prompt_text
    for private_value in (
        raw["device_id"],
        raw["ip_address"],
        raw["mac_address"],
        raw["name"],
        HOME_ID,
        CONTEXT["ssid"],
        CONTEXT["bssid"],
        "subnet_cidr",
        "discovery_sources",
    ):
        assert str(private_value).casefold() not in prompt_text.casefold()
    assert _enabled_config()["OPENAI_API_KEY"] not in prompt_text

    resolved = repository.identity_enrichment_jobs()[0]
    assert resolved["status"] == "resolved"
    assert resolved["resolution_provenance"] == "automated-official-web-search"
    assert resolved["resolution"]["resolution_provenance"] == "automated-official-web-search"
    history = repository.identity_history(device_id=resolved["device_id"], home_id=HOME_ID)
    assert "official-source:automated-official-web-search" in history[0]["identity_evidence"]
    devices = repository.devices(home_id=HOME_ID)
    assert len(devices) == 1
    assert devices[0]["model"] == "RF85C90N1AP"


def test_single_self_advertised_valid_model_is_not_sent_or_auto_resolved(repository):
    _scan(repository)
    job = _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        structured_provenance=[
            {"kind": "manufacturer", "source": "upnp", "value": "Samsung"},
            {"kind": "model", "source": "upnp", "value": "RF85C90N1AP"},
        ],
    )
    called = False

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert called is False
    assert outcome.eligible_count == 0
    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"
    assert repository.devices(home_id=HOME_ID) == []


def test_single_model_plus_matching_oui_and_independent_type_can_resolve(repository):
    _scan(repository)
    job = _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        structured_provenance=[
            {
                "kind": "manufacturer",
                "source": "physical-mac-oui",
                "value": "Samsung",
            },
            {"kind": "model", "source": "upnp", "value": "RF85C90N1AP"},
            {"kind": "device_type", "source": "mdns", "value": "fridge"},
        ],
    )

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=lambda **_: _response(
            [_matching_result(job["job_id"])], [OFFICIAL_URL]
        ),
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 1
    assert repository.devices(home_id=HOME_ID)[0]["model"] == "RF85C90N1AP"


def test_conflicting_physical_oui_blocks_even_two_advertised_model_sources(repository):
    _scan(repository)
    _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        structured_provenance=[
            {
                "kind": "manufacturer",
                "source": "physical-mac-oui",
                "value": "LG",
            },
            {"kind": "manufacturer", "source": "upnp", "value": "Samsung"},
            {"kind": "model", "source": "upnp", "value": "RF85C90N1AP"},
            {"kind": "model", "source": "spotify", "value": "RF85C90N1AP"},
        ],
    )
    called = False

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        return _response([], [])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert called is False
    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"


def test_structured_evidence_excludes_top_level_identity_and_keeps_source_provenance():
    evidence = structured_identity_evidence(
        {
            "manufacturer": "Samsung",
            "model": "RF85C90N1AP",
            "device_type": "fridge",
            "mac_address": "00:E0:64:00:00:01",
            "fingerprints": [
                "upnp-manufacturer:Samsung",
                "upnp-model:RF85C90N1AP",
                "spotify-model:RF85C90N1AP",
            ],
            "services": ["upnp"],
        }
    )
    assert evidence["model_hints"] == ["RF85C90N1AP"]
    assert {
        (proof["kind"], proof["source"], proof["value"])
        for proof in evidence["structured_provenance"]
    } >= {
        ("manufacturer", "physical-mac-oui", "Samsung"),
        ("model", "upnp", "RF85C90N1AP"),
        ("model", "spotify", "RF85C90N1AP"),
    }
    raw_only = structured_identity_evidence(
        {
            "manufacturer": "Samsung",
            "model": "RF85C90N1AP",
            "device_type": "fridge",
        }
    )
    assert raw_only == {}


@pytest.mark.parametrize(
    "tamper",
    ("evidence", "evidence_signature", "binding", "job_key"),
)
def test_tampered_persisted_job_is_never_sent_outbound(repository, tamper):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    if tamper == "evidence":
        _update_job_column(
            repository,
            job["job_id"],
            "evidence_json",
            json.dumps({**job["evidence"], "service_hints": ["tampered"]}),
        )
    elif tamper == "evidence_signature":
        _update_job_column(repository, job["job_id"], "evidence_signature", "c" * 64)
    elif tamper == "binding":
        _update_job_column(repository, job["job_id"], "physical_mac", "AA:BB:CC:00:60:99")
    else:
        _update_job_column(repository, job["job_id"], "job_key", "b" * 64)
    called = False

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("tampered job must not leave the server")

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert called is False
    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"


@pytest.mark.parametrize("inflight_change", ("evidence", "job_key", "status"))
def test_inflight_change_fails_resolution_cas(repository, inflight_change):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        if inflight_change == "evidence":
            changed = {**job["evidence"], "service_hints": ["https"]}
            _update_job_column(
                repository,
                job["job_id"],
                "evidence_json",
                json.dumps(changed, ensure_ascii=False, sort_keys=True),
            )
            _update_job_column(
                repository,
                job["job_id"],
                "evidence_signature",
                build_evidence_signature(changed),
            )
        elif inflight_change == "job_key":
            _update_job_column(repository, job["job_id"], "job_key", "a" * 64)
        else:
            _update_job_column(repository, job["job_id"], "status", "rejected")
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.attempted_count == 1
    assert outcome.resolved_count == 0
    assert repository.devices(home_id=HOME_ID) == []


@pytest.mark.parametrize(
    ("result_overrides", "citations"),
    (
        ({}, []),
        ({}, ["https://example.com/spoofed-citation"]),
        (
            {"official_source_url": "https://example.com/RF85C90N1AP"},
            ["https://example.com/RF85C90N1AP"],
        ),
        (
            {"official_source_url": "https://www.samsung.com:8443/sec/RF85C90N1AP"},
            ["https://www.samsung.com:8443/sec/RF85C90N1AP"],
        ),
        ({"model": "RF85C90N1AX"}, [OFFICIAL_URL]),
        ({"manufacturer": "LG"}, [OFFICIAL_URL]),
        ({"device_type": "router"}, [OFFICIAL_URL]),
    ),
)
def test_citation_spoof_unrelated_domain_and_hint_conflicts_never_resolve(
    repository,
    result_overrides: dict[str, Any],
    citations: list[str],
):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response([_matching_result(job["job_id"], **result_overrides)], citations)

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"
    assert repository.devices(home_id=HOME_ID) == []


def test_one_citation_resolves_one_ai_result_then_signed_catalog_closes_sibling(repository):
    _scan(
        repository,
        [
            _device(ip="192.168.60.20", mac="AA:BB:CC:00:60:20"),
            _device(ip="192.168.60.21", mac="AA:BB:CC:00:60:21"),
        ],
    )
    jobs = [
        _make_job_researchable(repository, job)
        for job in repository.identity_enrichment_jobs()
    ]

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response(
            [_matching_result(job["job_id"]) for job in jobs],
            [OFFICIAL_URL],
        )

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 1
    stored = repository.identity_enrichment_jobs()
    assert {job["status"] for job in stored} == {"resolved"}
    assert sum(bool((job.get("resolution") or {}).get("catalog_reused")) for job in stored) == 1


def test_annotation_outside_source_literal_never_resolves(repository):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    result = _matching_result(job["job_id"])

    def transport(**_: Any) -> Mapping[str, Any]:
        response = _response([result], [OFFICIAL_URL])
        content = response["output"][0]["content"][0]
        model_token = json.dumps("RF85C90N1AP")
        model_start = content["text"].find(model_token)
        content["annotations"][0]["start_index"] = model_start
        content["annotations"][0]["end_index"] = model_start + len(model_token)
        return response

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 0
    assert repository.devices(home_id=HOME_ID) == []


def test_partial_source_literal_annotation_never_resolves(repository):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        response = _response([_matching_result(job["job_id"])], [OFFICIAL_URL])
        response["output"][0]["content"][0]["annotations"][0]["start_index"] += 1
        return response

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 0
    assert repository.devices(home_id=HOME_ID) == []


@pytest.mark.parametrize(
    "url",
    (
        "https://sites.google.com/view/Chromecast4K/",
        "https://docs.google.com/document/d/Chromecast4K/",
        "https://drive.google.com/drive/folders/Chromecast4K/",
        "https://groups.google.com/g/Chromecast4K/",
        "https://support.google.com/googlenest/thread/Chromecast4K/",
    ),
)
def test_google_hosted_content_is_not_an_automated_official_source(repository, url):
    assert source_matches_registered_official_domain(url, "Google") is False
    _scan(repository)
    job = _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        model="Chromecast4K",
        manufacturer="Google",
        device_type="tv",
        structured_provenance=[
            {"kind": "manufacturer", "source": "googlecast", "value": "Google"},
            {"kind": "model", "source": "googlecast", "value": "Chromecast4K"},
            {"kind": "model", "source": "upnp", "value": "Chromecast4K"},
        ],
    )

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=lambda **_: _response(
            [
                _matching_result(
                    job["job_id"],
                    manufacturer="Google",
                    device_type="tv",
                    model="Chromecast4K",
                    official_source_url=url,
                )
            ],
            [url],
        ),
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 0
    assert repository.devices(home_id=HOME_ID) == []


def test_official_host_paths_are_normalized_and_google_support_requires_answer_shape():
    assert source_matches_registered_official_domain(
        "https://support.google.com/googlenest/answer/123456789/",
        "Google",
    )
    assert source_matches_registered_official_domain(
        "https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
        "Samsung",
    )
    for url, manufacturer in (
        ("https://support.google.com/googlenest/thread/123456789/", "Google"),
        ("https://support.google.com/googlenest/%61nswer/123456789/", "Google"),
        ("https://support.google.com/googlenest/answer/123456789/?hl=ko", "Google"),
        ("https://www.samsung.com//sec/refrigerators/RF85C90N1AP/", "Samsung"),
        ("https://www.samsung.com/sec/../community/RF85C90N1AP/", "Samsung"),
        ("https://www.samsung.com/sec/questions/RF85C90N1AP/", "Samsung"),
    ):
        assert source_matches_registered_official_domain(url, manufacturer) is False


def test_model_prefix_is_not_proof_of_the_full_product_code(repository):
    _scan(repository)
    job = _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        model="RF85",
    )
    result = _matching_result(job["job_id"], model="RF85")

    def transport(**_: Any) -> Mapping[str, Any]:
        response = _response([result], [OFFICIAL_URL])
        response["output"][0]["content"][0]["annotations"][0]["title"] = (
            "Samsung RF85C90N1AP refrigerator"
        )
        return response

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.attempted_count == 1
    assert outcome.resolved_count == 0
    assert repository.devices(home_id=HOME_ID) == []


def test_missing_completed_status_is_rejected(repository):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        response = _response([_matching_result(job["job_id"])], [OFFICIAL_URL])
        response.pop("status")
        return response

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.error_code == "IDENTITY_RESEARCH_FAILED"
    assert outcome.resolved_count == 0


def test_resolution_envelope_blocks_coordinated_persisted_product_tampering(repository):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 1
    resolved = repository.identity_enrichment_jobs()[0]
    assert repository.devices(home_id=HOME_ID)[0]["model"] == "RF85C90N1AP"

    tampered_resolution = {
        **resolved["resolution"],
        "model": "RF85C90N1AX",
        "canonical_name": "삼성 냉장고 (RF85C90N1AX)",
    }
    tampered_source = "https://www.samsung.com/sec/refrigerators/RF85C90N1AX/"
    _update_job_column(
        repository,
        resolved["job_id"],
        "resolution_json",
        json.dumps(tampered_resolution, ensure_ascii=False, sort_keys=True),
    )
    _update_job_column(repository, resolved["job_id"], "source_reference", tampered_source)
    resolution_id = resolved["resolution"]["history_resolution_id"]
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE device_identity_history SET model = ?, canonical_name = ? "
                "WHERE resolution_id = ?",
                ("RF85C90N1AX", "삼성 냉장고 (RF85C90N1AX)", resolution_id),
            )
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE device_identity_history SET model = :model, "
                    "canonical_name = :canonical_name WHERE resolution_id = :resolution_id"
                ),
                {
                    "model": "RF85C90N1AX",
                    "canonical_name": "삼성 냉장고 (RF85C90N1AX)",
                    "resolution_id": resolution_id,
                },
            )
    assert repository.devices(home_id=HOME_ID) == []


def test_unsigned_legacy_resolution_is_quarantined_instead_of_backfilled(repository):
    _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    assert research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    ).resolved_count == 1
    resolved = repository.identity_enrichment_jobs()[0]
    forged = {
        **resolved["resolution"],
        "model": "RF85C90N1AX",
        "canonical_name": "삼성 냉장고 (RF85C90N1AX)",
    }
    _update_job_column(
        repository,
        resolved["job_id"],
        "resolution_json",
        json.dumps(forged, ensure_ascii=False, sort_keys=True),
    )
    _update_job_column(
        repository,
        resolved["job_id"],
        "source_reference",
        "https://www.samsung.com/sec/refrigerators/RF85C90N1AX/",
    )
    _update_job_column(repository, resolved["job_id"], "resolution_signature", None)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            repository._quarantine_unsigned_legacy_resolutions(conn)
    else:
        with repository.engine.begin() as conn:
            repository._quarantine_unsigned_legacy_resolutions(conn)

    quarantined = repository.identity_enrichment_jobs()[0]
    assert quarantined["status"] == "review_required"
    assert quarantined["resolution"] is None
    assert quarantined["source_reference"] is None
    assert quarantined["resolution_signature"] is None
    assert repository.devices(home_id=HOME_ID) == []


def test_post_research_scan_finalize_is_idempotent_and_creates_one_notification(repository):
    scan = _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 1
    initial_notifications = repository.notifications(home_id=HOME_ID)
    assert len(initial_notifications) == 1
    initial_notification_id = initial_notifications[0]["notification_id"]
    assert repository.finalize_identity_researched_scan(scan["scan_id"], home_id=HOME_ID)
    assert repository.finalize_identity_researched_scan(scan["scan_id"], home_id=HOME_ID)
    notifications = repository.notifications(home_id=HOME_ID)
    assert len(notifications) == 1
    assert notifications[0]["notification_id"] == initial_notification_id
    assert notifications[0]["title"] == "보안 점검 완료"
    finalized = repository.scan_result(scan["scan_id"], home_id=HOME_ID)
    assert finalized is not None
    assert finalized["status"] == "completed"
    assert finalized["security_score"]["scan_complete"] is True
    assert finalized["security_score"]["coverage_complete"] is True


def test_finalize_atomically_replaces_existing_unsafe_completion_copy(repository):
    scan = _scan(repository)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    assert research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=lambda **_: _response(
            [_matching_result(job["job_id"])], [OFFICIAL_URL]
        ),
        environ=_enabled_config(),
    ).resolved_count == 1
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                """
                INSERT INTO notifications (
                    notification_id, home_id, type, title, message,
                    scan_id, scan_source, read, created_at
                ) VALUES (?, ?, 'scan_completed', '보안 점검 완료', '안전합니다.', ?, 'android-native', 0, ?)
                """,
                ("stale-finalize", HOME_ID, scan["scan_id"], "2026-08-21T00:00:00Z"),
            )
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO notifications (
                        notification_id, home_id, type, title, message,
                        scan_id, scan_source, read, created_at
                    ) VALUES (
                        'stale-finalize', :home_id, 'scan_completed', '보안 점검 완료',
                        '안전합니다.', :scan_id, 'android-native', 0, '2026-08-21T00:00:00Z'
                    )
                    """
                ),
                {"home_id": HOME_ID, "scan_id": scan["scan_id"]},
            )

    assert repository.finalize_identity_researched_scan(scan["scan_id"], home_id=HOME_ID)
    notifications = repository.notifications(home_id=HOME_ID)
    assert len(notifications) == 1
    assert notifications[0]["title"] == "보안 점검 완료"
    assert notifications[0]["message"] != "안전합니다."
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            stored = conn.execute(
                "SELECT title, message FROM notifications "
                "WHERE home_id = ? AND scan_id = ? AND type = 'scan_completed'",
                (HOME_ID, scan["scan_id"]),
            ).fetchall()
    else:
        with repository.engine.begin() as conn:
            stored = conn.execute(
                text(
                    "SELECT title, message FROM notifications "
                    "WHERE home_id = :home_id AND scan_id = :scan_id "
                    "AND type = 'scan_completed'"
                ),
                {"home_id": HOME_ID, "scan_id": scan["scan_id"]},
            ).all()
    assert len(stored) == 2
    assert all(row[0] == "보안 점검 완료" for row in stored)
    assert all(row[1] != "안전합니다." for row in stored)


def test_scan_post_only_wakes_background_research_and_returns_current_result(
    repository,
    monkeypatch,
):
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setattr(
        main_module,
        "require_home_scope",
        lambda _request: SimpleNamespace(home_id=HOME_ID, user_id="research-user"),
    )
    monkeypatch.setattr(main_module, "reject_non_actual_android_scan", lambda _scan: None)
    monkeypatch.setattr(
        main_module,
        "augment_android_observations",
        lambda devices, _context: devices,
    )
    monkeypatch.setattr(
        main_module,
        "research_pending_identities",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scan POST must not run external identity research")
        ),
    )
    monkeypatch.setattr(
        repository,
        "scan_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scan POST must not requery after persistence")
        ),
    )
    monkeypatch.setattr(
        repository,
        "finalize_identity_researched_scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scan POST must not finalize background research")
        ),
    )
    wake_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def wake(*args: Any, **kwargs: Any) -> None:
        wake_calls.append((args, kwargs))

    monkeypatch.setattr(main_module, "wake_identity_research_worker", wake)
    request_model = main_module.ScanRequest(
        scan_profile="quick",
        scan_source="android-native",
        network_context=CONTEXT,
        devices=[_device()],
    )
    response = main_module.start_security_scan(request_model, object())
    data = response["data"]
    assert wake_calls == [((), {})]
    assert data["status"] == "completed"
    # Background identity research must not hide the already observed
    # physical endpoint from the completed scan response.
    assert data["devices_found"] == 1
    assert data["identity_pending_count"] == 1
    assert data["identity_research_status"] == "review_required"
    assert data["identity_findings"] == []
    assert data["scan_complete"] is True
    assert data["coverage_complete"] is True
    jobs = repository.identity_enrichment_jobs(home_id=HOME_ID)
    assert len(jobs) == 1
    assert jobs[0]["status"] == "review_required"
    assert len(repository.notifications(home_id=HOME_ID)) == 1


def test_transport_partial_scan_is_never_finalized_after_identity_resolution(repository):
    partial_context = {
        **CONTEXT,
        "scan_diagnostics": {
            "candidate_coverage_complete": False,
            "tcp_scan_timed_out": True,
        },
    }
    scan = _scan(repository, context=partial_context)
    job = _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        return _response([_matching_result(job["job_id"])], [OFFICIAL_URL])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    assert outcome.resolved_count == 1
    assert repository.finalize_identity_researched_scan(scan["scan_id"], home_id=HOME_ID) is False
    partial = repository.scan_result(scan["scan_id"], home_id=HOME_ID)
    assert partial is not None
    assert partial["status"] == "partial"
    assert partial["security_score"]["scan_complete"] is False
    notifications = repository.notifications(home_id=HOME_ID)
    assert len(notifications) == 1
    assert notifications[0]["title"] == "보안 점검 일부 완료"


def test_legacy_partial_notifications_are_rewritten_without_deleting_history(repository):
    partial_context = {
        **CONTEXT,
        "scan_diagnostics": {
            "candidate_coverage_complete": False,
            "tcp_scan_timed_out": True,
        },
    }
    scan = _scan(repository, context=partial_context)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                """
                INSERT INTO notifications (
                    notification_id, home_id, type, title, message,
                    scan_id, scan_source, read, created_at
                ) VALUES (?, ?, 'scan_completed', '보안 점검 완료', '안전합니다.', ?, 'android-native', 0, ?)
                """,
                ("legacy-partial-copy", HOME_ID, scan["scan_id"], "2026-08-21T00:00:00Z"),
            )
            repository._normalize_legacy_public_device_data(conn)
            stored = conn.execute(
                "SELECT title, message FROM notifications "
                "WHERE home_id = ? AND scan_id = ? AND type = 'scan_completed'",
                (HOME_ID, scan["scan_id"]),
            ).fetchall()
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO notifications (
                        notification_id, home_id, type, title, message,
                        scan_id, scan_source, read, created_at
                    ) VALUES (
                        'legacy-partial-copy', :home_id, 'scan_completed',
                        '보안 점검 완료', '안전합니다.', :scan_id,
                        'android-native', 0, '2026-08-21T00:00:00Z'
                    )
                    """
                ),
                {"home_id": HOME_ID, "scan_id": scan["scan_id"]},
            )
            repository._normalize_legacy_public_device_data(conn)
            stored = conn.execute(
                text(
                    "SELECT title, message FROM notifications "
                    "WHERE home_id = :home_id AND scan_id = :scan_id "
                    "AND type = 'scan_completed'"
                ),
                {"home_id": HOME_ID, "scan_id": scan["scan_id"]},
            ).all()

    assert len(stored) == 2
    assert all(row[0] == "보안 점검 일부 완료" for row in stored)
    assert all(row[1] != "안전합니다." for row in stored)
    projected = repository.notifications(home_id=HOME_ID)
    assert len(projected) == 1
    assert projected[0]["title"] == "보안 점검 일부 완료"


def test_legacy_completed_scan_with_physical_endpoint_recomputes_forged_score_and_safe_notification(
    repository,
):
    scan = _scan(repository)
    forged_score = json.dumps(
        {
            "home_id": HOME_ID,
            "score": 100,
            "risk_level": "green",
            "summary": "점검 완료",
            "device_scores": [],
            "scan_complete": True,
            "coverage_complete": True,
        },
        ensure_ascii=False,
    )
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = 'completed', current_step = '점검 완료', "
                "security_score_json = ? WHERE scan_id = ?",
                (forged_score, scan["scan_id"]),
            )
            conn.execute(
                """
                INSERT INTO notifications (
                    notification_id, home_id, type, title, message,
                    scan_id, scan_source, read, created_at
                ) VALUES (?, ?, 'scan_completed', '보안 점검 완료', '안전합니다.', ?, 'android-native', 0, ?)
                """,
                ("legacy-complete", HOME_ID, scan["scan_id"], "2026-08-21T00:00:00Z"),
            )
            repository._normalize_legacy_public_device_data(conn)
            raw = conn.execute(
                "SELECT status, current_step, security_score_json FROM scans WHERE scan_id = ?",
                (scan["scan_id"],),
            ).fetchone()
            raw_status = raw["status"]
            raw_step = raw["current_step"]
            raw_score = json.loads(raw["security_score_json"])
    else:
        with repository.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE scans SET status = 'completed', current_step = '점검 완료', "
                    "security_score_json = :score WHERE scan_id = :scan_id"
                ),
                {"score": forged_score, "scan_id": scan["scan_id"]},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO notifications (
                        notification_id, home_id, type, title, message,
                        scan_id, scan_source, read, created_at
                    ) VALUES (
                        'legacy-complete', :home_id, 'scan_completed', '보안 점검 완료',
                        '안전합니다.', :scan_id, 'android-native', 0, '2026-08-21T00:00:00Z'
                    )
                    """
                ),
                {"home_id": HOME_ID, "scan_id": scan["scan_id"]},
            )
            repository._normalize_legacy_public_device_data(conn)
            raw = conn.execute(
                text(
                    "SELECT status, current_step, security_score_json "
                    "FROM scans WHERE scan_id = :scan_id"
                ),
                {"scan_id": scan["scan_id"]},
            ).mappings().one()
            raw_status = raw["status"]
            raw_step = raw["current_step"]
            raw_score = json.loads(raw["security_score_json"])

    assert raw_status == "completed"
    assert raw_step == "점검 완료"
    # `_scan` contains a fresh physical-MAC endpoint. Normalization must
    # replace the forged perfect score with its evidence-backed score rather
    # than treating this fixture as a service-only observation.
    assert raw_score["score"] == 88
    assert raw_score["score_status"] == "final"
    assert raw_score["scan_complete"] is True
    assert raw_score["coverage_complete"] is True
    notifications = repository.notifications(home_id=HOME_ID)
    assert len(notifications) == 1
    assert notifications[0]["message"] != "안전합니다."

    # Later resolution refreshes the same completion notification instead of
    # hiding the scan or adding a second alert.
    job = _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
    )
    assert research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=lambda **_: _response(
            [_matching_result(job["job_id"])], [OFFICIAL_URL]
        ),
        environ=_enabled_config(),
    ).resolved_count == 1
    assert repository.scan_result(scan["scan_id"], home_id=HOME_ID)["status"] == "completed"
    assert len(repository.notifications(home_id=HOME_ID)) == 1


@pytest.mark.parametrize("failure", (TimeoutError(), ValueError("invalid-json")))
def test_timeout_and_invalid_transport_response_leave_job_review_required(repository, failure):
    _scan(repository)
    _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])

    def transport(**_: Any) -> Mapping[str, Any]:
        if isinstance(failure, TimeoutError):
            raise failure
        return {"status": "completed", "output_text": "not-json"}

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    assert outcome.error_code == "IDENTITY_RESEARCH_FAILED"
    assert outcome.resolved_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"


def test_failed_batch_honors_persisted_backoff_before_retry(repository):
    _scan(repository)
    _make_job_researchable(repository, repository.identity_enrichment_jobs()[0])
    calls = 0

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal calls
        calls += 1
        raise IdentityResearchFailure("IDENTITY_RESEARCH_TRANSPORT_FAILED")

    first = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    second = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    job = repository.identity_enrichment_jobs()[0]
    assert first.error_code == "IDENTITY_RESEARCH_FAILED"
    assert second.attempted_count == 0
    assert calls == 1
    assert job["research_attempt_count"] == 1
    assert job["research_next_attempt_at"]


def test_non_concrete_model_is_not_sent_for_research(repository):
    _scan(repository, [_device(model="Family Hub")])
    _make_job_researchable(
        repository,
        repository.identity_enrichment_jobs()[0],
        model="Family Hub",
    )
    called = False

    def transport(**_: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        return _response([], [])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    assert called is False
    assert outcome.eligible_count == 0
    assert repository.identity_enrichment_jobs()[0]["status"] == "review_required"


def test_one_request_contains_at_most_eight_opaque_jobs(repository):
    devices = [
        _device(
            model=f"RF85C90N1A{index}",
            ip=f"192.168.60.{20 + index}",
            mac=f"AA:BB:CC:00:60:{20 + index:02X}",
        )
        for index in range(9)
    ]
    _scan(repository, devices)
    for index, job in enumerate(repository.identity_enrichment_jobs()):
        _make_job_researchable(repository, job, model=f"RF85C90N1A{index}")
    captured_batches: list[list[dict[str, Any]]] = []

    def transport(**kwargs: Any) -> Mapping[str, Any]:
        prompt = json.loads(kwargs["payload"]["input"])
        captured_batches.append(prompt["jobs"])
        return _response([], [])

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    second = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )
    third = research_pending_identities(
        repository,
        home_id=HOME_ID,
        transport=transport,
        environ=_enabled_config(),
    )

    assert [len(batch) for batch in captured_batches] == [8, 1]
    assert outcome.attempted_count == 8
    assert second.attempted_count == 1
    assert third.attempted_count == 0
    assert len(repository.identity_enrichment_jobs()) == 9
    attempts = sorted(
        int(job.get("research_attempt_count") or 0)
        for job in repository.identity_enrichment_jobs()
    )
    assert attempts == [1] * 9
    assert all(job.get("research_next_attempt_at") for job in repository.identity_enrichment_jobs())


def test_public_contract_drops_product_candidates_without_holding_completion():
    projected = _apply_public_identity_contract(
        {
            "status": "completed",
            "current_step": "점검 완료",
            "scan_complete": True,
            "coverage_complete": True,
            "identity_pending_count": 1,
            "identity_findings": [
                {
                    "display_name": "Samsung 냉장고 후보",
                    "identity_candidates": ["RF85C90N1AP"],
                    "risk_level": "red",
                }
            ],
            "high_risk_devices": 1,
            "security_score": {
                "score": 10,
                "score_status": "final",
                "risk_level": "red",
                "device_scores": [],
                "identity_incomplete": True,
                "identity_pending_count": 1,
            },
        }
    )

    assert projected["identity_findings"] == []
    assert projected["detected_connections"] == []
    assert projected["identity_pending_count"] == 0
    assert projected["identity_incomplete"] is False
    assert projected["unresolved_observation_count"] == 0
    assert projected["identity_research_status"] == "complete"
    assert projected["status"] == "completed"
    assert projected["scan_complete"] is True
    assert projected["coverage_complete"] is True
    assert projected["security_score"]["score"] == 10
    assert projected["security_score"]["score_status"] == "final"
    assert projected["security_score"]["identity_pending_count"] == 0
    assert projected["security_score"]["identity_incomplete"] is False
    assert projected["security_score"]["identity_research_status"] == "complete"
    assert projected["high_risk_devices"] == 1
    assert "Samsung" not in json.dumps(projected, ensure_ascii=False)


def test_public_contract_drops_legacy_refusal_only_finding_and_stale_count():
    projected = _apply_public_identity_contract(
        {
            "status": "completed",
            "current_step": "점검 완료",
            "identity_pending_count": 51,
            "identity_findings": [
                {
                    "device_id": "legacy-refusal-only",
                    "display_name": "",
                    "identity_status": "enriching",
                    "identity_evidence": ["TCP 연결 거부 응답"],
                    "risk_level": "unknown",
                    "detected": True,
                    "is_phantom": False,
                }
            ],
            "high_risk_devices": 0,
            "security_score": {
                "score": None,
                "score_status": "no_targets",
                "risk_level": "unknown",
                "device_scores": [],
                "scan_complete": True,
                "coverage_complete": True,
            },
        }
    )

    assert projected["identity_findings"] == []
    assert projected["detected_connections"] == []
    assert projected["identity_pending_count"] == 0
    assert projected["evidence_backed_observation_count"] == 0
    assert projected["unresolved_observation_count"] == 0
    assert projected["identity_research_status"] == "complete"
    assert projected["high_risk_devices"] == 0
    assert projected["security_score"]["score"] is None
    assert projected["security_score"]["score_status"] == "no_targets"


def test_public_devices_found_excludes_service_only_findings():
    def observed(device_id: str) -> dict[str, object]:
        return {
            "device_id": device_id,
            "display_name": "웹 관리 서비스 응답",
            "observed_service": "http",
            "observed_service_verified": True,
            "identity_status": "enriching",
            "risk_level": "yellow",
            "detected": True,
        }

    projected = _apply_public_identity_contract(
        {
            "status": "completed",
            "devices_found": 84,
            "identified_count": 52,
            "devices": [
                {
                    "device_id": "confirmed-a",
                    "canonical_name": "ipTIME 공유기 (A3004)",
                }
            ],
            "identity_pending_count": 83,
            "identity_findings": [
                # Neither a duplicate nor a distinct id may turn a bare HTTP
                # response into a resident-facing device row.
                observed("confirmed-a"),
                observed("observed-b"),
                observed("observed-c"),
            ],
        }
    )

    assert projected["identified_count"] == 1
    assert projected["identity_pending_count"] == 0
    assert projected["devices_found"] == 1
    assert projected["detected_connections"] == []


def test_public_score_events_and_scan_result_keep_score_without_product_guess(repository):
    raw = _device()
    raw.update(
        {
            "open_ports": [80, 554],
            "services": ["http", "onvif", "rtsp", "upnp"],
            "risk_signals": [
                "camera_candidate",
                "default_credentials_possible",
                "rtsp_open",
            ],
        }
    )
    scan = _scan(repository, [raw])
    events = repository.security_events(home_id=HOME_ID)
    result = repository.scan_result(scan["scan_id"], home_id=HOME_ID)
    score = repository.security_score(home_id=HOME_ID)
    assert events
    assert any(event["severity"] == "red" for event in events)
    assert any(event["title"] == "점검 중 확인된 보안 위험" for event in events)
    assert result is not None
    assert result["high_risk_devices"] >= 1
    assert score["risk_level"] == "red"

    public_payload = {
        "events": events,
        "score": _apply_public_identity_contract(score),
        "scan": _apply_public_identity_contract(result),
    }
    serialized = json.dumps(public_payload, ensure_ascii=False)
    for forbidden in (
        "추가로 감지된 연결",
        "식별이 끝나지",
        "식별 처리 중",
        "제품 정보 자동 확인",
        "제품 정보 확인",
        "제품 확인 필요",
        "알 수 없는 기기",
        "제조사 미확인",
    ):
        assert forbidden not in serialized
    assert isinstance(public_payload["score"]["score"], int)
    assert public_payload["score"]["score_status"] == "final"
    assert public_payload["score"]["scan_complete"] is True
    assert public_payload["scan"]["identity_findings"] == []
    assert public_payload["scan"]["identity_pending_count"] == 1


def test_enrichment_failure_log_never_contains_household_or_exception_payload(
    monkeypatch,
    caplog,
):
    private_values = {
        "ip": "192.168.60.77",
        "mac": "00:E0:64:12:34:56",
        "ssid": "Private Research Wi-Fi",
        "token": "secret-token-never-log",
        "fingerprint": "upnp-model:RF85C90N1AP",
    }

    def fail(_device: Mapping[str, Any]) -> dict[str, Any]:
        raise ValueError(" ".join(private_values.values()))

    monkeypatch.setattr(main_module, "_enrich_with_cve", fail)
    with caplog.at_level("WARNING", logger="home_guardian"):
        projected = main_module._enrich_device(
            {
                "device_id": "private-device-id",
                "home_id": HOME_ID,
                "ip_address": private_values["ip"],
                "mac_address": private_values["mac"],
                "ssid": private_values["ssid"],
                "token": private_values["token"],
                "fingerprints": [private_values["fingerprint"]],
            }
        )
    assert projected["is_unresolved"] is True
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert logs == "DEVICE_ENRICH_FAILED exception_class=ValueError"
    assert all(value not in logs for value in private_values.values())
