from __future__ import annotations

import json
import inspect
import sqlite3

import pytest
from sqlalchemy import text

from app.services.device_presentation import build_public_detected_connections
from app.storage.network_scope import (
    derive_network_scope_id,
    derive_strong_network_scope_ids,
    strong_network_scope_candidates_overlap,
)
from app.storage.sa_repository import SqlAlchemyRepository
from app.storage.scan_state import hold_partial_security, project_partial_security
from app.storage.scoring_helpers import scan_completed_message
from app.storage.sqlite_repository import SQLiteRepository, _SQLITE_SCHEMA_MIGRATION_ID


BASE_CONTEXT = {
    "ssid": "Home Private Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.50.10",
    "gateway_ip": "192.168.50.1",
    "subnet_cidr": "192.168.50.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}

TEST_HOME_ID = "home-network-scope-test"


def _bind_test_home(repo, home_id: str = TEST_HOME_ID) -> None:
    repo.upsert_user(
        {
            "user_id": f"network-scope-owner-{home_id}",
            "email": f"{home_id}@network-scope-test.invalid",
            "nickname": "네트워크 범위 테스트 사용자",
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


def _router(ip: str, mac: str, model: str = "A3004") -> dict:
    return {
        "name": "공유기",
        "device_type": "router",
        "manufacturer": "EFM Networks",
        "model": model,
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http"],
        "discovery_sources": ["ssdp"],
        "fingerprints": ["upnp-manufacturer:EFM Networks", f"upnp-model:{model}"],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _weak_device(ip: str, mac: str) -> dict:
    return {
        "name": "",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [80],
        "services": ["http"],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": [],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _family_hub_observation(ip: str, mac: str, *, getinfo: bool) -> dict:
    fingerprints = ["mdns-type:_spotify-connect._tcp.local"]
    if getinfo:
        fingerprints.extend(
            [
                "spotify-getinfo-done",
                "spotify-brand:Samsung",
                "spotify-model:Family_HUB",
                "spotify-name:SAMSUNG FAMILY HUB",
                "spotify-type:SPEAKER",
            ]
        )
    return {
        "name": "",
        "device_type": "speaker" if getinfo else "unknown",
        "manufacturer": "Samsung" if getinfo else "",
        "model": "Family_HUB" if getinfo else "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns", "server-neighbor"],
        "fingerprints": fingerprints,
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _computer_observation(ip: str, mac: str, hostname: str) -> dict:
    return {
        "name": hostname,
        "device_type": "computer",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [139, 445],
        "services": ["smb"],
        "discovery_sources": ["tcp-port-probe", "netbios"],
        "fingerprints": [f"netbios-name:{hostname}"],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _red_camera(ip: str, mac: str) -> dict:
    return {
        "name": "카메라",
        "device_type": "camera",
        "manufacturer": "Hikvision",
        "model": "DS-2CD2042",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [23, 80, 554, 3702],
        "services": ["telnet", "http", "rtsp", "onvif"],
        "discovery_sources": ["onvif", "ssdp"],
        "fingerprints": [
            "upnp-manufacturer:Hikvision",
            "upnp-model:DS-2CD2042",
            "onvif-device",
        ],
        "risk_signals": ["camera_candidate", "rtsp_open", "default_credentials_possible"],
        "vulnerabilities": [{"cve_id": "CVE-2021-36260", "severity": "critical"}],
    }


def _red_unresolved_connection(ip: str, mac: str) -> dict:
    return {
        "name": "",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip,
        "mac_address": mac,
        "open_ports": [23, 80],
        "services": ["telnet", "http"],
        "discovery_sources": ["android-neighbor", "tcp-port-probe"],
        "fingerprints": ["tcp:23", "tcp:80"],
        "risk_signals": ["telnet_open", "default_credentials_possible"],
        "vulnerabilities": [{"cve_id": "CVE-2024-0001", "severity": "critical"}],
    }


def _make_repositories(tmp_path):
    sqlite_repo = SQLiteRepository(db_path=str(tmp_path / "native.sqlite3"))
    sa_repo = SqlAlchemyRepository(
        f"sqlite+pysqlite:///{(tmp_path / 'sqlalchemy.sqlite3').as_posix()}"
    )
    _bind_test_home(sqlite_repo)
    _bind_test_home(sa_repo)
    return sqlite_repo, sa_repo


def _stored_scan_row(repository, scan_id: str) -> dict:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            row = conn.execute(
                "SELECT network_context_json, network_scope_id, security_score_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            return dict(row)
    with repository.engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT network_context_json, network_scope_id, security_score_json "
                "FROM scans WHERE scan_id = :scan_id"
            ),
            {"scan_id": scan_id},
        ).mappings().one()
        return dict(row)


def _replace_stored_security_score(repository, scan_id: str, payload: dict) -> None:
    serialized = json.dumps(payload, ensure_ascii=False)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE scans SET security_score_json = ? WHERE scan_id = ?",
                (serialized, scan_id),
            )
        return
    with repository.engine.begin() as conn:
        conn.execute(
            text("UPDATE scans SET security_score_json = :payload WHERE scan_id = :scan_id"),
            {"payload": serialized, "scan_id": scan_id},
        )


def _normalize_stored_public_data(repository) -> None:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            repository._normalize_legacy_public_device_data(conn)
        return
    with repository.engine.begin() as conn:
        repository._normalize_legacy_public_device_data(conn)


def _stored_snapshot_payloads(repository, scan_id: str) -> list[dict]:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            rows = conn.execute(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()
            return [json.loads(row[0]) for row in rows]
    with repository.engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT device_snapshot_json FROM scan_devices "
                "WHERE scan_id = :scan_id ORDER BY id ASC"
            ),
            {"scan_id": scan_id},
        ).fetchall()
        return [json.loads(row[0]) for row in rows]


def _insert_stored_snapshot(repository, scan_id: str, snapshot: dict) -> None:
    serialized = json.dumps(snapshot, ensure_ascii=False)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "INSERT INTO scan_devices (scan_id, device_snapshot_json) VALUES (?, ?)",
                (scan_id, serialized),
            )
        return
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scan_devices (scan_id, device_snapshot_json) "
                "VALUES (:scan_id, :snapshot)"
            ),
            {"scan_id": scan_id, "snapshot": serialized},
        )


def _rewrite_stored_scan_context(repository, scan_id: str, context: dict) -> None:
    serialized = json.dumps(context, ensure_ascii=False)
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            conn.execute(
                "UPDATE scans SET network_context_json = ?, status = 'completed', "
                "current_step = '점검 완료', devices_found = 999 WHERE scan_id = ?",
                (serialized, scan_id),
            )
        return
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scans SET network_context_json = :context, status = 'completed', "
                "current_step = '점검 완료', devices_found = 999 WHERE scan_id = :scan_id"
            ),
            {"context": serialized, "scan_id": scan_id},
        )


def _durable_device_source(repository, device_id: str) -> str | None:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            row = conn.execute(
                "SELECT scan_source FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            return str(row[0]) if row else None
    with repository.engine.begin() as conn:
        row = conn.execute(
            text("SELECT scan_source FROM devices WHERE device_id = :device_id"),
            {"device_id": device_id},
        ).first()
        return str(row[0]) if row else None


def _stored_history_physical_macs(repository) -> list[str | None]:
    if isinstance(repository, SQLiteRepository):
        with repository._connect() as conn:
            rows = conn.execute(
                "SELECT physical_mac FROM device_identity_history ORDER BY observed_at ASC"
            ).fetchall()
            return [row[0] for row in rows]
    with repository.engine.begin() as conn:
        rows = conn.execute(
            text("SELECT physical_mac FROM device_identity_history ORDER BY observed_at ASC")
        ).fetchall()
        return [row[0] for row in rows]


def test_scope_prefers_gateway_mac_then_bssid_and_uses_keyed_subnet_fallback():
    gateway = _router("192.168.50.1", "AA:BB:CC:00:00:01")
    via_gateway_a = derive_network_scope_id(
        home_id="home-a",
        network_context=BASE_CONTEXT,
        discovered_devices=[gateway],
    )
    via_gateway_b = derive_network_scope_id(
        home_id="home-a",
        network_context={**BASE_CONTEXT, "bssid": "10:20:30:40:50:61"},
        discovered_devices=[gateway],
    )
    assert via_gateway_a == via_gateway_b
    assert via_gateway_a and via_gateway_a.startswith("hgns1g-")

    via_bssid_a = derive_network_scope_id(
        home_id="home-a",
        network_context=BASE_CONTEXT,
        discovered_devices=[],
    )
    via_bssid_b = derive_network_scope_id(
        home_id="home-a",
        network_context={**BASE_CONTEXT, "bssid": "10:20:30:40:50:61"},
        discovered_devices=[],
    )
    assert via_bssid_a != via_bssid_b
    assert via_bssid_a and via_bssid_a.startswith("hgns1b-")

    fallback_a = derive_network_scope_id(
        home_id="home-a",
        network_context={k: v for k, v in BASE_CONTEXT.items() if k not in {"ssid", "bssid"}},
        discovered_devices=[],
    )
    fallback_b = derive_network_scope_id(
        home_id="home-a",
        network_context={
            **{k: v for k, v in BASE_CONTEXT.items() if k not in {"ssid", "bssid"}},
            "ssid": "A different Wi-Fi with the same private CIDR",
        },
        discovered_devices=[],
    )
    # Compatibility limitation: without gateway/BSSID evidence the keyed value
    # can isolate homes, but cannot distinguish two same-CIDR networks of one home.
    assert fallback_a == fallback_b
    assert fallback_a and fallback_a.startswith("hgns1s-")


def test_scope_exposes_gateway_and_bssid_candidates_without_raw_wifi_values():
    gateway = _router("192.168.50.1", "AA:BB:CC:00:00:01")
    candidates = derive_strong_network_scope_ids(
        home_id="home-a",
        network_context=BASE_CONTEXT,
        discovered_devices=[gateway],
    )
    other_band = derive_strong_network_scope_ids(
        home_id="home-a",
        network_context={**BASE_CONTEXT, "bssid": "10:20:30:40:50:61"},
        discovered_devices=[gateway],
    )

    assert len(candidates) == 2
    assert candidates[0].startswith("hgns1g-")
    assert candidates[1].startswith("hgns1b-")
    assert candidates[0] == derive_network_scope_id(
        home_id="home-a",
        network_context=BASE_CONTEXT,
        discovered_devices=[gateway],
    )
    assert strong_network_scope_candidates_overlap(candidates, other_band) is True
    assert all("Home Private Wi-Fi" not in value for value in candidates)
    assert all("10:20:30:40:50:60" not in value for value in candidates)


def test_scope_candidate_equivalence_rejects_subnet_only_and_different_gateway():
    first = derive_strong_network_scope_ids(
        home_id="home-a",
        network_context=BASE_CONTEXT,
        discovered_devices=[_router("192.168.50.1", "AA:BB:CC:00:00:01")],
    )
    different = derive_strong_network_scope_ids(
        home_id="home-a",
        network_context={**BASE_CONTEXT, "bssid": "10:20:30:40:50:61"},
        discovered_devices=[_router("192.168.50.1", "AA:BB:CC:00:00:02")],
    )
    subnet_only = derive_network_scope_id(
        home_id="home-a",
        network_context={
            key: value
            for key, value in BASE_CONTEXT.items()
            if key not in {"ssid", "bssid"}
        },
        discovered_devices=[],
    )

    assert strong_network_scope_candidates_overlap(first, different) is False
    assert strong_network_scope_candidates_overlap(first, [subnet_only]) is False


def test_scope_accepts_a_different_private_lan_range_without_environment_literals():
    other_lan = {
        **BASE_CONTEXT,
        "bssid": "AA:10:20:30:40:51",
        "local_ip": "10.42.7.10",
        "gateway_ip": "10.42.7.1",
        "subnet_cidr": "10.42.7.0/24",
    }
    scope = derive_network_scope_id(
        home_id="home-other-region",
        network_context=other_lan,
        discovered_devices=[_router("10.42.7.1", "AA:BB:CC:42:07:01")],
    )

    assert scope and scope.startswith("hgns1g-")


def test_partial_score_hold_never_downgrades_confirmed_red_risk():
    held = hold_partial_security(
        {
            "score": 22,
            "risk_level": "red",
            "summary": "확인된 위험",
            "device_scores": [{"risk_level": "red"}],
        }
    )
    assert held["score"] is None
    assert held["risk_level"] == "red"
    assert "확인된 위험 기기" in held["summary"]


def test_partial_score_projection_requires_a_valid_observed_numeric_aggregate():
    projected = project_partial_security(
        {
            "score": 22,
            "risk_level": "red",
            "summary": "확인된 위험",
            "device_scores": [{"score": 22, "risk_level": "red"}],
        }
    )
    missing = project_partial_security(
        {"score": None, "risk_level": "unknown", "device_scores": []}
    )
    scorer_failed = project_partial_security(
        {
            "score": 0,
            "risk_level": "red",
            "device_scores": [{"score": None, "risk_level": "unknown"}],
        }
    )

    assert projected["score"] == 22
    assert projected["score_status"] == "provisional"
    assert projected["risk_level"] == "red"
    assert "집 전체 최종 점수는 아니" in projected["summary"]
    assert "확인된 위험 기기" in projected["summary"]
    assert "다시 점검" in projected["summary"]
    assert missing["score"] is None and missing["score_status"] == "held"
    assert scorer_failed["score"] is None and scorer_failed["score_status"] == "held"
    assert scorer_failed["risk_level"] == "red"


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_real_unresolved_red_connection_stays_visible_without_fake_product(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    try:
        created = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _red_unresolved_connection("192.168.50.23", "AA:BB:CC:00:00:23")
            ],
        )

        assert created["devices"] == []
        assert created["devices_found"] == 1
        assert created["identified_count"] == 0
        assert created["identity_pending_count"] == 1
        assert created["high_risk_devices"] == 1
        assert created["status"] == "completed"
        assert created["current_step"] == "점검 완료"
        assert created["security_score"]["score"] == 50
        assert created["security_score"]["score_status"] == "final"
        assert created["security_score"]["scan_complete"] is True
        assert created["security_score"]["coverage_complete"] is True
        assert created["security_score"]["risk_level"] == "red"
        completed_summary = created["security_score"]["summary"]
        assert "위험" in completed_summary
        assert "다시 점검" not in completed_summary
        assert "다시 검사" not in completed_summary
        finding = created["identity_findings"][0]
        assert finding["display_name"].startswith("Wi-Fi 단말 · ")
        assert finding["risk_level"] == "red"
        observed = build_public_detected_connections([finding])
        assert len(observed) == 1
        assert observed[0]["display_name"] == finding["display_name"]
        serialized = json.dumps(finding, ensure_ascii=False)
        assert "연결된 장비" not in serialized
        assert "카메라" not in serialized
        assert "오디오" not in serialized
        assert "제조사 미확인" not in serialized
        assert "현재 Wi-Fi 이웃 확인" not in serialized

        status = repo.scan_status(created["scan_id"])
        result = repo.scan_result(created["scan_id"])
        dashboard = repo.dashboard()
        assert status and status["high_risk_devices"] == 1
        assert status["status"] == "completed"
        assert status["current_step"] == "점검 완료"
        assert result and result["high_risk_devices"] == 1
        assert result["status"] == "completed"
        assert result["current_step"] == "점검 완료"
        assert result["security_score"]["risk_level"] == "red"
        assert result["security_score"]["summary"] == completed_summary
        assert dashboard["summary"]["high_risk_devices"] == 1
        assert dashboard["summary"]["risk_level"] == "red"
        message = scan_completed_message(
            [], created["identity_findings"], created["security_score"]
        )
        assert "위험 기기 1대" in message
        assert "현재 Wi-Fi 이웃 확인" not in message

        singleton = {
            **_weak_device("192.168.50.190", "UNKNOWN-192.168.50.190"),
            "open_ports": [49153],
            "services": ["tcp-49153"],
        }
        identical_open_hosts = [
            {
                **_weak_device(
                    f"192.168.50.{last}",
                    f"UNKNOWN-192.168.50.{last}",
                ),
                "open_ports": [17654],
                "services": ["spotify-connect"],
                "discovery_sources": ["tcp-port-probe", "spotify-getinfo"],
                "fingerprints": ["spotify-probe:17654"],
            }
            for last in range(200, 208)
        ]
        refusal_only = {
            **_weak_device("192.168.50.199", "UNKNOWN-192.168.50.199"),
            "open_ports": [],
            "services": [],
            "discovery_sources": ["server-tcp-refused-presence"],
            "fingerprints": [],
        }
        cohort_scan = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _router("192.168.50.1", "AA:BB:CC:00:00:01"),
                singleton,
                *identical_open_hosts,
                refusal_only,
            ],
        )
        assert cohort_scan["devices_found"] == 1
        assert cohort_scan["identified_count"] == 1
        assert cohort_scan["identity_pending_count"] == 0
        assert len(cohort_scan["identity_findings"]) == 9
        cohort_cards = build_public_detected_connections(cohort_scan["identity_findings"])
        assert len(cohort_cards) == 0
        raw_by_ip = {
            item["ip_address"]: item
            for item in (repo._latest_observed_scan_devices() or [])
        }
        assert not raw_by_ip[singleton["ip_address"]].get("is_phantom")
        assert all(
            not raw_by_ip[item["ip_address"]].get("is_phantom")
            for item in identical_open_hosts
        )
        assert raw_by_ip[refusal_only["ip_address"]].get("is_phantom")
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("getinfo_success", [False, True])
def test_spotify_probe_cohort_stays_private_but_keeps_research_evidence(
    tmp_path,
    repository_kind,
    getinfo_success,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    attempted_probes = [
        {
            **_weak_device(
                f"192.168.50.{last}",
                f"UNKNOWN-192.168.50.{last}",
            ),
            "open_ports": [17654],
            "services": ["spotify-connect"],
            "discovery_sources": ["tcp-port-probe", "spotify-getinfo"],
            "fingerprints": [
                "spotify-probe:17654",
                *(["spotify-getinfo-done"] if getinfo_success else []),
            ],
        }
        for last in range(100, 118)
    ]

    try:
        created = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=attempted_probes,
        )
        result = repo.scan_result(created["scan_id"])
        assert result is not None
        cards = build_public_detected_connections(result["identity_findings"])

        assert result["devices_found"] == 0
        assert result["identified_count"] == 0
        assert result["identity_pending_count"] == 0
        assert result["security_score"]["score"] is None
        assert result["security_score"]["score_status"] == "no_targets"
        assert cards == []
        assert len(result["identity_findings"]) == 18
        assert len(repo.identity_findings()) == 18
        assert len(repo.identity_enrichment_jobs()) == 18
        assert repo.security_events() == []

        notification = scan_completed_message([], result["identity_findings"])
        assert "기기 18대" not in notification
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_same_cidr_different_bssid_does_not_share_identity_history(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    first = _router("192.168.50.20", "AA:BB:CC:00:00:20", model="A3004")
    weak_same_address = _weak_device("192.168.50.20", "AA:BB:CC:00:00:20")

    try:
        first_scan = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[first],
        )
        second_scan = repo.create_scan(
            scan_source="android-native",
            network_context={**BASE_CONTEXT, "ssid": "Other Wi-Fi", "bssid": "10:20:30:40:50:61"},
            discovered_devices=[weak_same_address],
        )

        assert repo.devices() == []
        first_row = _stored_scan_row(repo, first_scan["scan_id"])
        second_row = _stored_scan_row(repo, second_scan["scan_id"])
        assert first_row["network_scope_id"] != second_row["network_scope_id"]

        family_mac = "AA:BB:CC:00:00:70"
        awake = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _family_hub_observation("192.168.50.70", family_mac, getinfo=True)
            ],
        )
        assert awake["identified_count"] == 1
        sleeping = repo.create_scan(
            scan_source="android-native",
            network_context={
                **BASE_CONTEXT,
                "ssid": "Other Wi-Fi",
                "bssid": "10:20:30:40:50:61",
            },
            discovered_devices=[
                _family_hub_observation("192.168.50.70", family_mac, getinfo=False)
            ],
        )
        assert sleeping["devices"] == []
        assert sleeping["identified_count"] == 0
        assert sleeping["identity_pending_count"] == 1
        sleeping_cards = build_public_detected_connections(sleeping["identity_findings"])
        assert len(sleeping_cards) == 1
        assert sleeping_cards[0]["display_name"].startswith("Wi-Fi 단말 · ")
        latest_raw = repo._latest_observed_scan_devices()
        assert latest_raw and latest_raw[0].get("is_unresolved") is True
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_subnet_only_scope_is_latest_only_and_never_restores_identity_or_firmware(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    subnet_only_context = {
        key: value
        for key, value in BASE_CONTEXT.items()
        if key not in {"ssid", "bssid"}
    }
    mac = "AA:BB:CC:00:00:20"
    strong = {**_router("192.168.50.20", mac), "firmware": "Boa/0.94.14rc21"}
    weak = _weak_device("192.168.50.20", mac)

    try:
        repo.create_scan(
            scan_source="android-native",
            network_context=subnet_only_context,
            discovered_devices=[strong],
        )
        latest = repo.create_scan(
            scan_source="android-native",
            network_context=subnet_only_context,
            discovered_devices=[weak],
        )

        raw = repo._latest_observed_scan_devices()
        assert raw and len(raw) == 1
        assert raw[0].get("is_unresolved") is True
        assert raw[0]["firmware"] == "unknown"
        assert repo.devices() == []
        history = repo.identity_history(raw[0]["device_id"])
        assert history == []
        result = repo.scan_result(latest["scan_id"])
        assert result and result["devices"] == []
        assert result["devices_found"] == 1
        assert result["identity_pending_count"] == 1
        cards = build_public_detected_connections(result["identity_findings"])
        assert len(cards) == 1
        assert cards[0]["display_name"].startswith("Wi-Fi 단말 · ")
        assert len(result["identity_findings"]) == 1
        assert len(repo.identity_findings()) == 1
        assert len(repo.identity_enrichment_jobs()) >= 1
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_strong_scope_and_same_mac_restore_identity_firmware_and_scan_result(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    mac = "AA:BB:CC:00:00:20"
    strong = {**_router("192.168.50.20", mac), "firmware": "Boa/0.94.14rc21"}
    weak = _weak_device("192.168.50.20", mac)

    try:
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[strong],
        )
        latest = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[weak],
        )

        raw = repo._latest_observed_scan_devices()
        assert raw and len(raw) == 1
        assert raw[0]["model"] == "A3004"
        assert raw[0]["firmware"] == "Boa/0.94.14rc21"
        public = repo.devices()
        assert len(public) == 1 and public[0]["model"] == "A3004"
        result = repo.scan_result(latest["scan_id"])
        assert result and result["identity_pending_count"] == 0
        assert len(result["devices"]) == 1
        assert result["devices"][0]["model"] == "A3004"

        family_mac = "AA:BB:CC:00:00:70"
        awake = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _family_hub_observation("192.168.50.70", family_mac, getinfo=True)
            ],
        )
        assert awake["identified_count"] == 1
        sleeping = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _family_hub_observation("192.168.50.70", family_mac, getinfo=False)
            ],
        )
        assert sleeping["identified_count"] == 1
        assert sleeping["identity_pending_count"] == 0
        assert len(sleeping["devices"]) == 1
        family_device = sleeping["devices"][0]
        assert family_device["manufacturer"] == "삼성"
        assert family_device["model"] == "Family Hub"
        assert family_device["device_type"] == "fridge"
        assert family_device["name"] == "삼성 냉장고 (Family Hub)"

        unproven_mac = "AA:BB:CC:00:00:71"
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _family_hub_observation(
                    "192.168.50.71",
                    unproven_mac,
                    getinfo=False,
                )
            ],
        )
        unproven_sleeping = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _family_hub_observation(
                    "192.168.50.71",
                    unproven_mac,
                    getinfo=False,
                )
            ],
        )
        assert unproven_sleeping["devices"] == []
        assert unproven_sleeping["identified_count"] == 0
        assert unproven_sleeping["identity_pending_count"] == 1
        unproven_cards = build_public_detected_connections(
            unproven_sleeping["identity_findings"]
        )
        assert len(unproven_cards) == 1
        assert unproven_cards[0]["display_name"].startswith("Wi-Fi 단말 · ")
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_ip_reuse_with_different_real_mac_cannot_restore_identity_history(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    old_mac = "AA:BB:CC:00:00:20"
    new_mac = "AA:BB:CC:00:00:21"

    try:
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_router("192.168.50.20", old_mac)],
        )
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_weak_device("192.168.50.20", new_mac)],
        )

        raw = repo._latest_observed_scan_devices()
        assert raw and len(raw) == 1
        assert raw[0]["mac_address"] == new_mac
        assert raw[0].get("is_unresolved") is True
        assert repo.devices() == []
        history = repo.identity_history(raw[0]["device_id"])
        assert history
        assert all(item["model"] != "A3004" for item in history)
        assert all(
            item["identity_status"] not in {"resolved", "manual_resolved"}
            for item in history
        )

        # MAC이 없는 현재 컴퓨터도 같은 IP의 과거 메인보드 제조사를
        # 물려받지 않는다. 현재 NetBIOS/SMB 관측은 실제 호스트명만 유지한다.
        ip_address = "192.168.50.65"
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _computer_observation(
                    ip_address,
                    "A8:A1:59:FE:00:08",
                    "OLD-ASROCK-PC",
                )
            ],
        )
        assert repo.devices()[0]["manufacturer"] == "ASRock"

        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _computer_observation(
                    ip_address,
                    f"UNKNOWN-{ip_address}",
                    "CURRENT-PC",
                )
            ],
        )

        raw = repo._latest_observed_scan_devices()
        assert raw and len(raw) == 1
        assert raw[0]["manufacturer"] in {"", "알 수 없음"}
        assert raw[0].get("identity_family_verified") is not True
        assert repo.devices() == []
        findings = repo.identity_findings()
        assert len(findings) == 1
        assert findings[0]["display_name"] == "current-pc"
        assert findings[0]["host_name_verified"] is True
        assert "ASRock" not in str(findings)
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_alias_follows_same_mac_on_strong_scope_but_not_a_new_ip_occupant(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    mac = "AA:BB:CC:00:00:20"

    try:
        first = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_router("192.168.50.20", mac)],
        )
        repo.set_device_alias(first["devices"][0]["device_id"], "부모님 댁 공유기")

        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_weak_device("192.168.50.77", mac)],
        )
        same_device = repo.devices()
        assert len(same_device) == 1
        assert same_device[0]["name"] == "부모님 댁 공유기"

        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_router("192.168.50.77", "AA:BB:CC:00:00:21")],
        )
        new_occupant = repo.devices()
        assert len(new_occupant) == 1
        assert new_occupant[0]["name"] != "부모님 댁 공유기"
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_scope_storage_is_opaque_and_current_view_excludes_historical_offline_devices(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    try:
        old = _router("192.168.50.21", "AA:BB:CC:00:00:21")
        current = _router("192.168.50.22", "AA:BB:CC:00:00:22")
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[old],
        )
        latest = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[current],
        )

        assert [item["ip_address"] for item in repo._stored_devices()] == ["192.168.50.22"]
        assert repo.identity_history(), "historical resolver evidence was deleted"

        stored = _stored_scan_row(repo, latest["scan_id"])
        private_context = json.loads(stored["network_context_json"])
        assert "ssid" not in private_context
        assert "bssid" not in private_context
        assert BASE_CONTEXT["ssid"] not in stored["network_context_json"]
        assert BASE_CONTEXT["bssid"] not in stored["network_context_json"]
        assert stored["network_scope_id"].startswith("hgns1b-")
        assert stored["network_scope_id"] not in json.dumps(latest, ensure_ascii=False)
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_partial_scan_observed_score_is_provisional_with_repository_parity(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    partial_context = {
        **BASE_CONTEXT,
        "scan_diagnostics": {
            "candidate_coverage_complete": False,
            "tcp_scan_timed_out": True,
            "out_of_subnet_observations_dropped": 1,
        },
    }
    try:
        created = repo.create_scan(
            scan_source="android-native",
            network_context=partial_context,
            discovered_devices=[_router("192.168.50.20", "AA:BB:CC:00:00:20")],
        )
        assert created["status"] == "partial"
        assert isinstance(created["security_score"]["score"], (int, float))
        assert created["security_score"]["score_status"] == "provisional"
        assert created["security_score"]["scan_complete"] is False
        assert created["security_score"]["coverage_complete"] is False

        status = repo.scan_status(created["scan_id"])
        assert status and status["status"] == "partial"
        assert status["score_status"] == "provisional"
        result = repo.scan_result(created["scan_id"])
        assert result and result["status"] == "partial"
        assert result["security_score"]["score"] == created["security_score"]["score"]
        assert result["security_score"]["score_status"] == "provisional"
        assert result["security_score"]["scan_complete"] is False
        current_score = repo.security_score()
        assert current_score["score"] == created["security_score"]["score"]
        assert current_score["score_status"] == "provisional"
        assert current_score["scan_complete"] is False
        dashboard = repo.dashboard()
        assert dashboard["home"]["security_score"] == current_score["score"]
        assert dashboard["summary"]["score"] == current_score["score"]
        assert dashboard["summary"]["score_status"] == "provisional"
        assert repo.latest_scan_context()["scan_diagnostics"]["candidate_coverage_complete"] is False
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_partial_identity_hold_preserves_confirmed_red_across_repository_consumers(
    tmp_path,
    repository_kind,
):
    from app.main import _scan_push_title_body

    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    partial_context = {
        **BASE_CONTEXT,
        "scan_diagnostics": {
            "candidate_coverage_complete": False,
            "tcp_scan_timed_out": True,
        },
    }
    try:
        created = repo.create_scan(
            scan_source="android-native",
            network_context=partial_context,
            discovered_devices=[
                _red_camera("192.168.50.20", "AA:BB:CC:00:00:20"),
                _weak_device("192.168.50.21", "AA:BB:CC:00:00:21"),
            ],
        )

        assert created["status"] == "partial"
        assert created["identified_count"] == 1
        assert created["identity_pending_count"] == 1
        assert len(created["identity_findings"]) == 1
        assert len(repo.identity_findings()) == 1
        assert len(repo.identity_enrichment_jobs()) == 1
        assert created["high_risk_devices"] == 1
        assert isinstance(created["security_score"]["score"], (int, float))
        assert created["security_score"]["score_status"] == "provisional"
        assert created["security_score"]["risk_level"] == "red"
        assert "확인된 위험 기기" in created["security_score"]["summary"]

        stored = json.loads(_stored_scan_row(repo, created["scan_id"])["security_score_json"])
        assert stored["score"] == created["security_score"]["score"]
        assert stored["score_status"] == "provisional"
        assert stored["risk_level"] == "red"

        result = repo.scan_result(created["scan_id"])
        score = repo.security_score()
        dashboard = repo.dashboard()
        assert result and result["security_score"]["risk_level"] == "red"
        assert result["security_score"]["score"] == created["security_score"]["score"]
        assert result["security_score"]["score_status"] == "provisional"
        assert score["risk_level"] == "red" and score["score"] == created["security_score"]["score"]
        assert score["score_status"] == "provisional"
        assert dashboard["summary"]["risk_level"] == "red"
        assert dashboard["summary"]["score"] == score["score"]
        assert dashboard["summary"]["score_status"] == "provisional"
        assert dashboard["summary"]["high_risk_devices"] == 1
        assert dashboard["top_risks"][0]["risk_level"] == "red"

        push_title, push_body, _ = _scan_push_title_body(created)
        assert push_title == "위험한 기기가 발견됐어요"
        assert "확인된 위험 1대" in push_body

        # Startup/backfill normalization must recalculate a legacy partial row
        # from its observed snapshots without deleting them.
        _replace_stored_security_score(
            repo,
            created["scan_id"],
            {"score": None, "risk_level": "yellow", "device_scores": []},
        )
        _normalize_stored_public_data(repo)
        repaired = json.loads(_stored_scan_row(repo, created["scan_id"])["security_score_json"])
        assert repaired["score"] == created["security_score"]["score"]
        assert repaired["score_status"] == "provisional"
        assert repaired["risk_level"] == "red"
        assert repaired["identity_pending_count"] == 1
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_migration_backfills_scope_and_removes_legacy_raw_wifi_identifiers(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    db_path = tmp_path / ("native.sqlite3" if repository_kind == "sqlite" else "sqlalchemy.sqlite3")
    scan = repo.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[_router("192.168.50.20", "AA:BB:CC:00:00:20")],
    )
    legacy_context = json.dumps(BASE_CONTEXT, ensure_ascii=False)
    if repository_kind == "sqlite":
        with repo._connect() as conn:
            conn.execute(
                "UPDATE scans SET network_context_json = ?, network_scope_id = NULL WHERE scan_id = ?",
                (legacy_context, scan["scan_id"]),
            )
            conn.execute(
                "DELETE FROM repository_migrations WHERE migration_id = ?",
                (_SQLITE_SCHEMA_MIGRATION_ID,),
            )
    else:
        with repo.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE scans SET network_context_json = :context, network_scope_id = NULL "
                    "WHERE scan_id = :scan_id"
                ),
                {"context": legacy_context, "scan_id": scan["scan_id"]},
            )
        repo.close()

    reopened = (
        SQLiteRepository(db_path=str(db_path))
        if repository_kind == "sqlite"
        else SqlAlchemyRepository(f"sqlite+pysqlite:///{db_path.as_posix()}")
    )
    try:
        stored = _stored_scan_row(reopened, scan["scan_id"])
        assert stored["network_scope_id"]
        assert "ssid" not in json.loads(stored["network_context_json"])
        assert "bssid" not in json.loads(stored["network_context_json"])
        assert BASE_CONTEXT["ssid"] not in stored["network_context_json"]
        assert BASE_CONTEXT["bssid"] not in stored["network_context_json"]
    finally:
        if isinstance(reopened, SqlAlchemyRepository):
            reopened.close()
        if repository_kind == "sqlite":
            sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_non_authoritative_scans_are_private_and_cannot_replace_android_state(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    try:
        address = "192.168.50.20"
        mac = "AA:BB:CC:00:00:20"
        android = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_router(address, mac)],
        )
        android_private = repo._latest_observed_scan_devices()
        assert android_private
        durable_id = android_private[0]["device_id"]
        history_count = len(repo.identity_history())

        windows = repo.record_windows_port_probe(
            network_context=BASE_CONTEXT,
            discovered_devices=[_red_camera(address, mac)],
            home_id=TEST_HOME_ID,
        )
        with pytest.raises(ValueError, match="unsupported scan source"):
            repo.create_scan(
                scan_source="windows-port-probe",
                network_context=BASE_CONTEXT,
                discovered_devices=[_red_camera(address, mac)],
            )
        with pytest.raises(ValueError, match="unsupported scan source"):
            repo.create_scan(
                scan_source="mock-api",
                network_context={},
                discovered_devices=[_red_camera(address, mac)],
            )

        # The real Windows diagnostic can be persisted for private operations,
        # but public mobile result/status getters never return it.
        assert windows["scan_source"] == "windows-port-probe"
        assert repo.scan_status(windows["scan_id"]) is None
        assert repo.scan_result(windows["scan_id"]) is None

        # Current/latest/history remain Android-native only, even when the
        # legacy scans reuse the same address-derived durable key.
        assert repo._latest_observed_scan_devices() == android_private
        assert repo.devices() == android["devices"]
        assert len(repo.identity_history()) == history_count
        assert _durable_device_source(repo, durable_id) == "android-native"
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_reopen_rebounds_legacy_android_snapshots_and_marks_partial(
    tmp_path,
    repository_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    db_path = tmp_path / ("native.sqlite3" if repository_kind == "sqlite" else "sqlalchemy.sqlite3")
    scan = repo.create_scan(
        scan_source="android-native",
        network_context=BASE_CONTEXT,
        discovered_devices=[_router("192.168.50.20", "AA:BB:CC:00:00:20")],
    )
    original = _stored_snapshot_payloads(repo, scan["scan_id"])[0]
    foreign = {
        **original,
        "device_id": "legacy-foreign-private-host",
        "ip_address": "192.168.99.20",
        "mac_address": "AA:BB:CC:99:00:20",
        "last_seen": "2026-08-20T00:00:00Z",
    }
    _insert_stored_snapshot(repo, scan["scan_id"], foreign)
    _rewrite_stored_scan_context(repo, scan["scan_id"], BASE_CONTEXT)
    sa_repo.close()

    reopened = (
        SQLiteRepository(db_path=str(db_path))
        if repository_kind == "sqlite"
        else SqlAlchemyRepository(f"sqlite+pysqlite:///{db_path.as_posix()}")
    )
    try:
        stored = _stored_snapshot_payloads(reopened, scan["scan_id"])
        row = _stored_scan_row(reopened, scan["scan_id"])
        private_context = json.loads(row["network_context_json"])
        status = reopened.scan_status(scan["scan_id"], home_id=TEST_HOME_ID)
        result = reopened.scan_result(scan["scan_id"], home_id=TEST_HOME_ID)

        assert [item["ip_address"] for item in stored] == ["192.168.50.20", "192.168.99.20"]
        assert "scan_diagnostics" not in private_context
        assert status and status["status"] == "partial"
        assert status["devices_found"] == 1
        assert result and result["status"] == "partial"
        assert result["devices_found"] == 1
        assert isinstance(result["security_score"]["score"], (int, float))
        assert result["security_score"]["score_status"] == "provisional"
        assert "192.168.99.20" not in json.dumps(result, ensure_ascii=False)
    finally:
        if isinstance(reopened, SqlAlchemyRepository):
            reopened.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("invalid_kind", ["emulator", "documentation-device"])
def test_exact_invalid_android_scan_status_and_result_are_blocked(
    tmp_path,
    repository_kind,
    invalid_kind,
):
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    try:
        scan = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[_router("192.168.50.20", "AA:BB:CC:00:00:20")],
        )
        if invalid_kind == "emulator":
            _rewrite_stored_scan_context(
                repo,
                scan["scan_id"],
                {**BASE_CONTEXT, "is_emulator": True},
            )
        else:
            snapshot = _stored_snapshot_payloads(repo, scan["scan_id"])[0]
            snapshot.update(
                {
                    "device_id": "legacy-documentation-device",
                    "ip_address": "192.0.2.20",
                    "mac_address": "AA:BB:CC:00:00:20",
                }
            )
            if isinstance(repo, SQLiteRepository):
                with repo._connect() as conn:
                    conn.execute(
                        "DELETE FROM scan_devices WHERE scan_id = ?",
                        (scan["scan_id"],),
                    )
            else:
                with repo.engine.begin() as conn:
                    conn.execute(
                        text("DELETE FROM scan_devices WHERE scan_id = :scan_id"),
                        {"scan_id": scan["scan_id"]},
                    )
            _insert_stored_snapshot(repo, scan["scan_id"], snapshot)

        assert repo.scan_status(scan["scan_id"]) is None
        assert repo.scan_result(scan["scan_id"]) is None
    finally:
        sa_repo.close()


@pytest.mark.parametrize("repository_kind", ["sqlite", "sqlalchemy"])
def test_fingerprint_mac_never_becomes_physical_identity(
    tmp_path,
    repository_kind,
    monkeypatch,
):
    from app.services import device_identity

    def fail_if_neighbor_table_is_read(*_args, **_kwargs):
        raise AssertionError("storage must not read the repository host neighbour table")

    monkeypatch.setattr(device_identity, "local_neighbor_mac", fail_if_neighbor_table_is_read)
    sqlite_repo, sa_repo = _make_repositories(tmp_path)
    repo = sqlite_repo if repository_kind == "sqlite" else sa_repo
    observation = _weak_device("192.168.50.20", "")
    observation.pop("mac_address", None)
    observation["discovery_sources"] = ["mdns"]
    observation["fingerprints"] = [
        "mdns-txt:mac=AA:BB:CC:00:00:20",
        "advertised-id:AA-BB-CC-00-00-20",
    ]
    try:
        repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[observation],
        )
        stored = repo._latest_observed_scan_devices()
        assert stored and stored[0]["mac_address"].startswith("UNKNOWN-")
        assert _stored_history_physical_macs(repo) == [None]
    finally:
        sa_repo.close()


def test_sqlite_legacy_score_rewrite_uses_each_scan_row_home_id(tmp_path):
    repo = SQLiteRepository(db_path=str(tmp_path / "multi-home-score.sqlite3"))
    scan_ids: dict[str, str] = {}
    for suffix in ("alpha", "beta"):
        home_id = f"home-{suffix}"
        repo.upsert_user(
            {
                "user_id": f"score-owner-{suffix}",
                "email": f"score-owner-{suffix}@network-scope-test.invalid",
                "nickname": f"점수 테스트 사용자 {suffix}",
                "role": "user",
                "email_verified": True,
                "home_id": home_id,
            }
        )
        scan = repo.create_scan(
            scan_source="android-native",
            network_context=BASE_CONTEXT,
            discovered_devices=[
                _red_camera(
                    f"192.168.50.{20 if suffix == 'alpha' else 21}",
                    f"AA:BB:CC:00:00:{'20' if suffix == 'alpha' else '21'}",
                )
            ],
            home_id=home_id,
        )
        scan_ids[home_id] = scan["scan_id"]
        _replace_stored_security_score(
            repo,
            scan["scan_id"],
            {"home_id": "wrong-home", "score": 100, "risk_level": "green"},
        )

    _normalize_stored_public_data(repo)

    for home_id, scan_id in scan_ids.items():
        rewritten = json.loads(_stored_scan_row(repo, scan_id)["security_score_json"])
        assert rewritten["home_id"] == home_id
        assert rewritten["risk_level"] == "red"
