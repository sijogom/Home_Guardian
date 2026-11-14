from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, insert, select

from app.storage.sa_repository import (
    SqlAlchemyRepository,
    device_identity_history_table,
    identity_enrichment_jobs_table,
    scan_devices_table,
    scans_table,
)


HOME_ID = "home-sa-public-scan-contract"
CONTEXT = {
    "ssid": "Home Guardian Test Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.60.10",
    "gateway_ip": "192.168.60.1",
    "subnet_cidr": "192.168.60.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
    "scan_diagnostics": {
        "candidate_coverage_complete": True,
        "candidate_stimulation_complete": True,
        "tcp_transport_complete": True,
        "wifi_network_socket_binding_complete": True,
        "tcp_scan_timed_out": False,
    },
}


def make_repository(tmp_path, name: str, *, home_id: str = HOME_ID) -> SqlAlchemyRepository:
    repository = SqlAlchemyRepository(
        f"sqlite+pysqlite:///{(tmp_path / name).as_posix()}"
    )
    repository.upsert_user(
        {
            "user_id": f"owner-{home_id}",
            "email": f"{home_id}@sa-contract.invalid",
            "nickname": "SQLAlchemy 계약 테스트 사용자",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )
    return repository


def router() -> dict[str, object]:
    return {
        "name": "ipTIME 공유기 (A3004)",
        "device_type": "router",
        "manufacturer": "EFM Networks",
        "model": "A3004",
        "ip_address": "192.168.60.1",
        "mac_address": "B0:38:29:FE:00:09",
        "open_ports": [],
        "services": ["upnp"],
        "discovery_sources": ["ssdp", "upnp"],
        "fingerprints": [
            "upnp-manufacturer:EFM Networks",
            "upnp-model:A3004",
            "ssdp:InternetGatewayDevice",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
        "default_credentials": False,
        "encryption": "WPA3",
        "firmware": "1.0.0",
    }


def bare_tcp(ip_address: str, port: int, *, red: bool = False) -> dict[str, object]:
    return {
        "name": "",
        "device_type": "web-device",
        "manufacturer": "",
        "model": "",
        "ip_address": ip_address,
        "mac_address": f"UNKNOWN-{ip_address}",
        "open_ports": [port],
        "services": ["https-alt"],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": [f"tcp:{port}"],
        "risk_signals": ["default_credentials_possible"] if red else [],
        "vulnerabilities": (
            [{"cve_id": "CVE-2099-0001", "severity": "critical", "cvss": 10.0}]
            if red
            else []
        ),
    }


def family_hub(*, token: str, mac_address: str, getinfo: bool) -> dict[str, object]:
    fingerprints = [
        f"mdns-name:{token}",
        "mdns-type:._spotify-connect._tcp",
    ]
    if getinfo:
        fingerprints.extend(
            [
                "spotify-getinfo-done",
                "spotify-brand:Samsung",
                "spotify-model:Family_HUB",
                "spotify-name:SAMSUNG FAMILY HUB (F546)",
                "spotify-type:SPEAKER",
            ]
        )
    return {
        "name": "",
        "device_type": "speaker" if getinfo else "unknown",
        "manufacturer": "Samsung" if getinfo else "",
        "model": "Family_HUB" if getinfo else "",
        "ip_address": "192.168.60.3",
        "mac_address": mac_address,
        "open_ports": [17654] if getinfo else [],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns", "spotify-getinfo"] if getinfo else ["mdns"],
        "fingerprints": fingerprints,
        "risk_signals": [],
        "vulnerabilities": [],
    }


def insert_unrelated_history_snapshots(
    repository: SqlAlchemyRepository,
    *,
    after_scan_id: str,
    home_id: str,
    count: int = 401,
) -> None:
    """Place unrelated valid JSON rows ahead of one historical proof row."""

    noise_scan_id = f"{after_scan_id}-unrelated-history"
    snapshots = [
        {
            "scan_id": noise_scan_id,
            "device_snapshot_json": json.dumps(
                {
                    "mac_address": (
                        f"02:AA:{(index >> 24) & 0xFF:02X}:{(index >> 16) & 0xFF:02X}:"
                        f"{(index >> 8) & 0xFF:02X}:{index & 0xFF:02X}"
                    ),
                    "fingerprints": [
                        f"mdns-name:{0xA00000000000 + index:012X}",
                        "mdns-type:_spotify-connect._tcp.local",
                    ],
                },
                ensure_ascii=False,
            ),
        }
        for index in range(count)
    ]
    with repository.engine.begin() as conn:
        source_scan = conn.execute(
            select(
                scans_table.c.network_context_json,
                scans_table.c.network_scope_id,
            ).where(scans_table.c.scan_id == after_scan_id)
        ).mappings().one()
        conn.execute(
            insert(scans_table).values(
                scan_id=noise_scan_id,
                home_id=home_id,
                status="completed",
                progress=100,
                scan_profile="comprehensive",
                scan_source="android-native",
                network_context_json=source_scan["network_context_json"],
                network_scope_id=source_scan["network_scope_id"],
                current_step="점검 완료",
                devices_found=count,
                high_risk_devices=0,
                security_score_json="{}",
                created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        )
        conn.execute(insert(scan_devices_table), snapshots)


def assert_visible_aggregate_has_only_router(payload: dict[str, object]) -> None:
    assert payload["devices_found"] == 1
    assert payload["identity_pending_count"] == 0
    assert payload["high_risk_devices"] == 0
    assert payload["current_step"] == "점검 완료"


def test_sa_bare_transport_findings_stay_raw_but_never_inflate_public_aggregate(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        "home_guardian_ml.hybrid_scoring.predict_attack_probability",
        lambda _device: None,
    )
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'transport-contract.db').as_posix()}"
    repository = SqlAlchemyRepository(database_url)
    repository.upsert_user(
        {
            "user_id": "owner-transport-contract",
            "email": "transport-contract@sa-contract.invalid",
            "nickname": "전송 계층 계약 테스트",
            "role": "user",
            "email_verified": True,
            "home_id": HOME_ID,
        }
    )
    try:
        created = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                router(),
                bare_tcp("192.168.60.183", 8443),
                bare_tcp("192.168.60.221", 49155, red=True),
            ],
            home_id=HOME_ID,
        )
        assert_visible_aggregate_has_only_router(created)
        assert created["status"] == "completed"
        assert len(created["devices"]) == 1
        assert len(created["identity_findings"]) == 2
        assert created["events"] == []
        assert created["security_score"]["identity_incomplete"] is False
        assert created["security_score"]["identity_pending_count"] == 0
        assert len(created["security_score"]["device_scores"]) == 1

        raw_findings = repository.identity_findings(home_id=HOME_ID)
        assert len(raw_findings) == 2
        assert any(finding["risk_level"] == "red" for finding in raw_findings)
        assert repository.security_events(home_id=HOME_ID) == []

        with repository.engine.begin() as conn:
            stored = conn.execute(
                select(
                    scans_table.c.devices_found,
                    scans_table.c.high_risk_devices,
                    scans_table.c.current_step,
                    scans_table.c.security_score_json,
                ).where(scans_table.c.scan_id == created["scan_id"])
            ).mappings().one()
            snapshot_count = conn.execute(
                select(func.count())
                .select_from(scan_devices_table)
                .where(scan_devices_table.c.scan_id == created["scan_id"])
            ).scalar_one()
            job_count = conn.execute(
                select(func.count()).select_from(identity_enrichment_jobs_table)
            ).scalar_one()
        assert stored["devices_found"] == 1
        assert stored["high_risk_devices"] == 0
        assert stored["current_step"] == "점검 완료"
        stored_score = json.loads(stored["security_score_json"])
        assert stored_score["identity_pending_count"] == 0
        assert stored_score["identity_incomplete"] is False
        assert snapshot_count == 3
        assert job_count == 2

        status = repository.scan_status(created["scan_id"], home_id=HOME_ID)
        assert status is not None
        assert_visible_aggregate_has_only_router(status)
        result = repository.scan_result(created["scan_id"], home_id=HOME_ID)
        assert result is not None
        assert_visible_aggregate_has_only_router(result)
        assert len(result["identity_findings"]) == 2
        assert result["events"] == []
        dashboard = repository.dashboard(home_id=HOME_ID)
        assert dashboard["home"]["device_count"] == 1
        assert dashboard["home"]["identity_pending_count"] == 0
        assert dashboard["summary"]["high_risk_devices"] == 0
        assert dashboard["summary"]["identity_pending_count"] == 0
        assert dashboard["identity_findings"] == []
    finally:
        repository.close()

    reopened = SqlAlchemyRepository(database_url)
    try:
        status = reopened.scan_status(created["scan_id"], home_id=HOME_ID)
        result = reopened.scan_result(created["scan_id"], home_id=HOME_ID)
        assert status is not None and result is not None
        assert_visible_aggregate_has_only_router(status)
        assert_visible_aggregate_has_only_router(result)
        assert len(result["identity_findings"]) == 2
        assert len(reopened.identity_findings(home_id=HOME_ID)) == 2
        assert reopened.security_events(home_id=HOME_ID) == []
    finally:
        reopened.close()


def test_sa_hidden_red_transport_has_no_score_risk_or_event_effect(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "home_guardian_ml.hybrid_scoring.predict_attack_probability",
        lambda _device: None,
    )
    baseline = make_repository(tmp_path, "baseline.db")
    with_hidden_red = make_repository(tmp_path, "hidden-red.db")
    try:
        baseline_scan = baseline.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[router()],
            home_id=HOME_ID,
        )
        red_scan = with_hidden_red.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[router(), bare_tcp("192.168.60.221", 49155, red=True)],
            home_id=HOME_ID,
        )

        assert red_scan["high_risk_devices"] == baseline_scan["high_risk_devices"] == 0
        assert red_scan["events"] == baseline_scan["events"] == []
        assert red_scan["security_score"]["score"] == baseline_scan["security_score"]["score"]
        assert (
            red_scan["security_score"]["risk_level"]
            == baseline_scan["security_score"]["risk_level"]
        )
        assert (
            red_scan["security_score"]["device_scores"]
            == baseline_scan["security_score"]["device_scores"]
        )
        assert len(red_scan["identity_findings"]) == 1
        assert red_scan["identity_findings"][0]["risk_level"] == "red"
    finally:
        baseline.close()
        with_hidden_red.close()


def test_sa_family_hub_uses_attested_token_without_promoting_it_to_mac(tmp_path):
    repository = make_repository(tmp_path, "familyhub-token.db", home_id="home-sa-familyhub-token")
    home_id = "home-sa-familyhub-token"
    try:
        repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token="40CA63FE0003",
                    mac_address="40:CA:63:FE:00:03",
                    getinfo=True,
                )
            ],
            home_id=home_id,
        )
        sleeping = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token="40CA63FE0003",
                    mac_address="UNKNOWN-192.168.60.3",
                    getinfo=False,
                )
            ],
            home_id=home_id,
        )

        assert sleeping["devices_found"] == 1
        assert sleeping["identified_count"] == 1
        assert sleeping["identity_pending_count"] == 0
        assert len(sleeping["devices"]) == 1
        device = sleeping["devices"][0]
        assert device["manufacturer"] == "삼성"
        assert device["model"] == "Family Hub"
        assert device["device_type"] == "fridge"

        with repository.engine.begin() as conn:
            current_snapshot_json = conn.execute(
                select(scan_devices_table.c.device_snapshot_json)
                .where(scan_devices_table.c.scan_id == sleeping["scan_id"])
                .order_by(scan_devices_table.c.id.asc())
            ).scalar_one()
        current_snapshot = json.loads(current_snapshot_json)
        assert current_snapshot["mac_address"] == "UNKNOWN-192.168.60.3"
        assert "40:CA:63:FE:00:03" not in json.dumps(current_snapshot, ensure_ascii=False)
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("current_mac", "case_name"),
    [
        ("40:CA:63:FE:00:03", "physical-mac"),
        ("UNKNOWN-192.168.60.3", "advertised-token"),
    ],
)
def test_sa_family_hub_candidate_lookup_ignores_401_newer_unrelated_snapshots(
    tmp_path,
    current_mac,
    case_name,
):
    home_id = f"home-sa-familyhub-candidate-{case_name}"
    repository = make_repository(
        tmp_path,
        f"familyhub-candidate-{case_name}.db",
        home_id=home_id,
    )
    token = "40CA63FE0003"
    try:
        historical = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token=token,
                    mac_address="40:CA:63:FE:00:03",
                    getinfo=True,
                )
            ],
            home_id=home_id,
        )
        insert_unrelated_history_snapshots(
            repository,
            after_scan_id=historical["scan_id"],
            home_id=home_id,
        )

        sleeping = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token=token,
                    mac_address=current_mac,
                    getinfo=False,
                )
            ],
            home_id=home_id,
        )

        assert sleeping["identity_pending_count"] == 0
        assert sleeping["identified_count"] == 1
        assert len(sleeping["devices"]) == 1
        assert sleeping["devices"][0]["name"] == "삼성 냉장고 (Family Hub)"
        assert sleeping["devices"][0]["model"] == "Family Hub"
        assert sleeping["devices"][0]["device_type"] == "fridge"
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("current_token", "current_mac"),
    [
        ("40CA63FE0004", "UNKNOWN-192.168.60.3"),
        ("40CA63FE0003", "not-a-mac"),
    ],
    ids=["token-mismatch", "malformed-current-mac"],
)
def test_sa_family_hub_unbound_current_claim_does_not_restore_identity(
    tmp_path,
    current_token,
    current_mac,
):
    repository = make_repository(
        tmp_path,
        "familyhub-token-mismatch.db",
        home_id="home-sa-familyhub-token-mismatch",
    )
    home_id = "home-sa-familyhub-token-mismatch"
    try:
        repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token="40CA63FE0003",
                    mac_address="40:CA:63:FE:00:03",
                    getinfo=True,
                )
            ],
            home_id=home_id,
        )
        mismatched = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token=current_token,
                    mac_address=current_mac,
                    getinfo=False,
                )
            ],
            home_id=home_id,
        )

        assert mismatched["devices"] == []
        assert mismatched["identified_count"] == 0
        assert all(
            finding.get("display_name") != "삼성 냉장고 (Family Hub)"
            for finding in mismatched["identity_findings"]
        )
        with repository.engine.begin() as conn:
            snapshot_json = conn.execute(
                select(scan_devices_table.c.device_snapshot_json)
                .where(scan_devices_table.c.scan_id == mismatched["scan_id"])
            ).scalar_one()
        snapshot = json.loads(snapshot_json)
        assert snapshot.get("model") != "Family Hub"
        assert snapshot.get("manufacturer") not in {"Samsung", "삼성"}
    finally:
        repository.close()


def test_sa_legacy_unscoped_family_hub_history_matches_sqlite_contract(tmp_path):
    home_id = "home-sa-legacy-unscoped-familyhub"
    repository = make_repository(
        tmp_path,
        "legacy-unscoped-familyhub.db",
        home_id=home_id,
    )
    token = "40CA63FE0003"
    physical_mac = "40:CA:63:FE:00:03"
    try:
        historical = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token=token,
                    mac_address=physical_mac,
                    getinfo=True,
                )
            ],
            home_id=home_id,
        )
        with repository.engine.begin() as conn:
            conn.execute(
                scans_table.update()
                .where(scans_table.c.scan_id == historical["scan_id"])
                .values(network_scope_id=None)
            )
            conn.execute(
                device_identity_history_table.update()
                .where(device_identity_history_table.c.home_id == home_id)
                .values(network_scope_id=None, physical_mac=None)
            )

        sleeping = repository.create_scan(
            scan_source="android-native",
            network_context=CONTEXT,
            discovered_devices=[
                family_hub(
                    token=token,
                    mac_address=physical_mac,
                    getinfo=False,
                )
            ],
            home_id=home_id,
        )

        assert sleeping["devices_found"] == 1
        assert sleeping["identified_count"] == 1
        assert sleeping["identity_pending_count"] == 0
        assert len(sleeping["devices"]) == 1
        device = sleeping["devices"][0]
        assert device["manufacturer"] == "삼성"
        assert device["model"] == "Family Hub"
        assert device["device_type"] == "fridge"
    finally:
        repository.close()
