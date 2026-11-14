from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from conftest import bind_repository_home

from app.services.device_presentation import build_public_detected_connections
from app.storage.sqlite_repository import SQLiteRepository


HOME_ID = "home-sqlite-public-contract"
NETWORK_CONTEXT = {
    "ssid": "Home Guardian Test Wi-Fi",
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.50.10",
    "gateway_ip": "192.168.50.1",
    "subnet_cidr": "192.168.50.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
    "scan_diagnostics": {
        "candidate_stimulation_complete": True,
        "tcp_transport_complete": True,
        "wifi_binding_verified": True,
        "scan_timeout_reached": False,
    },
}


def _repository(db_path, *, home_id: str = HOME_ID) -> SQLiteRepository:
    return bind_repository_home(SQLiteRepository(db_path=db_path), home_id)


def _router() -> dict:
    return {
        "name": "",
        "device_type": "router",
        "manufacturer": "EFM Networks",
        "model": "A3004",
        "ip_address": "192.168.50.1",
        "mac_address": "B0:38:6A:00:00:01",
        "open_ports": [80],
        "services": ["http"],
        "encryption": "wpa3",
        "discovery_sources": ["upnp", "android-neighbor"],
        "fingerprints": [
            "upnp-manufacturer:EFM Networks",
            "upnp-model:A3004",
        ],
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _bare_tcp(ip_address: str, port: int, *, red: bool = False) -> dict:
    return {
        "name": "",
        "device_type": "unknown",
        "manufacturer": "",
        "model": "",
        "ip_address": ip_address,
        "mac_address": f"UNKNOWN-{ip_address}",
        "open_ports": [port],
        "services": [f"tcp-{port}"],
        "discovery_sources": ["tcp-port-probe"],
        "fingerprints": [f"tcp:{port}"],
        "risk_signals": ["default_credentials_possible"] if red else [],
        "vulnerabilities": (
            [{"cve_id": "CVE-2099-9999", "severity": "critical", "cvss": 10.0}]
            if red
            else []
        ),
    }


def _family_hub(
    *,
    ip_address: str,
    token: str,
    mac_address: str,
    structured_getinfo: bool,
) -> dict:
    fingerprints = [
        f"mdns-name:{token}",
        "mdns-type:_spotify-connect._tcp.local",
    ]
    if structured_getinfo:
        fingerprints.extend(
            [
                "spotify-getinfo-done",
                "spotify-brand:Samsung",
                "spotify-model:Family_HUB",
                "spotify-name:SAMSUNG FAMILY HUB (F546)",
            ]
        )
    return {
        "name": "",
        "device_type": "speaker" if structured_getinfo else "unknown",
        "manufacturer": "Samsung" if structured_getinfo else "",
        "model": "Family_HUB" if structured_getinfo else "",
        "ip_address": ip_address,
        "mac_address": mac_address,
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns", "server-neighbor"],
        "fingerprints": fingerprints,
        "risk_signals": [],
        "vulnerabilities": [],
    }


def _insert_unrelated_history_snapshots(
    repository: SQLiteRepository,
    *,
    after_scan_id: str,
    home_id: str,
    count: int = 401,
) -> None:
    """Place unrelated valid JSON rows ahead of one historical proof row."""

    noise_scan_id = f"{after_scan_id}-unrelated-history"
    created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    snapshots = [
        json.dumps(
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
        )
        for index in range(count)
    ]
    with repository._connect() as conn:
        source_scan = conn.execute(
            "SELECT network_context_json, network_scope_id FROM scans WHERE scan_id = ?",
            (after_scan_id,),
        ).fetchone()
        assert source_scan is not None
        conn.execute(
            """
            INSERT INTO scans (
                scan_id, home_id, status, progress, scan_profile, scan_source,
                network_context_json, network_scope_id, current_step,
                devices_found, high_risk_devices, security_score_json, created_at
            ) VALUES (?, ?, 'completed', 100, 'comprehensive', 'android-native',
                      ?, ?, '점검 완료', ?, 0, '{}', ?)
            """,
            (
                noise_scan_id,
                home_id,
                source_scan["network_context_json"],
                source_scan["network_scope_id"],
                count,
                created_at,
            ),
        )
        conn.executemany(
            "INSERT INTO scan_devices (scan_id, device_snapshot_json) VALUES (?, ?)",
            [(noise_scan_id, snapshot) for snapshot in snapshots],
        )


def test_bare_tcp_rows_remain_private_without_inflating_public_scan_aggregate(tmp_path):
    db_path = tmp_path / "public-contract.sqlite3"
    repository = _repository(db_path)
    created = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _router(),
            _bare_tcp("192.168.50.183", 8443),
            _bare_tcp("192.168.50.221", 49155),
        ],
    )

    assert len(created["identity_findings"]) == 2
    assert created["devices_found"] == 1
    assert created["identity_pending_count"] == 0
    assert created["current_step"] == "점검 완료"
    assert created["security_score"]["identity_incomplete"] is False
    assert created["security_score"]["score_status"] == "final"
    assert created["security_score"]["scan_complete"] is True

    with repository._connect() as conn:
        snapshot_count = conn.execute(
            "SELECT COUNT(*) FROM scan_devices WHERE scan_id = ?",
            (created["scan_id"],),
        ).fetchone()[0]
        stored_scan = conn.execute(
            "SELECT status, current_step, devices_found, high_risk_devices, security_score_json "
            "FROM scans WHERE scan_id = ?",
            (created["scan_id"],),
        ).fetchone()
        jobs = conn.execute(
            "SELECT evidence_json FROM identity_enrichment_jobs WHERE home_id = ?",
            (HOME_ID,),
        ).fetchall()
    assert snapshot_count == 3
    assert len(jobs) == 2
    assert all(
        json.loads(row["evidence_json"])["discovery_sources"] == ["tcp-port-probe"]
        for row in jobs
    )
    assert stored_scan["status"] == "completed"
    assert stored_scan["current_step"] == "점검 완료"
    assert stored_scan["devices_found"] == 1
    assert json.loads(stored_scan["security_score_json"])["identity_pending_count"] == 0

    # The research API deliberately retains the raw candidates. Public status,
    # result, dashboard and score aggregates use only visible device rows.
    assert len(repository.identity_findings()) == 2
    status = repository.scan_status(created["scan_id"])
    result = repository.scan_result(created["scan_id"])
    assert status is not None and status["devices_found"] == 1
    assert status["identity_pending_count"] == 0
    assert result is not None and result["devices_found"] == 1
    assert result["identity_pending_count"] == 0
    assert len(result["identity_findings"]) == 2
    assert repository.dashboard()["summary"]["identity_pending_count"] == 0
    assert repository.security_score()["identity_pending_count"] == 0

    reopened = _repository(db_path)
    reopened_status = reopened.scan_status(created["scan_id"])
    reopened_result = reopened.scan_result(created["scan_id"])
    assert reopened_status is not None and reopened_status["devices_found"] == 1
    assert reopened_status["identity_pending_count"] == 0
    assert reopened_result is not None and reopened_result["devices_found"] == 1
    assert reopened_result["identity_pending_count"] == 0
    with reopened._connect() as conn:
        reopened_scan = conn.execute(
            "SELECT devices_found, current_step, security_score_json FROM scans WHERE scan_id = ?",
            (created["scan_id"],),
        ).fetchone()
    assert reopened_scan["devices_found"] == 1
    assert reopened_scan["current_step"] == "점검 완료"
    assert json.loads(reopened_scan["security_score_json"])["identity_pending_count"] == 0


def test_hidden_red_transport_row_cannot_change_score_risk_or_events(tmp_path):
    repository = _repository(tmp_path / "hidden-red.sqlite3", home_id=f"{HOME_ID}-red")
    baseline = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[_router()],
    )
    combined = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _router(),
            _bare_tcp("192.168.50.183", 8443, red=True),
        ],
    )

    raw_findings = repository.identity_findings()
    assert len(raw_findings) == 1
    assert raw_findings[0]["risk_level"] == "red"
    assert combined["devices_found"] == 1
    assert combined["identity_pending_count"] == 0
    assert combined["high_risk_devices"] == 0
    baseline_event_keys = {
        (event["device_id"], event["severity"], event["title"])
        for event in baseline["events"]
    }
    combined_event_keys = {
        (event["device_id"], event["severity"], event["title"])
        for event in combined["events"]
    }
    assert combined_event_keys == baseline_event_keys
    assert all(
        event["device_id"] != raw_findings[0]["device_id"]
        for event in combined["events"]
    )
    assert combined["security_score"]["score"] == baseline["security_score"]["score"]
    assert combined["security_score"]["risk_level"] == baseline["security_score"]["risk_level"]
    assert all(
        row["device_id"] != raw_findings[0]["device_id"]
        for row in combined["security_score"]["device_scores"]
    )
    assert {
        (event["device_id"], event["severity"], event["title"])
        for event in repository.security_events()
    } == baseline_event_keys


def test_family_hub_token_continuity_recovers_family_without_promoting_token_to_mac(tmp_path):
    repository = _repository(tmp_path / "family-hub-token.sqlite3", home_id=f"{HOME_ID}-hub")
    token = "40CA63FE0003"
    physical_mac = "40:CA:63:FE:00:03"
    repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address=physical_mac,
                structured_getinfo=True,
            )
        ],
    )
    sleeping = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address="UNKNOWN-192.168.50.3",
                structured_getinfo=False,
            )
        ],
    )

    assert sleeping["identity_pending_count"] == 0
    assert sleeping["identified_count"] == 1
    assert len(sleeping["devices"]) == 1
    device = sleeping["devices"][0]
    assert device["name"] == "삼성 냉장고 (Family Hub)"
    assert device["manufacturer"] == "삼성"
    assert device["model"] == "Family Hub"
    assert device["device_type"] == "fridge"
    raw_current = repository._latest_scan_devices_only(f"{HOME_ID}-hub")
    assert raw_current is not None and len(raw_current) == 1
    assert raw_current[0]["mac_address"] == "UNKNOWN-192.168.50.3"


@pytest.mark.parametrize(
    ("current_mac", "case_name"),
    [
        ("40:CA:63:FE:00:03", "physical-mac"),
        ("UNKNOWN-192.168.50.3", "advertised-token"),
    ],
)
def test_family_hub_candidate_lookup_ignores_401_newer_unrelated_snapshots(
    tmp_path,
    current_mac,
    case_name,
):
    home_id = f"{HOME_ID}-candidate-{case_name}"
    repository = _repository(
        tmp_path / f"family-hub-candidate-{case_name}.sqlite3",
        home_id=home_id,
    )
    token = "40CA63FE0003"
    historical = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address="40:CA:63:FE:00:03",
                structured_getinfo=True,
            )
        ],
    )
    _insert_unrelated_history_snapshots(
        repository,
        after_scan_id=historical["scan_id"],
        home_id=home_id,
    )

    sleeping = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address=current_mac,
                structured_getinfo=False,
            )
        ],
    )

    assert sleeping["identity_pending_count"] == 0
    assert sleeping["identified_count"] == 1
    assert len(sleeping["devices"]) == 1
    assert sleeping["devices"][0]["name"] == "삼성 냉장고 (Family Hub)"
    assert sleeping["devices"][0]["model"] == "Family Hub"
    assert sleeping["devices"][0]["device_type"] == "fridge"


def test_family_hub_token_mismatch_does_not_reuse_history(tmp_path):
    repository = _repository(tmp_path / "family-hub-mismatch.sqlite3", home_id=f"{HOME_ID}-mismatch")
    repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token="40CA63FE0003",
                mac_address="40:CA:63:FE:00:03",
                structured_getinfo=True,
            )
        ],
    )
    mismatch = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.4",
                token="40CA63FE0004",
                mac_address="UNKNOWN-192.168.50.4",
                structured_getinfo=False,
            )
        ],
    )

    assert mismatch["devices"] == []
    assert mismatch["identified_count"] == 0
    # The token mismatch must not reuse Family Hub identity. Fresh neighbor
    # presence remains visible as an unresolved endpoint, without inventing a
    # Family Hub product identity from the mismatched token.
    assert mismatch["identity_pending_count"] == 1
    assert mismatch["identity_findings"][0]["display_name"].startswith("Wi-Fi 단말 · ")
    assert len(build_public_detected_connections(mismatch["identity_findings"])) == 1
    assert "현재 Wi-Fi 이웃 확인" not in str(mismatch)
    assert "Family Hub" not in str(mismatch["identity_findings"])
    assert len(repository.identity_findings()) == 1


def test_legacy_unscoped_family_hub_history_uses_current_real_mac_and_token(tmp_path):
    home_id = f"{HOME_ID}-legacy-unscoped-hub"
    repository = _repository(
        tmp_path / "legacy-unscoped-family-hub.sqlite3",
        home_id=home_id,
    )
    token = "40CA63FE0003"
    physical_mac = "40:CA:63:FE:00:03"
    historical = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address=physical_mac,
                structured_getinfo=True,
            )
        ],
    )
    with repository._connect() as conn:
        conn.execute(
            "UPDATE scans SET network_scope_id = NULL WHERE scan_id = ?",
            (historical["scan_id"],),
        )
        conn.execute(
            "UPDATE device_identity_history "
            "SET network_scope_id = NULL, physical_mac = NULL "
            "WHERE home_id = ?",
            (home_id,),
        )

    sleeping = repository.create_scan(
        network_context=NETWORK_CONTEXT,
        discovered_devices=[
            _family_hub(
                ip_address="192.168.50.3",
                token=token,
                mac_address=physical_mac,
                structured_getinfo=False,
            )
        ],
    )

    assert sleeping["identity_pending_count"] == 0
    assert sleeping["identified_count"] == 1
    assert len(sleeping["devices"]) == 1
    device = sleeping["devices"][0]
    assert device["name"] == "삼성 냉장고 (Family Hub)"
    assert device["model"] == "Family Hub"
    assert device["device_type"] == "fridge"
