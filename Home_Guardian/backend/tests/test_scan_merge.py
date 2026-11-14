"""현재 스캔과 같은 네트워크의 과거 식별 증거 병합 검증."""
import json
import sqlite3
from pathlib import Path

import pytest

from conftest import bind_repository_home
from app.services.device_presentation import build_public_detected_connections
from app.storage.sqlite_repository import (
    SQLiteRepository as RuntimeSQLiteRepository,
    _SQLITE_SCHEMA_MIGRATION_ID,
)


TEST_HOME_ID = "home-scan-merge-test"


def SQLiteRepository(*args, **kwargs):
    return bind_repository_home(RuntimeSQLiteRepository(*args, **kwargs), TEST_HOME_ID)

NC = {
    "bssid": "10:20:30:40:50:60",
    "local_ip": "192.168.50.10",
    "gateway_ip": "192.168.50.1",
    "subnet_cidr": "192.168.50.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}


def _dev(ip, name, *, mac=None, services, sources, ports=(80,), verified=True):
    fingerprints = (
        ["upnp-manufacturer:EFM Networks", "upnp-model:A3004"]
        if verified
        else []
    )
    return {
        "name": name,
        # Merge fixtures represent verified products unless a test explicitly uses
        # a weak signal. Public reads correctly exclude unresolved observations.
        "device_type": "router" if verified else "web-device",
        "manufacturer": "EFM Networks" if verified else "",
        "model": "A3004" if verified else "",
        "ip_address": ip,
        "mac_address": mac or f"UNKNOWN-{ip}",
        "open_ports": list(ports),
        "services": list(services),
        "discovery_sources": list(sources),
        "fingerprints": fingerprints,
        "vulnerabilities": [],
        "risk_signals": [],
    }


def _samsung_fridge_exact(
    *, ip: str = "192.168.50.3", mac: str = "40:CA:63:FE:00:03"
) -> dict:
    """구조화 광고에서 실제 삼성 냉장고 품번까지 확인된 관측."""

    return {
        "name": "",
        "device_type": "fridge",
        "ip_address": ip,
        "mac_address": mac,
        "manufacturer": "Samsung",
        "model": "RF85C90",
        "open_ports": [8080],
        "services": ["upnp"],
        "discovery_sources": ["ssdp"],
        "vulnerabilities": [],
        "risk_signals": [],
        "fingerprints": [
            "upnp-manufacturer:Samsung",
            "upnp-model:RF85C90",
            "upnp-type:refrigerator",
        ],
    }


def _ips(devices):
    return sorted(d["ip_address"] for d in devices)


def test_current_view_does_not_resurrect_devices_missing_from_latest_scan(tmp_path):
    repo = SQLiteRepository(db_path=str(tmp_path / "merge.db"))

    stable_mac = _dev("192.168.50.21", "공유기", mac="AA:BB:CC:11:22:33", services=["http"], sources=["ssdp"])
    stable_mdns = _dev("192.168.50.22", "TV", services=["mdns"], sources=["mdns"])
    transient = _dev("192.168.50.99", "확인되지 않은 신호", services=["media-alt"], sources=["tcp-port-probe"], ports=[8200], verified=False)
    present = _dev("192.168.50.5", "내 기기", mac="DD:EE:FF:44:55:66", services=["http"], sources=["tcp-port-probe"])

    # 스캔1: 네 기기 모두 관측
    repo.create_scan(scan_source="android-native", network_context=NC,
                     discovered_devices=[present, stable_mac, stable_mdns, transient])
    # 스캔2(최신): native 가 present 만 잡고 나머지 셋을 놓침
    latest = repo.create_scan(scan_source="android-native", network_context=NC,
                              discovered_devices=[present])

    devices = {d["ip_address"]: d for d in repo._stored_devices()}
    merged = sorted(devices)
    # 현재 목록은 최신 스캔에서 실제 관측된 항목만 포함한다. 과거의 안정적
    # MAC/mDNS 장비도 현재 온라인 또는 현재 기기처럼 되살리지 않는다.
    assert merged == ["192.168.50.5"]
    assert devices["192.168.50.5"]["online"] is True

    # 과거 관측과 식별 시도는 삭제하지 않고 private history에 보존한다.
    with repo._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_devices").fetchone()[0] == 5
    assert repo.identity_history()

    # 공개 scan_result 는 주소를 포함하지 않지만, 내부 병합 결과와 같은
    # 검증된 기기 수를 보여야 한다.
    public_devices = repo.scan_result(latest["scan_id"])["devices"]
    assert len(public_devices) == len(merged)
    assert all("ip_address" not in device and "mac_address" not in device for device in public_devices)


def test_merge_keeps_one_device_when_dhcp_changes_its_ip(tmp_path):
    """동일한 실제 MAC이 DHCP로 주소를 바꿔도 제품과 위험 상태를 잃지 않는다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "merge_dhcp.db"))
    mac = "AA:BB:CC:11:22:33"
    first = _dev("192.168.50.21", "공유기", mac=mac, services=["http"], sources=["ssdp"])
    second = _dev("192.168.50.77", "공유기", mac=mac, services=["http"], sources=["server-neighbor"])

    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[first])
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[second])

    stored = repo._stored_devices()
    assert len(stored) == 1
    assert stored[0]["ip_address"] == "192.168.50.77"
    assert stored[0]["mac_address"] == mac
    assert stored[0]["name"].startswith("ipTIME 공유기")


def test_identity_enrichment_obeys_retain_window_without_resurrecting_devices(tmp_path):
    """24시간 창은 현재 관측 장비의 증거 보강에만 쓰인다."""
    from datetime import UTC, datetime, timedelta

    repo = SQLiteRepository(db_path=str(tmp_path / "merge_time.db"))
    old = _dev("192.168.50.30", "옛 기기", mac="AA:BB:CC:00:00:01", services=["mdns"], sources=["mdns"])
    old["fingerprints"].append("http-server:Boa/0.94.14rc21")
    current = _dev("192.168.50.30", "현재 기기", mac="AA:BB:CC:00:00:01", services=["http"], sources=["tcp-port-probe"])

    s_old = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[old])
    # 그 스캔을 48시간 전으로 backdate
    old_time = (datetime.now(UTC) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
    with repo._connect() as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (old_time, s_old["scan_id"]))
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[current])

    devices = repo._stored_devices()
    assert _ips(devices) == ["192.168.50.30"]
    assert devices[0]["firmware"] == "unknown"

    # 24시간 이내(2시간 전)면 유지(미탐 방지)
    repo2 = SQLiteRepository(db_path=str(tmp_path / "merge_time2.db"))
    s_recent = repo2.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[old])
    recent_time = (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    with repo2._connect() as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (recent_time, s_recent["scan_id"]))
    repo2.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[current])
    devices2 = repo2._stored_devices()
    assert _ips(devices2) == ["192.168.50.30"]
    assert devices2[0]["online"] is True
    assert devices2[0]["firmware"] == "Boa/0.94.14rc21"


def test_identity_enrichment_obeys_twenty_scan_safety_cap(tmp_path):
    repo = SQLiteRepository(db_path=str(tmp_path / "merge-count-cap.db"))
    context = {**NC, "bssid": "10:20:30:40:50:60"}
    old = _dev(
        "192.168.50.30",
        "기기",
        mac="AA:BB:CC:00:00:01",
        services=["mdns"],
        sources=["mdns"],
    )
    old["fingerprints"].append("http-server:Boa/0.94.14rc21")
    current = _dev(
        "192.168.50.30",
        "기기",
        mac="AA:BB:CC:00:00:01",
        services=["http"],
        sources=["tcp-port-probe"],
    )
    other = _dev(
        "192.168.50.40",
        "다른 기기",
        mac="AA:BB:CC:00:00:02",
        services=["http"],
        sources=["tcp-port-probe"],
    )

    repo.create_scan(scan_source="android-native", network_context=context, discovered_devices=[old])
    for _ in range(20):
        repo.create_scan(scan_source="android-native", network_context=context, discovered_devices=[other])
    repo.create_scan(scan_source="android-native", network_context=context, discovered_devices=[current])

    devices = repo._stored_devices()
    assert _ips(devices) == ["192.168.50.30"]
    assert devices[0]["firmware"] == "unknown"


def test_merge_does_not_downgrade_confident_identity(tmp_path):
    """구조화 광고로 실제 품번까지 식별된 정체는 다음 약한 스캔에 강등되지 않는다.

    삼성 패밀리허브 냉장고의 Spotify getInfo 포트(17654)는 절전으로 간헐적으로만 열린다.
    Family Hub라는 제품군명만으로 확정하지 않고, UPnP에서 RF85C90 품번까지 확인된 뒤에는
    다음 절전 스캔이 같은 MAC을 칩 OUI/약한 서비스로만 줘도 정체가 깜빡이지 않아야 한다.
    """
    repo = SQLiteRepository(db_path=str(tmp_path / "merge_identity.db"))
    ip, mac = "192.168.50.3", "40:CA:63:FE:00:03"  # 40:CA:63 = Seongji 칩 OUI
    strong = _samsung_fridge_exact(ip=ip, mac=mac)
    weak = {
        "name": f"알 수 없는 기기 {ip}", "device_type": "audio", "ip_address": ip, "mac_address": mac,
        "manufacturer": "", "model": "LAN fingerprint", "open_ports": [17654],
        "services": ["mdns"], "discovery_sources": ["mdns"], "vulnerabilities": [], "risk_signals": [],
        "fingerprints": ["mdns-type:._spotify-connect._tcp", "mdns-name:40CA63FE0003"],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[strong])   # getInfo 성공
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[weak])     # 절전(약신호)

    devices = repo.devices()
    assert len(devices) == 1
    dev = devices[0]
    assert dev["manufacturer"] == "삼성"          # 칩셋 제조사로 덮어쓰지 않음
    assert dev["device_type"] == "fridge"
    assert dev["name"].startswith("삼성 냉장고")


def test_same_mac_familyhub_history_resolves_sleeping_appliance_family(tmp_path):
    """A sleeping Family Hub stays identified as a fridge family, not pending."""
    repo = SQLiteRepository(db_path=str(tmp_path / "familyhub_history.db"))
    mac = "40:CA:63:FE:00:03"
    awake = {
        "name": "",
        "device_type": "speaker",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "Samsung",
        "model": "Family_HUB",
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns"],
        "vulnerabilities": [],
        "risk_signals": [],
        "fingerprints": [
            "mdns-type:._spotify-connect._tcp",
            "spotify-getinfo-done",
            "spotify-brand:Samsung",
            "spotify-model:Family_HUB",
            "spotify-name:SAMSUNG FAMILY HUB (F546)",
            "spotify-type:SPEAKER",
        ],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[awake])

    sleeping = {
        "name": "",
        "device_type": "unknown",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "",
        "model": "",
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns", "server-neighbor"],
        "fingerprints": ["mdns-type:_spotify-connect._tcp.local"],
    }
    latest = repo.create_scan(
        scan_source="android-native", network_context=NC, discovered_devices=[sleeping]
    )

    devices = repo.devices()
    assert len(devices) == 1
    device = devices[0]
    assert device["name"] == "삼성 냉장고 (Family Hub)"
    assert device["manufacturer"] == "삼성"
    assert device["model"] == "Family Hub"
    assert device["device_type"] == "fridge"
    assert device["identity_status"] == "resolved"
    assert latest["identity_pending_count"] == 0


def test_same_mac_familyhub_subnet_history_migrates_to_strong_scope(tmp_path):
    """A prior subnet-only Family Hub proof survives the phone gaining L2 scope."""
    repo = SQLiteRepository(db_path=str(tmp_path / "familyhub_scope_migration.db"))
    mac = "40:CA:63:FE:00:03"
    awake = {
        "name": "",
        "device_type": "speaker",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "Samsung",
        "model": "Family_HUB",
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns"],
        "vulnerabilities": [],
        "risk_signals": [],
        "fingerprints": [
            "spotify-getinfo-done",
            "spotify-brand:Samsung",
            "spotify-model:Family_HUB",
            "spotify-name:SAMSUNG FAMILY HUB (F546)",
            "spotify-type:SPEAKER",
        ],
    }
    subnet_only_context = {key: value for key, value in NC.items() if key != "bssid"}
    repo.create_scan(
        scan_source="android-native",
        network_context=subnet_only_context,
        discovered_devices=[awake],
    )

    gateway = {
        **_dev("192.168.50.1", "공유기", mac="AA:BB:CC:50:00:01", services=["http"], sources=["ssdp"]),
    }
    sleeping = {
        "name": "",
        "device_type": "unknown",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "",
        "model": "",
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns", "server-neighbor"],
        "fingerprints": ["mdns-type:_spotify-connect._tcp.local"],
    }
    strong_scope_context = {**NC, "gateway_ip": "192.168.50.1"}
    latest = repo.create_scan(
        scan_source="android-native",
        network_context=strong_scope_context,
        discovered_devices=[gateway, sleeping],
    )

    assert latest["identity_pending_count"] == 0
    family = next(device for device in repo.devices() if device["model"] == "Family Hub")
    assert family["name"] == "삼성 냉장고 (Family Hub)"


def test_catalog_identity_is_restored_for_a_dormant_device_after_merge_window(tmp_path):
    """절전으로 광고가 끊겨도 같은 MAC의 과거 카탈로그 확정 품번은 서버가 재사용한다.

    최근 24시간 병합 범위를 지난 뒤에도 제품 자체의 MAC과 과거 resolved
    행이 일치하면, 현재 스캔의 빈 단서가 제품을 다시 미상으로 되돌리지
    않아야 한다. 이 경로는 IP/MAC를 하드코딩하는 것이 아니라 DB의
    catalog-backed identity와 현재 물리 MAC을 대조한다.
    """
    from datetime import UTC, datetime, timedelta

    repo = SQLiteRepository(db_path=str(tmp_path / "dormant_history.db"))
    mac = "40:CA:63:FE:00:03"
    strong = _samsung_fridge_exact(mac=mac)
    old_scan = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[strong])
    old_time = (datetime.now(UTC) - timedelta(days=60)).isoformat().replace("+00:00", "Z")
    with repo._connect() as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (old_time, old_scan["scan_id"]))

    dormant = {
        "name": "",
        "device_type": "unknown",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "",
        "model": "",
        "open_ports": [],
        "services": [],
        # 이번 점검에서 확인된 neighbor가 presence를 증명한다.
        # 과거 ``arp`` 캐시만으로는 확정 정체가 있어도 현재
        # 온라인으로 되살리지 않는다.
        "discovery_sources": ["android-neighbor"],
        "fingerprints": [],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[dormant])

    devices = repo.devices()
    assert len(devices) == 1
    device = devices[0]
    assert device["name"].startswith("삼성 냉장고")
    assert device["model"] == "RF85C90"
    assert device["device_type"] == "fridge"
    assert "서버에 이전에 확인된 제품 정보" in device["identity_evidence"]


def test_catalog_identity_restores_legacy_device_row_without_history(tmp_path):
    """구버전 DB처럼 identity-history가 없어도 확정 제품 행을 복원한다."""
    from datetime import UTC, datetime, timedelta

    repo = SQLiteRepository(db_path=str(tmp_path / "legacy_catalog_row.db"))
    mac = "40:CA:63:FE:00:03"
    strong = _samsung_fridge_exact(mac=mac)
    old_scan = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[strong])
    old_time = (datetime.now(UTC) - timedelta(days=60)).isoformat().replace("+00:00", "Z")
    with repo._connect() as conn:
        # Simulate the historical v0.x row: high-confidence product row,
        # but no separate device_identity_history record.
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (old_time, old_scan["scan_id"]))
        conn.execute("UPDATE devices SET confidence = 0.95")
        conn.execute("DELETE FROM device_identity_history")

    dormant = {
        "name": "",
        "device_type": "unknown",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "",
        "model": "",
        "open_ports": [],
        "services": [],
        "discovery_sources": ["android-neighbor"],
        "fingerprints": [],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[dormant])

    devices = repo.devices()
    assert len(devices) == 1
    assert devices[0]["name"].startswith("삼성 냉장고")
    assert devices[0]["model"] == "RF85C90"
    assert devices[0]["device_type"] == "fridge"


def test_catalog_identity_overrides_weak_oui_label_when_model_is_missing(tmp_path):
    """약한 칩/OUI 제조사와 Spotify 타입이 과거 확정 품번을 강등하지 않는다."""
    from datetime import UTC, datetime, timedelta

    repo = SQLiteRepository(db_path=str(tmp_path / "weak_oui_history.db"))
    mac = "40:CA:63:FE:00:03"
    strong = _samsung_fridge_exact(mac=mac)
    old_scan = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[strong])
    old_time = (datetime.now(UTC) - timedelta(days=60)).isoformat().replace("+00:00", "Z")
    with repo._connect() as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (old_time, old_scan["scan_id"]))

    # 실측과 같은 절전 재관측: 네트워크 칩 조직명과 Spotify 서비스만
    # 남고, 현재 관측에는 제품 모델이 없다. 이 정보만으로 제품을
    # 발명하지 말고, 같은 MAC의 서버 카탈로그 이력으로 복원해야 한다.
    dormant = {
        "name": "",
        "device_type": "audio",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "Seongji",
        "model": "LAN fingerprint",
        "open_ports": [17654],
        "services": ["mdns"],
        "discovery_sources": ["mdns"],
        "fingerprints": [
            "mdns-type:._spotify-connect._tcp",
            "mdns-name:40CA63FE0003",
        ],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[dormant])

    devices = repo.devices()
    assert len(devices) == 1
    assert devices[0]["name"].startswith("삼성 냉장고")
    assert devices[0]["model"] == "RF85C90"
    assert devices[0]["device_type"] == "fridge"
    assert devices[0]["identity_status"] == "resolved"


def test_catalog_identity_history_survives_current_row_being_marked_unresolved(tmp_path):
    """새 약한 관측이 기존 devices 행을 unresolved로 덮어써도 이력으로 복원한다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "history_after_unresolved.db"))
    mac = "40:CA:63:FE:00:03"
    strong = _samsung_fridge_exact(mac=mac)
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[strong])
    with repo._connect() as conn:
        # Simulate the exact production failure: a weak current observation
        # has already replaced the durable device row, while the resolved
        # identity-history evidence remains available for the same MAC.
        conn.execute(
            "UPDATE devices SET name = '', manufacturer = '삼성', model = 'RF85C90', is_unresolved = 1, confidence = 0.55"
        )

    current = {
        "name": "",
        "device_type": "audio",
        "ip_address": "192.168.50.3",
        "mac_address": mac,
        "manufacturer": "삼성",
        "model": "",
        "open_ports": [17654],
        "services": ["mdns"],
        "discovery_sources": ["mdns", "server-history"],
        "fingerprints": ["mdns-type:._spotify-connect._tcp", "spotify-model:Family_HUB"],
    }
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[current])

    devices = repo.devices()
    assert len(devices) == 1
    assert devices[0]["name"] == "삼성 냉장고 (RF85C90)"
    assert devices[0]["identity_status"] == "resolved"
    with repo._connect() as conn:
        assert conn.execute("SELECT is_unresolved FROM devices").fetchone()[0] == 0


def test_merge_keeps_repeated_weak_signal_internal_only(tmp_path):
    """반복 관측만으로 물품 종류를 확정하지 않고 공개 목록에 올리지 않는다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "merge2.db"))
    weak = _dev("192.168.50.77", "약신호 기기", services=["media-alt"], sources=["tcp-port-probe"], ports=[8200], verified=False)
    present = _dev("192.168.50.5", "내 기기", mac="DD:EE:FF:44:55:66", services=["http"], sources=["tcp-port-probe"])

    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[present, weak])
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[present, weak])
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[present])  # 최신: weak 놓침

    # 약신호 관측은 내부 증거로 보존하지만 최신 현재 목록으로 되살리지 않는다.
    assert len(repo.devices()) == 1
    raw = {d["ip_address"]: d for d in (repo._latest_observed_scan_devices() or [])}
    assert "192.168.50.77" not in raw
    with repo._connect() as conn:
        snapshots = [row[0] for row in conn.execute("SELECT device_snapshot_json FROM scan_devices").fetchall()]
    assert sum('"ip_address": "192.168.50.77"' in snapshot for snapshot in snapshots) == 2


def test_scan_completed_message_surfaces_caution_devices():
    """스캔 완료 알림이 '위험(red)' 0대여도 '주의(yellow)' 기기를 알려준다.
    (라우터 CVE 등으로 yellow 인 기기를 '위험 0대'만 보고 사용자가 놓치지 않게.)"""
    from app.storage.sqlite_repository import scan_completed_message

    def d(level):
        return {"risk_level": level}

    # 위험 0, 주의 2 → 주의를 명시해야 한다(예전엔 "위험 0대"만 보였음)
    msg = scan_completed_message([d("green"), d("yellow"), d("yellow")])
    assert "주의가 필요한 기기 2대" in msg
    # 위험이 있으면 위험 우선 표기
    assert "위험 1대" in scan_completed_message([d("red"), d("yellow")])
    assert "위험 기기 1대" in scan_completed_message([d("red"), d("green")])
    # 둘 다 없으면 안전 안내
    assert "위험·주의 기기는 없었어요" in scan_completed_message([d("green"), d("green")])
    # 완료했어도 평가 대상이 0대면 안전하다고 말하지 않는다.
    empty = scan_completed_message([])
    assert empty == "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."
    assert "안전" not in empty
    # 관측 기기는 있지만 모든 scorer가 실패한 fail-closed 결과를 원시 기기 등급만 보고
    # "위험·주의 없음"으로 뒤집어 알리지 않는다.
    failed = scan_completed_message(
        [d("green")],
        security_summary={
            "score": 0,
            "risk_level": "red",
            "device_scores": [{"device_id": "dev-1", "score": None, "risk_level": "unknown"}],
        },
    )
    assert failed == "점검은 완료됐지만 기기 점수를 계산하지 못했어요. 기기별 실패 안내를 확인해 주세요."
    assert "위험·주의 기기는 없었어요" not in failed


def test_parse_iso_normalizes_naive_to_aware_so_merge_never_crashes(tmp_path):
    """타임존 없는 타임스탬프가 섞여도 병합(aware-naive 빼기)이 크래시하지 않는다.

    모든 타임스탬프는 utc_now()로 Z(aware)지만, 형식이 하나라도 어긋나면 기기목록 전체가
    TypeError 로 죽는 단일 실패점이 된다 → _parse_iso 가 naive 를 UTC 로 통일해 방어한다.
    """
    from datetime import UTC
    from app.storage.sqlite_repository import _parse_iso

    assert _parse_iso("2026-06-17T11:00:00").tzinfo is not None          # naive → aware(UTC)
    assert _parse_iso("2026-06-17T12:00:00Z").tzinfo is not None         # aware 유지
    # aware - (정규화된 naive) 가 크래시하지 않아야 한다
    assert (_parse_iso("2026-06-17T12:00:00Z") - _parse_iso("2026-06-17T11:00:00")).total_seconds() == 3600

    # 병합 경로에서 한 스캔의 created_at 이 naive 여도 devices() 가 죽지 않는다.
    repo = SQLiteRepository(db_path=str(tmp_path / "merge_naive.db"))
    present = _dev("192.168.50.5", "내 기기", mac="DD:EE:FF:44:55:66", services=["http"], sources=["tcp-port-probe"])
    old = _dev("192.168.50.40", "옛 기기", mac="AA:BB:CC:00:00:09", services=["mdns"], sources=["mdns"])
    s_naive = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[old])
    with repo._connect() as conn:  # created_at 을 타임존 없는 형식으로 변조
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", ("2026-06-17T01:00:00", s_naive["scan_id"]))
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[present])
    ips = _ips(repo._stored_devices())  # 크래시 없이 반환되어야 한다
    assert "192.168.50.5" in ips


def test_open_port_cohorts_are_never_phantom_without_refusal_only_evidence():
    """동일 OPEN 포트·개수만으로 학원 장비를 phantom 처리하지 않는다."""
    from app.storage.sqlite_repository import (
        normalize_observed_device,
        phantom_port_echo_mask,
    )

    def bare(
        ip,
        port,
        *,
        mac=None,
        fps=(),
        sources=("tcp-port-probe",),
        manufacturer="",
        model="",
        firmware="",
    ):
        return {
            "ip_address": ip,
            "mac_address": mac or f"UNKNOWN-{ip}",
            "open_ports": [port],
            "fingerprints": list(fps),
            "discovery_sources": list(sources),
            "name": "",
            "manufacturer": manufacturer,
            "model": model,
            "firmware": firmware,
        }

    # OPEN은 주소별 실재 근거다. 한 기기든 동일 제품 수십 대든 이름,
    # 모델, 포트가 같다는 이유로 제거하지 않는다.
    singleton = bare("192.168.0.130", 49152)
    normalized = normalize_observed_device(singleton, "android-native")
    assert not normalized.get("is_phantom")
    assert normalized.get("is_unresolved") is True
    assert phantom_port_echo_mask([singleton]) == [False]
    identical_open_products = [
        bare(
            f"192.168.0.{last}",
            49152,
            manufacturer="Vendor",
            model="Same Model",
        )
        for last in range(130, 162)
    ]
    assert phantom_port_echo_mask(identical_open_products) == [False] * 32

    # 응답 전 getInfo 시도 표식만 같아도 실제 OPEN 결과를 취소할 수 없다.
    attempted_probe_echo = [
        bare(
            f"192.168.0.{last}",
            49157,
            sources=("tcp-port-probe", "spotify-getinfo"),
            fps=("spotify-probe:49157",),
        )
        for last in range(170, 178)
    ]
    assert phantom_port_echo_mask(attempted_probe_echo) == [False] * 8

    refusal_only = {
        **bare("192.168.0.200", 49159, sources=("tcp-refused-presence",)),
        "open_ports": [],
    }
    refused_but_open = bare(
        "192.168.0.201",
        49159,
        sources=("tcp-refused-presence", "tcp-port-probe"),
    )
    refused_with_mdns = {
        **bare("192.168.0.202", 49159, sources=("tcp-refused-presence", "mdns")),
        "open_ports": [],
        "fingerprints": ["mdns-name:academy-device.local"],
    }
    assert phantom_port_echo_mask(
        [refusal_only, refused_but_open, refused_with_mdns]
    ) == [True, False, False]

def test_server_banner_firmware_is_sticky_across_scans(tmp_path):
    """서버 배너(firmware)는 기기의 안정적 속성이라, native 가 한 스캔에서 배너를 일시적으로 놓쳐도
    마지막으로 잡힌 값을 유지해야 한다. 그러지 않으면 Boa 등 취약 배너로 잡힌 CVE 가 다음 스캔에
    사라져 '위험→안전' 깜빡임(거짓 안심)이 생긴다. 단 배너를 한 번도 못 본 기기는 unknown 유지(미생성).
    """
    from app.storage.scoring_helpers import scoring_with_cve

    repo = SQLiteRepository(db_path=str(tmp_path / "sticky.db"))

    def firmware_and_cves(ip):
        # Server banners remain private matching evidence until an actual product
        # identity is confirmed. Test their persistence without exposing them.
        raw = {device["ip_address"]: device for device in (repo._latest_observed_scan_devices() or [])}
        device = raw[ip]
        enriched = scoring_with_cve(device)
        return (device.get("firmware"), [v.get("cve_id") for v in (enriched.get("vulnerabilities") or [])])

    # 스캔1: Boa 배너 캡처 → firmware 승격 + CVE
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[
        {"name": "공유기 후보 192.168.50.1", "device_type": "router", "ip_address": "192.168.50.1",
         "mac_address": "AA:BB:CC:00:00:01", "open_ports": [80],
         "fingerprints": ["http-server:Boa/0.94.14rc21"], "discovery_sources": ["tcp-port-probe"]},
    ])
    assert firmware_and_cves("192.168.50.1") == ("Boa/0.94.14rc21", ["CVE-2022-45956"])

    # 스캔2: 배너 미캡처(일시적) → firmware/CVE 유지(깜빡임 없음)
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[
        {"name": "공유기 후보 192.168.50.1", "device_type": "router", "ip_address": "192.168.50.1",
         "mac_address": "AA:BB:CC:00:00:01", "open_ports": [80], "fingerprints": [], "discovery_sources": ["tcp-port-probe"]},
    ])
    fw, cves = firmware_and_cves("192.168.50.1")
    assert fw == "Boa/0.94.14rc21" and "CVE-2022-45956" in cves

    # 회귀: 배너를 한 번도 못 본 기기는 unknown 유지(가짜 firmware 생성 금지)
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[
        {"name": "x", "device_type": "computer", "ip_address": "192.168.50.9", "mac_address": "UNKNOWN-9",
         "open_ports": [139, 445], "fingerprints": [], "discovery_sources": ["tcp-port-probe"]},
    ])
    assert firmware_and_cves("192.168.50.9") == ("unknown", [])

def test_normalize_robust_to_partial_and_none_device_data():
    """실기기/native 가 불완전·이상 데이터(필드 None, 누락, 이상 MAC/포트)를 보내도 normalize 가
    크래시하면 안 된다. 한 기기가 터지면 전체 스캔이 실패(silent total fail)하기 때문이다.
    (과거 .get(key, default) 는 키가 None 값으로 존재하면 None 을 반환해 순회 시 크래시했음.)
    """
    from app.storage.sqlite_repository import normalize_observed_device

    cases = [
        {"ip_address": "192.168.0.3", "mac_address": None, "manufacturer": None, "name": None,
         "device_type": None, "fingerprints": None, "open_ports": None, "risk_signals": None,
         "services": None, "discovery_sources": None, "vulnerabilities": None},  # 모든 리스트 필드 None
        {"ip_address": "192.168.0.2"},  # 필드 거의 없음
        {"ip_address": "192.168.0.4", "open_ports": ["abc", -1, "80"], "fingerprints": [None, 123, "mdns-txt:ci=31"]},
        {"ip_address": "192.168.0.8", "name": "우리집 📷", "manufacturer": "삼성電子"},  # 유니코드/이모지
    ]
    for raw in cases:
        d = normalize_observed_device(raw, "android-native")  # 크래시하면 테스트 실패
        assert d["ip_address"] == raw["ip_address"]
        assert isinstance(d["open_ports"], list)
        assert isinstance(d["fingerprints"], list)


def _cam(mac):
    return {"name": "카메라", "device_type": "camera", "ip_address": "192.168.50.50", "mac_address": mac,
            "manufacturer": "Hikvision", "model": "DS-2CD2042WD-I", "open_ports": [554, 80], "services": ["rtsp", "http"],
            "discovery_sources": ["ws-discovery"], "fingerprints": ["upnp-manufacturer:Hikvision", "upnp-model:DS-2CD2042WD-I"], "vulnerabilities": [],
            "risk_signals": ["camera_candidate"]}


def _weak(mac):
    return {"name": "정체불명 기기", "device_type": "web-device", "ip_address": "192.168.50.50", "mac_address": mac,
            "manufacturer": "알 수 없음", "model": "LAN fingerprint", "open_ports": [80], "services": ["http"],
            "discovery_sources": ["tcp-port-probe"], "fingerprints": [], "vulnerabilities": [], "risk_signals": []}


def test_dhcp_ip_reuse_does_not_inherit_gone_device_identity(tmp_path):
    """같은 IP 라도 real MAC 이 다르면 DHCP 가 IP 를 다른 기기에 재할당한 것이다. 떠난 강정체 기기
    (카메라, MAC1)의 정체·critical CVE 를 새 점유자(약정체, MAC2)가 물려받으면 안 된다(거짓 red).
    실측 재현: 머지가 IP 로만 그룹화하고 best-identity 를 MAC 무시하고 상속해 프린터가 'Hikvision 카메라'가 됐음."""
    repo = SQLiteRepository(db_path=str(tmp_path / "reuse.db"))
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[_cam("AA:BB:CC:00:00:01")])
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[_weak("AA:BB:CC:00:00:02")])
    # 새 점유자는 약신호이므로 공개하지 않는다. 핵심은 떠난 카메라 정체가
    # 새 MAC에 붙어 공개되는 일이 없다는 것이다.
    assert repo.devices() == []
    raw = {x["ip_address"]: x for x in (repo._latest_observed_scan_devices() or [])}["192.168.50.50"]
    assert raw.get("is_unresolved") is True
    assert raw["mac_address"] == "AA:BB:CC:00:00:02"


def test_same_mac_flicker_keeps_strong_identity(tmp_path):
    """반대로 *같은* real MAC 의 깜빡임(강신호→약신호)은 stickiness 가 유지돼야 한다(미탐 방지).
    DHCP 가드가 정당한 같은-기기 병합까지 막으면 안 된다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "flicker.db"))
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[_cam("AA:BB:CC:00:00:01")])
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[_weak("AA:BB:CC:00:00:01")])
    devices = repo.devices()
    assert len(devices) == 1
    d = devices[0]
    assert d["device_type"] == "camera", "같은 MAC 인데 강정체 stickiness 가 깨짐"
    assert d["manufacturer"] == "하이크비전"


def test_service_only_signals_stay_private_but_l2_endpoints_remain_visible(tmp_path):
    """서비스-only 행은 비공개로 두고 physical MAC/fresh neighbor는 센다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "counts.db"))
    corroborated = {"name": "", "device_type": "unknown", "ip_address": "192.168.50.1",
                    "mac_address": "02:00:00:50:00:01", "manufacturer": "", "model": "", "open_ports": [80],
                    "services": ["http"], "discovery_sources": ["mdns"],
                    "fingerprints": ["mdns-type:_example._tcp"], "risk_signals": []}
    singleton = {"name": "", "device_type": "unknown", "ip_address": "192.168.50.190",
                 "mac_address": "UNKNOWN-192.168.50.190", "open_ports": [49153], "services": ["tcp-49153"],
                 "discovery_sources": ["tcp-port-probe"], "fingerprints": [], "risk_signals": []}
    neighbor = {"name": "", "device_type": "unknown", "ip_address": "192.168.50.191",
                "mac_address": "UNKNOWN-192.168.50.191", "open_ports": [49152], "services": ["tcp-49152"],
                "discovery_sources": ["tcp-port-probe", "android-neighbor"], "fingerprints": [], "risk_signals": []}
    small_cohort = [
        {"name": "", "device_type": "unknown", "ip_address": f"192.168.50.{last}",
         "mac_address": f"UNKNOWN-192.168.50.{last}", "open_ports": [49154], "services": ["tcp-49154"],
         "discovery_sources": ["tcp-port-probe"], "fingerprints": [], "risk_signals": []}
        for last in range(210, 217)
    ]
    echo_cohort = [
        {"name": "", "device_type": "unknown", "ip_address": f"192.168.50.{last}",
         "mac_address": f"UNKNOWN-192.168.50.{last}", "open_ports": [17654], "services": ["spotify-connect"],
         "discovery_sources": ["tcp-port-probe", "spotify-getinfo"],
         "fingerprints": ["spotify-probe:17654"], "risk_signals": []}
        for last in range(200, 208)
    ]
    result = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[corroborated, singleton, neighbor, *small_cohort, *echo_cohort],
    )
    assert result["devices_found"] == 2
    assert result["identified_count"] == 0
    assert result["identity_pending_count"] == 2
    assert result["high_risk_devices"] == 0
    raw = {item["ip_address"]: item for item in (repo._latest_observed_scan_devices() or [])}
    assert not raw[corroborated["ip_address"]].get("is_phantom")
    assert not raw[singleton["ip_address"]].get("is_phantom")
    assert not raw[neighbor["ip_address"]].get("is_phantom")
    assert all(not raw[item["ip_address"]].get("is_phantom") for item in small_cohort)
    assert all(not raw[item["ip_address"]].get("is_phantom") for item in echo_cohort)

    # 18개 관측은 모두 private snapshot과 자동조사 작업에 남는다. 이 중
    # physical MAC 1개와 fresh neighbor 1개만 실제 L2 단말로 공개한다.
    msgs = [n["message"] for n in repo.notifications() if n.get("type") == "scan_completed"]
    assert msgs and "기기 2대" in msgs[0]
    assert "현재 Wi-Fi 이웃 확인" not in msgs[0]
    assert "18대" not in msgs[0]
    # scan_result(앱 3화면 공통 소스)도 동일
    scan_result = repo.scan_result(result["scan_id"])
    assert scan_result["devices_found"] == 2
    assert scan_result["identity_pending_count"] == 2
    assert len(scan_result["identity_findings"]) == 18
    public_cards = build_public_detected_connections(scan_result["identity_findings"])
    assert len(public_cards) == 2
    assert all(card["display_name"].startswith("Wi-Fi 단말 · ") for card in public_cards)
    assert {card["device_id"] for card in public_cards} == {
        item["device_id"]
        for item in scan_result["identity_findings"]
        if item.get("observed_service") == "neighbor-presence"
    }
    assert "현재 Wi-Fi 이웃 확인" not in str(scan_result)
    assert len(repo.identity_findings()) == 18
    assert len(repo.identity_enrichment_jobs()) == 18


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_identical_open_port_hosts_are_all_preserved(tmp_path, repository_kind):
    """동일 서비스 장비가 8대 이상이어도 주소별 OPEN 관측을 모두 유지한다."""

    if repository_kind == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "same-open-port.db"))
    else:
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{(tmp_path / 'same-open-port-sa.db').as_posix()}"
            ),
            TEST_HOME_ID,
        )
    observed = [
        {
            "name": "학원 컴퓨터",
            "device_type": "computer",
            "ip_address": f"192.168.50.{last}",
            "mac_address": f"UNKNOWN-192.168.50.{last}",
            "manufacturer": "",
            "model": "",
            "open_ports": [445],
            "services": ["smb"],
            "discovery_sources": ["tcp-port-probe"],
            "fingerprints": [],
            "risk_signals": [],
        }
        for last in range(100, 112)
    ]

    result = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=observed,
    )

    assert result["devices_found"] == 12
    assert result["identified_count"] == 0
    assert result["identity_pending_count"] == 12
    snapshot = repo._latest_observed_scan_devices() or []
    assert len(snapshot) == 12
    assert all(not item.get("is_phantom") for item in snapshot)
    assert {item["ip_address"] for item in snapshot} == {
        item["ip_address"] for item in observed
    }


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_operational_refusal_fanout_keeps_all_real_observations(
    tmp_path,
    repository_kind,
):
    """운영 회귀: refusal 51개만 버리고 실제 근거가 있는 33개는 모두 보존한다.

    현장 로그 형태(스캐너 1개 + refusal-only 51개 + 실제 연결 33개)를
    재현한다. 실제 연결 32개가 같은 화면용 이름·종류여도 IP와 각 mDNS
    응답 근거가 다르면 서로 다른 장비다. 이름이나 모델 유사성으로 합치면
    학원처럼 동일 제품이 여러 대 있는 네트워크를 다시 누락하게 된다.
    """

    if repository_kind == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "refusal-fanout.db"))
    else:
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{(tmp_path / 'refusal-fanout-sa.db').as_posix()}"
            ),
            TEST_HOME_ID,
        )
    real_device = _cam("AA:BB:CC:50:00:50")
    scanner_self = {
        "name": "점검 휴대폰",
        "device_type": "phone",
        "ip_address": NC["local_ip"],
        "mac_address": "AA:BB:CC:50:00:10",
        "manufacturer": "Samsung",
        "model": "SM-S921N",
        "open_ports": [],
        "services": ["self-device"],
        "discovery_sources": ["self"],
        "fingerprints": ["self-model:SM-S921N"],
        "risk_signals": ["self_device"],
    }
    refusal_only = [
        {
            "name": "",
            "device_type": "unknown",
            "ip_address": f"192.168.50.{last}",
            "mac_address": f"UNKNOWN-192.168.50.{last}",
            "manufacturer": "",
            "model": "",
            "open_ports": [],
            "services": [],
            "discovery_sources": [
                "tcp-refused-presence"
                if last % 2
                else "server-tcp-refused-presence"
            ],
            "fingerprints": [],
            "risk_signals": [],
        }
        for last in range(150, 201)
    ]
    # 모든 행은 같은 화면용 이름과 같은 종류지만, 각각 다른 주소에서
    # 고유한 mDNS 응답을 제공한다. refusal 표시는 부가 전송 진단일 뿐이며
    # 독립된 mDNS 근거가 함께 있으면 그 실제 관측을 제거해서는 안 된다.
    real_unresolved = [
        {
            "name": "학원 컴퓨터",
            "device_type": "computer",
            "ip_address": f"192.168.50.{last}",
            "mac_address": f"UNKNOWN-192.168.50.{last}",
            "manufacturer": "",
            "model": "",
            "open_ports": [],
            "services": ["mdns"],
            "discovery_sources": ["tcp-refused-presence", "mdns"],
            "fingerprints": [
                f"mdns-name:academy-pc-{last}.local",
                "mdns-type:_workstation._tcp.local",
            ],
            "risk_signals": [],
        }
        for last in range(100, 132)
    ]

    result = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[scanner_self, real_device, *real_unresolved, *refusal_only],
    )

    assert result["devices_found"] == 33
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 32
    assert len(result["devices"]) == 1
    assert len(result["identity_findings"]) == 32
    assert len(repo.identity_enrichment_jobs()) == 32

    private_snapshot = repo._latest_observed_scan_devices() or []
    assert len(private_snapshot) == 85
    assert sum(bool(item.get("is_phantom")) for item in private_snapshot) == 51
    real_ips = {item["ip_address"] for item in real_unresolved}
    preserved_real = {
        item["ip_address"]
        for item in private_snapshot
        if item["ip_address"] in real_ips and not item.get("is_phantom")
    }
    assert preserved_real == real_ips
    assert len(repo.devices()) == 1
    if repository_kind == "sqlite":
        with repo._connect() as conn:
            durable_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            snapshot_count = conn.execute("SELECT COUNT(*) FROM scan_devices").fetchone()[0]
    else:
        from sqlalchemy import text

        with repo.engine.begin() as conn:
            durable_count = conn.execute(text("SELECT COUNT(*) FROM devices")).scalar_one()
            snapshot_count = conn.execute(text("SELECT COUNT(*) FROM scan_devices")).scalar_one()
    # Refusal telemetry remains only in the immutable scan snapshot for
    # diagnosis. The scanner itself and all 33 independently observed devices
    # remain durable, while none of the 51 refusal-only rows are promoted.
    assert durable_count == 34
    assert snapshot_count == 85

    scan_result = repo.scan_result(result["scan_id"])
    assert scan_result["devices_found"] == 33
    assert scan_result["identity_pending_count"] == 32
    messages = [
        item["message"]
        for item in repo.notifications()
        if "확인했" in item.get("message", "")
    ]
    assert messages and "기기 33대" in messages[0]
    assert "51" not in messages[0]


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_stale_arp_is_phantom_and_fresh_neighbors_remain_public_findings(
    tmp_path,
    repository_kind,
):
    """과거 ARP는 phantom, fresh neighbor는 현재 L2 단말로 공개한다."""

    if repository_kind == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "stale-arp.db"))
    else:
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{(tmp_path / 'stale-arp-sa.db').as_posix()}"
            ),
            TEST_HOME_ID,
        )

    def presence_observation(last: int, source: str, mac: str) -> dict:
        return {
            "name": "학원 컴퓨터",
            "device_type": "computer",
            "ip_address": f"192.168.50.{last}",
            # ARP-only에서는 이 MAC 자체도 캐시의 일부이므로 freshness가
            # 아니다. neighbor source가 같이 있을 때만 현재 근거다.
            "mac_address": mac,
            "manufacturer": "",
            "model": "",
            "open_ports": [],
            "services": [],
            "discovery_sources": [source],
            "fingerprints": [],
            "risk_signals": [],
        }

    stale_android_arp = presence_observation(
        140, "android-arp", "AA:BB:CC:50:01:40"
    )
    stale_server_arp = presence_observation(141, "arp", "AA:BB:CC:50:01:41")
    fresh_android_neighbor = presence_observation(
        142, "android-neighbor", "AA:BB:CC:50:01:42"
    )
    fresh_server_neighbor = presence_observation(
        143, "server-neighbor", "AA:BB:CC:50:01:43"
    )
    exact_product = _cam("AA:BB:CC:50:01:44")

    result = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[
            exact_product,
            stale_android_arp,
            stale_server_arp,
            fresh_android_neighbor,
            fresh_server_neighbor,
        ],
    )

    assert result["devices_found"] == 3
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 2
    assert len(result["identity_findings"]) == 2
    assert len(repo.identity_enrichment_jobs()) == 2

    snapshot = repo._latest_observed_scan_devices() or []
    assert len(snapshot) == 5
    by_ip = {item["ip_address"]: item for item in snapshot}
    assert by_ip["192.168.50.140"].get("is_phantom") is True
    assert by_ip["192.168.50.141"].get("is_phantom") is True
    assert not by_ip["192.168.50.142"].get("is_phantom")
    assert not by_ip["192.168.50.143"].get("is_phantom")

    scan_result = repo.scan_result(result["scan_id"])
    assert scan_result is not None
    assert scan_result["devices_found"] == 3
    assert scan_result["identity_pending_count"] == 2
    public_cards = build_public_detected_connections(scan_result["identity_findings"])
    assert len(public_cards) == 2
    assert all(card["display_name"].startswith("Wi-Fi 단말 · ") for card in public_cards)
    assert len({card["device_id"] for card in public_cards}) == 2
    messages = [
        item["message"]
        for item in repo.notifications()
        if item.get("type") == "scan_completed"
    ]
    assert messages and "기기 3대" in messages[0]
    assert "5대" not in messages[0]


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_approved_identity_never_revives_a_fresh_stale_arp_observation(
    tmp_path,
    repository_kind,
):
    """제품 승인은 정체만 증명하며 최신 presence를 증명하지 않는다."""

    if repository_kind == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "approved-stale-arp.db"))
    else:
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{(tmp_path / 'approved-stale-arp-sa.db').as_posix()}"
            ),
            TEST_HOME_ID,
        )

    mac = "AA:BB:CC:50:02:60"
    first = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[_weak(mac)],
    )
    assert first["devices_found"] == 1
    assert first["identity_pending_count"] == 1
    first_cards = build_public_detected_connections(first["identity_findings"])
    assert len(first_cards) == 1
    assert first_cards[0]["display_name"].startswith("Wi-Fi 단말 · ")
    assert len(first["identity_findings"]) == 1
    assert len(repo.identity_findings()) == 1
    jobs = repo.identity_enrichment_jobs(status_filter="review_required")
    assert len(jobs) == 1
    repo.resolve_identity_enrichment_job(
        jobs[0]["job_id"],
        manufacturer="Samsung",
        device_type="fridge",
        model="RF85C90N1AP",
        source_reference="https://www.samsung.com/sec/refrigerators/RF85C90N1AP/",
    )

    stale_arp = {
        "name": "",
        "device_type": "unknown",
        "ip_address": "192.168.50.50",
        "mac_address": mac,
        "manufacturer": "",
        "model": "",
        "open_ports": [],
        "services": [],
        "discovery_sources": ["arp"],
        "fingerprints": [],
        "risk_signals": [],
    }
    latest = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[stale_arp],
    )

    assert latest["devices_found"] == 0
    assert latest["identified_count"] == 0
    assert latest["identity_pending_count"] == 0
    assert latest["devices"] == []
    assert latest["identity_findings"] == []
    assert repo.devices() == []
    current = repo._latest_observed_scan_devices() or []
    assert len(current) == 1
    assert current[0].get("is_phantom") is True


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_reopen_reclassifies_legacy_refusal_only_snapshot(
    tmp_path,
    repository_kind,
):
    """배포 직후 과거 refusal/ARP-only 행을 현재 장비로 되살리지 않는다."""

    database_path = tmp_path / f"legacy-refusal-{repository_kind}.db"

    def open_repository():
        if repository_kind == "sqlite":
            return SQLiteRepository(db_path=str(database_path))
        from app.storage.sa_repository import SqlAlchemyRepository

        return bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{database_path.as_posix()}"
            ),
            TEST_HOME_ID,
        )

    repo = open_repository()
    real_device = _cam("AA:BB:CC:50:00:61")
    refusal = {
        "name": "연결된 장비",
        "device_type": "unknown",
        "ip_address": "192.168.50.160",
        "mac_address": "UNKNOWN-192.168.50.160",
        "manufacturer": "",
        "model": "",
        "open_ports": [],
        "services": [],
        "discovery_sources": ["server-tcp-refused-presence"],
        "fingerprints": [],
        "risk_signals": [],
    }
    stale_arp = {
        "name": "학원 컴퓨터",
        "device_type": "computer",
        "ip_address": "192.168.50.161",
        "mac_address": "AA:BB:CC:50:01:61",
        "manufacturer": "",
        "model": "",
        "open_ports": [],
        "services": [],
        "discovery_sources": ["android-arp"],
        "fingerprints": [],
        "risk_signals": [],
    }
    # 24시간 병합 창 안에 같은 MAC의 과거 확정 제품이 있어도,
    # 식별 정보만 보강할 수 있을 뿐 최신 stale-ARP presence 판정을
    # 해제하면 안 된다.
    repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[
            _samsung_fridge_exact(
                ip=stale_arp["ip_address"],
                mac=stale_arp["mac_address"],
            )
        ],
    )
    created = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[real_device, refusal, stale_arp],
    )
    assert created["devices_found"] == 1
    assert created["identified_count"] == 1
    assert created["identity_pending_count"] == 0
    artifact_snapshots = [
        item
        for item in (repo._latest_observed_scan_devices() or [])
        if item["ip_address"] in {refusal["ip_address"], stale_arp["ip_address"]}
    ]
    assert len(artifact_snapshots) == 2
    assert all(item.get("is_phantom") is True for item in artifact_snapshots)
    artifact_ids = {item["device_id"] for item in artifact_snapshots}

    # 과거 버전이 이 행을 ordinary device로 저장하고 식별 작업까지 열어 둔
    # 상태를 DB에 재현한다. 현재 코드로 새 스캔을 만드는 것만으로는 이
    # 배포 직후 회귀를 검증할 수 없으므로 저장 결과만 의도적으로 되돌린다.
    if repository_kind == "sqlite":
        with repo._connect() as conn:
            scope_id = conn.execute(
                "SELECT network_scope_id FROM scans WHERE scan_id = ?",
                (created["scan_id"],),
            ).fetchone()[0]
    else:
        from sqlalchemy import text

        with repo.engine.begin() as conn:
            scope_id = conn.execute(
                text("SELECT network_scope_id FROM scans WHERE scan_id = :scan_id"),
                {"scan_id": created["scan_id"]},
            ).scalar_one()
    repo._upsert_identity_enrichment_jobs(
        artifact_snapshots,
        home_id=TEST_HOME_ID,
        network_scope_id=scope_id,
    )

    if repository_kind == "sqlite":
        with repo._connect() as conn:
            rows = conn.execute(
                "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ?",
                (created["scan_id"],),
            ).fetchall()
            for row in rows:
                snapshot = json.loads(row["device_snapshot_json"])
                if snapshot.get("device_id") not in artifact_ids:
                    continue
                snapshot["is_phantom"] = False
                conn.execute(
                    "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
                    (json.dumps(snapshot, ensure_ascii=False), row["id"]),
                )
            conn.execute(
                "UPDATE identity_enrichment_jobs SET status = 'review_required', "
                "blocked_reason = NULL WHERE device_id IN (?, ?)",
                tuple(sorted(artifact_ids)),
            )
            conn.execute(
                "UPDATE scans SET devices_found = 3 WHERE scan_id = ?",
                (created["scan_id"],),
            )
            conn.execute(
                "UPDATE notifications SET message = ? WHERE scan_id = ? ",
                (
                    "제품 1개와 추가 연결 2개를 확인했어요.",
                    created["scan_id"],
                ),
            )
            conn.execute(
                "DELETE FROM repository_migrations WHERE migration_id = ?",
                (_SQLITE_SCHEMA_MIGRATION_ID,),
            )
    else:
        from sqlalchemy import text

        with repo.engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT id, device_snapshot_json FROM scan_devices "
                    "WHERE scan_id = :scan_id"
                ),
                {"scan_id": created["scan_id"]},
            ).mappings().all()
            for row in rows:
                snapshot = json.loads(row["device_snapshot_json"])
                if snapshot.get("device_id") not in artifact_ids:
                    continue
                snapshot["is_phantom"] = False
                conn.execute(
                    text(
                        "UPDATE scan_devices SET device_snapshot_json = :snapshot "
                        "WHERE id = :id"
                    ),
                    {
                        "snapshot": json.dumps(snapshot, ensure_ascii=False),
                        "id": row["id"],
                    },
                )
            conn.execute(
                text(
                    "UPDATE identity_enrichment_jobs SET status = 'review_required', "
                    "blocked_reason = NULL WHERE device_id IN (:first_id, :second_id)"
                ),
                {
                    "first_id": sorted(artifact_ids)[0],
                    "second_id": sorted(artifact_ids)[1],
                },
            )
            conn.execute(
                text("UPDATE scans SET devices_found = 3 WHERE scan_id = :scan_id"),
                {"scan_id": created["scan_id"]},
            )
            conn.execute(
                text(
                    "UPDATE notifications SET message = :message "
                    "WHERE scan_id = :scan_id"
                ),
                {
                    "message": "제품 1개와 추가 연결 2개를 확인했어요.",
                    "scan_id": created["scan_id"],
                },
            )
        repo.close()

    reopened = open_repository()
    result = reopened.scan_result(created["scan_id"])
    assert result is not None
    assert result["devices_found"] == 1
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 0
    assert len(reopened.devices()) == 1
    current_snapshot = reopened._latest_observed_scan_devices() or []
    artifacts_after_reopen = [
        item
        for item in current_snapshot
        if item["ip_address"] in {refusal["ip_address"], stale_arp["ip_address"]}
    ]
    assert len(artifacts_after_reopen) == 2
    assert all(item.get("is_phantom") is True for item in artifacts_after_reopen)
    assert reopened.identity_enrichment_jobs(status_filter="review_required") == []
    quarantined = [
        job
        for job in reopened.identity_enrichment_jobs()
        if job["device_id"] in artifact_ids
    ]
    assert len(quarantined) == 2
    assert all(job["status"] == "superseded" for job in quarantined)
    completion_messages = [
        item["message"]
        for item in reopened.notifications()
        if item.get("type") == "scan_completed"
    ]
    assert completion_messages and "기기 1대" in completion_messages[0]
    assert "추가 연결" not in completion_messages[0]


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_legacy_invalid_resolution_is_quarantined_before_constraint_copy(
    tmp_path,
    repository_kind,
):
    """이전 resolved 행을 먼저 격리해 스키마 교체가 전체 실패하지 않는다."""

    database_path = tmp_path / f"legacy-invalid-resolution-{repository_kind}.db"
    with sqlite3.connect(database_path) as conn:
        conn.executescript(
            """
            CREATE TABLE homes (
                home_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL
            );
            INSERT INTO homes (home_id, name, mode)
            VALUES ('home-scan-merge-test', '테스트 홈', 'user');

            CREATE TABLE identity_enrichment_jobs (
                job_id TEXT PRIMARY KEY,
                job_key TEXT NOT NULL UNIQUE,
                home_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                network_scope_id TEXT,
                physical_mac TEXT,
                evidence_binding_signature TEXT,
                status TEXT NOT NULL CHECK (
                    status IN ('review_required', 'resolved', 'rejected', 'blocked')
                ),
                blocked_reason TEXT,
                evidence_json TEXT NOT NULL,
                evidence_signature TEXT NOT NULL,
                seen_count INTEGER NOT NULL CHECK (seen_count >= 1),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolution_json TEXT,
                source_reference TEXT,
                resolution_provenance TEXT,
                resolution_signature TEXT,
                resolved_at TEXT
            );
            INSERT INTO identity_enrichment_jobs (
                job_id, job_key, home_id, device_id, network_scope_id,
                physical_mac, evidence_binding_signature, status,
                blocked_reason, evidence_json,
                evidence_signature, seen_count, first_seen_at, last_seen_at,
                updated_at, resolution_json, source_reference,
                resolution_provenance, resolution_signature, resolved_at
            ) VALUES (
                'legacy-invalid-job', 'legacy-invalid-key',
                'home-scan-merge-test', 'device-legacy-invalid',
                'hgns1b-0123456789abcdef0123456789abcdef', NULL, NULL,
                'resolved', NULL, '{}', 'legacy-evidence-signature', 1,
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                '2026-01-01T00:00:00Z',
                '{"manufacturer":"Samsung","model":"RF85C90"}',
                'https://www.samsung.com/sec/refrigerators/',
                'operator-reviewed', 'legacy-signed-value',
                '2026-01-01T00:00:00Z'
            );
            INSERT INTO identity_enrichment_jobs (
                job_id, job_key, home_id, device_id, network_scope_id,
                physical_mac, evidence_binding_signature, status,
                blocked_reason, evidence_json, evidence_signature, seen_count,
                first_seen_at, last_seen_at, updated_at, resolution_json,
                source_reference, resolution_provenance, resolution_signature,
                resolved_at
            ) VALUES (
                'legacy-malformed-binding-job', 'legacy-malformed-binding-key',
                'home-scan-merge-test', 'device-legacy-malformed-binding',
                'hgns1b-0123456789abcdef0123456789abcdef', NULL,
                'hges1-garbage', 'resolved', NULL, '{}',
                'legacy-evidence-signature-2', 1,
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                '2026-01-01T00:00:00Z',
                '{"manufacturer":"Samsung","model":"RF85C90"}',
                'https://www.samsung.com/sec/refrigerators/',
                'operator-reviewed', 'legacy-signed-value-2',
                '2026-01-01T00:00:00Z'
            );
            """
        )

    if repository_kind == "sqlite":
        repo = RuntimeSQLiteRepository(db_path=str(database_path))
        with repo._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM identity_enrichment_jobs ORDER BY job_id"
            ).fetchall()
            create_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'identity_enrichment_jobs'"
            ).fetchone()[0]
    else:
        from sqlalchemy import text
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = SqlAlchemyRepository(
            f"sqlite+pysqlite:///{database_path.as_posix()}"
        )
        with repo.engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM identity_enrichment_jobs ORDER BY job_id"
                )
            ).mappings().all()
            create_sql = conn.execute(
                text(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'identity_enrichment_jobs'"
                )
            ).scalar_one()

    assert len(rows) == 2
    for row in rows:
        assert row["status"] == "review_required"
        assert row["blocked_reason"] == "INVALID_LEGACY_RESOLUTION_REVIEW_REQUIRED"
        assert row["resolution_json"] is None
        assert row["source_reference"] is None
        assert row["resolution_signature"] is None
    assert "'superseded'" in str(create_sql)
    assert "evidence_binding_signature IS NOT NULL" in str(create_sql)
    if repository_kind == "sqlalchemy":
        repo.close()


def test_postgres_schema_quarantines_legacy_resolutions_before_constraints():
    """정적 PostgreSQL 배포 스키마도 같은 안전 순서를 지킨다."""

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "storage"
        / "postgres_schema.sql"
    )
    schema = schema_path.read_text(encoding="utf-8")
    unsigned_quarantine = schema.index(
        "UNSIGNED_LEGACY_RESOLUTION_REVIEW_REQUIRED"
    )
    invalid_quarantine = schema.index(
        "INVALID_LEGACY_RESOLUTION_REVIEW_REQUIRED"
    )
    first_constraint_replacement = schema.index("DO $$", invalid_quarantine)
    assert unsigned_quarantine < invalid_quarantine < first_constraint_replacement


@pytest.mark.parametrize("repository_kind", ("sqlite", "sqlalchemy"))
def test_identical_product_evidence_keeps_distinct_hosts(tmp_path, repository_kind):
    """학원처럼 동일 모델 여러 대가 있어도 서로 다른 실제 호스트는 모두 보존한다."""

    if repository_kind == "sqlite":
        repo = SQLiteRepository(db_path=str(tmp_path / "identical-products.db"))
    else:
        from app.storage.sa_repository import SqlAlchemyRepository

        repo = bind_repository_home(
            SqlAlchemyRepository(
                f"sqlite+pysqlite:///{(tmp_path / 'identical-products-sa.db').as_posix()}"
            ),
            TEST_HOME_ID,
        )
    first = _cam("AA:BB:CC:50:00:51")
    second = {
        **_cam("AA:BB:CC:50:00:52"),
        "ip_address": "192.168.50.51",
    }

    result = repo.create_scan(
        scan_source="android-native",
        network_context=NC,
        discovered_devices=[first, second],
    )

    assert result["devices_found"] == 2
    assert result["identified_count"] == 2
    assert result["identity_pending_count"] == 0
    assert len(result["devices"]) == 2
    private_snapshot = repo._latest_observed_scan_devices() or []
    assert len(private_snapshot) == 2
    assert all(not item.get("is_phantom") for item in private_snapshot)
    assert len(repo.devices()) == 2


def test_scan_result_does_not_recount_historical_identity_findings(tmp_path):
    """과거 약한 관측은 재식별 이력으로만 남고 최신 결과의 대기 수에 누적되지 않는다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "historical-findings.db"))
    real = _dev(
        "192.168.50.1",
        "공유기",
        mac="AA:BB:CC:50:00:01",
        services=["http"],
        sources=["ssdp"],
    )
    weak = _dev(
        "192.168.50.200",
        "확인되지 않은 신호",
        services=["telnet"],
        sources=["tcp-port-probe"],
        ports=[23],
        verified=False,
    )

    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[real, weak])
    # The same weak observation is stable enough for private merge history.
    repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[real, weak])
    latest = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[real])

    result = repo.scan_result(latest["scan_id"])
    assert result is not None
    assert result["identity_pending_count"] == 0
    assert result["devices_found"] == 1
    assert result["identity_findings"] == []


def test_scanner_self_observation_is_not_a_household_device(tmp_path):
    """스캔을 수행한 휴대폰은 공개 기기·점수·대기 수에 포함하지 않는다."""
    repo = SQLiteRepository(db_path=str(tmp_path / "self-observation.db"))
    self_device = {
        "name": "삼성 휴대폰",
        "device_type": "phone",
        "manufacturer": "Samsung",
        "model": "SM-T720",
        "ip_address": "192.168.50.10",
        "mac_address": "AA:BB:CC:50:00:10",
        "open_ports": [],
        "services": ["self-device"],
        "discovery_sources": ["self"],
        "fingerprints": ["self-model:SM-T720"],
        "vulnerabilities": [],
        "risk_signals": ["self_device"],
    }
    router = _dev(
        "192.168.50.1",
        "공유기",
        mac="AA:BB:CC:50:00:01",
        services=["http"],
        sources=["ssdp"],
    )

    result = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=[self_device, router])
    assert result["devices_found"] == 1
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 0
    assert all(device["model"] != "SM-T720" for device in result["devices"])
    assert all(device["model"] != "SM-T720" for device in repo.devices())

