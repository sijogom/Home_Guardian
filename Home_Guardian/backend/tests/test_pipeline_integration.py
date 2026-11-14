"""전체 탐지 파이프라인 통합 검증 — 이번 세션 수정(냉장고/유령/Boa/jargon/native우회)이 함께 동작하는지.

scan 제출 → normalize 저장 → 병합 → enrich(identity+CVE) → 유령 분리 까지 실제 경로로 한 번에 검증한다.
단위 테스트가 각 조각을 보장하지만, 통합에서 서로 간섭하지 않는지(회귀)를 영구 고정한다.

**중요(운영 형식)**: 입력은 합성 단축형이 아니라 *실제 네이티브가 보내는 형식*을 쓴다. 즉 ① HTTP 서버 배너는
model/firmware 가 아니라 `http-server:` fingerprint 로, ② device_type 은 네이티브가 프로토콜만 보고 단정한
값('tv'=googlecast, 'hub'=homekit)으로 준다. 이렇게 해야 "합성 테스트는 통과하나 운영에선 휴면"인 버그
(native device_type 우위, 배너 형식 불일치)를 이 테스트가 실제로 잡는다.
"""
from app.storage.scoring_helpers import scoring_with_cve, visible_identity_findings
from app.storage.sqlite_repository import SQLiteRepository as RuntimeSQLiteRepository
from conftest import bind_repository_home


TEST_HOME_ID = "home-pipeline-integration-test"


def SQLiteRepository(*args, **kwargs):
    return bind_repository_home(RuntimeSQLiteRepository(*args, **kwargs), TEST_HOME_ID)

NC = {
    "local_ip": "192.168.0.5",
    "gateway_ip": "192.168.0.1",
    "subnet_cidr": "192.168.0.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}


def test_full_pipeline_real_world_mix(tmp_path):
    repo = SQLiteRepository(db_path=str(tmp_path / "pipe.db"))
    scanned = [
        # 절전 냉장고: native 가 _spotify-connect 보고 audio 로 보냄, getInfo 없음 → 'Seongji 오디오' 금지
        {
            "name": "스피커 후보 192.168.0.3", "device_type": "audio", "ip_address": "192.168.0.3",
            "mac_address": "UNKNOWN-192.168.0.3", "open_ports": [17654],
            "fingerprints": ["mdns-name:40CA63FE0003", "mdns-type:._spotify-connect._tcp"],
            "discovery_sources": ["mdns", "tcp-port-probe"], "vulnerabilities": [], "risk_signals": [],
        },
        # SMB PC: 139/445 → computer 유지(미탐 금지)
        {
            "name": "알 수 없는 기기 192.168.0.2", "device_type": "unknown", "ip_address": "192.168.0.2",
            "mac_address": "UNKNOWN-192.168.0.2", "open_ports": [139, 445],
            "fingerprints": [], "discovery_sources": ["tcp-port-probe"], "vulnerabilities": [], "risk_signals": [],
        },
        # 학원 PC처럼 동일 단일 포트를 여럿이 열어도 주소별 OPEN 관측은
        # 각각 실제 연결이다. cohort 크기만으로 제거하면 안 된다.
        *[
            {
                "name": "", "device_type": "unknown", "ip_address": f"192.168.0.{last}",
                "mac_address": f"UNKNOWN-192.168.0.{last}", "open_ports": [49152],
                "fingerprints": [], "discovery_sources": ["tcp-port-probe"], "vulnerabilities": [], "risk_signals": [],
            }
            for last in range(130, 138)
        ],
        # 반대로 실제 응답·neighbor·광고 없이 refusal만 있는 주소는
        # 중간 장비의 일괄 응답일 수 있으므로 제품/연결 수에서 제외한다.
        {
            "name": "", "device_type": "unknown", "ip_address": "192.168.0.139",
            "mac_address": "UNKNOWN-192.168.0.139", "open_ports": [],
            "fingerprints": [], "discovery_sources": ["tcp-refused-presence"],
            "vulnerabilities": [], "risk_signals": [],
        },
        # Boa 취약 웹서버 공유기(제조사 미상): CVE-2022-45956 잡혀야(미탐 방지).
        # *운영 형식*: 배너는 model/firmware 가 아니라 http-server:/ssdp-server: fingerprint 로만 온다.
        # native 가 'tplink' 등으로 deviceTypeHint 를 못 정하면 device_type 도 약하게 온다.
        {
            "name": "공유기 후보 192.168.0.1", "device_type": "router", "ip_address": "192.168.0.1",
            "mac_address": "UNKNOWN-192.168.0.1",
            "open_ports": [80], "fingerprints": ["http-server:Boa/0.94.14rc21", "ssdp-server:Boa/0.94.14rc21"],
            "discovery_sources": ["tcp-port-probe", "ssdp"], "vulnerabilities": [], "risk_signals": [],
        },
        # Nest Mini: *운영 형식* — native 가 googlecast 보고 device_type='tv' 로 단정해 보냄.
        # 백엔드가 md=Nest Mini 로 speaker 재판정해야(native 'tv' 우위에 우회되면 안 됨).
        {
            "name": "스피커 후보 192.168.0.12", "device_type": "tv", "ip_address": "192.168.0.12",
            "mac_address": "UNKNOWN-192.168.0.12", "open_ports": [8009],
            "fingerprints": ["mdns-type:._googlecast._tcp", "mdns-txt:md=Nest Mini"],
            "discovery_sources": ["mdns"], "vulnerabilities": [], "risk_signals": [],
        },
        # HomeKit Hue 전구: *운영 형식* — native 가 'hue' 보고 device_type='hub' 로 단정해 보냄.
        # 백엔드가 ci=5 로 light 재판정해야(native 'hub' 우위에 우회되면 안 됨).
        {
            "name": "스마트홈 후보 192.168.0.16", "device_type": "hub", "ip_address": "192.168.0.16",
            "mac_address": "UNKNOWN-192.168.0.16", "open_ports": [80],
            "fingerprints": ["mdns-type:._hap._tcp", "mdns-txt:ci=5", "mdns-txt:md=Hue lamp"],
            "discovery_sources": ["mdns"], "vulnerabilities": [], "risk_signals": [],
        },
        # Sonos: native 가 audio 로 주고 제조사 미추출 → 백엔드가 _sonos 로 Sonos 추출 + CVE-2018-11316(미탐 방지).
        {
            "name": "스피커 후보 192.168.0.17", "device_type": "audio", "ip_address": "192.168.0.17",
            "mac_address": "UNKNOWN-192.168.0.17", "open_ports": [1400],
            "fingerprints": ["mdns-type:._sonos._tcp"],
            "discovery_sources": ["mdns"], "vulnerabilities": [], "risk_signals": [],
        },
    ]
    result = repo.create_scan(scan_source="android-native", network_context=NC, discovered_devices=scanned)
    public_devices = repo.devices()
    identity_findings = repo.identity_findings()
    resident_findings = visible_identity_findings(identity_findings)
    resident_ids = {item["device_id"] for item in resident_findings}
    raw_devices = repo._latest_observed_scan_devices() or []
    raw_by_ip = {d["ip_address"]: d for d in raw_devices}
    # Public DTOs deliberately omit IP/MAC.  Test association through the
    # internal observed record's opaque device_id instead of putting a network
    # address back into the user-facing contract.
    public_by_observed_ip = {
        address: next((device for device in public_devices if device.get("device_id") == raw.get("device_id")), None)
        for address, raw in raw_by_ip.items()
    }

    # mDNS/SSDP 서비스 응답은 원시 identity_findings와 자동조사 입력에
    # 남지만, 그것만으로 기기 카드나 공개 수를 만들지는 않는다.
    for hidden_ip in ("192.168.0.3", "192.168.0.1"):
        assert hidden_ip in raw_by_ip
        assert raw_by_ip[hidden_ip].get("is_unresolved")
        assert not raw_by_ip[hidden_ip].get("is_phantom")
        assert public_by_observed_ip[hidden_ip] is None
        assert any(item["device_id"] == raw_by_ip[hidden_ip]["device_id"] for item in identity_findings)
        assert raw_by_ip[hidden_ip]["device_id"] not in resident_ids

    # 반복 OPEN cohort 여덟 건은 원시 조사 자료로 각각 보존하되, TCP
    # 응답만으로 여덟 대의 실제 기기가 있다고 공개하지 않는다.
    open_cohort_ips = tuple(f"192.168.0.{last}" for last in range(130, 138))
    for observed_ip in open_cohort_ips:
        assert observed_ip in raw_by_ip
        assert not raw_by_ip[observed_ip].get("is_phantom")
        assert public_by_observed_ip[observed_ip] is None
        assert any(
            item["device_id"] == raw_by_ip[observed_ip]["device_id"]
            for item in identity_findings
        )
        assert raw_by_ip[observed_ip]["device_id"] not in resident_ids
    refusal_ip = "192.168.0.139"
    assert raw_by_ip[refusal_ip].get("is_phantom")
    assert not any(
        item["device_id"] == raw_by_ip[refusal_ip]["device_id"]
        for item in identity_findings
    )
    assert result["devices_found"] == len(public_devices) + len(resident_findings)
    assert len(resident_findings) == 3

    # 약한 Boa 신호의 취약점 근거는 서버 내부에서 유지되어 후속 식별에 쓸 수 있으나,
    # 지금은 정확한 물품명으로 검증되지 않았으므로 공개하지 않는다.
    router_cves = [v.get("cve_id") for v in scoring_with_cve(raw_by_ip["192.168.0.1"]).get("vulnerabilities", [])]
    assert "CVE-2022-45956" in router_cves

    # SMB/HomeKit의 구조화된 종류 근거는 미식별 연결로는 공개하되,
    # 실제 제조사·품번을 확인하기 전까지 제품 카드로 승격하지 않는다.
    for pending_ip in ("192.168.0.2", "192.168.0.16"):
        assert public_by_observed_ip[pending_ip] is None
        assert any(item["device_id"] == raw_by_ip[pending_ip]["device_id"] for item in identity_findings)
        assert raw_by_ip[pending_ip]["device_id"] in resident_ids

    # Sonos 전용 mDNS 서비스는 제조사 단서이지만 모델/품번 증거는 아니다.
    # 따라서 임의의 "Sonos 스피커"로 공개하지 않고 실제 미식별 연결로 검토 큐에 남긴다.
    sonos_ip = "192.168.0.17"
    assert public_by_observed_ip[sonos_ip] is None
    assert any(item["device_id"] == raw_by_ip[sonos_ip]["device_id"] for item in identity_findings)
    assert raw_by_ip[sonos_ip]["device_id"] not in resident_ids

    # Nest Mini라는 모델 단서는 종류를 speaker로 보정하기에는 충분하지만,
    # Google Cast는 타사 제품도 사용하는 프로토콜이므로 제조사 증거는 아니다.
    # 입력에 구조화된 제조사 근거가 없는 이 관측도 임의 제품명으로 공개하지
    # 않지만, 검증된 speaker 종류 관측으로는 공개 연결에 남긴다.
    nest_ip = "192.168.0.12"
    assert public_by_observed_ip[nest_ip] is None
    assert raw_by_ip[nest_ip]["device_type"] == "speaker"
    assert any(item["device_id"] == raw_by_ip[nest_ip]["device_id"] for item in identity_findings)
    assert raw_by_ip[nest_ip]["device_id"] in resident_ids

    # 공개 전수: 임시명, 칩셋·OUI 식별자, 네트워크 분석값이 남지 않는다.
    forbidden = ("OUI", "확인 필요", "알 수 없는 기기", "정체불명", "Seongji", "Realtek", "Espressif")
    for device in public_devices:
        exposed = " ".join(str(device.get(field) or "") for field in ("name", "manufacturer", "model"))
        assert not any(term.lower() in exposed.lower() for term in forbidden)
        assert "ip_address" not in device
        assert "mac_address" not in device
