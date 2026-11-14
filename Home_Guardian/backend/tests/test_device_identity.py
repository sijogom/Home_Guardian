from app.services.device_identity import (
    brand_from_advertised,
    device_type_from_signals,
    identify_device,
    model_from_advertised,
    vendor_from_model_prefix,
    vendor_from_oui,
)


def test_oui_lookup_uses_longest_ieee_registry_prefix(monkeypatch, tmp_path):
    """MA-S(36) → MA-M(28) → MA-L(24) 최장 접두사가 우선한다."""
    from app.services import device_identity

    combined = tmp_path / "oui.csv"
    combined.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,001122,Large Vendor,Large address\n"
        "MA-M,0011223,Medium Vendor,Medium address\n"
        "MA-S,001122334,Small Vendor,Small address\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(device_identity, "OUI_CSV_PATH", combined)
    device_identity._load_oui_db.cache_clear()
    try:
        assert vendor_from_oui("00:11:22:33:4A:BC") == "Small Vendor"
        assert vendor_from_oui("00:11:22:3F:4A:BC") == "Medium Vendor"
        assert vendor_from_oui("00:11:22:EF:4A:BC") == "Large Vendor"
    finally:
        device_identity._load_oui_db.cache_clear()


def test_oui_lookup_rejects_local_and_multicast_even_if_registry_overlaps(monkeypatch, tmp_path):
    """랜덤/local-admin·multicast MAC은 CSV에 같은 접두사가 있어도 제조사 근거가 아니다."""
    from app.services import device_identity

    combined = tmp_path / "oui.csv"
    combined.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,021122,False Local Vendor,address\n"
        "MA-L,011122,False Multicast Vendor,address\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(device_identity, "OUI_CSV_PATH", combined)
    device_identity._load_oui_db.cache_clear()
    try:
        assert vendor_from_oui("02:11:22:33:44:55") is None
        assert vendor_from_oui("01:11:22:33:44:55") is None
    finally:
        device_identity._load_oui_db.cache_clear()


def test_oui_lookup_rejects_conflicting_official_assignment(monkeypatch, tmp_path):
    """한 IEEE 접두사에 서로 다른 조직이 있으면 임의로 하나를 제조사로 택하지 않는다."""
    from app.services import device_identity

    combined = tmp_path / "oui.csv"
    combined.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,080030,NETWORK RESEARCH CORPORATION,address 1\n"
        "MA-L,080030,ROYAL MELBOURNE INST OF TECH,address 2\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(device_identity, "OUI_CSV_PATH", combined)
    device_identity._load_oui_db.cache_clear()
    try:
        assert vendor_from_oui("08:00:30:12:34:56") is None
    finally:
        device_identity._load_oui_db.cache_clear()


def test_vendor_from_oui_resolves_known_prefixes_from_full_db():
    # IEEE OUI 전체 DB(backend/app/data/oui.csv) 로 실제 등록 prefix 를 식별한다.
    assert vendor_from_oui("64:1B:2F:FE:00:05") == "Samsung"
    assert vendor_from_oui("0C:75:D2:AA:BB:CC") == "Hikvision"


def test_vendor_from_model_prefix_samsung():
    assert vendor_from_model_prefix("SM-G991N") == "Samsung"
    assert vendor_from_model_prefix("RT-AX88U") == "ASUS"


def test_compat_resolver_keeps_oui_and_type_private_without_model():
    result = identify_device(
        {
            "mac_address": "64:1B:2F:FE:00:06",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.5",
            "device_type": "tv",
            "open_ports": [8001],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "Samsung"
    assert result["identity_status"] == "enriching"
    assert result["canonical_name"] == ""


def test_compat_resolver_retains_unknown_signal_as_unresolved_observation():
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.9",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.9",
            "device_type": "unknown",
            "open_ports": [80],
            "discovery_sources": ["tcp-port-probe"],
        }
    )
    assert result["identity_status"] == "enriching"
    assert result["is_unresolved"] is True
    assert result["canonical_name"] == ""


def test_compat_resolver_does_not_invent_name_without_evidence():
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.50",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.50",
            "device_type": "unknown",
            "open_ports": [],
            "discovery_sources": [],
        }
    )
    assert result["identity_status"] == "unresolved"
    assert result["canonical_name"] == ""


def test_identify_skips_self_device():
    from app.services.device_identity import resolve_device_identity

    device = {
        "mac_address": "본인-기기",
        "name": "내 휴대폰 (SM-G991N)",
        "risk_signals": ["self_device"],
    }
    assert identify_device(device) == resolve_device_identity(device)


def test_legacy_identify_entrypoint_cannot_reintroduce_fallback_labels():
    """The compatibility API must stay a thin central-resolver wrapper."""
    import inspect

    source = inspect.getsource(identify_device)
    assert "resolve_device_identity(device)" in source
    for forbidden in (
        "웹 관리 기기",
        "제조사 미확인",
        "정체불명 기기",
        "알 수 없는 기기",
        "기기 후보",
        "임시 인터넷 신호",
    ):
        assert forbidden not in source


def test_identify_keeps_real_manufacturer_and_name():
    """이미 식별된 기기는 임시 이름이 아니므로 이름을 덮지 않는다."""
    result = identify_device(
        {
            "mac_address": "64:1B:2F:FE:00:06",
            "manufacturer": "Samsung",
            "name": "거실 패밀리허브",
            "device_type": "fridge",
            "open_ports": [8080],
        }
    )
    assert "suggested_name" not in result


def test_raw_model_code_without_structured_provenance_is_not_public():
    result = identify_device(
        {
            "mac_address": "64:1B:2F:FE:00:06",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 1",
            "device_type": "fridge",
            "model": "RF85N9003SL",
            "open_ports": [8080],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "Samsung"
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""


# ── Spotify Connect getInfo 기반 범용 제조사·모델 식별(하드코딩 0) ──


def test_name_from_advertised_uses_user_set_friendly_name():
    """사용자가 정한 친근한 이름(googlecast fn '거실 TV')을 표시명으로 쓰되, 브랜드명을 포함하는
    기기 기본 이름('Samsung-FamilyHub')은 한국어 생성명이 더 친숙하므로 제외한다."""
    from app.services.device_identity import name_from_advertised

    assert name_from_advertised(["mdns-txt:fn=거실 TV"]) == "거실 TV"
    assert name_from_advertised(["spotify-name:안방 스피커"]) == "안방 스피커"
    assert name_from_advertised(["spotify-name:Samsung-FamilyHub"]) is None  # 브랜드 포함 → 기기 기본명
    assert name_from_advertised(["mdns-txt:fn=40:CA:63:FE:00:03"]) is None  # MAC → 친근한 이름 아님

    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.30",
            "manufacturer": "Google",
            "name": "알 수 없는 기기 192.168.0.30",
            "device_type": "tv",
            "fingerprints": ["mdns-type:._googlecast._tcp", "mdns-txt:fn=거실 TV", "mdns-txt:md=Chromecast Ultra"],
            "open_ports": [8009],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""


def test_brand_from_advertised_takes_arbitrary_oem_brand():
    """getInfo brandDisplayName 은 키워드 맵에 없는 브랜드(Sonos/Denon/Bose)도 그대로 채택한다."""
    assert brand_from_advertised(["spotify-brand:Sonos"]) == "Sonos"
    assert brand_from_advertised(["spotify-brand:Denon"]) == "Denon"
    assert brand_from_advertised(["mdns-txt:manufacturer=Bose"]) == "Bose"


def test_cast_family_names_do_not_become_public_products():
    """Cast family/name strings alone are classification clues, not product proof."""
    def cast_tv(md: str) -> dict:
        return identify_device(
            {
                "mac_address": "UNKNOWN-192.168.0.50",
                "manufacturer": "Google",  # native 가 _googlecast 보고 단정
                "name": "알 수 없는 기기 192.168.0.50",
                "device_type": "tv",
                "fingerprints": ["mdns-type:._googlecast._tcp", f"mdns-txt:md={md}"],
                "open_ports": [8009],
                "discovery_sources": ["mdns"],
            }
        )

    for advertised_model in ("Sony BRAVIA 4K", "Chromecast Ultra", "Google TV"):
        resolved = cast_tv(advertised_model)
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""


def test_samsung_family_hub_getinfo_resolves_family_on_first_scan_without_part_number():
    """A real Family Hub getInfo response resolves on any network.

    실제 기기 응답의 구조화 필드(네트워크 주소와 무관): brandDisplayName='Samsung',
    modelDisplayName='Family_HUB'(언더스코어), remoteName='SAMSUNG FAMILY HUB (F546)',
    deviceType='SPEAKER'. 종류는 모델/이름의 'family hub' 로 fridge(SPEAKER 단정보다 우선).
    """
    from app.services.device_identity import device_type_from_signals
    from app.storage.sqlite_repository import normalize_observed_device

    # 언더스코어 모델명 단독으로도 fridge 로 분류돼야 한다(remoteName 없을 때 대비).
    assert device_type_from_signals(["spotify-model:Family_HUB"], [], []) == "fridge"

    # Use a different private subnet, IP, MAC and home scope from the real test
    # environment.  No historical row is required for a live getInfo result.
    device = normalize_observed_device(
        {
            "ip_address": "10.42.7.23",
            "mac_address": "AA:BB:CC:DD:EE:23",
            "manufacturer": "Samsung",
            "model": "Family_HUB",
            "device_type": "audio",
            "name": "",
            "fingerprints": [
                "mdns-type:._spotify-connect._tcp",
                "spotify-getinfo-done",
                "spotify-brand:Samsung",
                "spotify-model:Family_HUB",
                "spotify-name:SAMSUNG FAMILY HUB (F546)",
                "spotify-type:SPEAKER",
            ],
            "open_ports": [17654],
            "discovery_sources": ["mdns"],
        },
        "android-native",
        home_id="home-other-region",
    )
    assert device["device_type"] == "fridge"
    assert device["manufacturer"] == "Samsung"
    assert device["model"] == "Family Hub"
    assert device["canonical_name"] == "삼성 냉장고 (Family Hub)"
    assert device["identity_status"] == "resolved"
    assert device["is_unresolved"] is False


def test_family_hub_current_scan_requires_complete_structured_getinfo_bundle():
    """Completion, Samsung brand, and Family Hub model/name must travel together."""

    base = {
        "mac_address": "AA:BB:CC:DD:EE:24",
        "manufacturer": "Samsung",
        "model": "",
        "name": "",
        "device_type": "fridge",
        "open_ports": [17654],
        "services": ["spotify-connect"],
        "discovery_sources": ["mdns"],
    }
    incomplete_fingerprint_sets = [
        # Raw mDNS name plus an open port is not a structured getInfo result.
        ["mdns-name:Samsung-FamilyHub", "spotify-probe:17654"],
        # A completion marker cannot borrow the raw mDNS instance name.
        ["spotify-getinfo-done", "mdns-name:Samsung-FamilyHub"],
        # Samsung without a structured Family Hub model/name is insufficient.
        ["spotify-getinfo-done", "spotify-brand:Samsung", "mdns-name:Samsung-FamilyHub"],
        # Family Hub without a structured Samsung brand is insufficient.
        ["spotify-getinfo-done", "spotify-model:Family_HUB", "mdns-name:Samsung-FamilyHub"],
        # Conflicting structured brands must fail closed.
        [
            "spotify-getinfo-done",
            "spotify-brand:Samsung",
            "spotify-brand:Other",
            "spotify-model:Family_HUB",
        ],
    ]

    for fingerprints in incomplete_fingerprint_sets:
        resolved = identify_device({**base, "fingerprints": fingerprints})
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""
        assert resolved["model"] == ""


def test_netbios_name_remains_an_internal_clue_without_a_product_model():
    """NetBIOS host names are useful evidence but are not public product names."""
    from app.services.device_identity import name_from_advertised

    assert name_from_advertised(["netbios-name:TESTPC-MAIN"]) == "TESTPC-MAIN"
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.65",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.65",
            "device_type": "computer",
            "fingerprints": ["netbios-name:TESTPC-MAIN"],
            "open_ports": [445],
            "discovery_sources": ["tcp-port-probe"],
        }
    )
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""
    assert result["model"] == ""


def test_oui_company_names_resolve_verified_computer_family_without_product_models():
    """실측 PC는 모델을 제공하지 않아도 OUI+SMB로 제조사·컴퓨터군을 확인한다."""
    from app.services.device_identity import resolve_device_identity

    for mac in (
        "A8:A1:59:FE:00:08",
        "34:5A:60:FE:00:01",
    ):
        resolved = resolve_device_identity(
            {
                "mac_address": mac,
                "manufacturer": "",
                "model": "",
                "name": "",
                "device_type": "computer",
                "open_ports": [139, 445],
                "services": ["smb"],
                "discovery_sources": ["server-neighbor", "netbios"],
                "fingerprints": ["netbios-name:HOME-PC"],
            }
        )
        assert resolved["identity_status"] == "resolved"
        assert resolved["canonical_name"] in {"ASRock 컴퓨터", "MSI 컴퓨터"}
        assert resolved["manufacturer"]
        assert resolved["model"] == ""
        assert resolved["identity_family_verified"] is True
        assert resolved["is_unresolved"] is False


def test_printer_identified_from_ipp_usb_keys():
    """프린터가 IPP 표준 TXT(usb_MFG/usb_MDL)로 제조사·모델을 광고하면 그대로 식별한다."""
    from app.services.device_identity import brand_from_advertised, model_from_advertised

    assert brand_from_advertised(["mdns-txt:usb_MFG=HP"]) == "HP"
    assert model_from_advertised(["mdns-txt:usb_MDL=OfficeJet Pro 8710"]) == "OfficeJet Pro 8710"
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.40",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.40",
            "device_type": "printer",
            "fingerprints": ["mdns-type:._ipp._tcp", "mdns-txt:usb_MFG=HP", "mdns-txt:usb_MDL=OfficeJet Pro 8710"],
            "open_ports": [631],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "HP"
    assert result["identity_status"] == "resolved"
    assert result["canonical_name"] == "HP 프린터 (OfficeJet Pro 8710)"


def test_model_from_advertised_chooses_one_concrete_model_without_source_priority():
    """Family/placeholder values are skipped; concrete conflicts are rejected."""
    assert model_from_advertised(["mdns-txt:md=Chromecast Ultra"]) == "Chromecast Ultra"
    assert model_from_advertised(["mdns-txt:model=AppleTV5,3"]) == "AppleTV5,3"
    assert model_from_advertised(["mdns-txt:am=AudioAccessory5,1"]) == "AudioAccessory5,1"
    # AirPlay capability bitmaps are not competing product models.
    assert model_from_advertised(["mdns-txt:md=0,1,2", "mdns-txt:model=Mac14,9"]) == "Mac14,9"
    # A one-letter placeholder does not conflict with a concrete named model.
    assert model_from_advertised(["mdns-txt:model=X", "spotify-model:Arc"]) == "Arc"
    # OSS 기본값은 건너뛰고 실제 모델 채택
    assert model_from_advertised(["spotify-model:go-librespot", "mdns-txt:model=RealModel"]) == "RealModel"
    # A family alias never shadows a concrete UPnP part number.
    assert model_from_advertised(["spotify-model:Family Hub", "upnp-model:RF85C90"]) == "RF85C90"
    assert model_from_advertised(["spotify-model:Family Hub"]) is None
    # Two different concrete structured models are conflicting evidence.
    assert model_from_advertised(["upnp-model:RF85C90", "mdns-txt:model:RF85C91"]) == "RF85C90"
    assert model_from_advertised(["upnp-model:RF85C90", "mdns-txt:model=RF85C91"]) is None


def test_structured_apple_mac_identifier_resolves_without_exact_catalog_entry():
    resolved = identify_device(
        {
            "name": "",
            "manufacturer": "Apple",
            "model": "Mac15,6",
            "device_type": "computer",
            "mac_address": "UNKNOWN-192.0.2.10",
            "open_ports": [5000, 7000],
            "services": ["admin", "mdns", "tcp-7000"],
            "fingerprints": [
                "mdns-txt:am=Mac15,6",
                "mdns-txt:model=Mac15,6",
                "mdns-type:_airplay._tcp.local",
                "mdns-type:_raop._tcp.local",
            ],
        }
    )

    assert resolved["identity_status"] == "resolved"
    assert resolved["manufacturer"] == "Apple"
    assert resolved["device_type"] == "computer"
    assert resolved["model"] == "Mac15,6"
    assert resolved["canonical_name"] == "애플 컴퓨터 (Mac15,6)"


def test_mac_prefix_does_not_turn_arbitrary_model_into_apple_product():
    resolved = identify_device(
        {
            "manufacturer": "",
            "model": "machine123",
            "device_type": "computer",
            "mac_address": "UNKNOWN-192.0.2.11",
            "open_ports": [5000],
            "services": ["admin"],
            "fingerprints": ["mdns-txt:model=machine123"],
        }
    )

    assert resolved["manufacturer"] != "Apple"
    assert resolved["identity_status"] != "resolved"


def test_brand_from_advertised_skips_software_receivers():
    """OSS Spotify 리시버 기본값(librespot 등)은 하드웨어 제조사가 아니므로 제외한다."""
    assert brand_from_advertised(["spotify-brand:librespot"]) is None
    assert brand_from_advertised(["spotify-brand:go-librespot"]) is None
    assert model_from_advertised(["spotify-model:go-librespot"]) is None
    # 리터럴 "Spotify"(컨트롤러 측 정체성, 하드웨어 OEM 아님)도 제조사로 쓰지 않는다.
    assert brand_from_advertised(["spotify-brand:Spotify"]) is None


def test_device_type_fridge_from_advertised_name_beats_audio():
    """기능 신호(_spotify-connect=audio)보다 가전 이름(familyhub)이 우선 → 냉장고."""
    blob = ["mdns-type:._spotify-connect._tcp", "spotify-name:Samsung-FamilyHub"]
    assert device_type_from_signals(blob, [], []) == "fridge"


def test_homekit_ci_category_beats_generic_hub():
    """HomeKit(_hap)은 조명·도어록·카메라·온도계가 전부 같은 _hap 서비스를 쓰므로 '_hap→hub' 단정은
    과잉추정이다. mDNS TXT의 'ci'(Apple HAP 액세서리 카테고리, 웹 검증값)가 실제 종류를 주므로 우선한다.
    (모든 HomeKit IoT 대상 — 냉장고 한 기기가 아니라 종류 전반을 데이터로 식별.)"""
    def t(ci):
        return device_type_from_signals(["mdns-type:._hap._tcp", f"mdns-txt:ci={ci}"], [], [])

    assert t("5") == "light"        # Lighting
    assert t("6") == "lock"         # Locks
    assert t("7") == "plug"         # Outlet
    assert t("9") == "thermostat"   # Thermostat
    assert t("17") == "camera"      # IP Camera
    assert t("2") == "hub"          # Bridge (진짜 허브)
    # 확장 카테고리(HAP-NodeJS 레퍼런스로 검증) — HomeKit TV·도어벨·스피커·라우터·셋톱 등 흔한 기기
    assert t("18") == "camera"      # Video Doorbell(카메라 내장)
    assert t("26") == "speaker"     # Speaker
    assert t("31") == "tv"          # Television
    assert t("33") == "router"      # WiFi Router
    assert t("34") == "audio"       # Audio Receiver
    assert t("35") == "tv"          # TV Set Top Box
    assert t("36") == "tv"          # TV Streaming Stick
    # 전용 라벨이 없는 종류(센서·팬·에어컨·공기청정기)는 정직한 일반값 'iot'
    assert t("3") == "iot"          # Fan
    assert t("10") == "iot"         # Sensor
    assert t("19") == "iot"         # Air Purifier
    assert t("21") == "iot"         # Air Conditioner
    # ci 없거나 미검증 카테고리면 종류 미상 → 'hub' 단정 대신 정직한 일반값 'iot'.
    # (_hap 은 전구·도어락·플러그 등 모든 종류가 쓰는 프로토콜이라 'hub' 단정 자체가 오탐.
    #  실제 허브는 위 ci=2 에서 잡힘.)
    assert device_type_from_signals(["mdns-type:._hap._tcp"], [], []) == "iot"
    assert t("99") == "iot"


def test_device_type_uses_concrete_spotify_type():
    """getInfo deviceType(구체값)이 있으면 그걸 쓰고, 구체 타입 없는 일반 _spotify-connect
    만으로는 종류를 단정하지 않는다(Spotify Connect 는 스피커·TV·냉장고에 모두 실리므로
    'audio' 단정은 휴면 냉장고를 '오디오 기기'로 오탐시킨다)."""
    blob = ["spotify-type:SPEAKER", "mdns-type:._spotify-connect._tcp"]
    assert device_type_from_signals(blob, [], []) == "speaker"
    # 구체 타입 없는 bare _spotify-connect → 미상(None). 종류를 지어내지 않는다.
    assert device_type_from_signals(["mdns-type:._spotify-connect._tcp"], [], []) is None


def test_identify_spotify_receiver_uses_self_reported_brand():
    """_spotify-connect 리시버가 getInfo 로 알린 브랜드/모델로 식별된다(어느 집 기기든 동일)."""
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.40",
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.40",
            "device_type": "speaker",
            "fingerprints": [
                "mdns-type:._spotify-connect._tcp",
                "spotify-brand:Sonos",
                "spotify-model:Arc",
                "spotify-type:SPEAKER",
            ],
            "open_ports": [1400],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "Sonos"
    assert result["identity_status"] == "resolved"
    assert result["canonical_name"] == "Sonos 스피커 (Arc)"


def test_identify_familyhub_family_alias_stays_unresolved():
    """Family Hub is a family alias; a real Samsung part number is still required."""
    result = identify_device(
        {
            "mac_address": "40:CA:63:FE:00:03",  # Seongji 칩 OUI — 단독으론 삼성으로 못 봄
            "manufacturer": "알 수 없음",
            "name": "스피커 후보 192.168.0.3",
            "device_type": "fridge",  # normalize 가 familyhub 신호로 판정한 종류
            "fingerprints": [
                "mdns-type:._spotify-connect._tcp",
                "spotify-brand:Samsung",
                "spotify-model:Family Hub",
                "spotify-name:Samsung-FamilyHub",
            ],
            "open_ports": [8080],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "Samsung"
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""
    assert result["model"] == ""


def test_identify_pi_running_librespot_keeps_oui_as_private_clue():
    """RPi OUI is retained, but librespot is not a Raspberry Pi board model."""
    result = identify_device(
        {
            "mac_address": "B8:27:EB:11:22:33",  # Raspberry Pi Foundation OUI
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.7",
            "device_type": "computer",
            "fingerprints": [
                "mdns-type:._spotify-connect._tcp",
                "spotify-brand:librespot",
                "spotify-model:librespot",
            ],
            "open_ports": [22],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["manufacturer"] == "Raspberry Pi"
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""
    assert result["model"] == ""


# ── 적대적 환각 점검(없는 정보를 지어내지 않음) ──


def test_real_fridge_signals_do_not_hallucinate_samsung():
    """저장된 실제 냉장고 신호(mDNS 이름=MAC + _spotify-connect, TXT/getInfo 없음)만으로는
    삼성으로 단정하지 않는다. 광고 이름의 MAC 모양 문자열은 물리 MAC/OUI
    근거가 아니므로 주소 기반 ID·이력·별칭 키로 승격하지 않는다."""
    from app.services.device_identity import mac_from_fingerprints

    fps = ["mdns-name:40CA63FE0003", "mdns-type:._spotify-connect._tcp"]
    mac = mac_from_fingerprints(fps)
    assert mac is None
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.3",
            "manufacturer": "알 수 없음",
            "name": "스피커 후보 192.168.0.3",
            "device_type": "audio",
            "fingerprints": fps,
            "open_ports": [],
            "discovery_sources": ["mdns"],
        }
    )
    assert result.get("manufacturer") != "Samsung"  # 없는 삼성 신호를 지어내지 않음


def test_advertised_mac_shaped_values_never_become_physical_mac():
    from app.services.device_identity import mac_from_fingerprints

    assert mac_from_fingerprints(
        [
            "mdns-name:64:1B:2F:FE:00:06",
            "ssdp-usn:uuid:camera-64-1B-2F-FE-00-06",
            "mdns-txt:fn=641B2FFE0006",
        ]
    ) is None


def test_name_only_brand_plus_weak_protocol_does_not_resolve_product():
    from app.services.device_identity import resolve_device_identity

    observations = (
        {
            "device_type": "camera",
            "fingerprints": ["mdns-name:Samsung Living Camera", "mdns-type:._rtsp._tcp.local"],
            "services": ["rtsp"],
        },
        {
            "device_type": "tv",
            "fingerprints": ["netbios-name:LG Electronics TV", "mdns-type:._googlecast._tcp.local"],
            "services": ["googlecast"],
        },
        {
            "device_type": "tv",
            "fingerprints": ["mdns-name:SamsungTV", "mdns-type:._googlecast._tcp.local"],
            "services": ["googlecast"],
        },
    )

    for observation in observations:
        resolved = resolve_device_identity(observation)
        assert resolved["identity_status"] != "resolved"
        assert resolved["identity_family_verified"] is False
        assert resolved["canonical_name"] == ""


def test_dormant_spotify_device_is_not_labeled_audio_or_chip_vendor():
    """휴면(getInfo 미응답) 냉장고: bare _spotify-connect 만 보이고 구체 deviceType 이 없으면
    종류를 단정하지 않는다(사용자 실집: 삼성 냉장고가 '성지(Seongji) 오디오 기기'로 오탐됐던 버그).

    두 가지를 동시에 막는다:
      1) Spotify Connect 는 스피커·TV·냉장고에 모두 실리므로 'audio'로 단정하지 않는다(틀린 '오디오 기기').
      2) 종류를 모르는데 칩 OUI 제조사(Seongji)를 기기 이름으로 쓰지 않는다 — 사회적 약자 사용자는
         칩/브랜드명만으론 TV·냉장고를 구별할 수 없다. 정직하게 '정체불명 기기 + 이름 지정 유도'로 안내한다.
    (활성화돼 getInfo 가 응답하면 '삼성 냉장고'로 식별 — test_samsung_family_hub_identified_from_real_getinfo.)
    """
    result = identify_device(
        {
            "mac_address": "40:CA:63:FE:00:03",  # 냉장고 Wi-Fi 칩(Seongji) OUI
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.3",
            "device_type": "unknown",
            "fingerprints": ["mdns-name:40CA63FE0003", "mdns-type:._spotify-connect._tcp"],
            "open_ports": [],
            "discovery_sources": ["mdns"],
        }
    )
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""
    assert result["is_unresolved"] is True
    assert result["model"] == ""


def test_placeholder_manufacturer_not_leaked_as_jargon():
    """제조사 placeholder("OUI 확인 필요" 등 구버전 스캐너 잔재)가 기기 이름이나 제조사 필드에
    전문용어로 노출되지 않는다(실측: 저장 데이터의 192.168.0.12/.65/.1 manufacturer='OUI 확인 필요'가
    'OUI 확인 필요 공유기'로 표시되던 것). 사회적 약자가 못 알아보는 jargon → 미상으로 정리."""
    from app.storage.sqlite_repository import normalize_observed_device

    device = normalize_observed_device(
        {
            "ip_address": "192.168.0.12",
            "mac_address": "UNKNOWN-192.168.0.12",
            "manufacturer": "OUI 확인 필요",
            "device_type": "web-device",
            "name": "웹 관리 기기 후보 192.168.0.12",
            "open_ports": [80, 443],
            "fingerprints": [],
            "discovery_sources": ["tcp-port-probe"],
        },
        "android-native",
    )
    assert "OUI" not in device["name"] and "확인 필요" not in device["name"]      # 이름에 jargon 금지
    assert "OUI" not in device["manufacturer"] and "확인 필요" not in device["manufacturer"]  # 제조사 필드도


def test_real_dormant_fridge_native_audio_is_not_seongji_audio():
    """실측 회귀: 사용자 LAN 의 냉장고(.3)가 절전(getInfo 미응답)일 때 native 가 보내는 실제 입력
    (device_type='audio', fingerprints=[mdns-name:MAC, mdns-type:._spotify-connect._tcp], 17654)을
    그대로 저장경로(normalize)에 넣어도 'Seongji 오디오 기기'가 되지 않아야 한다.

    이 케이스가 중요한 이유: identify_device 단위 테스트는 device_type='unknown'으로 통과했지만,
    실제 native 는 _spotify-connect 를 보고 device_type='audio'를 보낸다. normalize 가 그 'audio'를
    신뢰하면(구체 getInfo 타입 없이) 오탐이 되살아난다 → spotify_only_audio_guess 가드로 미상 처리.
    """
    from app.storage.sqlite_repository import normalize_observed_device

    device = normalize_observed_device(
        {
            "ip_address": "192.168.0.3",
            "mac_address": "UNKNOWN-192.168.0.3",
            "device_type": "audio",  # native 가 bare _spotify-connect 보고 보내는 실제값
            "name": "스피커 후보 192.168.0.3",
            "open_ports": [17654],
            "fingerprints": ["mdns-name:40CA63FE0003", "mdns-type:._spotify-connect._tcp"],
            "discovery_sources": ["mdns", "tcp-port-probe"],
        },
        "android-native",
    )
    assert device["device_type"] != "audio"          # bare _spotify-connect → 'audio' 단정 금지
    assert "오디오" not in device["name"]              # 틀린 '오디오 기기' 라벨 금지
    assert "Seongji" not in device["name"]            # 칩 제조사를 기기 이름으로 쓰지 않음
    assert device["name"] == ""                       # 공개용 임시 이름을 저장하지 않음
    assert device["is_unresolved"] is True             # 내부 미해결 신호로만 보관


def test_oui_vendor_without_type_is_not_a_public_product():
    """An OUI vendor alone remains private enrichment, never a product label."""
    result = identify_device(
        {
            "mac_address": "40:CA:63:FE:00:03",  # OUI → Seongji
            "manufacturer": "알 수 없음",
            "name": "알 수 없는 기기 192.168.0.3",
            "device_type": "unknown",
            "fingerprints": [],
            "open_ports": [80],  # has_signal True 라 phantom 아님
            "discovery_sources": ["tcp-port-probe"],
        }
    )
    assert result["identity_status"] != "resolved"
    assert result["canonical_name"] == ""
    assert result["is_unresolved"] is True
    assert result["model"] == ""


def test_random_mac_is_not_falsely_branded():
    """locally-administered(랜덤) MAC 은 IEEE OUI 에 없어 거짓 제조사를 만들지 않는다."""
    from app.services.device_identity import vendor_from_oui

    for random_mac in ("4A:11:22:33:44:55", "AE:BB:CC:DD:EE:FF", "02:00:5E:10:20:30"):
        assert vendor_from_oui(random_mac) is None


def test_netbios_name_is_preserved_not_overridden():
    """native 가 NetBIOS 로 얻은 실제 PC 이름은 임시 이름이 아니므로 추정 이름으로 덮지 않는다."""
    result = identify_device(
        {
            "mac_address": "UNKNOWN-192.168.0.2",
            "manufacturer": "알 수 없음",
            "name": "DESKTOP-AB12CD",
            "device_type": "computer",
            "fingerprints": ["netbios-name:DESKTOP-AB12CD"],
            "open_ports": [445],
            "discovery_sources": ["tcp-port-probe"],
        }
    )
    assert "suggested_name" not in result  # 실제 이름 유지(덮지 않음)

def test_self_advertised_brand_enables_cve_match_not_false_negative():
    """기기가 mDNS/ONVIF 로 스스로 알리는 브랜드(_sonos._tcp, name 의 reolink/wyze 등)를 제조사로
    살려야 CVE 매처가 vendor 를 풀 수 있다. 브랜드 키워드가 빠지면 manufacturer 가 미추출되어
    카탈로그에 CVE 가 있어도 미탐(false-negative)된다. 어느 집 기기든 동일(IP/MAC 하드코딩 아님).
    """
    from app.services.cve_matcher import CveMatcher
    matcher = CveMatcher()

    def identify_then_match(fingerprints, device_type):
        ident = identify_device(
            {
                "manufacturer": "알 수 없음",
                "name": "알 수 없는 기기 x",
                "device_type": device_type,
                "mac_address": "UNKNOWN-x",
                "open_ports": [],
                "fingerprints": fingerprints,
                "discovery_sources": ["mdns"],
            }
        )
        manu = ident.get("manufacturer")
        cves = [c.get("cve_id") for c in matcher.match_device(manufacturer=manu, model=None, device_type=device_type)]
        return manu, cves

    # 자기-광고 브랜드 → 제조사 추출 → 카탈로그 CVE 매칭(미탐 아님)
    manu, cves = identify_then_match(["mdns-type:._sonos._tcp"], "audio")
    assert manu == "Sonos" and "CVE-2018-11316" in cves
    manu, cves = identify_then_match(["mdns-name:reolink-rlc-810a"], "camera")
    assert manu == "Reolink" and "CVE-2020-25169" in cves
    manu, cves = identify_then_match(["mdns-name:wyze-cam-pan"], "camera")
    assert manu == "Wyze" and "CVE-2019-9564" in cves

    # 브랜드 토큰이 없으면(광고 안 함) 정직하게 미추출 — 가짜 제조사를 지어내지 않는다.
    manu, cves = identify_then_match([], "camera")
    assert not manu and cves == []

def test_cast_airplay_speaker_models_not_misidentified_as_tv():
    """_googlecast/_airplay 는 TV·스피커 공용 프로토콜이라 'tv' 단정은 스마트 스피커를 오탐한다.
    광고된 모델명이 스피커 계열(Nest Mini/Audio, Google Home, HomePod)이면 speaker 로 본다.
    순수 Chromecast·Apple TV 는 그대로 tv(회귀 안전). 어느 집 기기든 동일(IP/MAC 하드코딩 아님).
    """
    spk = lambda fps: device_type_from_signals(fps, [], [])
    # 스마트 스피커 → speaker (이전엔 _googlecast/_airplay 로 tv 오탐)
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Nest Mini"]) == "speaker"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Nest Audio"]) == "speaker"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Google Home Mini"]) == "speaker"
    assert spk(["mdns-type:._airplay._tcp", "mdns-type:._raop._tcp", "mdns-txt:model=AudioAccessory5,1"]) == "speaker"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Chromecast Audio"]) == "speaker"
    # TV 계열은 그대로 tv (회귀 방지)
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Chromecast"]) == "tv"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Chromecast Ultra"]) == "tv"
    assert spk(["mdns-type:._airplay._tcp", "mdns-txt:model=AppleTV6,2"]) == "tv"
    # 적대적 회귀 가드: 'hub' 가 든 cast 기기(Nest Hub=디스플레이)는 화면이 있어 speaker 가 아니다 → tv.
    # 단 순수 스피커(Google Home/Mini)는 그대로 speaker(과한 제외 방지).
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Google Home Hub"]) == "tv"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Google Home"]) == "speaker"
    assert spk(["mdns-type:._googlecast._tcp", "mdns-txt:md=Google Home Mini"]) == "speaker"

def test_native_protocol_guess_overridden_by_clear_signal():
    """native 가 프로토콜만 보고 단정한 모호 종류('tv'=googlecast/airplay, 'hub'=homekit/hue)는
    백엔드가 명확한 신호(ci 카테고리·cast 모델명)로 재판정해야 한다. 그러지 않으면 ci/cast-speaker
    보정이 운영에서 우회된다(실측: 네이티브가 Nest Mini/HomePod 를 'tv', HomeKit Hue 전구를 'hub' 로 보냄).
    단 신호가 없으면 native 'tv'/'hub' 를 유지해 진짜 TV·허브는 안전.
    """
    from app.storage.sqlite_repository import normalize_observed_device

    def native(nt, fps, ports=None):
        return normalize_observed_device(
            {"ip_address": "192.168.0.50", "mac_address": "UNKNOWN-x", "manufacturer": "알 수 없음",
             "name": "x", "device_type": nt, "fingerprints": fps, "open_ports": ports or [],
             "discovery_sources": ["mdns"]},
            "android-native",
        )["device_type"]

    # 네이티브 'tv' 단정을 신호가 재판정 → 스마트 스피커
    assert native("tv", ["mdns-type:._googlecast._tcp", "mdns-txt:md=Nest Mini"], [8009]) == "speaker"
    assert native("tv", ["mdns-type:._airplay._tcp", "mdns-type:._raop._tcp", "mdns-txt:model=AudioAccessory5,1"]) == "speaker"
    # 네이티브 'hub' 단정을 ci 가 재판정 → 조명
    assert native("hub", ["mdns-type:._hap._tcp", "mdns-txt:ci=5", "mdns-txt:md=Hue lamp"], [80]) == "light"
    # 회귀: 진짜 TV·허브·브리지는 그대로
    assert native("tv", ["mdns-type:._googlecast._tcp", "mdns-txt:md=Chromecast"], [8009]) == "tv"
    assert native("tv", ["mdns-type:._airplay._tcp", "mdns-txt:model=AppleTV6,2"]) == "tv"
    assert native("hub", ["mdns-type:._smartthings._tcp"]) == "hub"
    assert native("hub", ["mdns-type:._hue._tcp"]) == "hub"  # Hue 브리지는 허브
    # 신호가 없으면 native 'tv' 유지(진짜 TV 안전)
    assert native("tv", ["mdns-name:randombox"]) == "tv"
    # 회귀 가드(적대적 검증): native 'tv' 는 *고신뢰* 신호(ci·cast 모델)로만 재판정한다.
    # 약한 토큰 추정(_rtsp→camera)으로 뒤집으면 화면공유로 _rtsp 를 광고하는 webOS TV 가 camera 로
    # 잘못 분류된다. 따라서 webOS TV+rtsp 는 camera 가 아니라 tv 로 유지돼야 한다.
    assert native("tv", ["webos", "mdns-type:._rtsp._tcp"], [554]) == "tv"
    # native 'hub' 도 마찬가지 — 약한 신호로 안 뒤집힘(SmartThings 허브가 rtsp 봐도 hub 유지)
    assert native("hub", ["mdns-type:._smartthings._tcp", "mdns-type:._rtsp._tcp"], [554]) == "hub"


def test_server_banner_fingerprint_promoted_to_firmware_for_cve_match():
    """네이티브는 HTTP/SSDP 서버 배너를 firmware 필드가 아니라 http-server:/ssdp-server: fingerprint
    로 보낸다. 취약 서버 배너 CVE 매칭(Boa 등)은 firmware 를 읽으므로, normalize 가 배너를 firmware 로
    승격하지 않으면 제조사 미상 공유기의 Boa 배너가 미탐된다(실측: 운영 형식에서 휴면이던 버그).
    """
    from app.storage.sqlite_repository import normalize_observed_device
    from app.services.cve_matcher import CveMatcher

    matcher = CveMatcher()
    # 실제 네이티브 형식: 배너는 fingerprint 에만, firmware/model 은 비어 옴
    d = normalize_observed_device(
        {"ip_address": "192.168.0.1", "mac_address": "UNKNOWN-1", "manufacturer": "알 수 없음",
         "name": "공유기 후보 192.168.0.1", "device_type": "router",
         "fingerprints": ["http-server:Boa/0.94.14rc21", "ssdp-server:Boa/0.94.14rc21"],
         "open_ports": [80], "discovery_sources": ["tcp-port-probe", "ssdp"]},
        "android-native",
    )
    assert d["firmware"] == "Boa/0.94.14rc21"  # 배너가 firmware 로 승격됨
    cves = [c.get("cve_id") for c in matcher.match_device(
        manufacturer=d["manufacturer"], model=d["model"], firmware=d["firmware"], device_type="router")
        if c.get("source") == "server_banner"]
    assert "CVE-2022-45956" in cves  # 미탐 방지(운영 형식에서)

    # 회귀: 명시 firmware 가 있으면 배너로 덮지 않는다
    d2 = normalize_observed_device(
        {"ip_address": "192.168.0.2", "mac_address": "UNKNOWN-2", "device_type": "router",
         "firmware": "v1.2.3", "fingerprints": ["http-server:nginx"], "discovery_sources": ["ssdp"]},
        "android-native",
    )
    assert d2["firmware"] == "v1.2.3"
    # 배너가 없으면 unknown 유지(빈 입력 안전)
    d3 = normalize_observed_device(
        {"ip_address": "192.168.0.3", "mac_address": "UNKNOWN-3", "device_type": "computer",
         "fingerprints": ["mdns-type:._workstation._tcp"], "discovery_sources": ["mdns"]},
        "android-native",
    )
    assert d3["firmware"] == "unknown"
    # 보안(방어적 길이 제한): 악의적 LAN 기기가 거대 배너를 광고해도 firmware 가 무한정 커지지 않는다
    # (저장/UI 표시 보호). 잘려도 'boa' 토큰은 남아 CVE 매칭은 유지.
    d4 = normalize_observed_device(
        {"ip_address": "192.168.0.4", "mac_address": "UNKNOWN-4", "device_type": "router",
         "fingerprints": ["http-server:" + ("Boa " * 5000)], "discovery_sources": ["tcp-port-probe"]},
        "android-native",
    )
    assert len(d4["firmware"]) <= 200
    cves4 = [c.get("cve_id") for c in matcher.match_device(
        manufacturer="알 수 없음", model=d4["model"], firmware=d4["firmware"], device_type="router")
        if c.get("source") == "server_banner"]
    assert "CVE-2022-45956" in cves4


def test_dial_multiscreen_is_tv_but_mediarenderer_stays_ambiguous():
    """DIAL(urn:dial-multiscreen-org, SSDP ST)은 스마트TV·셋톱박스 등 영상/캐스팅 타겟 전용이라 tv.
    한국 가정 흔한 IPTV 셋톱박스 커버리지를 넓힌다. 스피커(HomePod/Sonos/Nest)는 DIAL 을 광고하지
    않아 영향 없음. MediaRenderer 는 TV·AVR·사운드바(오디오) 공용이라 모호 → 매핑하지 않는다(오디오 오탐 방지).
    """
    t = lambda fps: device_type_from_signals(fps, [], [])
    assert t(["ssdp-st:urn:dial-multiscreen-org:service:dial:1"]) == "tv"
    assert t(["ssdp-st:urn:dial-multiscreen-org:service:dial:1", "webos"]) == "tv"
    # MediaRenderer 단독은 종류를 단정하지 않는다(오디오 기기를 tv 로 오탐하지 않음)
    assert t(["ssdp-st:urn:schemas-upnp-org:device:MediaRenderer:1"]) is None
    # 오디오 신호는 그대로 audio(회귀 방지)
    assert t(["mdns-type:._raop._tcp"]) == "audio"
    # 스마트 스피커는 DIAL 무관 — cast-speaker 보정 유지
    assert t(["mdns-type:._googlecast._tcp", "mdns-txt:md=Nest Mini"]) == "speaker"

def test_oui_non_brand_registrations_not_shown_as_manufacturer():
    """IEEE OUI 의 'Private'·'IEEE Registration Authority' 등 비-브랜드 등록은 제조사로 노출하지 않는다.
    사회적 약자에게 'Private 기기'·'IEEE Registration Authority' 는 의미 불명이고, 후자는 MA-M/MA-S
    서브블록 보유자라 24비트 조회로는 실제 제조사도 알 수 없다 → None(정체불명)으로 처리. 진짜 브랜드는 유지.
    """
    # 'Private' 등록(AC:DE:48)·'IEEE Registration Authority' 프리픽스 → None
    assert vendor_from_oui("AC:DE:48:11:22:33") is None
    # 진짜 브랜드 OUI 는 그대로(회귀 방지)
    assert vendor_from_oui("64:1B:2F:FE:00:05") == "Samsung"
    assert vendor_from_oui("0C:75:D2:11:22:33") == "Hikvision"
    # Private OUI 기기는 'Private' 가 manufacturer 로 새지 않고 정체불명으로 안내
    result = identify_device(
        {"mac_address": "AC:DE:48:11:22:33", "manufacturer": "알 수 없음",
         "name": "알 수 없는 기기 192.168.0.50", "device_type": "unknown",
         "open_ports": [80], "discovery_sources": ["mdns"]}
    )
    assert not result.get("manufacturer")
    assert "Private" not in str(result.get("manufacturer"))


def test_lg_thinq_air_conditioner_requires_explicit_product_evidence():
    """LG ThinQ 서비스 자체는 여러 제품이 공유하므로 AC 표시는 광고된 종류가 있을 때만 허용한다."""
    from app.services.device_identity import resolve_device_identity

    generic = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "",
            "device_type": "",
            "fingerprints": ["mdns-type:._lg-smart-device._tcp.local"],
            "discovery_sources": ["mdns"],
        }
    )
    assert generic["manufacturer"] == "LG"
    assert generic["device_type"] == ""
    assert generic["identity_status"] != "resolved"

    aircon = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "WIN_056905_WW",
            "device_type": "",
            "fingerprints": [
                "mdns-type:._lg-smart-device._tcp.local",
                "mdns-txt:product=air_conditioner",
                "mdns-txt:model=WIN_056905_WW",
            ],
            "discovery_sources": ["mdns"],
        }
    )
    assert aircon["identity_status"] == "resolved"
    assert aircon["manufacturer"] == "LG"
    assert aircon["device_type"] == "air_conditioner"
    assert aircon["canonical_name"] == "LG 에어컨 (WIN_056905_WW)"


def test_kt_upnp_gateway_requires_an_advertised_product_model():
    """KT manufacturer+gateway category stays pending until UPnP provides a model."""
    from app.services.device_identity import resolve_device_identity

    resolved = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "",
            "device_type": "",
            "fingerprints": [
                "upnp-manufacturer:KT",
                "upnp-type:InternetGatewayDevice",
            ],
            "discovery_sources": ["ssdp"],
        }
    )
    assert resolved["identity_status"] == "enriching"
    assert resolved["manufacturer"] == "KT"
    assert resolved["device_type"] == "router"
    assert resolved["canonical_name"] == ""

    model_bearing = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "",
            "device_type": "",
            "fingerprints": [
                "upnp-manufacturer:KT",
                "upnp-model:KM06-507H",
                "upnp-type:InternetGatewayDevice",
            ],
            "discovery_sources": ["ssdp"],
        }
    )
    assert model_bearing["identity_status"] == "resolved"
    assert model_bearing["canonical_name"] == "KT 공유기 (KM06-507H)"

