from __future__ import annotations

from typing import Any

import pytest

from app.storage.sqlite_repository import normalize_observed_device
from app.services.device_presentation import (
    FORBIDDEN_DEVICE_NAME_TERMS,
    apply_device_presentation,
    bind_trusted_manual_identity,
    build_identity_finding,
    build_public_detected_connections,
    is_safe_device_alias,
    normalize_stored_network_context,
    normalized_storage_fields,
    public_device_id,
    sanitize_public_notification,
    sanitize_public_network_context,
    sanitize_public_payload,
)


def test_identity_finding_never_uses_internal_queue_or_bare_protocol_type_name():
    finding = build_identity_finding(
        {
            "device_id": "device-finding",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "identity_note": "서버가 수집한 단서를 제품 카탈로그와 대조하고 있어요.",
            "device_type": "camera",
            "identity_candidates": [
                {"label": "카메라 제품 정보 확인 중", "kind": "제품 종류"},
            ],
            "identity_evidence": ["네트워크 기기 설명"],
            "risk_level": "yellow",
        }
    )

    assert finding["display_name"] == ""
    assert finding["identity_candidates"] == []
    assert build_public_detected_connections([finding]) == []
    assert "식별 처리 중인 네트워크 기기" not in str(finding)
    assert "서버가 수집한 단서를" not in str(finding)
    assert "제품 정보 확인 중" not in str(finding)


def test_identity_finding_does_not_expose_model_less_manufacturer_candidate():
    finding = build_identity_finding(
        {
            "device_id": "device-samsung-fridge-finding",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "device_type": "fridge",
            "identity_candidates": [
                {"label": "삼성 냉장고 품번 확인 중", "kind": "품번 조회"},
            ],
        }
    )

    assert finding["display_name"] == ""
    assert finding["identity_candidates"] == []
    assert build_public_detected_connections([finding]) == []
    assert "manufacturer" not in finding
    assert "model" not in finding
    assert "device_type" not in finding
    assert "삼성" not in str(finding)
    assert "확인 중" not in str(finding)


def test_identity_finding_exposes_only_a_structured_three_fact_product_clue():
    finding = build_identity_finding(
        {
            "device_id": "device-structured-fridge-finding",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "manufacturer": "Samsung Electronics",
            "model": "RF85C90",
            "device_type": "fridge",
            "fingerprints": [
                "upnp-manufacturer:Samsung Electronics",
                "upnp-model:RF85C90",
            ],
            "identity_candidates": [
                {
                    "label": "삼성 냉장고 (RF85C90)",
                    "kind": "품번 대조",
                    "confidence": "0.94",
                },
                {
                    "label": "삼성 카메라 (SNV-5080)",
                    "kind": "서버 카탈로그 후보",
                    "catalog_id": "weak-camera",
                    "confidence": "0.91",
                },
            ],
            "identity_evidence": ["제품 제조사 광고", "제품 품번 단서"],
        }
    )

    assert finding["display_name"] == "삼성 냉장고 (RF85C90)"
    assert finding["manufacturer"] == "삼성"
    assert finding["model"] == "RF85C90"
    assert finding["device_type"] == "fridge"
    assert finding["identity_candidates"] == [
        {
            "label": "삼성 냉장고 (RF85C90)",
            "kind": "확인된 제품 단서",
            "confidence": 0.94,
        }
    ]
    assert "카메라" not in str(finding)

    detected = build_public_detected_connections([finding])
    assert detected == [
        {
            "device_id": finding["device_id"],
            "display_name": "삼성 냉장고 (RF85C90)",
            "name": "삼성 냉장고 (RF85C90)",
            "device_type": "fridge",
            "identity_status": "enriching",
            "presentation_kind": "observed_connection",
            "product_clue_verified": True,
            "identity_note": "기기가 직접 보낸 제조사·제품명·품번 단서를 확인했어요. 서버가 최종 제품 정보와 대조하고 있어요.",
            "identity_evidence": ["기기가 보낸 식별 정보"],
            "identity_candidates": [],
            "online": True,
            "last_seen": "",
            "risk_level": "yellow",
            "risk_summary": "확인된 보안 신호를 기준으로 현재 상태를 계산했어요.",
            "detected": True,
            "is_identity_finding": True,
            "manufacturer": "삼성",
            "model": "RF85C90",
            "observed_type_verified": True,
        }
    ]


def test_product_clue_keeps_same_ip_service_as_supporting_metadata():
    finding = build_identity_finding(
        {
            "device_id": "device-structured-fridge-with-mdns",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "manufacturer": "Samsung Electronics",
            "model": "RF85C90",
            "device_type": "fridge",
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": [
                "upnp-manufacturer:Samsung Electronics",
                "upnp-model:RF85C90",
            ],
            "identity_candidates": [
                {
                    "label": "삼성 냉장고 (RF85C90)",
                    "kind": "품번 대조",
                    "confidence": "0.94",
                }
            ],
            "identity_evidence": ["제품 제조사 광고", "제품 품번 단서"],
        }
    )

    assert finding["display_name"] == "삼성 냉장고 (RF85C90)"
    assert finding["observed_service"] == "mdns"
    assert finding["observed_service_verified"] is True

    detected = build_public_detected_connections([finding])
    assert len(detected) == 1
    assert detected[0]["display_name"] == "삼성 냉장고 (RF85C90)"
    assert detected[0]["observed_service"] == "mdns"
    assert detected[0]["observed_service_verified"] is True


def test_detected_connection_rejects_forged_friendly_product_clue():
    forged = {
        "device_id": "public-device-forged",
        "display_name": "삼성 냉장고 (RF85C90)",
        "manufacturer": "삼성",
        "model": "RF85C90",
        "device_type": "fridge",
        "identity_candidates": [],
        "detected": True,
    }

    detected = build_public_detected_connections([forged])

    assert detected == []


def test_identity_finding_quarantines_friendly_oui_raw_and_family_only_clues():
    finding = build_identity_finding(
        {
            "device_id": "device-weak-camera-finding",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "name": "Samsung front camera",
            "manufacturer": "Samsung Electronics",
            "model": "SNV-5080",
            "device_type": "camera",
            "fingerprints": ["mdns-name:Samsung front camera", "oui:Samsung Electronics"],
            "identity_candidates": [
                {
                    "label": "삼성 카메라 (SNV-5080)",
                    "kind": "서버 카탈로그 후보",
                    "catalog_id": "weak-camera",
                },
                {"label": "Sonos 오디오 기기", "kind": "제품군 후보"},
                {"label": "카메라", "kind": "제품 종류"},
            ],
            "identity_evidence": [
                "mdns-name:Samsung front camera",
                "카메라 응답 정보",
                "네트워크 제조사 조회 단서",
            ],
            "identity_note": "Samsung front camera 제품 후보를 확인하고 있어요.",
            "risk_level": "red",
            "risk_summary": "Sonos 오디오 기기 설정 위험을 확인했어요.",
            "online": True,
        }
    )

    assert finding["display_name"] == ""
    assert finding["identity_candidates"] == []
    assert finding["identity_evidence"] == [
        "기기가 보낸 네트워크 응답",
        "네트워크 등록 정보 단서",
    ]
    assert finding["detected"] is True
    assert finding["retry_after_scan"] is True
    assert finding["risk_level"] == "red"
    assert finding["risk_summary"] == "보안 위험 신호가 있어 먼저 확인이 필요해요."
    assert "manufacturer" not in finding
    assert "model" not in finding
    assert "device_type" not in finding
    assert build_public_detected_connections([finding]) == []
    for forbidden in ("Samsung", "삼성", "SNV-5080", "Sonos", "오디오 기기", "카메라"):
        assert forbidden not in str(finding)


def _contains_forbidden(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return any(term.lower() in lowered for term in FORBIDDEN_DEVICE_NAME_TERMS) or any(
            term in lowered
            for term in (
                "espressif",
                "realtek",
                "seongji",
                "esp32",
                "chipset",
                "ieee",
                "oui",
                "private",
                "registration authority",
                "ma-m",
                "ma-s",
                "iana",
                "등록기관",
            )
        )
    if isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_forbidden(key) or _contains_forbidden(item) for key, item in value.items())
    return False


def test_confirmation_needed_label_is_removed_from_storage_and_public_notifications():
    label = "\uD655\uC778 \uD544\uC694 \uAE30\uAE30"
    storage_fields = normalized_storage_fields(
        {
            "name": label,
            "device_type": "web-device",
            "manufacturer": "",
            "model": "",
        }
    )
    notification = sanitize_public_notification(
        {
            "title": f"{label} notice",
            "message": f"{label} needs another check.",
            "device_name": label,
        }
    )
    payload = sanitize_public_payload({"cached": {"device_name": label}})

    assert label in FORBIDDEN_DEVICE_NAME_TERMS
    assert not is_safe_device_alias(label)
    assert storage_fields["name"] == ""
    assert storage_fields["is_unresolved"] is True
    assert label not in str(notification)
    assert label not in str(payload)


@pytest.mark.parametrize(
    "label",
    (
        "TCP 서비스 응답",
        "기기 정보 방송 응답",
        "연결된 장비",
        "현재 Wi-Fi 이웃 확인",
        "알 수 없는 기기",
        "제조사 미확인",
    ),
)
def test_all_generic_device_terms_are_blocked_from_every_public_text_path(label):
    notification = sanitize_public_notification(
        {
            "title": f"{label} 알림",
            "message": f"{label}의 상태를 확인했어요.",
            "device_name": label,
        }
    )
    payload = sanitize_public_payload(
        {
            "alias": label,
            "identity_note": f"{label} 상태",
            "accessibility_label": f"{label} 카드",
            "nested": {"display_name": label},
        }
    )

    assert not is_safe_device_alias(label)
    assert label not in str(notification)
    assert label not in str(payload)
    assert "alias" not in payload
    assert "identity_note" not in payload
    assert "accessibility_label" not in payload


def test_unresolved_storage_clears_stale_public_name_and_weak_candidates():
    stored = normalized_storage_fields(
        {
            "device_id": "device-legacy-unresolved",
            "identity_status": "enriching",
            "is_unresolved": True,
            "name": "삼성 카메라 (SNV-5080)",
            "canonical_name": "삼성 카메라 (SNV-5080)",
            "manufacturer": "Samsung Electronics",
            "model": "SNV-5080",
            "device_type": "camera",
            "fingerprints": ["mdns-name:Samsung camera", "oui:Samsung Electronics"],
            "identity_candidates": [
                {
                    "label": "삼성 카메라 (SNV-5080)",
                    "kind": "서버 카탈로그 후보",
                    "catalog_id": "weak-camera",
                }
            ],
            "identity_family_verified": True,
        }
    )

    assert stored["name"] == ""
    assert stored["canonical_name"] == ""
    assert stored["identity_status"] == "enriching"
    assert stored["identity_candidates"] == []
    assert stored["identity_family_verified"] is False
    assert stored["is_resolved"] is False
    assert stored["is_unresolved"] is True

    # Raw fields remain private resolver facts. Without structured product or
    # category/host proof, no generic resident-facing card is manufactured.
    finding = build_identity_finding({**stored, "device_id": "device-legacy-unresolved"})
    assert finding["display_name"] == ""
    assert build_public_detected_connections([finding]) == []
    assert finding["identity_candidates"] == []
    assert "삼성" not in str(finding)
    assert "SNV-5080" not in str(finding)
    assert "카메라" not in str(finding)


def test_raw_mdns_source_and_product_like_fields_are_not_product_provenance():
    presented = apply_device_presentation(
        {
            "name": "거실 냉장고",
            "device_type": "fridge",
            "manufacturer": "Samsung Electronics",
            "model": "RF85C90",
            "discovery_sources": ["mdns"],
            "fingerprints": ["familyhub"],
        }
    )

    assert presented is None


def test_familyhub_getinfo_presentation_is_network_independent():
    """A first-scan Family Hub DTO is public only with its structured getInfo proof."""
    presented = apply_device_presentation(
        {
            "device_id": "device-other-region-familyhub",
            "home_id": "home-other-region",
            "identity_status": "resolved",
            "identity_family_verified": True,
            "identity_resolver_version": "server-identity-1.0.0",
            "manufacturer": "Samsung",
            "model": "Family Hub",
            "device_type": "fridge",
            "fingerprints": [
                "spotify-getinfo-done",
                "spotify-brand:Samsung",
                "spotify-model:Family_HUB",
                "spotify-name:SAMSUNG FAMILY HUB (F546)",
            ],
            "is_unresolved": False,
            "is_phantom": False,
            "canonical_name": "삼성 냉장고 (Family Hub)",
        }
    )

    assert presented is not None
    assert presented["canonical_name"] == "삼성 냉장고 (Family Hub)"
    assert presented["model"] == "Family Hub"
    assert presented["device_type"] == "fridge"


def test_resolved_and_manual_status_strings_cannot_bypass_product_provenance():
    forged = {
        "identity_status": "resolved",
        "identity_resolver_version": "server-identity-1.0.0",
        "identity_confidence": 0.99,
        "canonical_name": "삼성 냉장고 (RF85C90)",
        "manufacturer": "Samsung",
        "model": "RF85C90",
        "device_type": "fridge",
        "is_resolved": True,
        "is_unresolved": False,
    }
    assert apply_device_presentation(forged) is None
    assert apply_device_presentation({**forged, "identity_status": "manual_resolved"}) is None


def test_job_validated_manual_identity_uses_an_unforgeable_in_process_binding():
    approved = bind_trusted_manual_identity(
        {
            "identity_status": "manual_resolved",
            "canonical_name": "ipTIME 공유기 (A3004NS-M)",
            "manufacturer": "iptime(EFM)",
            "model": "A3004NS-M",
            "device_type": "router",
            "is_resolved": True,
            "is_unresolved": False,
        }
    )

    presented = apply_device_presentation(approved)
    assert presented is not None
    assert presented["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"


def test_exact_catalog_marker_is_revalidated_before_presentation():
    from app.services.device_identity import resolve_device_identity

    resolved = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "",
            "device_type": "router",
            "fingerprints": [
                "http-title:ipTIME A3004NS-M",
                "http-model:A3004NS-M",
                "upnp-type:InternetGatewayDevice",
            ],
            "discovery_sources": ["tcp-port-probe", "ssdp"],
        }
    )
    assert resolved["identity_status"] == "resolved"

    presented = apply_device_presentation(resolved)
    assert presented is not None
    assert presented["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"

    # Status and product fields survive in the forged row, but removing the
    # resolver-owned exact marker closes the catalog-only presentation path.
    assert apply_device_presentation({**resolved, "identity_candidates": []}) is None


def test_normalized_structured_products_keep_verified_catalog_and_model_paths():
    cases = (
        (
            "192.168.0.31",
            "AA:BB:CC:00:00:31",
            "fridge",
            [
                "upnp-manufacturer:Samsung",
                "upnp-model:RF85C90",
            ],
            "삼성 냉장고 (RF85C90)",
        ),
        (
            "192.168.0.32",
            "AA:BB:CC:00:00:32",
            "router",
            [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004NS-M",
                "upnp-type:InternetGatewayDevice",
            ],
            "ipTIME 공유기 (A3004NS-M)",
        ),
        (
            "192.168.0.33",
            "AA:BB:CC:00:00:33",
            "air_conditioner",
            [
                "mdns-type:._lg-smart-device._tcp.local",
                "mdns-txt:manufacturer=LG",
                "mdns-txt:model=WIN_056905_WW",
                "mdns-txt:product=air_conditioner",
            ],
            "LG 에어컨 (WIN_056905_WW)",
        ),
        (
            "192.168.0.34",
            "AA:BB:CC:00:00:34",
            "router",
            [
                "upnp-manufacturer:KT",
                "upnp-model:KM06-507H",
                "upnp-type:InternetGatewayDevice",
            ],
            "KT 공유기 (KM06-507H)",
        ),
    )

    for ip, mac, device_type, fingerprints, expected in cases:
        normalized = normalize_observed_device(
            {
                "ip_address": ip,
                "mac_address": mac,
                "device_type": device_type,
                "fingerprints": fingerprints,
                "discovery_sources": ["mdns", "ssdp"],
            },
            "android-native",
        )
        presented = apply_device_presentation(normalized)
        assert presented is not None
        assert presented["canonical_name"] == expected


def test_verified_computer_family_without_board_model_is_visible():
    device = normalize_observed_device(
        {
            "ip_address": "192.168.0.22",
            "mac_address": "A8:A1:59:FE:00:08",
            "name": "HOME-PC",
            "manufacturer": "",
            "model": "",
            "device_type": "computer",
            "open_ports": [22, 139, 445],
            "services": ["smb"],
            "discovery_sources": ["server-neighbor", "server-tcp-probe", "netbios"],
            "fingerprints": ["netbios-name:HOME-PC"],
            "risk_signals": [],
        },
        "android-native",
    )

    presented = apply_device_presentation(device)
    assert presented is not None
    assert presented["canonical_name"] == "ASRock 컴퓨터 - home-pc"
    assert presented["model"] == ""
    assert presented["identity_family_verified"] is True


def test_verified_computer_host_name_is_sanitized_and_kept_separate_from_model():
    device = normalize_observed_device(
        {
            "ip_address": "192.168.0.65",
            "mac_address": "34:5A:60:FE:00:01",
            "manufacturer": "",
            "model": "",
            "device_type": "computer",
            "open_ports": [139, 445],
            "services": ["smb", "mdns"],
            "discovery_sources": ["server-tcp-probe", "netbios", "mdns"],
            "fingerprints": [
                "mdns-name:TESTPC-MAIN [AA:BB:CC:DD:EE:FF]._workstation._tcp.local",
                "netbios-name:TESTPC-MAIN",
            ],
            "risk_signals": [],
        },
        "android-native",
    )

    presented = apply_device_presentation(device)
    assert presented is not None
    assert presented["canonical_name"] == "MSI 컴퓨터 - testpc-main"
    assert presented["model"] == ""
    assert "AA:BB:CC:DD:EE:FF" not in str(presented)


def test_model_less_computer_family_without_oui_proof_stays_hidden():
    forged = {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "manufacturer": "ASRock",
        "model": "",
        "device_type": "computer",
        "open_ports": [139, 445],
        "identity_status": "resolved",
        "identity_family_verified": True,
        "canonical_name": "ASRock 컴퓨터",
        "is_resolved": True,
        "is_unresolved": False,
    }
    assert apply_device_presentation(forged) is None


def test_sonos_service_without_model_stays_a_neutral_identity_finding():
    device = normalize_observed_device(
        {
            "device_id": "sonos-family",
            "ip_address": "192.168.0.24",
            "name": "스피커 후보",
            "device_type": "audio",
            "fingerprints": ["mdns-type:._sonos._tcp"],
            "discovery_sources": ["mdns"],
            "open_ports": [1400],
        },
        "android-native",
    )

    assert apply_device_presentation(device) is None
    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert finding["observed_service"] == "mdns"
    assert finding["observed_service_verified"] is True
    assert finding["observed_source_only"] is True
    assert finding["observation_suffix_verified"] is True
    assert finding["identity_candidates"] == []
    detected = build_public_detected_connections([finding])
    assert detected == []
    assert "Sonos" not in str(finding)
    assert "오디오 기기" not in str(finding)
    assert "스피커" not in str(finding)


def test_internal_board_identifier_is_not_published_as_a_retail_model():
    device = normalize_observed_device(
        {
            "device_id": "apple-board-identifier",
            "ip_address": "192.168.0.25",
            "name": "iPad (334)",
            "manufacturer": "",
            "model": "J617AP",
            "device_type": "phone",
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": [
                "mdns-name:iPad (334)",
                "mdns-txt:model=J617AP",
                "mdns-type:._companion-link._tcp",
            ],
        },
        "android-native",
    )

    assert apply_device_presentation(device) is None
    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert finding["observed_service"] == "mdns"
    assert finding["observed_service_verified"] is True
    detected = build_public_detected_connections([finding])
    assert detected == []
    assert "J617AP" not in str(finding)


@pytest.mark.parametrize(
    "probe_source",
    ["tcp-port-probe", "server-protocol-probe", "server-tcp-probe"],
)
def test_unknown_open_service_stays_diagnostic_only(probe_source):
    device = normalize_observed_device(
        {
            "device_id": "open-service-observation",
            "ip_address": "192.168.0.26",
            "mac_address": "UNKNOWN-192.168.0.26",
            "open_ports": [49153],
            "services": ["tcp-49153"],
            "discovery_sources": [probe_source],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert finding["observed_service"] == "tcp-service"
    assert finding["observed_service_verified"] is True
    assert finding["observed_port"] == 49153
    assert finding["observed_port_verified"] is True
    assert finding["observation_suffix_verified"] is True
    detected = build_public_detected_connections([finding])
    assert detected == []


def test_spotify_probe_attempt_falls_back_to_private_tcp_diagnostic():
    device = normalize_observed_device(
        {
            "device_id": "spotify-probe-attempt",
            "ip_address": "192.168.0.30",
            "mac_address": "UNKNOWN-192.168.0.30",
            "open_ports": [17654],
            "services": ["spotify-connect"],
            "discovery_sources": ["tcp-port-probe", "spotify-getinfo"],
            "fingerprints": ["spotify-probe:17654"],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert "Spotify" not in finding["display_name"]
    assert finding["observed_service"] == "tcp-service"
    assert finding["observed_port"] == 17654
    assert finding["observed_port_verified"] is True
    assert finding["observation_suffix_verified"] is True

    detected = build_public_detected_connections([finding])
    assert detected == []


@pytest.mark.parametrize(
    ("sources", "fingerprints"),
    [
        (
            ["tcp-port-probe", "spotify-getinfo"],
            ["spotify-probe:17654", "spotify-getinfo-done"],
        ),
        (
            ["mdns"],
            ["mdns-type:_spotify-connect._tcp.local"],
        ),
        (
            ["server-protocol-probe", "spotify-connect"],
            ["spotify-probe:17654"],
        ),
    ],
)
def test_verified_spotify_response_stays_diagnostic_without_product_guess(
    sources,
    fingerprints,
):
    device = normalize_observed_device(
        {
            "device_id": "verified-spotify-response",
            "ip_address": "192.168.0.31",
            "mac_address": "UNKNOWN-192.168.0.31",
            "open_ports": [17654],
            "services": ["spotify-connect"],
            "discovery_sources": sources,
            "fingerprints": fingerprints,
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert finding["observed_service"] == "spotify-connect"
    assert finding["observed_service_verified"] is True

    detected = build_public_detected_connections([finding])
    assert detected == []


def test_server_refusal_only_never_becomes_tcp_service_observation():
    device = normalize_observed_device(
        {
            "device_id": "server-refusal-only",
            "ip_address": "192.168.0.29",
            "mac_address": "UNKNOWN-192.168.0.29",
            "open_ports": [],
            "services": [],
            "discovery_sources": ["server-tcp-refused-presence"],
            "fingerprints": [],
        },
        "server-probe",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert "observed_service" not in finding
    assert build_public_detected_connections([finding]) == []


def test_fresh_neighbor_only_is_visible_with_stable_non_product_label():
    device = normalize_observed_device(
        {
            "device_id": "neighbor-only-observation",
            "ip_address": "192.168.0.27",
            "mac_address": "UNKNOWN-192.168.0.27",
            "open_ports": [],
            "services": [],
            "discovery_sources": ["android-neighbor"],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"].startswith("Wi-Fi 단말 · ")
    assert finding["observed_service"] == "neighbor-presence"
    assert finding["observed_service_verified"] is True
    assert finding["observation_suffix_verified"] is True
    detected = build_public_detected_connections([finding])
    assert len(detected) == 1
    assert detected[0]["display_name"] == finding["display_name"]
    assert detected[0]["device_type"] == "network"
    assert "현재 Wi-Fi 이웃 확인" not in str(finding)


def test_fresh_neighbor_and_tcp_transport_use_l2_label_not_tcp_label():
    device = normalize_observed_device(
        {
            "device_id": "neighbor-with-open-port",
            "ip_address": "192.168.0.31",
            "mac_address": "UNKNOWN-192.168.0.31",
            "open_ports": [49153],
            "services": ["tcp-49153"],
            "discovery_sources": ["android-neighbor", "tcp-port-probe"],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"].startswith("Wi-Fi 단말 · ")
    assert finding["observed_service"] == "neighbor-presence"
    assert "TCP 서비스 응답" not in str(finding)
    assert "현재 Wi-Fi 이웃 확인" not in str(finding)
    detected = build_public_detected_connections([finding])
    assert len(detected) == 1
    assert detected[0]["display_name"] == finding["display_name"]


def test_physical_mac_proves_l2_endpoint_but_stale_arp_only_does_not():
    current = normalize_observed_device(
        {
            "device_id": "physical-mac-mdns",
            "ip_address": "192.168.0.44",
            "mac_address": "34:5A:60:FE:00:01",
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": [],
        },
        "android-native",
    )
    stale = normalize_observed_device(
        {
            "device_id": "stale-arp-physical-mac",
            "ip_address": "192.168.0.45",
            "mac_address": "34:5A:60:FE:00:02",
            "services": [],
            "discovery_sources": ["android-arp"],
            "fingerprints": [],
        },
        "android-native",
    )

    current_finding = build_identity_finding(current)
    stale_finding = build_identity_finding(stale)
    assert current_finding["display_name"].startswith("Wi-Fi 단말 · ")
    assert len(build_public_detected_connections([current_finding])) == 1
    assert stale_finding["display_name"] == ""
    assert build_public_detected_connections([stale_finding]) == []


def test_l2_label_prefers_safe_alias_then_observed_hostname():
    aliased = normalize_observed_device(
        {
            "device_id": "neighbor-with-alias",
            "ip_address": "192.168.0.46",
            "mac_address": "AA:BB:CC:00:00:46",
            "alias": "거실 태블릿",
            "discovery_sources": ["android-neighbor", "mdns"],
            "fingerprints": ["mdns-name:test-owner-Tab-S5e"],
        },
        "android-native",
    )
    host_only = normalize_observed_device(
        {
            "device_id": "neighbor-with-host",
            "ip_address": "192.168.0.47",
            "mac_address": "AA:BB:CC:00:00:47",
            "discovery_sources": ["server-neighbor", "mdns"],
            "fingerprints": ["mdns-name:Samsung-FamilyHub"],
        },
        "server-probe",
    )

    aliased_finding = build_identity_finding({**aliased, "alias": "거실 태블릿"})
    host_finding = build_identity_finding(host_only)
    assert aliased_finding["display_name"] == "거실 태블릿"
    assert aliased_finding["alias"] == "거실 태블릿"
    assert host_finding["display_name"] == "samsung-familyhub"
    assert [
        item["display_name"]
        for item in build_public_detected_connections([aliased_finding, host_finding])
    ] == ["거실 태블릿", "samsung-familyhub"]


def test_structured_unknown_model_keeps_reported_type_as_unresolved_product_clue():
    finding = build_identity_finding(
        {
            "device_id": "structured-unknown-model",
            "home_id": "home-finding",
            "identity_status": "enriching",
            "manufacturer": "Samsung",
            "model": "XYZ-9000",
            "device_type": "fridge",
            "services": ["upnp"],
            "discovery_sources": ["upnp"],
            "fingerprints": [
                "upnp-manufacturer:Samsung",
                "upnp-model:XYZ-9000",
            ],
        }
    )

    assert finding["display_name"] == "삼성 냉장고 (XYZ-9000)"
    detected = build_public_detected_connections([finding])
    assert len(detected) == 1
    assert detected[0]["product_clue_verified"] is True
    assert detected[0]["identity_status"] == "enriching"


@pytest.mark.parametrize("source", ["mdns", "ssdp", "onvif"])
def test_protocol_source_only_observation_stays_diagnostic(source):
    device = normalize_observed_device(
        {
            "device_id": f"source-only-{source}",
            "ip_address": "192.168.0.28",
            "mac_address": "UNKNOWN-192.168.0.28",
            "open_ports": [],
            "services": [],
            "discovery_sources": [source],
            "fingerprints": [],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == ""
    assert finding["observed_service"] == source
    assert finding["observed_source_only"] is True
    assert finding["observed_source_only_verified"] is True
    assert finding["observation_suffix_verified"] is True
    detected = build_public_detected_connections([finding])
    assert detected == []


def test_verified_camera_type_uses_type_name_and_keeps_onvif_as_supporting_evidence():
    device = normalize_observed_device(
        {
            "device_id": "verified-camera-observation",
            "ip_address": "192.168.0.32",
            "device_type": "camera",
            "services": ["onvif"],
            "discovery_sources": ["onvif"],
            "fingerprints": ["onvif-ws-discovery"],
            "identity_evidence": ["카메라 응답 정보"],
        },
        "android-native",
    )

    finding = build_identity_finding(device)
    assert finding["display_name"] == f"카메라 · {finding['observation_suffix']}"
    assert finding["observed_type"] == "camera"
    assert finding["observed_type_verified"] is True
    assert finding["observed_service"] == "onvif"
    assert finding["observed_service_verified"] is True

    detected = build_public_detected_connections([finding])
    assert len(detected) == 1
    assert detected[0]["display_name"] == finding["display_name"]
    assert detected[0]["device_type"] == "camera"
    assert detected[0]["observed_service"] == "onvif"


def test_paired_smb_ports_stay_a_neutral_finding_without_product_identity():
    device = normalize_observed_device(
        {
            "ip_address": "192.168.0.23",
            "name": "DESKTOP-HOME",
            "manufacturer": "",
            "model": "",
            "device_type": "computer",
            "open_ports": [139, 445],
            "services": ["smb"],
            "discovery_sources": ["tcp-port-probe"],
            "fingerprints": ["netbios-name:DESKTOP-HOME"],
            "risk_signals": [],
        },
        "android-native",
    )

    assert apply_device_presentation(device) is None
    finding = build_identity_finding(device)
    assert finding["display_name"] == "desktop-home"
    assert finding["observed_type"] == "computer"
    assert finding["observed_type_verified"] is True
    assert finding["observed_host_name"] == "desktop-home"
    assert finding["host_name_verified"] is True
    assert finding["observed_service"] == "smb"
    assert finding["observed_service_verified"] is True
    assert "manufacturer" not in finding
    assert "model" not in finding
    detected = build_public_detected_connections([finding])
    assert detected[0]["display_name"] == "desktop-home"
    assert detected[0]["presentation_kind"] == "observed_connection"
    assert detected[0]["product_clue_verified"] is False
    assert detected[0]["observed_service"] == "smb"


def test_same_evidence_backed_name_keeps_distinct_observations_by_device_id():
    findings = [
        build_identity_finding(
            {
                "device_id": device_id,
                "home_id": "home-same-name",
                "ip_address": f"192.168.0.{index + 60}",
                "mac_address": f"A8:A1:59:41:2C:{index + 61:02X}",
                "manufacturer": "ASRock",
                "device_type": "computer",
                "open_ports": [139, 445],
                "services": ["smb", "netbios"],
                "discovery_sources": ["server-neighbor", "netbios"],
                "fingerprints": ["netbios-name:TESTPC"],
            }
        )
        for index, device_id in enumerate(("device-same-name-a", "device-same-name-b"))
    ]

    detected = build_public_detected_connections(findings)

    assert len(detected) == 2
    assert len({item["device_id"] for item in detected}) == 2
    assert {item["device_id"] for item in detected} == {
        item["device_id"] for item in findings
    }
    assert {item["display_name"] for item in detected} == {
        "ASRock 컴퓨터 - testpc"
    }


def test_public_device_id_masks_legacy_lan_address_in_direct_and_nested_payloads():
    raw_id = "dev-192-168-10-21"
    expected = public_device_id(raw_id, "home-private-id")

    presented = apply_device_presentation(
        {
            "device_id": raw_id,
            "home_id": "home-private-id",
            "device_type": "router",
            "manufacturer": "iptime(EFM)",
            "model": "A3004",
            "discovery_sources": ["ssdp"],
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004",
                "upnp-type:InternetGatewayDevice",
            ],
        }
    )
    nested = sanitize_public_payload(
        {
            "home_id": "home-private-id",
            "event": {"device_id": raw_id},
        }
    )

    assert presented is not None
    assert presented["device_id"] == expected
    assert nested["event"]["device_id"] == expected
    assert "192-168-10-21" not in presented["device_id"]
    assert "192-168-10-21" not in nested["event"]["device_id"]


def test_compressed_ipv6_is_removed_from_public_payloads_and_device_ids():
    raw_ids = ("device-fe80::1", "device-2001:db8::1", "device-::1")

    for raw_id in raw_ids:
        public_id = public_device_id(raw_id, "home-ipv6")
        payload = sanitize_public_payload(
            {
                "home_id": "home-ipv6",
                "device_id": raw_id,
                "nested": {"observed_at": raw_id, raw_id: "must not be public"},
            }
        )

        assert public_id.startswith("device-")
        assert public_id != raw_id
        assert payload["device_id"] == public_id
        assert raw_id not in str(payload)

    presented = apply_device_presentation(
        {
            "device_id": "device-fe80::1",
            "home_id": "home-ipv6",
            "device_type": "router",
            "manufacturer": "iptime(EFM)",
            "model": "A3004",
            "discovery_sources": ["ssdp"],
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004",
                "upnp-type:InternetGatewayDevice",
            ],
        }
    )

    assert presented is not None
    assert presented["device_id"] == public_device_id("device-fe80::1", "home-ipv6")
    assert "fe80::1" not in str(presented)


def test_public_device_dto_uses_an_allowlist_for_legacy_snapshot_fields():
    presented = apply_device_presentation(
        {
            "device_id": "device-allowlist",
            "home_id": "home-allowlist",
            "device_type": "router",
            "manufacturer": "iptime(EFM)",
            "model": "A3004",
            "discovery_sources": ["ssdp"],
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004",
                "upnp-type:InternetGatewayDevice",
            ],
            "online": False,
            "last_seen": "2026-08-13T00:00:00Z",
            "default_credentials": True,
            "encryption": "wpa2",
            "scan_source": "android-native",
            "confidence": 0.91,
            "security_score": 72,
            "risk_level": "yellow",
            "risk_summary": "검토가 필요해요.",
            "recommended_actions": ["업데이트를 확인해 주세요."],
            "alias": "우리 집 공유기",
            "vulnerabilities": [{"cve_id": "CVE-2026-0001", "severity": "high"}],
            "risk_explanations": [{"summary_ko": "보안 설정을 확인해 주세요."}],
            "location": "거실",
            "room": "안방",
            "display_name": "거실 공유기",
            "guessed_product": "SafeHome Router (R-1)",
            "serial_hint": "serial-1234",
            "future_legacy_field": "must not cross the public boundary",
        }
    )

    assert presented is not None
    assert presented["scan_source"] == "android-native"
    assert presented["risk_level"] == "yellow"
    assert presented["alias"] == "우리 집 공유기"
    assert presented["discovery_sources"] == ["ssdp"]
    assert presented["vulnerabilities"] == [{"cve_id": "CVE-2026-0001", "severity": "high"}]
    assert presented["risk_explanations"] == [{"summary_ko": "보안 설정을 확인해 주세요."}]
    assert not {
        "location",
        "room",
        "display_name",
        "guessed_product",
        "serial_hint",
        "future_legacy_field",
    }.intersection(presented)


def test_network_context_keeps_validated_addresses_only_in_private_storage_projection():
    private_context = normalize_stored_network_context(
        {
            "local_ip": "192.168.50.23",
            "gateway_ip": "192.168.50.1",
            "subnet_cidr": "192.168.50.0/24",
            "interface_type": "wifi",
            "is_private_network": True,
            "scanner_note": "Realtek OUI web-device",
        }
    )

    assert private_context == {
        "local_ip": "192.168.50.23",
        "gateway_ip": "192.168.50.1",
        "subnet_cidr": "192.168.50.0/24",
        "interface_type": "wifi",
        "is_private_network": True,
    }
    assert sanitize_public_network_context(private_context) == {
        "interface_type": "wifi",
        "is_private_network": True,
    }


def test_scan_diagnostics_keep_only_bounded_aggregate_counters():
    private_context = normalize_stored_network_context(
        {
            "interface_type": "wifi",
            "is_private_network": True,
            "scan_diagnostics": {
                "subnet_host_count": 254,
                "candidate_host_count": 37,
                "candidate_coverage_complete": False,
                "neighbor_proc_source_available_before": True,
                "neighbor_ip_source_available_before": False,
                "neighbor_source_available_before": True,
                "neighbor_proc_source_available_after": True,
                "neighbor_ip_source_available_after": True,
                "neighbor_source_available_after": True,
                "neighbor_probe_complete": True,
                "neighbor_presence_confirmed": False,
                "neighbor_coverage_complete": False,
                "candidate_stimulation_complete": False,
                "tcp_transport_complete": False,
                "wifi_network_socket_binding_required": True,
                "wifi_network_socket_binding_complete": False,
                "server_probe_l2_unverified": True,
                "observation_limit_reached": True,
                "arp_entries_before_probe": 4.0,
                "arp_entries_after_probe": 5,
                "arp_observation_hosts": 3,
                "arp_stale_entries_suppressed": 2,
                "neighbor_fresh_state_hosts": 1,
                "neighbor_unverified_hosts": 2,
                "tcp_hosts": 11,
                "tcp_probe_completed_hosts": 37,
                "wifi_network_socket_bind_attempts": 42,
                "wifi_network_socket_bind_failures": 1,
                "physical_mac_hosts": 3,
                "manufacturer_hint_hosts": 2,
                "model_hint_hosts": 1,
                "raw_observation_count": 15,
                "observation_host_limit": 512,
                "observation_overflow_events": 3,
                "observation_hosts_dropped": 2,
                "observation_hosts_evicted": 1,
                "observation_receive_buffer_dropped": 0,
                "subnet_cidr": "192.168.50.0/24",
                "local_ip": "192.168.50.23",
                "negative": -1,
                "too_large": 2_000_000,
                "boolean_is_not_a_count": True,
                "unsafe_text": "Realtek OUI",
            },
        }
    )

    assert private_context["scan_diagnostics"] == {
        "subnet_host_count": 254,
        "candidate_host_count": 37,
        "candidate_coverage_complete": False,
        "neighbor_proc_source_available_before": True,
        "neighbor_ip_source_available_before": False,
        "neighbor_source_available_before": True,
        "neighbor_proc_source_available_after": True,
        "neighbor_ip_source_available_after": True,
        "neighbor_source_available_after": True,
        "neighbor_probe_complete": True,
        "neighbor_presence_confirmed": False,
        "neighbor_coverage_complete": False,
        "candidate_stimulation_complete": False,
        "tcp_transport_complete": False,
        "wifi_network_socket_binding_required": True,
        "wifi_network_socket_binding_complete": False,
        "server_probe_l2_unverified": True,
        "observation_limit_reached": True,
        "arp_entries_before_probe": 4,
        "arp_entries_after_probe": 5,
        "arp_observation_hosts": 3,
        "arp_stale_entries_suppressed": 2,
        "neighbor_fresh_state_hosts": 1,
        "neighbor_unverified_hosts": 2,
        "tcp_hosts": 11,
        "tcp_probe_completed_hosts": 37,
        "wifi_network_socket_bind_attempts": 42,
        "wifi_network_socket_bind_failures": 1,
        "physical_mac_hosts": 3,
        "manufacturer_hint_hosts": 2,
        "model_hint_hosts": 1,
        "raw_observation_count": 15,
        "observation_host_limit": 512,
        "observation_overflow_events": 3,
        "observation_hosts_dropped": 2,
        "observation_hosts_evicted": 1,
        "observation_receive_buffer_dropped": 0,
    }
    assert sanitize_public_network_context(private_context) == {
        "interface_type": "wifi",
        "is_private_network": True,
        "scan_diagnostics": {
            "subnet_host_count": 254,
            "candidate_host_count": 37,
            "candidate_coverage_complete": False,
            "neighbor_proc_source_available_before": True,
            "neighbor_ip_source_available_before": False,
            "neighbor_source_available_before": True,
            "neighbor_proc_source_available_after": True,
            "neighbor_ip_source_available_after": True,
            "neighbor_source_available_after": True,
            "neighbor_probe_complete": True,
            "neighbor_presence_confirmed": False,
            "neighbor_coverage_complete": False,
            "candidate_stimulation_complete": False,
            "tcp_transport_complete": False,
            "wifi_network_socket_binding_required": True,
            "wifi_network_socket_binding_complete": False,
            "server_probe_l2_unverified": True,
            "observation_limit_reached": True,
            "arp_entries_before_probe": 4,
            "arp_entries_after_probe": 5,
            "arp_observation_hosts": 3,
            "arp_stale_entries_suppressed": 2,
            "neighbor_fresh_state_hosts": 1,
            "neighbor_unverified_hosts": 2,
            "tcp_hosts": 11,
            "tcp_probe_completed_hosts": 37,
            "wifi_network_socket_bind_attempts": 42,
            "wifi_network_socket_bind_failures": 1,
            "physical_mac_hosts": 3,
            "manufacturer_hint_hosts": 2,
            "model_hint_hosts": 1,
            "raw_observation_count": 15,
            "observation_host_limit": 512,
            "observation_overflow_events": 3,
            "observation_hosts_dropped": 2,
            "observation_hosts_evicted": 1,
            "observation_receive_buffer_dropped": 0,
        },
    }


def test_user_alias_wins_only_when_it_is_safe():
    raw = {
        "device_type": "router",
        "manufacturer": "iptime(EFM)",
        "model": "A3004",
        "discovery_sources": ["ssdp"],
        "fingerprints": [
            "upnp-manufacturer:EFM Networks",
            "upnp-model:A3004",
            "upnp-type:InternetGatewayDevice",
        ],
        "alias": "우리 집 공유기",
    }
    assert apply_device_presentation(raw)["name"] == "우리 집 공유기"

    unsafe = {**raw, "alias": "Realtek 공유기"}
    presented = apply_device_presentation(unsafe)
    assert presented is not None
    assert presented["name"] == "ipTIME 공유기 (A3004)"
    assert "alias" not in presented
    assert not is_safe_device_alias("제조사 미확인 기기")
    assert not is_safe_device_alias("ESP32 장치")


def test_non_product_chipset_name_never_becomes_a_brand_or_model():
    presented = apply_device_presentation(
        {
            "name": "정체불명 기기",
            "device_type": "camera",
            "manufacturer": "Espressif Systems",
            "model": "ESP32-CAM",
            "discovery_sources": ["ws-discovery"],
        }
    )

    # A chipset/ONVIF category is detection evidence, not a product identity.
    assert presented is None


def test_bare_port_guess_is_hidden_instead_of_fabricating_a_device_name():
    assert (
        apply_device_presentation(
            {
                "name": "웹 관리 기기",
                "device_type": "web-device",
                "open_ports": [80],
                "scan_source": "android-native",
            }
        )
        is None
    )


def test_public_device_and_notification_payloads_remove_internal_discovery_text():
    presented = apply_device_presentation(
        {
            "device_type": "router",
            "manufacturer": "iptime(EFM)",
            "model": "A3004",
            "discovery_sources": ["ssdp"],
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004",
                "upnp-type:InternetGatewayDevice",
                "realtek chipset",
            ],
            "risk_signals": ["unknown device"],
            "firmware": "Realtek firmware",
            "vulnerabilities": [{"cve_id": "CVE-2026-0001", "vendor": "Realtek", "severity": "high"}],
        }
    )
    assert presented is not None
    assert not _contains_forbidden(presented)
    assert presented["fingerprints"] == [] if "fingerprints" in presented else True

    notification = sanitize_public_notification(
        {
            "title": "제조사 미확인 기기 경고",
            "message": "Realtek chipset 신호를 찾았습니다.",
            "description": "정체불명 기기입니다.",
            "action_guide": "ESP32를 확인하세요.",
        }
    )
    assert not _contains_forbidden(notification)


def test_registration_authority_text_is_not_a_public_brand_alias_or_nested_payload():
    presented = apply_device_presentation(
        {
            "name": "IEEE Registration Authority 공유기",
            "device_type": "router",
            "manufacturer": "IEEE Registration Authority",
            "model": "MA-S OUI",
            "fingerprints": ["ssdp:InternetGatewayDevice"],
        }
    )

    assert presented is None
    assert not is_safe_device_alias("IANA 등록기관 공유기")
    assert not is_safe_device_alias("Private 기기")
    assert is_safe_device_alias("우리 집 공유기")

    payload = sanitize_public_payload(
        {
            "manufacturer": "IEEE Registration Authority",
            "model": "MA-M",
            "OUI Registration Authority": "이 키도 공개하면 안 됩니다.",
            "recommended_actions": [
                "OUI 등록기관 정보를 확인하세요.",
                "공유기 비밀번호를 바꾸세요.",
            ],
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2026-0001",
                    "summary_ko": "Private 등록기관 신호를 찾았습니다.",
                    "remediation_ko": "IANA 정보를 확인하세요.",
                }
            ],
            "nested": {
                "action_guide": "MA-S 등록값을 확인하세요.",
                "IEEE Registration Authority": "이 키도 공개하면 안 됩니다.",
            },
            "actual_product": "삼성 전자 제품을 확인하세요.",
        }
    )
    notification = sanitize_public_notification(
        {
            "title": "IEEE Registration Authority 기기 안내",
            "message": "OUI 등록기관 신호를 찾았습니다.",
            "action_guide": "MA-M 값을 확인하세요.",
        }
    )

    assert not _contains_forbidden(payload)
    assert payload["recommended_actions"] == ["공유기 비밀번호를 바꾸세요."]
    assert payload["vulnerabilities"] == [{"cve_id": "CVE-2026-0001"}]
    assert payload["nested"] == {}
    assert payload["actual_product"] == "삼성 전자 제품을 확인하세요."
    assert not _contains_forbidden(notification)


def test_public_device_dto_never_returns_ip_or_mac_addresses():
    presented = apply_device_presentation(
        {
            "device_id": "device-1",
            "device_type": "fridge",
            "manufacturer": "Samsung Electronics",
            "model": "RF85C90",
            "fingerprints": [
                "spotify-brand:Samsung",
                "spotify-model:RF85C90",
            ],
            "ip_address": "192.168.10.24",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "nested": {"source_ip": "10.0.0.8", "source_mac": "00:11:22:33:44:55"},
        }
    )

    assert presented is not None
    serialized = str(presented)
    assert "ip_address" not in presented
    assert "mac_address" not in presented
    assert "192.168.10.24" not in serialized
    assert "AA:BB:CC:DD:EE:FF" not in serialized
    assert "10.0.0.8" not in serialized
    assert "00:11:22:33:44:55" not in serialized


def test_notification_redacts_literal_network_addresses():
    notification = sanitize_public_notification(
        {
            "title": "Device at 192.168.0.12 needs attention",
            "message": "MAC AA:BB:CC:DD:EE:FF was observed",
            "description": "Source 2001:db8::1",
        }
    )

    serialized = str(notification)
    assert "192.168.0.12" not in serialized
    assert "AA:BB:CC:DD:EE:FF" not in serialized
    assert "2001:db8::1" not in serialized


def test_notification_redacts_each_compressed_ipv6_form():
    for address in ("fe80::1", "2001:db8::1", "::1"):
        notification = sanitize_public_notification(
            {
                "title": f"Device at {address} needs attention",
                "message": "검사 결과를 확인해 주세요.",
                "device_id": f"device-{address}",
            }
        )

        assert notification["title"] == "기기 확인 안내"
        assert address not in str(notification)
        assert notification["device_id"].startswith("device-")
        assert notification["device_id"] != f"device-{address}"


def test_notification_projects_forged_legacy_device_labels_but_preserves_real_copy():
    forged = sanitize_public_notification(
        {
            "title": "SafeHome camera (R-1) 보안 안내",
            "message": "SafeHome camera (R-1)의 설정을 확인해 주세요.",
            "device_name": "SafeHome camera (R-1)",
        }
    )
    real = {
        "title": "삼성 냉장고 (RF85C90) 보안 안내",
        "message": "삼성 냉장고 (RF85C90)의 업데이트 상태를 확인해 주세요.",
    }

    assert forged["title"] == "기기 확인 안내"
    assert "SafeHome" not in str(forged)
    assert "device_name" not in forged
    assert sanitize_public_notification(real) == real


def test_http_server_banner_never_becomes_a_public_model():
    presented = apply_device_presentation(
        {
            "device_type": "router",
            "manufacturer": "Samsung",
            "model": "Boa/0.94.14rc21",
            "fingerprints": [
                "http-server:Boa/0.94.14rc21",
                "ssdp-st:InternetGatewayDevice",
            ],
        }
    )

    assert presented is None


def test_raw_harmless_identity_does_not_become_public_without_product_evidence():
    # A protocol can verify a category, but harmless raw vendor/model strings
    # cannot attach themselves to that public category without provenance.
    type_only = apply_device_presentation(
        {
            "device_type": "router",
            "manufacturer": "SafeHome",
            "model": "R-1",
            "discovery_sources": ["ssdp"],
            "fingerprints": ["ssdp-st:InternetGatewayDevice"],
        }
    )
    assert type_only is None

    assert apply_device_presentation(
        {
            "device_type": "router",
            "manufacturer": "SafeHome",
            "model": "R-1",
            "discovery_sources": ["ssdp"],
        }
    ) is None

    # Known products remain visible when a device self-advertises both values
    # through a structured protocol description.
    presented = apply_device_presentation(
        {
            "device_type": "router",
            "manufacturer": "EFM Networks",
            "model": "A3004",
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004",
            ],
        }
    )
    assert presented is not None
    assert presented["canonical_name"] == "ipTIME 공유기 (A3004)"
