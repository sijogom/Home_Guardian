from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.main import (
    _apply_public_identity_contract,
    _apply_scan_completion_contract,
    _scan_push_title_body,
    app,
    issue_token_pair,
    repository,
)
from app.scan_validation import (
    actual_android_scan_rejection_reasons,
    enforce_declared_subnet_boundary,
    scan_coverage_complete,
    scan_is_partial,
    strip_untrusted_self_claims,
)
from app.services.device_presentation import (
    normalize_stored_network_context,
    sanitize_public_network_context,
)


NETWORK_CONTEXT = {
    "local_ip": "192.168.50.20",
    "gateway_ip": "192.168.50.1",
    "subnet_cidr": "192.168.50.0/24",
    "interface_type": "wifi",
    "is_private_network": True,
}

client = TestClient(app)


def _owner_headers(user_id: str) -> dict[str, str]:
    user = repository.upsert_user(
        {
            "user_id": user_id,
            "email": f"{user_id}@scan-validation.invalid",
            "nickname": f"스캔 검증 사용자 {user_id}",
            "role": "user",
            "email_verified": True,
            "home_id": f"home-{user_id}",
        }
    )
    tokens = issue_token_pair(user)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _device(ip_address: str, *, fingerprints: list[str] | None = None) -> dict[str, object]:
    return {
        "device_id": f"private-{ip_address}",
        "ip_address": ip_address,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "fingerprints": fingerprints or [],
        "discovery_sources": ["ssdp"],
    }


def test_untrusted_self_claims_are_removed_without_dropping_endpoint_evidence():
    cleaned = strip_untrusted_self_claims(
        {
            "device_id": "self-192-168-50-44",
            "name": "내 휴대폰 (SM-F956N)",
            "ip_address": "192.168.50.44",
            "mac_address": "AA:BB:CC:DD:EE:44",
            "services": ["self-device", "http"],
            "discovery_sources": ["self", "ssdp"],
            "risk_signals": ["self_device", "open_telnet"],
            "fingerprints": [
                "self-android",
                "self-manufacturer:samsung",
                "self-model:SM-F956N",
                "upnp-model:RT-AX58U",
            ],
            "source": "self",
            "open_ports": [80],
        }
    )

    assert cleaned["device_id"] is None
    assert cleaned["name"] is None
    assert "source" not in cleaned
    assert cleaned["services"] == ["http"]
    assert cleaned["discovery_sources"] == ["ssdp"]
    assert cleaned["risk_signals"] == ["open_telnet"]
    assert cleaned["fingerprints"] == ["upnp-model:RT-AX58U"]
    assert cleaned["ip_address"] == "192.168.50.44"
    assert cleaned["mac_address"] == "AA:BB:CC:DD:EE:44"
    assert cleaned["open_ports"] == [80]


def test_actual_android_context_requires_local_and_gateway_inside_declared_subnet():
    reasons = actual_android_scan_rejection_reasons(
        {**NETWORK_CONTEXT, "gateway_ip": "192.168.60.1"},
        [],
    )

    assert "공유기 주소와 Wi-Fi 서브넷이 일치하지 않음" in reasons
    assert all("192.168.60.1" not in reason for reason in reasons)


def test_out_of_subnet_observations_and_endpoint_evidence_are_quarantined():
    boundary = enforce_declared_subnet_boundary(
        {
            **NETWORK_CONTEXT,
            "scan_diagnostics": {
                "candidate_coverage_complete": True,
                # The native scanner already quarantined two observations that
                # are no longer present in the transported device list.
                "out_of_subnet_observations_dropped": 2,
            },
        },
        [
            _device("192.168.50.41", fingerprints=["ssdp-location:http://192.168.50.41/root.xml"]),
            _device("192.168.60.42"),
            _device("192.168.50.43", fingerprints=["spotify-endpoint:192.168.60.43|1400|/info"]),
            _device("192.168.50.45", fingerprints=["ssdp-location:https://outside.example/device.xml"]),
        ],
    )

    assert [device["ip_address"] for device in boundary.devices] == [
        "192.168.50.41",
        "192.168.50.43",
        "192.168.50.45",
    ]
    assert boundary.devices[1]["fingerprints"] == []
    assert boundary.devices[2]["fingerprints"] == []
    assert boundary.dropped_count == 3
    assert boundary.quarantined_endpoint_count == 2
    assert boundary.network_context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "out_of_subnet_observations_dropped": 3,
        "endpoint_evidence_quarantined": 2,
    }
    assert scan_is_partial(boundary.network_context) is True
    assert scan_coverage_complete(boundary.network_context) is False
    second_pass = enforce_declared_subnet_boundary(
        boundary.network_context,
        boundary.devices,
        prior_dropped=boundary.dropped_count,
        prior_quarantined_endpoints=boundary.quarantined_endpoint_count,
    )
    assert second_pass.dropped_count == 3
    assert second_pass.quarantined_endpoint_count == 2


def test_model_version_text_is_not_mistaken_for_endpoint_address():
    boundary = enforce_declared_subnet_boundary(
        NETWORK_CONTEXT,
        [_device("192.168.50.44", fingerprints=["upnp-model:Firmware 1.2.3.4"])],
    )

    assert len(boundary.devices) == 1
    assert boundary.dropped_count == 0
    assert scan_is_partial(boundary.network_context) is False


def test_local_hostname_location_is_quarantined_without_dropping_observation():
    boundary = enforce_declared_subnet_boundary(
        NETWORK_CONTEXT,
        [
            _device(
                "192.168.50.44",
                fingerprints=[
                    "ssdp-location:http://living-room-tv.local:1400/root.xml",
                    "upnp-model:Verified-Model-44",
                ],
            )
        ],
    )

    assert len(boundary.devices) == 1
    assert boundary.dropped_count == 0
    assert boundary.quarantined_endpoint_count == 1
    assert boundary.devices[0]["fingerprints"] == ["upnp-model:Verified-Model-44"]
    assert boundary.network_context["scan_diagnostics"] == {
        "endpoint_evidence_quarantined": 1,
    }
    assert scan_is_partial(boundary.network_context) is True
    assert scan_coverage_complete(boundary.network_context) is False

    second_pass = enforce_declared_subnet_boundary(
        boundary.network_context,
        boundary.devices,
        prior_dropped=boundary.dropped_count,
        prior_quarantined_endpoints=boundary.quarantined_endpoint_count,
    )
    assert len(second_pass.devices) == 1
    assert second_pass.quarantined_endpoint_count == 1


def test_public_hostname_location_is_quarantined_without_hiding_observation():
    boundary = enforce_declared_subnet_boundary(
        NETWORK_CONTEXT,
        [_device("192.168.50.44", fingerprints=["ssdp-location:http://device.example/root.xml"])],
    )

    assert len(boundary.devices) == 1
    assert boundary.devices[0]["fingerprints"] == []
    assert boundary.dropped_count == 0
    assert boundary.quarantined_endpoint_count == 1
    assert scan_is_partial(boundary.network_context) is True


def test_invalid_or_foreign_endpoint_evidence_never_hides_in_subnet_device():
    boundary = enforce_declared_subnet_boundary(
        NETWORK_CONTEXT,
        [
            _device(
                "192.168.50.44",
                fingerprints=[
                    "ssdp-location:http://user:secret@192.168.50.44/root.xml",
                    "onvif-endpoint:192.168.60.44|80|/onvif/device_service",
                    "mdns-host:living-room.local|5353|/",
                    "spotify-endpoint:192.168.50.44|1400|/info",
                    "upnp-model:Verified-Model-44",
                ],
            )
        ],
    )

    assert len(boundary.devices) == 1
    assert boundary.devices[0]["fingerprints"] == [
        "spotify-endpoint:192.168.50.44|1400|/info",
        "upnp-model:Verified-Model-44",
    ]
    assert boundary.dropped_count == 0
    assert boundary.quarantined_endpoint_count == 3
    assert boundary.network_context["scan_diagnostics"] == {
        "endpoint_evidence_quarantined": 3,
    }


def test_partial_scan_requires_explicit_negative_diagnostic_evidence():
    assert scan_is_partial(NETWORK_CONTEXT) is False
    assert scan_coverage_complete(NETWORK_CONTEXT) is None
    assert scan_is_partial({"scan_diagnostics": {"candidate_coverage_complete": False}}) is True
    # Neighbor-table access is optional on modern Android. A missing source is
    # diagnostic evidence, not a transport failure by itself.
    assert scan_is_partial({"scan_diagnostics": {"neighbor_coverage_complete": False}}) is False
    assert scan_coverage_complete(
        {
            "scan_diagnostics": {
                "candidate_coverage_complete": True,
                "neighbor_coverage_complete": False,
            }
        }
    ) is True
    assert scan_is_partial({"scan_diagnostics": {"tcp_scan_timed_out": True}}) is True
    assert scan_is_partial({"scan_diagnostics": {"tcp_scan_timed_out": False}}) is False
    assert scan_is_partial({"scan_diagnostics": {"candidate_stimulation_complete": False}}) is True
    assert scan_is_partial({"scan_diagnostics": {"neighbor_source_available_after": False}}) is False
    assert scan_is_partial({"scan_diagnostics": {"neighbor_probe_complete": False}}) is False
    assert scan_is_partial({"scan_diagnostics": {"neighbor_presence_confirmed": False}}) is False
    assert scan_is_partial({"scan_diagnostics": {"tcp_transport_complete": False}}) is True
    assert scan_is_partial({"scan_diagnostics": {"wifi_network_socket_binding_complete": False}}) is True
    assert scan_is_partial({"scan_diagnostics": {"arp_stale_entries_suppressed": 1}}) is False
    assert scan_is_partial({"scan_diagnostics": {"neighbor_unverified_hosts": 1}}) is False
    assert scan_is_partial(
        {"scan_diagnostics": {"arp_entries_before_probe": 0, "arp_entries_after_probe": 0}}
    ) is False
    assert scan_coverage_complete(
        {"scan_diagnostics": {"candidate_stimulation_complete": False}}
    ) is False
    assert scan_is_partial({"scan_diagnostics": {"observation_limit_reached": True}}) is True
    assert scan_coverage_complete(
        {"scan_diagnostics": {"arp_stale_entries_suppressed": 1}}
    ) is None
    assert scan_coverage_complete(
        {
            "scan_diagnostics": {
                "candidate_stimulation_complete": True,
                "tcp_transport_complete": True,
                "wifi_network_socket_binding_complete": True,
            }
        }
    ) is None


def test_partial_scan_projects_observed_numeric_score_without_hiding_confirmed_red_risk():
    projected = _apply_scan_completion_contract(
        {
            "status": "completed",
            "current_step": "점검 완료",
            "high_risk_devices": 1,
            "devices_found": 2,
            "security_score": {
                "score": 24,
                "risk_level": "red",
                "device_scores": [{"risk_level": "red"}, {"risk_level": "green"}],
            },
        },
        {"scan_diagnostics": {"tcp_scan_timed_out": True}},
    )

    assert projected["status"] == "partial"
    assert projected["security_score"]["score"] == 24
    assert projected["security_score"]["score_status"] == "provisional"
    assert projected["security_score"]["scan_complete"] is False
    assert projected["security_score"]["coverage_complete"] is False
    assert projected["security_score"]["risk_level"] == "red"
    title, body, _ = _scan_push_title_body(projected)
    assert title == "위험한 기기가 발견됐어요"
    assert "다시 점검" in body


def test_partial_identity_projection_does_not_erase_a_provisional_observed_score():
    projected = _apply_public_identity_contract(
        _apply_scan_completion_contract(
            {
                "status": "completed",
                "current_step": "점검 완료",
                "identity_pending_count": 1,
                "high_risk_devices": 1,
                "security_score": {
                    "score": 38,
                    "risk_level": "red",
                    "device_scores": [{"score": 38, "risk_level": "red"}],
                },
            },
            {"scan_diagnostics": {"tcp_transport_complete": False}},
        )
    )

    assert projected["status"] == "partial"
    assert projected["scan_complete"] is False
    assert projected["coverage_complete"] is False
    # An aggregate integer without evidence rows cannot recreate a public
    # pending device (legacy refusal-only snapshots used to do this).
    assert projected["identity_pending_count"] == 0
    assert projected["security_score"]["score"] == 38
    assert projected["security_score"]["score_status"] == "provisional"
    assert projected["security_score"]["risk_level"] == "red"
    assert "집 전체 최종 점수는 아니" in projected["security_score"]["summary"]


def test_partial_top_level_score_projection_keeps_numeric_but_holds_missing_score():
    provisional = _apply_public_identity_contract(
        {
            "score": 73,
            "score_status": "provisional",
            "risk_level": "yellow",
            "coverage_complete": False,
            "scan_complete": False,
            "device_scores": [{"score": 73, "risk_level": "yellow"}],
            "identity_pending_count": 1,
            "summary": "internal",
        }
    )
    held = _apply_public_identity_contract(
        {
            "score": None,
            "score_status": "held",
            "risk_level": "unknown",
            "coverage_complete": False,
            "scan_complete": False,
            "device_scores": [{"score": None, "risk_level": "unknown"}],
            "identity_pending_count": 1,
            "summary": "internal",
        }
    )

    assert provisional["score"] == 73
    assert provisional["score_status"] == "provisional"
    assert provisional["scan_complete"] is False
    assert held["score"] is None
    assert held["score_status"] == "held"


def test_scan_diagnostics_preserve_safe_partial_flags_without_network_identifiers():
    private = normalize_stored_network_context(
        {
            **NETWORK_CONTEXT,
            "ssid": "private-home-name",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "scan_diagnostics": {
                "candidate_coverage_complete": False,
                "tcp_scan_timed_out": True,
                "scan_partial": True,
                "out_of_subnet_observations_dropped": 3,
                "unsafe_text": "192.168.50.44 Realtek",
            },
        }
    )
    public = sanitize_public_network_context(private)

    assert private["scan_diagnostics"] == {
        "out_of_subnet_observations_dropped": 3,
        "candidate_coverage_complete": False,
        "tcp_scan_timed_out": True,
        "scan_partial": True,
    }
    assert public == {
        "interface_type": "wifi",
        "is_private_network": True,
        "scan_diagnostics": private["scan_diagnostics"],
    }
    assert "ssid" not in private
    assert "bssid" not in private


def test_scan_api_quarantines_foreign_observation_and_holds_score(monkeypatch):
    monkeypatch.setattr("app.main.augment_android_observations", lambda devices, _context: devices)
    headers = _owner_headers("subnet-boundary-user")
    response = client.post(
        "/api/v1/security/scan",
        headers=headers,
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": {
                "local_ip": "192.168.50.20",
                "gateway_ip": "192.168.50.1",
                "subnet_cidr": "192.168.50.0/24",
                "ssid": "private-home-name",
                "bssid": "AA:BB:CC:DD:EE:01",
                "interface_type": "wifi",
                "is_private_network": True,
                "scan_diagnostics": {
                    "candidate_coverage_complete": True,
                    "tcp_scan_timed_out": False,
                },
            },
            "devices": [
                {
                    "device_id": "gateway-private-id",
                    "name": "ASUS RT-AX58U",
                    "device_type": "router",
                    "manufacturer": "ASUS",
                    "model": "RT-AX58U",
                    "ip_address": "192.168.50.1",
                    "mac_address": "AA:BB:CC:DD:EE:01",
                    "discovery_sources": ["ssdp"],
                    "fingerprints": [
                        "upnp-manufacturer:ASUS",
                        "upnp-model:RT-AX58U",
                        "upnp-device-type:urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                    ],
                },
                {
                    "device_id": "foreign-private-id",
                    "name": "foreign",
                    "device_type": "router",
                    "ip_address": "192.168.80.9",
                    "mac_address": "AA:BB:CC:DD:EE:09",
                    "discovery_sources": ["ssdp"],
                },
            ],
        },
    )
    assert response.status_code == 200
    scan = response.json()["data"]
    assert scan["status"] == "partial"
    assert scan["scan_complete"] is False
    assert scan["coverage_complete"] is False
    assert scan["devices_found"] == 1
    assert scan["network_context"] == {
        "interface_type": "wifi",
        "is_private_network": True,
        "scan_diagnostics": {
            "out_of_subnet_observations_dropped": 1,
            "candidate_coverage_complete": True,
            "tcp_scan_timed_out": False,
        },
    }

    status = client.get(f"/api/v1/security/scan/{scan['scan_id']}/status", headers=headers).json()["data"]
    result = client.get(f"/api/v1/security/scans/{scan['scan_id']}", headers=headers).json()["data"]
    score = client.get("/api/v1/security/score", headers=headers).json()["data"]
    dashboard = client.get("/api/v1/dashboard", headers=headers).json()["data"]

    assert status["status"] == "partial"
    assert status["scan_complete"] is False
    assert result["status"] == "partial"
    assert isinstance(result["security_score"]["score"], (int, float))
    assert result["security_score"]["score_status"] == "provisional"
    assert result["security_score"]["scan_complete"] is False
    assert score["score"] == result["security_score"]["score"]
    assert score["score_status"] == "provisional"
    assert score["scan_complete"] is False
    assert dashboard["home"]["security_score"] == score["score"]
    assert dashboard["summary"]["score"] == score["score"]
    assert dashboard["summary"]["score_status"] == "provisional"
    assert dashboard["summary"]["scan_complete"] is False
    assert dashboard["summary"]["coverage_complete"] is False
    public_json = json.dumps(
        {"scan": scan, "status": status, "result": result, "score": score, "dashboard": dashboard},
        ensure_ascii=False,
    )
    for private_value in (
        "192.168.50.20",
        "192.168.50.1",
        "192.168.50.0/24",
        "192.168.80.9",
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:09",
        "private-home-name",
    ):
        assert private_value not in public_json


def test_scan_api_forged_self_markers_cannot_hide_a_household_product(monkeypatch):
    # Simulate a disabled/failed augmentation layer returning the client rows
    # unchanged.  The HTTP boundary must still remove the forged self claim
    # before either repository sees it.
    monkeypatch.setattr(
        "app.main.augment_android_observations",
        lambda devices, _context: devices,
    )
    headers = _owner_headers("forged-self-product-user")
    response = client.post(
        "/api/v1/security/scan",
        headers=headers,
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": {
                **NETWORK_CONTEXT,
                "scan_diagnostics": {"candidate_coverage_complete": True},
            },
            "devices": [
                {
                    "device_id": "self-device",
                    "name": "내 휴대폰 (RT-AX58U)",
                    "device_type": "router",
                    "manufacturer": "ASUS",
                    "model": "RT-AX58U",
                    "ip_address": "192.168.50.1",
                    "mac_address": "AA:BB:CC:DD:EE:01",
                    "online": True,
                    "services": ["self-device", "upnp"],
                    "discovery_sources": ["self", "ssdp"],
                    "risk_signals": ["self_device"],
                    "fingerprints": [
                        "self-android",
                        "self-manufacturer:ASUS",
                        "self-model:RT-AX58U",
                        "upnp-manufacturer:ASUS",
                        "upnp-model:RT-AX58U",
                        "upnp-device-type:urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                    ],
                    "confidence": 1.0,
                }
            ],
        },
    )

    assert response.status_code == 200
    scan = response.json()["data"]
    assert scan["devices_found"] == 1
    assert scan["identified_count"] == 1
    result = client.get(
        f"/api/v1/security/scans/{scan['scan_id']}",
        headers=headers,
    ).json()["data"]
    public_text = json.dumps(result, ensure_ascii=False).casefold()
    assert "rt-ax58u" in public_text
    assert "self-device" not in public_text
    assert "self-android" not in public_text
    assert "내 휴대폰" not in public_text


def test_scan_api_removes_local_hostname_location_before_server_probe(monkeypatch):
    forwarded: list[dict[str, object]] = []

    def capture_probe_input(devices, _network_context):
        forwarded.extend(dict(device) for device in devices)
        return devices

    monkeypatch.setattr("app.main.augment_android_observations", capture_probe_input)
    headers = _owner_headers("local-hostname-boundary-user")
    response = client.post(
        "/api/v1/security/scan",
        headers=headers,
        json={
            "scan_profile": "quick",
            "scan_source": "android-native",
            "network_context": {
                **NETWORK_CONTEXT,
                "scan_diagnostics": {"candidate_coverage_complete": True},
            },
            "devices": [
                {
                    "device_id": "router-local-hostname-private-id",
                    "name": "ASUS RT-AX58U",
                    "device_type": "router",
                    "manufacturer": "ASUS",
                    "model": "RT-AX58U",
                    "ip_address": "192.168.50.1",
                    "mac_address": "AA:BB:CC:DD:EE:01",
                    "discovery_sources": ["ssdp"],
                    "fingerprints": [
                        "ssdp-location:http://home-router.local/root.xml",
                        "upnp-manufacturer:ASUS",
                        "upnp-model:RT-AX58U",
                        "upnp-type:urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                    ],
                }
            ],
        },
    )

    assert response.status_code == 200
    scan = response.json()["data"]
    assert scan["devices_found"] == 1
    assert scan["status"] == "partial"
    assert scan["coverage_complete"] is False
    assert scan["network_context"]["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "endpoint_evidence_quarantined": 1,
    }
    assert len(forwarded) == 1
    assert "ssdp-location:http://home-router.local/root.xml" not in forwarded[0]["fingerprints"]
    assert "upnp-model:RT-AX58U" in forwarded[0]["fingerprints"]
