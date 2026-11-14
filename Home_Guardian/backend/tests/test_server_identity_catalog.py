import errno
import ipaddress
import json
from pathlib import Path
import struct

import pytest

import app.services.device_identity as device_identity
import app.services.identity_enrichment as identity_enrichment
import app.services.server_protocol_probe as server_protocol_probe
import app.storage.sqlite_repository as sqlite_repository
from conftest import bind_repository_home
from app.services.device_identity import (
    resolve_device_identity,
    search_product_catalog,
    verified_catalog_identity,
)
from app.services.device_presentation import is_self_observation
from app.storage.sqlite_repository import SQLiteRepository as RuntimeSQLiteRepository


TEST_STORAGE_HOME_ID = "home-server-catalog-test"


def SQLiteRepository(*args, **kwargs):
    return bind_repository_home(RuntimeSQLiteRepository(*args, **kwargs), TEST_STORAGE_HOME_ID)


NETWORK = {
    "local_ip": "192.168.90.20",
    "gateway_ip": "192.168.90.1",
    "subnet_cidr": "192.168.90.0/24",
    "is_private_network": True,
    "interface_type": "wifi",
}

TEST_ROUTE_BINDING = server_protocol_probe._RouteInterfaceBinding(
    name="eth0",
    ipv4="192.168.50.12",
    ifindex=2,
)


def _use_test_route_binding(monkeypatch):
    monkeypatch.setattr(
        server_protocol_probe,
        "_android_gateway_mac",
        lambda _devices, _context: "64:1B:2F:FE:00:06",
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_same_current_gateway_l2",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_gateway_neighbor",
        lambda _gateway, _binding: (set(), True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({}, True),
    )
    # Individual tests override the relevant path.  Keep the other interface-
    # scoped UDP passes deterministic and offline.
    monkeypatch.setattr(
        server_protocol_probe, "_discover_mdns", lambda _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns_unicast",
        lambda _hosts, _binding: ({}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_discover_ssdp", lambda _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp_unicast",
        lambda _hosts, _binding: ({}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_discover_onvif", lambda _binding: ({}, True)
    )


def _android_self_observation(
    *,
    local_ip: str = "192.168.50.10",
    mac_address: str = "본인-기기",
) -> dict:
    return {
        "device_id": "self-192-168-50-10",
        "name": "내 휴대폰 (SM-F956N)",
        "device_type": "phone",
        "manufacturer": "samsung",
        "model": "SM-F956N",
        "ip_address": local_ip,
        "mac_address": mac_address,
        "online": True,
        "open_ports": [],
        "services": ["self-device"],
        "default_credentials": False,
        "encryption": "unknown",
        "vulnerabilities": [],
        "discovery_sources": ["self"],
        "fingerprints": [
            "self-android",
            "self-manufacturer:samsung",
            "self-model:SM-F956N",
        ],
        "risk_signals": ["self_device"],
        "confidence": 1.0,
    }


def _attest_self_for_test(
    monkeypatch,
    observations,
    *,
    trusted_client_ip="192.168.50.10",
    context=None,
    refreshed_hosts=None,
    refresh_complete=True,
    post_mac="DA:F5:1E:FE:00:0A",
):
    context = context or {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": "192.168.50.1",
        "local_ip": "192.168.50.10",
    }
    if refreshed_hosts is None:
        refreshed_hosts = {"192.168.50.10"}
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_exact_neighbor",
        lambda host, binding: (
            set(refreshed_hosts),
            refresh_complete,
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: (
            {"192.168.50.10": post_mac} if post_mac else {}
        ),
    )
    server_protocol_probe._attest_current_android_self(
        observations,
        context,
        trusted_client_ip=trusted_client_ip,
        route_interface="eth0",
        interface_binding=TEST_ROUTE_BINDING,
        pre_refresh_neighbors={"192.168.50.10": post_mac} if post_mac else {},
    )


def test_current_self_attestation_binds_exact_build_to_fresh_neighbor(monkeypatch):
    observations = [_android_self_observation()]

    _attest_self_for_test(monkeypatch, observations)

    assert observations[0]["mac_address"] == "DA:F5:1E:FE:00:0A"
    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) == {
        "manufacturer_hints": ["Samsung"],
        "model_hints": ["SM-F956N"],
        "device_type_hints": ["phone"],
        "structured_provenance": [
            {
                "kind": "manufacturer",
                "source": "authenticated-self-android",
                "value": "Samsung",
            },
            {
                "kind": "model",
                "source": "authenticated-self-android",
                "value": "SM-F956N",
            },
            {
                "kind": "device_type",
                "source": "authenticated-self-android",
                "value": "phone",
            },
        ],
    }


def test_current_self_attestation_accepts_verified_gateway_hairpin(monkeypatch):
    observations = [_android_self_observation()]

    _attest_self_for_test(
        monkeypatch,
        observations,
        trusted_client_ip="192.168.50.1",
    )

    assert observations[0]["mac_address"] == "DA:F5:1E:FE:00:0A"
    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is not None


@pytest.mark.parametrize(
    ("trusted_client_ip", "context"),
    [
        (
            "192.168.50.11",
            {
                "subnet_cidr": "192.168.50.0/24",
                "gateway_ip": "192.168.50.1",
                "local_ip": "192.168.50.10",
            },
        ),
        (
            "192.168.50.10",
            {
                "subnet_cidr": "192.168.60.0/24",
                "gateway_ip": "192.168.60.1",
                "local_ip": "192.168.50.10",
            },
        ),
    ],
    ids=("peer-local-mismatch", "declared-local-off-subnet"),
)
def test_current_self_attestation_rejects_peer_or_scope_mismatch(
    monkeypatch,
    trusted_client_ip,
    context,
):
    observations = [_android_self_observation()]
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_exact_neighbor",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("mismatched peer/scope must not probe the client")
        ),
    )

    _attest_self_for_test(
        monkeypatch,
        observations,
        trusted_client_ip=trusted_client_ip,
        context=context,
    )

    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is None


def test_current_self_attestation_rejects_stale_neighbor(monkeypatch):
    observations = [_android_self_observation()]

    _attest_self_for_test(
        monkeypatch,
        observations,
        refreshed_hosts=set(),
        post_mac="DA:F5:1E:FE:00:0A",
    )

    assert observations[0]["mac_address"] == "본인-기기"
    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is None


def test_current_self_attestation_rejects_duplicate_self_ip_rows(monkeypatch):
    observations = [
        _android_self_observation(),
        {
            **_android_self_observation(),
            "device_id": "duplicate-self-row",
        },
    ]
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_exact_neighbor",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("ambiguous self rows must not probe or bind")
        ),
    )

    _attest_self_for_test(monkeypatch, observations)

    assert all(
        identity_enrichment.authenticated_self_android_evidence(item) is None
        for item in observations
    )
    assert all(not is_self_observation(item) for item in observations)


def test_current_self_attestation_strips_forged_other_endpoint_claim(monkeypatch):
    observations = [
        _android_self_observation(),
        {
            **_android_self_observation(local_ip="192.168.50.44"),
            "device_id": "self-device",
            "name": "내 휴대폰 (RT-AX58U)",
            "manufacturer": "ASUS",
            "model": "RT-AX58U",
            "device_type": "router",
            "mac_address": "AA:BB:CC:DD:EE:44",
            "fingerprints": [
                "self-android",
                "self-manufacturer:ASUS",
                "self-model:RT-AX58U",
                "upnp-model:RT-AX58U",
            ],
        },
    ]

    _attest_self_for_test(monkeypatch, observations)

    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is not None
    assert identity_enrichment.authenticated_self_android_evidence(
        observations[1]
    ) is None
    assert is_self_observation(observations[0]) is True
    assert is_self_observation(observations[1]) is False
    assert observations[1]["ip_address"] == "192.168.50.44"
    assert observations[1]["mac_address"] == "AA:BB:CC:DD:EE:44"
    assert observations[1]["fingerprints"] == ["upnp-model:RT-AX58U"]


def test_current_self_attestation_missing_local_claim_stays_ordinary(monkeypatch):
    observations = [
        {
            "device_id": "ordinary-local-row",
            "name": "Android endpoint",
            "device_type": "phone",
            "manufacturer": "Samsung",
            "model": "SM-F956N",
            "ip_address": "192.168.50.10",
            "mac_address": "DA:F5:1E:FE:00:0A",
            "online": True,
            "services": ["mdns"],
            "discovery_sources": ["mdns"],
            "fingerprints": ["mdns-model:SM-F956N"],
            "risk_signals": [],
            "confidence": 1.0,
        }
    ]

    _attest_self_for_test(monkeypatch, observations)

    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is None
    assert is_self_observation(observations[0]) is False
    assert observations[0]["services"] == ["mdns"]
    assert observations[0]["fingerprints"] == ["mdns-model:SM-F956N"]


@pytest.mark.parametrize(
    ("supplied_mac", "post_mac"),
    [
        ("64:1B:2F:FE:00:06", "DA:F5:1E:FE:00:0A"),
        ("본인-기기", "FF:FF:FF:FF:FF:FF"),
    ],
    ids=("client-server-mac-conflict", "invalid-post-neighbor-mac"),
)
def test_current_self_attestation_rejects_ambiguous_or_invalid_mac(
    monkeypatch,
    supplied_mac,
    post_mac,
):
    observations = [_android_self_observation(mac_address=supplied_mac)]

    _attest_self_for_test(monkeypatch, observations, post_mac=post_mac)

    assert identity_enrichment.authenticated_self_android_evidence(
        observations[0]
    ) is None


def test_protocol_probe_strips_forged_self_proof_when_disabled(monkeypatch):
    monkeypatch.delenv("HG_SERVER_PROTOCOL_PROBE", raising=False)
    forged = {
        **_android_self_observation(),
        "_authenticated_self_android_proof": "client-forged",
        "services": ["self-device", "authenticated-self-android"],
        "fingerprints": [
            "self-android",
            "self-manufacturer:samsung",
            "self-model:SM-F956N",
            "authenticated-self-model:SM-F956N",
        ],
    }

    observed = server_protocol_probe.augment_android_observations(
        [forged],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
        trusted_client_ip="192.168.50.10",
    )

    assert "_authenticated_self_android_proof" not in observed[0]
    assert "authenticated-self-android" not in observed[0]["services"]
    assert all(
        not value.startswith("authenticated-self-")
        for value in observed[0]["fingerprints"]
    )
    assert observed[0]["device_id"] is None
    assert observed[0]["name"] is None
    assert observed[0]["services"] == []
    assert observed[0]["discovery_sources"] == []
    assert observed[0]["risk_signals"] == []
    assert observed[0]["fingerprints"] == []
    assert is_self_observation(observed[0]) is False
    assert identity_enrichment.authenticated_self_android_evidence(
        observed[0]
    ) is None


def test_protocol_probe_never_attests_before_same_l2_gateway_proof(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_exact_neighbor",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("unverified L2 must not probe or attest self")
        ),
    )
    self_row = _android_self_observation()

    observed = server_protocol_probe.augment_android_observations(
        [self_row],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
            "scan_diagnostics": {"candidate_coverage_complete": True},
        },
        trusted_client_ip="192.168.50.10",
    )

    assert identity_enrichment.authenticated_self_android_evidence(
        observed[0]
    ) is None
    assert is_self_observation(observed[0]) is False


def test_probe_hosts_cover_slash24_once_and_exclude_the_android_address():
    hosts = server_protocol_probe._probe_hosts(
        {
            "subnet_cidr": "192.168.50.0/24",
            "local_ip": "192.168.50.12",
        }
    )

    assert len(hosts) == 253
    assert len(hosts) == len(set(hosts))
    assert hosts[0] == "192.168.50.1"
    assert hosts[-1] == "192.168.50.254"
    assert "192.168.50.12" not in hosts


@pytest.mark.parametrize(
    ("subnet_cidr", "local_ip", "expected_first", "expected_last", "gap_bounds"),
    [
        (
            "192.168.52.0/22",
            "192.168.52.10",
            "192.168.52.1",
            "192.168.55.254",
            (1, 3),
        ),
        (
            "10.20.0.0/16",
            "10.20.0.9",
            "10.20.0.1",
            "10.20.255.254",
            (127, 130),
        ),
    ],
)
def test_large_subnet_probe_hosts_are_bounded_uniform_and_include_both_ends(
    subnet_cidr,
    local_ip,
    expected_first,
    expected_last,
    gap_bounds,
):
    hosts = server_protocol_probe._probe_hosts(
        {"subnet_cidr": subnet_cidr, "local_ip": local_ip}
    )

    assert len(hosts) == server_protocol_probe.PROBE_MAX_HOSTS
    assert len(hosts) == len(set(hosts))
    assert hosts[0] == expected_first
    assert hosts[-1] == expected_last
    assert local_ip not in hosts
    numeric = [int(ipaddress.ip_address(host)) for host in hosts]
    gaps = [right - left for left, right in zip(numeric, numeric[1:])]
    assert min(gaps) >= gap_bounds[0]
    assert max(gaps) <= gap_bounds[1]


def test_android_and_current_interface_hosts_are_prioritized_outside_uniform_sample():
    context = {"subnet_cidr": "10.20.0.0/16", "local_ip": "10.20.0.9"}
    scope = server_protocol_probe._subnet_host_scope(context)
    assert scope is not None
    sampled = server_protocol_probe._probe_hosts(context)
    android_host = "10.20.250.77"
    neighbor_host = "10.20.251.88"
    assert android_host not in sampled
    assert neighbor_host not in sampled

    hosts = server_protocol_probe._prioritized_probe_hosts(
        sampled,
        scope,
        [{"ip_address": android_host}, {"ip_address": "10.21.0.8"}],
        {
            neighbor_host: "AA:BB:CC:DD:EE:FF",
            "172.20.0.8": "00:11:22:33:44:55",
        },
        "10.20.0.1",
    )

    assert hosts[:3] == ["10.20.0.1", android_host, neighbor_host]
    assert len(hosts) == server_protocol_probe.PROBE_MAX_HOSTS
    assert len(hosts) == len(set(hosts))
    assert "10.21.0.8" not in hosts
    assert "172.20.0.8" not in hosts


def test_server_observation_result_never_exceeds_api_device_cap(monkeypatch):
    monkeypatch.delenv("HG_SERVER_PROTOCOL_PROBE", raising=False)
    context = {"scan_diagnostics": {"candidate_coverage_complete": True}}
    devices = [
        {"ip_address": f"192.168.{index // 254}.{index % 254 + 1}"}
        for index in range(server_protocol_probe.PROBE_MAX_HOSTS + 9)
    ]

    observed = server_protocol_probe.augment_android_observations(devices, context)

    assert len(observed) == server_protocol_probe.PROBE_MAX_HOSTS
    assert observed == devices[: server_protocol_probe.PROBE_MAX_HOSTS]
    assert context["scan_diagnostics"]["scan_partial"] is True


def test_large_subnet_allowlist_accepts_unsampled_hosts_only_inside_declared_scope():
    context = {"subnet_cidr": "10.20.0.0/16", "local_ip": "10.20.0.9"}
    scope = server_protocol_probe._subnet_host_scope(context)
    assert scope is not None
    sampled = server_protocol_probe._probe_hosts(context)
    unsampled = "10.20.250.77"
    assert unsampled not in sampled

    assert server_protocol_probe._canonical_allowed_host(unsampled, scope) == unsampled
    assert server_protocol_probe._canonical_allowed_host("10.21.0.8", scope) is None
    assert server_protocol_probe._canonical_allowed_host("10.20.0.9", scope) is None


def test_upnp_local_hostname_is_rejected_before_any_socket_fetch(monkeypatch):
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("local hostname must not be resolved or fetched")

    monkeypatch.setattr(server_protocol_probe.socket, "create_connection", fail_if_called)

    assert (
        server_protocol_probe._upnp_evidence(
            "192.168.90.44",
            "http://living-room-tv.local:1400/root.xml",
            TEST_ROUTE_BINDING,
        )
        == ([], True)
    )


def test_ssdp_parser_preserves_usn_and_rejects_cross_host_location():
    gateway_uuid = "11111111-2222-4333-8444-555555555555"
    evidence = server_protocol_probe._parse_ssdp_response(
        (
            "HTTP/1.1 200 OK\r\n"
            f"USN: uuid:{gateway_uuid}::upnp:rootdevice\r\n"
            "ST: upnp:rootdevice\r\n"
            "LOCATION: http://192.168.90.44/rootDesc.xml\r\n\r\n"
        ).encode("ascii"),
        source_host="192.168.90.1",
    )

    assert f"ssdp-usn:uuid:{gateway_uuid}::upnp:rootdevice" in evidence
    assert "ssdp-st:upnp:rootdevice" in evidence
    assert not any(value.startswith("ssdp-location:") for value in evidence)


def test_server_catalog_registers_samsung_model_with_product_name(tmp_path, monkeypatch):
    observation = {
        "manufacturer": "Samsung",
        "model": "RF85C90",
        "device_type": "web-device",
        "fingerprints": [
            "mdns-txt:manufacturer=Samsung",
            "mdns-txt:model=RF85C90",
        ],
        "discovery_sources": ["mdns"],
    }
    resolved = resolve_device_identity(observation)
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "삼성 냉장고 (RF85C90)"
    assert any(item.get("catalog_id") == "samsung-familyhub-refrigerator" for item in resolved["identity_candidates"])

    catalog = device_identity._load_product_catalog()
    assert len(catalog) >= 15
    assert len({entry["catalog_id"] for entry in catalog}) == len(catalog)
    for entry in catalog:
        assert entry["source_url"].startswith("https://")
        assert entry["source_title"]
        assert entry["source_version"]
        assert entry["source_date"]
        assert entry["source_date_kind"] in {"published", "document_version", "retrieved"}
        assert entry["verified_at"]
        assert all(
            device_identity._is_conservative_catalog_model_pattern(pattern)
            for pattern in entry["model_patterns"]
        )

    catalog_match = search_product_catalog(observation)[0]
    assert catalog_match["catalog_id"] == "samsung-familyhub-refrigerator"
    assert catalog_match["source_url"].startswith("https://www.samsung.com/")
    assert catalog_match["source_title"]
    assert catalog_match["source_version"]
    assert catalog_match["source_date_kind"] == "retrieved"
    assert catalog_match["verified_at"]

    invalid_source = {**catalog[0], "source_url": "https://example.com/not-official"}
    assert device_identity._validated_product_catalog_entry(invalid_source) is None
    broad_model_pattern = {
        **catalog[0],
        "model_patterns": [r"^A[0-9A-Z-]+$"],
        "verified_models": ["A3004"],
    }
    assert device_identity._validated_product_catalog_entry(broad_model_pattern) is None

    invalid_payload = [dict(entry) for entry in catalog]
    invalid_payload[0]["source_url"] = "https://example.com/not-official"
    invalid_path = tmp_path / "invalid-device-product-catalog.json"
    invalid_path.write_text(json.dumps(invalid_payload), encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setattr(device_identity, "PRODUCT_CATALOG_PATH", invalid_path)
        device_identity._load_product_catalog.cache_clear()
        with pytest.raises(RuntimeError, match="failed provenance validation"):
            device_identity._load_product_catalog()
    device_identity._load_product_catalog.cache_clear()


def test_server_catalog_accepts_additional_valid_provenance_entry(tmp_path, monkeypatch):
    catalog = [dict(entry) for entry in device_identity._load_product_catalog()]
    additional = {
        **catalog[0],
        "catalog_id": "raspberry-pi-computer-additional-test",
    }
    expanded_path = tmp_path / "expanded-device-product-catalog.json"
    expanded_path.write_text(
        json.dumps([*catalog, additional], ensure_ascii=False),
        encoding="utf-8",
    )

    with monkeypatch.context() as patch:
        patch.setattr(device_identity, "PRODUCT_CATALOG_PATH", expanded_path)
        device_identity._load_product_catalog.cache_clear()
        expanded = device_identity._load_product_catalog()
        assert len(expanded) == len(catalog) + 1
        assert expanded[-1]["catalog_id"] == additional["catalog_id"]
    device_identity._load_product_catalog.cache_clear()


def test_server_catalog_registers_iptime_model_with_product_name():
    resolved = resolve_device_identity(
        {
            "manufacturer": "EFM Networks",
            "model": "A3004NS-M",
            "device_type": "web-device",
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A3004NS-M",
            ],
            "discovery_sources": ["ssdp"],
        }
    )
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"


def test_server_catalog_registers_samsung_tablet_model_with_product_name():
    resolved = resolve_device_identity(
        {
            "manufacturer": "Samsung",
            "model": "SM-T720",
            "device_type": "phone",
            "fingerprints": ["mdns-txt:manufacturer=Samsung", "mdns-txt:model=SM-T720"],
            "discovery_sources": ["mdns"],
        }
    )
    assert resolved["identity_status"] == "resolved"
    assert resolved["device_type"] == "tablet"
    assert resolved["canonical_name"] == "삼성 태블릿 (SM-T720)"
    assert any(item.get("catalog_id") == "samsung-galaxy-tab-s5e" for item in resolved["identity_candidates"])


def test_raw_friendly_brand_and_model_do_not_bypass_structured_provenance():
    resolved = resolve_device_identity(
        {
            "name": "Samsung Living",
            "manufacturer": "",
            "model": "RF85C90",
            "device_type": "fridge",
            "fingerprints": [],
            "discovery_sources": ["tcp-port-probe"],
        }
    )

    assert resolved["identity_status"] == "enriching"
    assert resolved["canonical_name"] == ""
    assert resolved["identity_family_verified"] is False

    alias_only_matches = search_product_catalog(
        {
            "manufacturer": "EFM Networks",
            "model": "",
            "device_type": "router",
            "fingerprints": ["upnp-manufacturer:EFM Networks"],
            "discovery_sources": ["ssdp"],
        }
    )
    assert alias_only_matches
    assert all(match["match_kind"] != "exact_model" for match in alias_only_matches)
    assert all(not match["model"] for match in alias_only_matches)

    oui_only = resolve_device_identity(
        {
            "mac_address": "64:E5:99:12:34:56",
            "manufacturer": "",
            "model": "",
            "device_type": "unknown",
            "fingerprints": [],
            "services": [],
            "discovery_sources": ["android-neighbor"],
        }
    )
    assert oui_only["manufacturer"] == "iptime(EFM)"
    assert oui_only["model"] == ""
    assert oui_only["identity_status"] != "resolved"
    assert oui_only["canonical_name"] == ""

    unsupported_model = resolve_device_identity(
        {
            "manufacturer": "EFM Networks",
            "model": "A9999ZZ",
            "device_type": "router",
            "fingerprints": [
                "upnp-manufacturer:EFM Networks",
                "upnp-model:A9999ZZ",
            ],
            "discovery_sources": ["ssdp"],
        }
    )
    assert unsupported_model["identity_status"] != "resolved"
    assert unsupported_model["canonical_name"] == ""
    assert all(
        candidate.get("kind") != "서버 카탈로그 확정"
        for candidate in unsupported_model["identity_candidates"]
    )


def test_family_only_advertisements_never_become_public_product_models():
    observations = (
        ("Samsung", "Family Hub", "SPEAKER"),
        ("Sonos", "Sonos", "SPEAKER"),
        ("Sony", "BRAVIA", "TV"),
        ("Google", "Chromecast", "TV"),
        ("Roborock", "Roborock", "SPEAKER"),
    )

    for brand, model, product_type in observations:
        resolved = resolve_device_identity(
            {
                "fingerprints": [
                    f"spotify-brand:{brand}",
                    f"spotify-model:{model}",
                    f"spotify-type:{product_type}",
                ],
                "discovery_sources": ["mdns"],
            }
        )
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""
        assert resolved["model"] == ""


def test_chipset_and_server_software_identifiers_never_become_products():
    for brand, model in (
        ("Realtek", "RTL8197F"),
        ("Espressif", "ESP32"),
        ("Samsung", "Boa/0.94.14rc21"),
    ):
        resolved = resolve_device_identity(
            {
                "fingerprints": [
                    f"upnp-manufacturer:{brand}",
                    f"upnp-model:{model}",
                    "upnp-type:InternetGatewayDevice",
                ],
                "discovery_sources": ["ssdp"],
            }
        )
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""


def test_arbitrary_friendly_advertised_model_is_not_a_part_number():
    for model in ("Living Room", "Kitchen"):
        resolved = resolve_device_identity(
            {
                "fingerprints": [
                    "mdns-type:._lg-smart-device._tcp.local",
                    "mdns-txt:product=air_conditioner",
                    f"mdns-txt:model={model}",
                ],
                "discovery_sources": ["mdns"],
            }
        )
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""


def test_manufacturer_scoped_named_product_model_can_resolve():
    resolved = resolve_device_identity(
        {
            "fingerprints": [
                "spotify-brand:Sonos",
                "spotify-model:Arc",
                "spotify-type:SPEAKER",
            ],
            "discovery_sources": ["mdns"],
        }
    )
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "Sonos 스피커 (Arc)"


def test_concrete_model_beats_family_alias_but_concrete_conflict_stays_pending():
    concrete = resolve_device_identity(
        {
            "fingerprints": [
                "spotify-brand:Samsung",
                "spotify-model:Family Hub",
                "upnp-manufacturer:Samsung",
                "upnp-model:RF85C90",
            ],
            "discovery_sources": ["mdns", "ssdp"],
        }
    )
    assert concrete["identity_status"] == "resolved"
    assert concrete["canonical_name"] == "삼성 냉장고 (RF85C90)"

    conflict = resolve_device_identity(
        {
            "fingerprints": [
                "upnp-manufacturer:Samsung",
                "upnp-model:RF85C90",
                "mdns-txt:manufacturer=Samsung",
                "mdns-txt:model=RF85C91",
            ],
            "discovery_sources": ["mdns", "ssdp"],
        }
    )
    assert conflict["identity_status"] != "resolved"
    assert conflict["canonical_name"] == ""
    assert conflict["model"] == ""


def test_conflicting_structured_brand_cannot_be_overridden_by_model_prefix_or_catalog():
    for fingerprints in (
        [
            "upnp-manufacturer:Samsung",
            "mdns-txt:manufacturer=LG",
            "upnp-model:RF85C90",
            "upnp-type:InternetGatewayDevice",
        ],
        [
            "upnp-manufacturer:Samsung",
            "upnp-model:A3004NS-M",
            "upnp-type:InternetGatewayDevice",
        ],
        [
            "mdns-txt:manufacturer=Samsung",
            "mdns-txt:model=WIN_056905_WW",
            "mdns-txt:product=air_conditioner",
            "mdns-type:._lg-smart-device._tcp.local",
        ],
    ):
        resolved = resolve_device_identity(
            {"fingerprints": fingerprints, "discovery_sources": ["mdns", "ssdp"]}
        )
        assert resolved["identity_status"] != "resolved"
        assert resolved["canonical_name"] == ""


def test_history_only_catalog_marker_is_revalidated_without_raw_fingerprints():
    record = {
        "scan_source": "android-native",
        "identity_status": "resolved",
        "resolver_version": device_identity.IDENTITY_RESOLVER_VERSION,
        "identity_confidence": 0.96,
        "is_unresolved": False,
        "is_phantom": False,
        "manufacturer": "iptime(EFM)",
        "model": "A3004NS-M",
        "device_type": "router",
        "mac_address": "AA:BB:CC:90:00:20",
        "candidates_json": json.dumps(
            [
                {
                    "label": "ipTIME 공유기 (A3004NS-M)",
                    "kind": "서버 카탈로그 확정",
                    "catalog_id": "iptime-router",
                }
            ],
            ensure_ascii=False,
        ),
    }

    restored = verified_catalog_identity(record)
    assert restored == {
        "manufacturer": "iptime(EFM)",
        "model": "A3004NS-M",
        "device_type": "router",
        "evidence": "서버에 이전에 확인된 품번과 현재 장치 대조",
    }

    korean_display_record = {
        **record,
        "manufacturer": "삼성",
        "model": "RF85C90",
        "device_type": "fridge",
        "candidates_json": json.dumps(
            [
                {
                    "label": "삼성 냉장고 (RF85C90)",
                    "kind": "서버 카탈로그 확정",
                    "catalog_id": "samsung-familyhub-refrigerator",
                }
            ],
            ensure_ascii=False,
        ),
    }
    korean_restored = verified_catalog_identity(korean_display_record)
    assert korean_restored is not None
    assert korean_restored["manufacturer"] == "삼성"
    assert korean_restored["model"] == "RF85C90"

    record["candidates_json"] = json.dumps(
        [
            {
                "label": "ipTIME 공유기 (A3004NS-M)",
                "kind": "서버 카탈로그 후보",
                "catalog_id": "iptime-router",
            }
        ],
        ensure_ascii=False,
    )
    assert verified_catalog_identity(record) is None

    record.update(
        manufacturer="Samsung",
        model="Family Hub",
        device_type="fridge",
        candidates_json=json.dumps(
            [
                {
                    "label": "삼성 냉장고 (Family Hub)",
                    "kind": "서버 카탈로그 확정",
                    "catalog_id": "samsung-familyhub-refrigerator",
                }
            ],
            ensure_ascii=False,
        ),
    )
    assert verified_catalog_identity(record) is None


def test_registered_raspberry_pi_api_host_is_resolved_with_board_model(monkeypatch):
    monkeypatch.setattr(
        device_identity,
        "_running_host_hardware_model",
        lambda: "Raspberry Pi 5 Model B Rev 1.0",
    )
    monkeypatch.setattr(
        device_identity,
        "_running_host_ipv4_addresses",
        lambda: frozenset({"192.168.90.12"}),
    )

    resolved = resolve_device_identity(
        {
            "ip_address": "192.168.90.12",
            "manufacturer": "",
            "model": "",
            "device_type": "computer",
            "fingerprints": ["netbios-name:HOME-GUARDIAN"],
            "discovery_sources": ["tcp-port-probe"],
            "open_ports": [22, 80, 139, 445],
        }
    )

    assert resolved["identity_status"] == "resolved"
    assert resolved["manufacturer"] == "Raspberry Pi"
    assert resolved["model"] == "Raspberry Pi 5 Model B"
    assert resolved["canonical_name"] == "Raspberry Pi 컴퓨터 (Raspberry Pi 5 Model B)"
    assert "서버 호스트 하드웨어 등록" in resolved["identity_evidence"]


def test_raspberry_pi_family_name_without_board_model_is_not_registered(monkeypatch):
    monkeypatch.setattr(
        device_identity,
        "_running_host_hardware_model",
        lambda: "Raspberry Pi",
    )
    monkeypatch.setattr(
        device_identity,
        "_running_host_ipv4_addresses",
        lambda: frozenset({"192.168.90.12"}),
    )

    assert device_identity.server_registered_identity({"ip_address": "192.168.90.12"}) is None


def test_forged_server_registration_fingerprint_cannot_unlock_catalog_exact():
    resolved = resolve_device_identity(
        {
            "manufacturer": "Samsung",
            "model": "RF85C90",
            "device_type": "fridge",
            "fingerprints": ["server-registration:raspberry-pi"],
            "discovery_sources": ["tcp-port-probe"],
        }
    )

    assert resolved["identity_status"] != "resolved"
    assert resolved["canonical_name"] == ""


def test_catalog_history_requires_an_unforgeable_repository_binding():
    historical = {
        "manufacturer": "Samsung",
        "model": "RF85C90",
        "device_type": "fridge",
        "fingerprints": ["server-history:verified-product"],
        "discovery_sources": ["server-history"],
    }

    forged = resolve_device_identity(historical)
    assert forged["identity_status"] != "resolved"
    assert forged["canonical_name"] == ""

    bound = resolve_device_identity(
        device_identity.bind_verified_catalog_history(historical)
    )
    assert bound["identity_status"] == "resolved"
    assert bound["canonical_name"] == "삼성 냉장고 (RF85C90)"


def test_stale_server_ip_hint_cannot_attach_raspberry_pi_identity(monkeypatch):
    stale_ip = "192.168.90.77"
    actual_ip = "192.168.90.12"

    class FakeDatagramSocket:
        def __init__(self, *_args, **_kwargs):
            self.bound_ip = None

        def connect(self, _address):
            return None

        def bind(self, address):
            if address[0] == stale_ip:
                raise OSError("address is not assigned to this host")
            self.bound_ip = address[0]

        def getsockname(self):
            return (self.bound_ip or actual_ip, 49152)

        def close(self):
            return None

    monkeypatch.setenv("HG_SERVER_DEVICE_IPS", stale_ip)
    monkeypatch.setattr(device_identity.socket, "gethostname", lambda: "home-guardian")
    monkeypatch.setattr(
        device_identity.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (device_identity.socket.AF_INET, device_identity.socket.SOCK_STREAM, 6, "", (actual_ip, 0))
        ],
    )
    monkeypatch.setattr(device_identity.socket, "socket", FakeDatagramSocket)
    monkeypatch.setattr(
        device_identity,
        "_running_host_hardware_model",
        lambda: "Raspberry Pi 5 Model B Rev 1.0",
    )

    device_identity._running_host_ipv4_addresses.cache_clear()
    try:
        assigned = device_identity._running_host_ipv4_addresses()
        assert actual_ip in assigned
        assert stale_ip not in assigned
        assert device_identity.server_registered_identity({"ip_address": stale_ip}) is None
        assert device_identity.server_registered_identity({"ip_address": actual_ip}) is not None
    finally:
        device_identity._running_host_ipv4_addresses.cache_clear()


def test_storage_keeps_unknown_mac_when_only_advertised_mac_is_available():
    """Storage never turns an mDNS name into physical MAC/OUI identity."""
    normalized = sqlite_repository.normalize_observed_device(
        {
            "ip_address": "192.168.90.55",
            "mac_address": "UNKNOWN-192.168.90.55",
            "device_type": "computer",
            "open_ports": [139, 445],
            "fingerprints": ["netbios-name:DESKTOP", "mdns-name:641B2FFE0006"],
            "discovery_sources": ["tcp-port-probe"],
        },
        scan_source="android-native",
    )

    assert normalized["mac_address"] == "UNKNOWN-192.168.90.55"
    assert normalized["manufacturer"] == ""
    assert normalized["model"] == ""
    assert normalized["canonical_name"] == ""
    assert normalized["identity_status"] == "enriching"
    assert normalized["is_unresolved"] is True


def test_server_protocol_probe_merges_verified_zero_conf_evidence(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.20"],
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_one",
        lambda host, _binding: (
            (
                (
                    host,
                        {
                            "brand": "Samsung",
                            "model": "Family_HUB",
                            "name": "Kitchen",
                            "type": "STEREO",
                    },
                )
                if host == "192.168.50.20"
                else None
            ),
            True,
        ),
    )

    observed = server_protocol_probe.augment_android_observations(
        [
            {
                "ip_address": "192.168.50.20",
                "open_ports": [80],
                "discovery_sources": ["tcp-port-probe"],
                "fingerprints": [],
            }
        ],
        {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"},
    )

    assert len(observed) == 1
    item = observed[0]
    assert item["open_ports"] == [80, 17654]
    assert "server-protocol-probe" in item["discovery_sources"]
    assert "spotify-getinfo-done" in item["fingerprints"]
    assert "spotify-brand:Samsung" in item["fingerprints"]
    assert "spotify-model:Family_HUB" in item["fingerprints"]
    # The probe carries evidence only. It does not hard-code a resident name.
    assert item.get("manufacturer") is None
    assert item.get("model") is None

    resolved = resolve_device_identity(item)
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "삼성 냉장고 (Family Hub)"
    assert resolved["model"] == "Family Hub"


def test_server_mdns_direct_recovery_uses_the_full_android_service_set():
    required = {
        "_http._tcp.local",
        "_https._tcp.local",
        "_rtsp._tcp.local",
        "_onvif._tcp.local",
        "_axis-video._tcp.local",
        "_matter._tcp.local",
        "_matterc._udp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_companion-link._tcp.local",
        "_hap._tcp.local",
        "_homekit._tcp.local",
        "_ipp._tcp.local",
        "_ipps._tcp.local",
        "_printer._tcp.local",
        "_pdl-datastream._tcp.local",
        "_smb._tcp.local",
        "_workstation._tcp.local",
        "_smartthings._tcp.local",
        "_smarthome._tcp.local",
        "_samsungmsf._tcp.local",
        "_androidtvremote2._tcp.local",
        "_hue._tcp.local",
        "_amzn-wplay._tcp.local",
        "_sonos._tcp.local",
        "_roku-rcp._tcp.local",
        "_viziocast._tcp.local",
        "_miio._udp.local",
        "_nanoleafapi._tcp.local",
        "_spotify-connect._tcp.local",
        "_lg-smart-device._tcp.local",
    }

    assert set(server_protocol_probe.MDNS_SERVICE_TYPES) == required
    assert server_protocol_probe.MDNS_UNICAST_QUERY_TYPES is server_protocol_probe.MDNS_SERVICE_TYPES
    assert set(server_protocol_probe.MDNS_QUERY_TYPES) == required | {
        "_services._dns-sd._udp.local"
    }


def test_refused_only_tcp_host_is_not_published_as_a_device(monkeypatch):
    host = "192.168.50.40"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({}, {host}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert observed == []


def test_tcp_scan_tracks_refused_transport_without_open_ports(monkeypatch):
    host = "192.168.50.41"
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_tcp_observation",
        lambda _host, _port, _binding: (server_protocol_probe._TCP_REFUSED, True),
    )

    ports, responsive_hosts, complete = server_protocol_probe._scan_tcp_ports(
        [host], TEST_ROUTE_BINDING
    )

    assert ports == {}
    assert responsive_hosts == {host}
    assert complete is True


def test_server_neighbor_ping_sweep_is_explicit_and_bounded(monkeypatch):
    calls = []
    monkeypatch.setenv("HG_SERVER_NEIGHBOR_PING_SWEEP", "1")
    monkeypatch.setattr(server_protocol_probe.shutil, "which", lambda name: "/sbin/ping" if name == "ping" else None)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return server_protocol_probe.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(server_protocol_probe.subprocess, "run", fake_run)
    responsive, complete = server_protocol_probe._refresh_local_neighbors(
        ["192.168.50.20", "192.168.50.21"],
        TEST_ROUTE_BINDING,
    )

    assert responsive == {"192.168.50.20", "192.168.50.21"}
    assert complete is True
    assert {call[0][-1] for call in calls} == {"192.168.50.20", "192.168.50.21"}
    assert all(call[0][1:3] == ["-I", "eth0"] for call in calls)
    assert all(call[1]["timeout"] == 1.5 for call in calls)
    assert all(call[1]["stdout"] is server_protocol_probe.subprocess.DEVNULL for call in calls)


def test_interface_ping_distinguishes_unreachable_from_local_error(monkeypatch):
    monkeypatch.setattr(
        server_protocol_probe.subprocess,
        "run",
        lambda command, **_kwargs: server_protocol_probe.subprocess.CompletedProcess(
            command, 1
        ),
    )
    assert server_protocol_probe._run_interface_ping(
        "192.168.50.20", TEST_ROUTE_BINDING, "/sbin/ping"
    ) == (False, True)

    monkeypatch.setattr(
        server_protocol_probe.subprocess,
        "run",
        lambda command, **_kwargs: server_protocol_probe.subprocess.CompletedProcess(
            command, 2
        ),
    )
    assert server_protocol_probe._run_interface_ping(
        "192.168.50.20", TEST_ROUTE_BINDING, "/sbin/ping"
    ) == (False, False)


@pytest.mark.parametrize(
    "failure",
    (
        OSError("ping executable failed"),
        server_protocol_probe.subprocess.TimeoutExpired("ping", 1.5),
        ValueError("invalid ping invocation"),
    ),
)
def test_interface_ping_execution_failure_is_incomplete(monkeypatch, failure):
    def fail_run(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(server_protocol_probe.subprocess, "run", fail_run)

    assert server_protocol_probe._run_interface_ping(
        "192.168.50.20", TEST_ROUTE_BINDING, "/sbin/ping"
    ) == (False, False)


def test_missing_ping_binary_makes_gateway_and_enabled_full_sweep_incomplete(
    monkeypatch,
):
    monkeypatch.setenv("HG_SERVER_NEIGHBOR_PING_SWEEP", "1")
    monkeypatch.setattr(server_protocol_probe.shutil, "which", lambda _name: None)

    assert server_protocol_probe._refresh_gateway_neighbor(
        "192.168.50.1", TEST_ROUTE_BINDING
    ) == (set(), False)
    assert server_protocol_probe._refresh_local_neighbors(
        ["192.168.50.1", "192.168.50.20"], TEST_ROUTE_BINDING
    ) == (set(), False)


def test_server_arp_uses_current_route_interface_for_duplicate_private_cidr(tmp_path, monkeypatch):
    route_path = tmp_path / "route"
    route_path.write_text(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        "tun0 0032A8C0 00000000 0001 0 0 500 00FFFFFF 0 0 0\n"
        "eth0 0032A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n",
        encoding="utf-8",
    )
    arp_path = tmp_path / "arp"
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.50.20 0x1 0x2 AA:BB:CC:DD:EE:20 * tun0\n"
        "192.168.50.21 0x1 0x2 AA:BB:CC:DD:EE:21 * eth0\n"
        "192.168.50.22 0x1 0x0 AA:BB:CC:DD:EE:22 * eth0\n"
        "192.168.50.23 0x1 0x2 AA:BB:CC:DD:EE:23 * eth0\n"
        "192.168.50.23 0x1 0x2 DA:F5:1E:FE:00:0A * eth0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(server_protocol_probe, "PROC_NET_ROUTE_PATH", str(route_path))
    monkeypatch.setattr(server_protocol_probe, "PROC_NET_ARP_PATH", str(arp_path))

    interface = server_protocol_probe._routing_interface(
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        }
    )

    assert interface == "eth0"
    assert server_protocol_probe._local_neighbor_entries(interface) == {
        "192.168.50.21": "AA:BB:CC:DD:EE:21"
    }


def test_server_udp_binding_requires_selected_interface_address_and_ifindex(monkeypatch):
    monkeypatch.setattr(
        server_protocol_probe,
        "_interface_ipv4_address",
        lambda interface: "192.168.50.12" if interface == "eth0" else None,
    )
    monkeypatch.setattr(
        server_protocol_probe.socket,
        "if_nametoindex",
        lambda interface: 7 if interface == "eth0" else 0,
    )

    binding = server_protocol_probe._resolve_route_interface_binding(
        "eth0", {"subnet_cidr": "192.168.50.0/24"}
    )

    assert binding == server_protocol_probe._RouteInterfaceBinding(
        name="eth0", ipv4="192.168.50.12", ifindex=7
    )
    assert (
        server_protocol_probe._resolve_route_interface_binding(
            "eth0", {"subnet_cidr": "192.168.60.0/24"}
        )
        is None
    )


def test_server_tcp_socket_is_bound_to_exact_interface_and_local_ipv4(monkeypatch):
    calls = []

    class BoundTcpSocket:
        def setsockopt(self, level, option, value):
            calls.append(("setsockopt", level, option, value))

        def bind(self, address):
            calls.append(("bind", address))

        def settimeout(self, timeout):
            calls.append(("timeout", timeout))

        def connect(self, address):
            calls.append(("connect", address))

        def close(self):
            calls.append(("close",))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    monkeypatch.setattr(
        server_protocol_probe.socket,
        "socket",
        lambda family, kind, protocol: (
            BoundTcpSocket()
            if (
                family,
                kind,
                protocol,
            )
            == (
                server_protocol_probe.socket.AF_INET,
                server_protocol_probe.socket.SOCK_STREAM,
                server_protocol_probe.socket.IPPROTO_TCP,
            )
            else None
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("process-default connection fallback is forbidden")
        ),
    )

    with server_protocol_probe._new_interface_tcp_connection(
        "192.168.50.44",
        80,
        TEST_ROUTE_BINDING,
        timeout=0.45,
    ):
        pass

    assert calls[:4] == [
        (
            "setsockopt",
            server_protocol_probe.socket.SOL_SOCKET,
            server_protocol_probe.SO_BINDTODEVICE,
            b"eth0\x00",
        ),
        ("bind", ("192.168.50.12", 0)),
        ("timeout", 0.45),
        ("connect", ("192.168.50.44", 80)),
    ]


def test_server_unicast_bind_failure_has_no_default_route_fallback(monkeypatch):
    class BindFailureSocket:
        closed = False

        def setsockopt(self, *_args):
            raise OSError("SO_BINDTODEVICE denied")

        def close(self):
            self.closed = True

    created = BindFailureSocket()
    monkeypatch.setattr(
        server_protocol_probe.socket, "socket", lambda *_args: created
    )
    monkeypatch.setattr(
        server_protocol_probe.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("process-default connection fallback is forbidden")
        ),
    )

    assert (
        server_protocol_probe._preflight_interface_unicast_binding(
            TEST_ROUTE_BINDING
        )
        is False
    )
    assert created.closed is True


def test_all_tcp_product_probes_receive_the_selected_binding(monkeypatch):
    calls = []

    class ResponseConnection:
        def __init__(self, response):
            self.response = response

        def settimeout(self, _timeout):
            return None

        def sendall(self, _payload):
            return None

        def recv(self, _size):
            response, self.response = self.response, b""
            return response

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    responses = {
        server_protocol_probe.PROBE_PORT: (
            b'HTTP/1.0 200 OK\r\n\r\n'
            b'{"brandDisplayName":"Samsung","modelDisplayName":"RF85C90"}'
        ),
        8080: b"HTTP/1.0 200 OK\r\n\r\n<title>ipTIME A3004NS-M</title>",
        1400: (
            b"HTTP/1.0 200 OK\r\n\r\n"
            b"<root><UDN>uuid:11111111-2222-4333-8444-555555555555</UDN>"
            b"<manufacturer>Samsung</manufacturer>"
            b"<modelName>RF85C90</modelName></root>"
        ),
        22: b"",
    }

    def connection(host, port, binding, *, timeout):
        calls.append((host, port, binding, timeout))
        return ResponseConnection(responses[port])

    monkeypatch.setattr(
        server_protocol_probe,
        "_new_interface_tcp_connection",
        connection,
    )

    info, info_complete = server_protocol_probe._get_info(
        "192.168.50.42", TEST_ROUTE_BINDING
    )
    is_open, tcp_complete = server_protocol_probe._probe_tcp(
        "192.168.50.42", 22, TEST_ROUTE_BINDING
    )
    http, http_complete = server_protocol_probe._http_evidence(
        "192.168.50.42", 8080, TEST_ROUTE_BINDING
    )
    upnp, upnp_complete = server_protocol_probe._upnp_evidence(
        "192.168.50.42",
        "http://192.168.50.42:1400/root.xml",
        TEST_ROUTE_BINDING,
    )

    assert info == {"brand": "Samsung", "model": "RF85C90", "name": "", "type": ""}
    assert info_complete is True
    assert (is_open, tcp_complete) == (True, True)
    assert http_complete is True and "http-title:ipTIME A3004NS-M" in http
    assert upnp_complete is True
    assert "upnp-udn:uuid:11111111-2222-4333-8444-555555555555" in upnp
    assert "upnp-manufacturer:Samsung" in upnp
    assert "upnp-model:RF85C90" in upnp
    assert len(calls) == 4
    assert all(call[2] == TEST_ROUTE_BINDING for call in calls)


@pytest.mark.parametrize(
    "error_number",
    [
        errno.ENETDOWN,
        errno.ENODEV,
        errno.EADDRNOTAVAIL,
        errno.EMFILE,
        errno.ENOBUFS,
    ],
)
def test_tcp_product_probes_treat_local_transport_errors_as_incomplete(
    monkeypatch,
    error_number,
):
    def fail_connection(*_args, **_kwargs):
        raise OSError(error_number, "simulated local transport failure")

    monkeypatch.setattr(
        server_protocol_probe,
        "_new_interface_tcp_connection",
        fail_connection,
    )

    assert server_protocol_probe._get_info("192.168.50.42", TEST_ROUTE_BINDING) == (
        None,
        False,
    )
    assert server_protocol_probe._probe_tcp(
        "192.168.50.42", 80, TEST_ROUTE_BINDING
    ) == (False, False)
    assert server_protocol_probe._http_evidence(
        "192.168.50.42", 80, TEST_ROUTE_BINDING
    ) == ([], False)
    assert server_protocol_probe._upnp_evidence(
        "192.168.50.42",
        "http://192.168.50.42:1400/root.xml",
        TEST_ROUTE_BINDING,
    ) == ([], False)


@pytest.mark.parametrize(
    "make_error",
    [
        pytest.param(
            lambda: ConnectionRefusedError(errno.ECONNREFUSED, "connection refused"),
            id="connection-refused",
        ),
        pytest.param(
            lambda: server_protocol_probe.socket.timeout("timed out"),
            id="socket-timeout",
        ),
    ],
)
def test_tcp_peer_negative_remains_a_complete_observation(monkeypatch, make_error):
    def fail_connection(*_args, **_kwargs):
        raise make_error()

    monkeypatch.setattr(
        server_protocol_probe,
        "_new_interface_tcp_connection",
        fail_connection,
    )

    assert server_protocol_probe._probe_tcp(
        "192.168.50.42", 80, TEST_ROUTE_BINDING
    ) == (False, True)


def test_netbios_unicast_uses_ifindex_checked_udp_binding(monkeypatch):
    calls = []

    class BoundUdpSocket:
        def settimeout(self, timeout):
            calls.append(("timeout", timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(
        server_protocol_probe,
        "_new_interface_udp_socket",
        lambda binding: calls.append(("socket", binding)) or BoundUdpSocket(),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_send_udp_on_interface",
        lambda _sock, _payload, destination, binding: calls.append(
            ("send", destination, binding)
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_recv_udp_on_interface",
        lambda _sock, _size, binding: (
            calls.append(("recv", binding))
            or (b"HEADER-HOME-PC\x00-TAIL", ("192.168.50.44", 137))
        ),
    )

    assert server_protocol_probe._netbios_name(
        "192.168.50.44", TEST_ROUTE_BINDING
    ) == ("HEADER-HOME-PC", True)
    assert ("socket", TEST_ROUTE_BINDING) in calls
    assert ("send", ("192.168.50.44", 137), TEST_ROUTE_BINDING) in calls
    assert ("recv", TEST_ROUTE_BINDING) in calls


def test_server_udp_receive_drops_same_cidr_packet_from_other_interface():
    class PacketSocket:
        def __init__(self, received_ifindex):
            self.received_ifindex = received_ifindex

        def recvmsg(self, _max_bytes, _ancillary_size):
            packet_info = struct.pack(
                "=I4s4s",
                self.received_ifindex,
                server_protocol_probe.socket.inet_aton("192.168.50.22"),
                server_protocol_probe.socket.inet_aton("192.168.50.12"),
            )
            return (
                b"same-cidr-evidence",
                [
                    (
                        server_protocol_probe.socket.IPPROTO_IP,
                        server_protocol_probe.IP_PKTINFO,
                        packet_info,
                    )
                ],
                0,
                ("192.168.50.22", 5353),
            )

    assert (
        server_protocol_probe._recv_udp_on_interface(
            PacketSocket(received_ifindex=9), 9_000, TEST_ROUTE_BINDING
        )
        is None
    )
    assert server_protocol_probe._recv_udp_on_interface(
        PacketSocket(received_ifindex=TEST_ROUTE_BINDING.ifindex),
        9_000,
        TEST_ROUTE_BINDING,
    ) == (b"same-cidr-evidence", ("192.168.50.22", 5353))


def test_mdns_bind_failure_returns_incomplete_without_default_interface(monkeypatch):
    class BindFailureSocket:
        closed = False

        def sendmsg(self, *_args, **_kwargs):
            raise AssertionError("send must not follow a failed interface bind")

        def recvmsg(self, *_args, **_kwargs):
            raise AssertionError("receive must not follow a failed interface bind")

        def setsockopt(self, *_args):
            return None

        def bind(self, address):
            assert address == (
                server_protocol_probe.MDNS_GROUP,
                server_protocol_probe.MDNS_PORT,
            )
            raise OSError("simulated interface bind failure")

        def close(self):
            self.closed = True

    created = BindFailureSocket()
    monkeypatch.setattr(
        server_protocol_probe.socket, "socket", lambda *_args: created
    )

    assert server_protocol_probe._discover_mdns(TEST_ROUTE_BINDING) == ({}, False)
    assert created.closed is True


def test_server_udp_bind_failure_marks_scan_partial(monkeypatch):
    host = "192.168.50.42"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_discover_mdns", lambda _binding: ({}, False)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": "192.168.50.1",
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }

    assert server_protocol_probe.augment_android_observations([], context) == []
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "scan_partial": True,
    }


def test_server_tcp_local_transport_error_marks_scan_partial(monkeypatch):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    scan_tcp_ports = server_protocol_probe._scan_tcp_ports
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: [gateway, target],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(server_protocol_probe, "LAN_DISCOVERY_PORTS", (80,))
    monkeypatch.setattr(server_protocol_probe, "LAN_PORT_WORKERS", 2)
    monkeypatch.setattr(server_protocol_probe, "_scan_tcp_ports", scan_tcp_ports)

    def fail_connection(*_args, **_kwargs):
        raise OSError(errno.ENETDOWN, "simulated interface down")

    monkeypatch.setattr(
        server_protocol_probe,
        "_new_interface_tcp_connection",
        fail_connection,
    )
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }

    assert server_protocol_probe.augment_android_observations([], context) == []
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "scan_partial": True,
    }


def test_server_unicast_preflight_failure_preserves_android_observations(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    original = {
        "ip_address": "192.168.50.1",
        "mac_address": "64:1B:2F:FE:00:06",
        "fingerprints": ["android-gateway"],
    }
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": "192.168.50.1",
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: ["192.168.50.1"]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: False,
    )
    full_probe_calls = {"ping": 0, "tcp": 0}
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda *_args: full_probe_calls.__setitem__(
            "tcp", full_probe_calls["tcp"] + 1
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda *_args: full_probe_calls.__setitem__(
            "ping", full_probe_calls["ping"] + 1
        ),
    )

    assert server_protocol_probe.augment_android_observations([original], context) == [original]
    assert full_probe_calls == {"ping": 0, "tcp": 0}
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_gateway_l2_proof_requires_matching_current_physical_mac():
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": "192.168.50.1",
        "local_ip": "192.168.50.10",
    }
    android = [
        {
            "ip_address": "192.168.50.1",
            "mac_address": "64:1B:2F:FE:00:06",
        }
    ]

    assert server_protocol_probe._same_current_gateway_l2(
        android,
        context,
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        {"192.168.50.1"},
    )
    assert not server_protocol_probe._same_current_gateway_l2(
        android,
        context,
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        {"192.168.50.1": "AA:BB:CC:DD:EE:01"},
        {"192.168.50.1"},
    )
    assert not server_protocol_probe._same_current_gateway_l2(
        android,
        context,
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        set(),
    )
    assert not server_protocol_probe._same_current_gateway_l2(
        [],
        context,
        {},
        {"192.168.50.1": "64:1B:2F:FE:00:06"},
        {"192.168.50.1"},
    )


def test_matching_current_gateway_uuid_permits_bounded_pi_augmentation(monkeypatch):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    gateway_uuid = "11111111-2222-4333-8444-555555555555"
    original = [
        {
            "ip_address": gateway,
            "mac_address": f"UNKNOWN-{gateway}",
            "discovery_sources": ["ssdp"],
            "fingerprints": [f"upnp-udn:UUID:{gateway_uuid.upper()}"],
        }
    ]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway, target]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_gateway_neighbor",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("UUID-only proof must not require gateway ICMP")
        ),
    )
    ssdp_calls = []

    def discover_ssdp_unicast(hosts, binding):
        ssdp_calls.append((list(hosts), binding))
        if list(hosts) == [gateway]:
            return (
                {
                    gateway: [
                        f"ssdp-usn:uuid:{gateway_uuid}::upnp:rootdevice"
                    ]
                },
                True,
            )
        return {}, True

    monkeypatch.setattr(
        server_protocol_probe, "_discover_ssdp_unicast", discover_ssdp_unicast
    )
    sweep_calls = []
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda hosts, binding: (sweep_calls.append((list(hosts), binding)) or set(), True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, set(), True)
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: ({}, True))
    monkeypatch.setattr(
        server_protocol_probe, "_discover_mdns_unicast", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: ({}, True))
    monkeypatch.setattr(server_protocol_probe, "_discover_onvif", lambda _binding: ({}, True))
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert sweep_calls == [([gateway, target], TEST_ROUTE_BINDING)]
    assert ssdp_calls[0] == ([gateway], TEST_ROUTE_BINDING)
    assert ([gateway, target], TEST_ROUTE_BINDING) in ssdp_calls
    assert "server_probe_l2_unverified" not in context["scan_diagnostics"]


def test_gateway_uuid_can_be_reconfirmed_from_safe_root_description(monkeypatch):
    gateway = "192.168.50.1"
    gateway_uuid = "11111111-2222-4333-8444-555555555555"
    location = f"http://{gateway}:49152/rootDesc.xml"
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp_unicast",
        lambda hosts, binding: (
            ({gateway: [f"ssdp-location:{location}"]}, True)
            if hosts == [gateway] and binding == TEST_ROUTE_BINDING
            else ({}, False)
        ),
    )
    upnp_calls = []
    monkeypatch.setattr(
        server_protocol_probe,
        "_upnp_evidence",
        lambda host, current_location, binding: (
            upnp_calls.append((host, current_location, binding))
            or ([f"upnp-udn:UUID:{gateway_uuid.upper()}"], True)
        ),
    )

    assert server_protocol_probe._same_current_gateway_uuid(
        {gateway_uuid}, gateway, TEST_ROUTE_BINDING
    )
    assert upnp_calls == [(gateway, location, TEST_ROUTE_BINDING)]


@pytest.mark.parametrize(
    ("android_fingerprint", "server_evidence"),
    [
        (
            "ssdp-usn:uuid:11111111-2222-4333-8444-555555555555::upnp:rootdevice",
            {
                "192.168.50.1": [
                    "ssdp-usn:uuid:11111111-2222-4333-8444-666666666666::upnp:rootdevice"
                ]
            },
        ),
        (
            "ssdp-usn:uuid:not-a-strong-uuid",
            {
                "192.168.50.1": [
                    "ssdp-usn:uuid:not-a-strong-uuid::upnp:rootdevice"
                ]
            },
        ),
        (
            "ssdp-usn:uuid:11111111-2222-4333-8444-555555555555::upnp:rootdevice",
            {
                "192.168.50.42": [
                    "ssdp-usn:uuid:11111111-2222-4333-8444-555555555555::upnp:rootdevice"
                ]
            },
        ),
        (
            "upnp-udn:uuid:11111111-2222-4333-8444-555555555555",
            {
                "192.168.50.1": [
                    "ssdp-location:http://192.168.50.42/rootDesc.xml"
                ]
            },
        ),
    ],
    ids=("mismatch", "malformed", "other-source", "unsafe-location"),
)
def test_gateway_uuid_failure_never_starts_non_gateway_probe(
    monkeypatch,
    android_fingerprint,
    server_evidence,
):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    original = [
        {
            "ip_address": gateway,
            "mac_address": f"UNKNOWN-{gateway}",
            "discovery_sources": ["ssdp"],
            "fingerprints": [android_fingerprint],
        }
    ]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway, target]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    ssdp_calls = []
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp_unicast",
        lambda hosts, _binding: (ssdp_calls.append(list(hosts)) or server_evidence, True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_upnp_evidence",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("unsafe gateway description must not be fetched")
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("unverified UUID must not start a subnet ping sweep")
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("unverified UUID must not start a subnet TCP sweep")
        ),
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert all(call == [gateway] for call in ssdp_calls)
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_same_cidr_other_l2_gateway_skips_all_pi_augmentation(monkeypatch):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    android_gateway_mac = "64:1B:2F:FE:00:06"
    other_l2_gateway_mac = "AA:BB:CC:DD:EE:01"
    original = [
        {
            "ip_address": gateway,
            "mac_address": android_gateway_mac,
            "discovery_sources": ["android-arp"],
            "fingerprints": [],
        },
        {
            "ip_address": target,
            "mac_address": "AA:BB:CC:DD:EE:42",
            "discovery_sources": ["android-arp"],
            "fingerprints": [],
        },
    ]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway, target]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    neighbor_reads = iter(
        (
            {gateway: other_l2_gateway_mac},
            {gateway: other_l2_gateway_mac},
        )
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_gateway_neighbor",
        lambda candidate, _binding: ({candidate}, True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    full_probe_calls = {"ping": 0, "tcp": 0}
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda *_args: full_probe_calls.__setitem__(
            "ping", full_probe_calls["ping"] + 1
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda *_args: full_probe_calls.__setitem__(
            "tcp", full_probe_calls["tcp"] + 1
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns",
        lambda _binding: (_ for _ in ()).throw(
            AssertionError("other-L2 evidence must not be queried")
        ),
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert full_probe_calls == {"ping": 0, "tcp": 0}
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_missing_android_gateway_evidence_blocks_full_pi_sweep(monkeypatch):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    original = [
        {
            "ip_address": target,
            "mac_address": "AA:BB:CC:DD:EE:42",
            "discovery_sources": ["android-arp"],
        }
    ]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    # A stale deployment variable must not restore the removed fallback.
    monkeypatch.setenv("HG_SERVER_ALLOW_MACLESS_ANDROID_L2", "1")

    def fail_pi_lan_access(*_args, **_kwargs):
        raise AssertionError("MAC-less Android scans must not access the Pi LAN")

    for name in (
        "_routing_interface",
        "_resolve_route_interface_binding",
        "_preflight_interface_unicast_binding",
        "_local_neighbor_entries",
        "_refresh_gateway_neighbor",
        "_refresh_local_neighbors",
        "_scan_tcp_ports",
    ):
        monkeypatch.setattr(server_protocol_probe, name, fail_pi_lan_access)

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_pi_without_route_to_android_subnet_preserves_native_coverage(monkeypatch):
    gateway = "192.168.50.1"
    gateway_mac = "64:1B:2F:FE:00:06"
    original = [
        {
            "ip_address": gateway,
            "mac_address": gateway_mac,
            "discovery_sources": ["android-arp"],
        }
    ]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: None
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: None,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("an unroutable remote subnet must not touch Pi neighbours")
        ),
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_gateway_ping_execution_failure_blocks_full_pi_sweep(monkeypatch):
    gateway = "192.168.50.1"
    gateway_mac = "64:1B:2F:FE:00:06"
    original = [{"ip_address": gateway, "mac_address": gateway_mac}]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: {gateway: gateway_mac},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_gateway_neighbor",
        lambda _gateway, _binding: (set(), False),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_same_current_gateway_l2",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("incomplete gateway probe must fail before L2 approval")
        ),
    )
    full_probe_calls = {"ping": 0, "tcp": 0}
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda *_args: full_probe_calls.__setitem__(
            "ping", full_probe_calls["ping"] + 1
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda *_args: full_probe_calls.__setitem__(
            "tcp", full_probe_calls["tcp"] + 1
        ),
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert full_probe_calls == {"ping": 0, "tcp": 0}
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_ping_failure_without_other_gateway_freshness_marks_partial(monkeypatch):
    gateway = "192.168.50.1"
    gateway_mac = "64:1B:2F:FE:00:06"
    original = [{"ip_address": gateway, "mac_address": gateway_mac}]
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_resolve_route_interface_binding",
        lambda _interface, _context: TEST_ROUTE_BINDING,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_preflight_interface_unicast_binding",
        lambda _binding: True,
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: {gateway: gateway_mac},
    )
    # A normally executed ping may report the gateway unreachable.  With no
    # newly learned ARP entry there is no current-L2 proof, so the pass cannot
    # be complete and no broader host pass may begin.
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_gateway_neighbor",
        lambda _gateway, _binding: (set(), True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    full_probe_calls = {"ping": 0, "tcp": 0}
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda *_args: full_probe_calls.__setitem__(
            "ping", full_probe_calls["ping"] + 1
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda *_args: full_probe_calls.__setitem__(
            "tcp", full_probe_calls["tcp"] + 1
        ),
    )

    assert server_protocol_probe.augment_android_observations(original, context) == original
    assert full_probe_calls == {"ping": 0, "tcp": 0}
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "server_probe_l2_unverified": True,
    }


def test_enabled_full_ping_sweep_execution_failure_marks_scan_partial(monkeypatch):
    gateway = "192.168.50.1"
    target = "192.168.50.42"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    monkeypatch.setenv("HG_SERVER_NEIGHBOR_PING_SWEEP", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe, "_probe_hosts", lambda _context: [gateway, target]
    )
    monkeypatch.setattr(
        server_protocol_probe, "_routing_interface", lambda _context: "eth0"
    )
    monkeypatch.setattr(
        server_protocol_probe, "_local_neighbor_entries", lambda _interface: {}
    )
    sweep_calls = []

    def incomplete_sweep(hosts, binding):
        sweep_calls.append((list(hosts), binding))
        return set(), False

    monkeypatch.setattr(
        server_protocol_probe, "_refresh_local_neighbors", incomplete_sweep
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )
    context = {
        "subnet_cidr": "192.168.50.0/24",
        "gateway_ip": gateway,
        "local_ip": "192.168.50.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }

    assert server_protocol_probe.augment_android_observations([], context) == []
    assert sweep_calls == [([gateway, target], TEST_ROUTE_BINDING)]
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "scan_partial": True,
    }


def test_large_server_probe_subnet_continues_bounded_pass_and_marks_partial(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    original = {"ip_address": "192.168.53.200", "fingerprints": ["upnp-model:RF85C90"]}
    context = {
        "subnet_cidr": "192.168.52.0/22",
        "gateway_ip": "192.168.52.1",
        "local_ip": "192.168.52.10",
        "scan_diagnostics": {"candidate_coverage_complete": True},
    }
    sampled = server_protocol_probe._probe_hosts(context)
    assert original["ip_address"] not in sampled
    sweep_calls = []
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda hosts, binding: (sweep_calls.append((list(hosts), binding)) or set(), True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    assert server_protocol_probe.augment_android_observations([original], context) == [original]
    assert len(sweep_calls) == 1
    probed_hosts, binding = sweep_calls[0]
    assert binding == TEST_ROUTE_BINDING
    assert probed_hosts[0] == "192.168.52.1"
    assert original["ip_address"] in probed_hosts
    assert len(probed_hosts) == server_protocol_probe.PROBE_MAX_HOSTS
    assert len(probed_hosts) == len(set(probed_hosts))
    assert context["scan_diagnostics"] == {
        "candidate_coverage_complete": True,
        "scan_partial": True,
    }


def test_server_protocol_probe_merges_arp_tcp_ssdp_and_http_evidence(monkeypatch):
    """The Pi pass must recover hosts the phone did not report, without naming by port."""
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.20", "192.168.50.21"],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: {"192.168.50.20": "64:1B:2F:FE:00:06", "192.168.50.21": "AA:BB:CC:DD:EE:FF"},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({"192.168.50.20": [80, 445]}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns",
        lambda _binding: {"192.168.50.21": ["mdns-type:._googlecast._tcp.local", "mdns-txt:md=Chromecast"]},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {"192.168.50.20": {"mac": "64:1B:2F:FE:00:06", "hostname": "HOME-PC"}},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp",
        lambda _binding: {"192.168.50.21": ["ssdp-st:urn:schemas-upnp-org:device:MediaServer:1"]},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_http_evidence",
        lambda _host, _port, _binding: (["http-model:A3004NS-M"], True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_netbios_name",
        lambda _host, _binding: ("HOME-PC", True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert {item["ip_address"] for item in observed} == {"192.168.50.20", "192.168.50.21"}
    tcp_host = next(item for item in observed if item["ip_address"] == "192.168.50.20")
    assert tcp_host["mac_address"] == "64:1B:2F:FE:00:06"
    assert set(tcp_host["open_ports"]) == {80, 445}
    assert "server-tcp-probe" in tcp_host["discovery_sources"]
    assert "netbios" in tcp_host["discovery_sources"]
    assert "http-model:A3004NS-M" in tcp_host["fingerprints"]
    assert "netbios-name:HOME-PC" in tcp_host["fingerprints"]
    ssdp_host = next(item for item in observed if item["ip_address"] == "192.168.50.21")
    assert ssdp_host["open_ports"] == [1900]
    assert "ssdp" in ssdp_host["discovery_sources"]
    assert "mdns" in ssdp_host["discovery_sources"]
    assert "mdns-txt:md=Chromecast" in ssdp_host["fingerprints"]
    assert "dhcp-lease" in tcp_host["discovery_sources"]
    assert "dhcp-hostname:HOME-PC" in tcp_host["fingerprints"]


def test_server_protocol_probe_rejects_all_evidence_outside_request_allowlist(monkeypatch):
    """Private addresses on another Pi NIC/VPN must not join this scan."""
    allowed = "192.168.50.20"
    other_private = "10.44.0.20"
    vpn_private = "172.20.0.8"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", allowed],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: {
            allowed: "64:1B:2F:FE:00:06",
            other_private: "AA:BB:CC:DD:EE:20",
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {
            allowed: {"mac": "64:1B:2F:FE:00:06", "hostname": "HOME-ROUTER"},
            other_private: {"mac": "AA:BB:CC:DD:EE:20", "hostname": "VPN-DEVICE"},
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({allowed: [80], other_private: [17654]}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns",
        lambda _binding: {
            allowed: ["mdns-txt:model=A3004NS-M"],
            other_private: ["mdns-txt:model=OFF-SUBNET-MDNS"],
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns_unicast",
        lambda _hosts, _binding: {vpn_private: ["mdns-txt:model=VPN-MDNS"]},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp",
        lambda _binding: {
            allowed: [f"ssdp-location:http://{allowed}/device.xml"],
            other_private: [f"ssdp-location:http://{other_private}/off-subnet.xml"],
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp_unicast",
        lambda _hosts, _binding: {vpn_private: ["ssdp-server:VPN-UPNP"]},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_http_evidence",
        lambda host, _port, _binding: ([f"http-model:{host}-HTTP"], True),
    )
    upnp_calls = []

    def fake_upnp(host, location, _binding):
        upnp_calls.append((host, location))
        return ["upnp-model:A3004NS-M"], True

    monkeypatch.setattr(server_protocol_probe, "_upnp_evidence", fake_upnp)
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    # A defensive filter also covers a malformed/misbehaving protocol worker
    # that reports a host other than the one it was asked to probe.
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_one",
        lambda _host, _binding: (
            (
                vpn_private,
                {"brand": "VPN", "model": "OFF-SUBNET", "name": "", "type": ""},
            ),
            True,
        ),
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert [item["ip_address"] for item in observed] == [allowed]
    assert observed[0]["mac_address"] == "64:1B:2F:FE:00:06"
    assert "mdns-txt:model=A3004NS-M" in observed[0]["fingerprints"]
    assert upnp_calls == [(allowed, f"http://{allowed}/device.xml")]
    serialized = repr(observed)
    assert other_private not in serialized
    assert vpn_private not in serialized
    assert "OFF-SUBNET" not in serialized
    assert "VPN-" not in serialized


def test_server_protocol_probe_merges_direct_ssdp_when_multicast_is_filtered(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(server_protocol_probe, "_probe_hosts", lambda _context: ["192.168.50.1"])
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp",
        lambda _binding: {},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp_unicast",
        lambda _hosts, _binding: {
            "192.168.50.1": [
                "ssdp-server:KT UPnP/1.0",
                "ssdp-location:http://192.168.50.1:80/rootDesc.xml",
            ]
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_upnp_evidence",
        lambda _host, _location, _binding: (
            [
                "upnp-manufacturer:KT",
                "upnp-model:KM06-507H",
                "upnp-type:urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            ],
            True,
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert len(observed) == 1
    item = observed[0]
    assert "ssdp" in item["discovery_sources"]
    assert "ssdp-server:KT UPnP/1.0" in item["fingerprints"]
    assert "upnp-manufacturer:KT" in item["fingerprints"]
    assert "upnp-model:KM06-507H" in item["fingerprints"]
    assert resolve_device_identity(item)["canonical_name"] == "KT 공유기 (KM06-507H)"


def test_onvif_probe_match_is_merged_once_without_refreshing_mac(monkeypatch):
    host = "192.168.50.43"
    other_subnet = "10.44.0.43"
    payload = (
        b'<?xml version="1.0"?>'
        b'<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        b'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        b'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        b'<e:Body><d:ProbeMatches><d:ProbeMatch>'
        b'<d:Types>dn:NetworkVideoTransmitter</d:Types>'
        b'<d:Scopes>onvif://www.onvif.org/name/FrontDoor '
        b'onvif://www.onvif.org/hardware/DS-2CD2042</d:Scopes>'
        b'</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>'
    )
    evidence = server_protocol_probe._parse_onvif_probe_match(payload)
    assert "onvif-ws-discovery" in evidence
    assert "onvif-type:dn:NetworkVideoTransmitter" in evidence
    assert "onvif-scope:onvif://www.onvif.org/hardware/DS-2CD2042" in evidence

    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_onvif",
        lambda _binding: ({host: evidence, other_subnet: evidence}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert len(observed) == 1
    item = observed[0]
    assert item["ip_address"] == host
    assert item["mac_address"] == f"UNKNOWN-{host}"
    assert item["open_ports"] == [3702]
    assert item["services"] == ["onvif"]
    assert item["discovery_sources"] == ["ws-discovery"]
    assert item["fingerprints"] == evidence
    assert other_subnet not in repr(observed)


def test_server_protocol_probe_rechecks_neighbors_after_tcp_warmup(monkeypatch):
    """A host that only answers ARP after the TCP pass must not be dropped."""
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.77"],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(
        ({}, {}, {"192.168.50.77": "AA:BB:CC:DD:EE:77"})
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: next(neighbor_reads))
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert len(observed) == 1
    assert observed[0]["ip_address"] == "192.168.50.77"
    assert observed[0]["mac_address"] == "AA:BB:CC:DD:EE:77"
    assert observed[0]["open_ports"] == []
    assert observed[0]["discovery_sources"] == ["server-neighbor"]


def test_server_protocol_probe_drops_unchanged_stale_neighbor_without_current_evidence(monkeypatch):
    stale = "192.168.50.70"
    newly_learned = "192.168.50.71"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", stale, newly_learned],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(
        (
            {stale: "AA:BB:CC:DD:EE:70"},
            {stale: "AA:BB:CC:DD:EE:70"},
            {
                stale: "AA:BB:CC:DD:EE:70",
                newly_learned: "AA:BB:CC:DD:EE:71",
            },
        )
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    # A stale lease must not turn the unchanged ARP cache row back into a
    # current observation.
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {
            stale: {"mac": "AA:BB:CC:DD:EE:70", "hostname": "OLD-LEASE"}
        },
    )
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert [item["ip_address"] for item in observed] == [newly_learned]
    assert observed[0]["mac_address"] == "AA:BB:CC:DD:EE:71"
    assert stale not in repr(observed)
    assert "OLD-LEASE" not in repr(observed)


def test_multicast_presence_does_not_refresh_unchanged_stale_arp_mac(monkeypatch):
    host = "192.168.50.73"
    stale_mac = "AA:BB:CC:DD:EE:73"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(
        ({host: stale_mac}, {host: stale_mac}, {host: stale_mac})
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns",
        lambda _binding: (
            {host: ["mdns-type:_googlecast._tcp.local", "mdns-txt:md=Chromecast"]},
            True,
        ),
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert len(observed) == 1
    assert observed[0]["ip_address"] == host
    assert observed[0]["mac_address"] == f"UNKNOWN-{host}"
    assert observed[0]["discovery_sources"] == ["mdns"]
    assert "mdns-txt:md=Chromecast" in observed[0]["fingerprints"]
    assert stale_mac not in repr(observed)
    assert "server-neighbor" not in observed[0]["discovery_sources"]


def test_android_only_new_occupant_keeps_verified_mac_over_stale_pi_arp(monkeypatch):
    host = "192.168.50.72"
    stale_mac = "AA:BB:CC:DD:EE:70"
    android_mac = "64:1B:2F:FE:00:06"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(
        ({host: stale_mac}, {host: stale_mac}, {host: stale_mac})
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {host: {"mac": stale_mac, "hostname": "PREVIOUS-OCCUPANT"}},
    )
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [
            {
                "ip_address": host,
                "mac_address": android_mac,
                "open_ports": [],
                "services": [],
                "discovery_sources": ["android-arp"],
                "fingerprints": [],
            }
        ],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert len(observed) == 1
    assert observed[0]["mac_address"] == android_mac
    assert observed[0]["discovery_sources"] == ["android-arp"]
    assert stale_mac not in repr(observed)
    assert "PREVIOUS-OCCUPANT" not in repr(observed)


def test_server_protocol_probe_does_not_apply_mismatched_lease_to_active_new_occupant(monkeypatch):
    host = "192.168.50.80"
    old_mac = "AA:BB:CC:DD:EE:01"
    current_mac = "64:1B:2F:FE:00:06"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(
        ({host: old_mac}, {host: old_mac}, {host: current_mac})
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {host: {"mac": old_mac, "hostname": "PREVIOUS-TV"}},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({host: [80]}, True),
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_http_evidence",
        lambda _host, _port, _binding: ([], True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert len(observed) == 1
    assert observed[0]["mac_address"] == current_mac
    assert "dhcp-lease" not in observed[0]["discovery_sources"]
    assert "PREVIOUS-TV" not in repr(observed)


def test_valid_lease_cannot_supply_mac_without_post_scan_arp(monkeypatch):
    host = "192.168.50.81"
    lease_mac = "AA:BB:CC:DD:EE:81"
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", host],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    neighbor_reads = iter(({host: lease_mac}, {host: lease_mac}, {}))
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: next(neighbor_reads),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_refresh_local_neighbors",
        lambda _hosts, _binding: (set(), True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_dhcp_lease_entries",
        lambda: {host: {"mac": lease_mac, "hostname": "LEASE-ONLY-NAME"}},
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({host: [80]}, True),
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp_unicast", lambda _hosts, _binding: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_http_evidence",
        lambda _host, _port, _binding: ([], True),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_netbios_name", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [],
        {
            "subnet_cidr": "192.168.50.0/24",
            "gateway_ip": "192.168.50.1",
            "local_ip": "192.168.50.10",
        },
    )

    assert len(observed) == 1
    assert observed[0]["mac_address"] == f"UNKNOWN-{host}"
    assert "dhcp-lease" not in observed[0]["discovery_sources"]
    assert "LEASE-ONLY-NAME" not in repr(observed)


def test_server_probe_queries_lg_thinq_service_and_keeps_product_evidence(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.42"],
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe,
        "_scan_tcp_ports",
        lambda _hosts, _binding: ({"192.168.50.42": [9761]}, True),
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_mdns",
        lambda _binding: {
            "192.168.50.42": [
                "mdns-type:._lg-smart-device._tcp.local",
                "mdns-txt:product=air_conditioner",
                "mdns-txt:model=WIN_056905_WW",
            ]
        },
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )
    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )
    assert len(observed) == 1
    item = observed[0]
    assert 9761 in item["open_ports"]
    assert "mdns" in item["discovery_sources"]
    assert "mdns-type:._lg-smart-device._tcp.local" in item["fingerprints"]
    assert resolve_device_identity(item)["canonical_name"] == "LG 에어컨 (WIN_056905_WW)"


def _mdns_record(name: str, record_type: int, payload: bytes) -> bytes:
    return (
        server_protocol_probe._encode_dns_name(name)
        + struct.pack("!HHIH", record_type, 1, 120, len(payload))
        + payload
    )


def _mdns_packet(*records: bytes) -> bytes:
    return struct.pack("!6H", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def _mdns_txt(*values: str) -> bytes:
    encoded = [value.encode("utf-8") for value in values]
    return b"".join(bytes([len(value)]) + value for value in encoded)


def _mdns_srv(target: str, port: int) -> bytes:
    return struct.pack("!HHH", 0, 0, port) + server_protocol_probe._encode_dns_name(target)


def test_mdns_packet_parser_keeps_service_and_product_txt_evidence():
    ptr = server_protocol_probe._encode_dns_name("Kitchen._googlecast._tcp.local")
    packet = _mdns_packet(
        _mdns_record("_googlecast._tcp.local", 12, ptr),
        _mdns_record(
            "Kitchen._googlecast._tcp.local", 33, _mdns_srv("kitchen.local", 8009)
        ),
        _mdns_record("Kitchen._googlecast._tcp.local", 16, _mdns_txt("md=Nest Mini")),
        _mdns_record("kitchen.local", 1, ipaddress.IPv4Address("192.168.50.21").packed),
    )

    attributed = server_protocol_probe._parse_mdns_packet(packet)
    evidence = attributed["192.168.50.21"]

    assert "mdns-type:_googlecast._tcp.local" in evidence
    assert "mdns-name:Kitchen._googlecast._tcp.local" in evidence
    assert "mdns-txt:md=Nest Mini" in evidence
    assert "mdns-host:192.168.50.21" in evidence
    assert "mdns-port:8009" in evidence


def test_mdns_packet_parser_attributes_multi_responder_records_by_srv_address():
    living_instance = "Living._airplay._tcp.local"
    studio_instance = "Studio._googlecast._tcp.local"
    packet = _mdns_packet(
        _mdns_record(
            "_airplay._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(living_instance),
        ),
        _mdns_record(
            "_googlecast._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(studio_instance),
        ),
        _mdns_record(living_instance, 33, _mdns_srv("living.local", 7000)),
        _mdns_record(studio_instance, 33, _mdns_srv("studio.local", 8009)),
        _mdns_record(living_instance, 16, _mdns_txt("model=Mac15,6")),
        _mdns_record(studio_instance, 16, _mdns_txt("md=Chromecast")),
        _mdns_record("living.local", 1, ipaddress.IPv4Address("192.168.50.31").packed),
        _mdns_record("living.local", 28, ipaddress.IPv6Address("fd00::31").packed),
        _mdns_record("studio.local", 1, ipaddress.IPv4Address("192.168.50.32").packed),
    )

    attributed = server_protocol_probe._parse_mdns_packet(
        packet, source_host="192.168.50.99"
    )

    assert set(attributed) == {"192.168.50.31", "fd00::31", "192.168.50.32"}
    assert "mdns-txt:model=Mac15,6" in attributed["192.168.50.31"]
    assert "mdns-txt:md=Chromecast" not in attributed["192.168.50.31"]
    assert "mdns-port:7000" in attributed["192.168.50.31"]
    assert "mdns-txt:model=Mac15,6" in attributed["fd00::31"]
    assert "mdns-port:7000" in attributed["fd00::31"]
    assert "mdns-txt:md=Chromecast" in attributed["192.168.50.32"]
    assert "mdns-txt:model=Mac15,6" not in attributed["192.168.50.32"]
    assert "mdns-port:8009" in attributed["192.168.50.32"]


def test_mdns_packet_parser_keeps_identical_models_on_distinct_addresses():
    first_instance = "Room-A._googlecast._tcp.local"
    second_instance = "Room-B._googlecast._tcp.local"
    packet = _mdns_packet(
        _mdns_record(
            "_googlecast._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(first_instance),
        ),
        _mdns_record(
            "_googlecast._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(second_instance),
        ),
        _mdns_record(first_instance, 33, _mdns_srv("room-a.local", 8009)),
        _mdns_record(second_instance, 33, _mdns_srv("room-b.local", 8009)),
        _mdns_record(first_instance, 16, _mdns_txt("md=Nest Mini")),
        _mdns_record(second_instance, 16, _mdns_txt("md=Nest Mini")),
        _mdns_record("room-a.local", 1, ipaddress.IPv4Address("192.168.50.41").packed),
        _mdns_record("room-b.local", 1, ipaddress.IPv4Address("192.168.50.42").packed),
    )

    attributed = server_protocol_probe._parse_mdns_packet(packet)

    assert set(attributed) == {"192.168.50.41", "192.168.50.42"}
    assert "mdns-txt:md=Nest Mini" in attributed["192.168.50.41"]
    assert "mdns-txt:md=Nest Mini" in attributed["192.168.50.42"]
    assert "mdns-name:Room-A._googlecast._tcp.local" in attributed["192.168.50.41"]
    assert "mdns-name:Room-B._googlecast._tcp.local" in attributed["192.168.50.42"]


def test_mdns_packet_parser_does_not_fallback_multi_target_packet_to_udp_source():
    first_instance = "First._airplay._tcp.local"
    second_instance = "Second._airplay._tcp.local"
    packet = _mdns_packet(
        _mdns_record(
            "_airplay._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(first_instance),
        ),
        _mdns_record(
            "_airplay._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(second_instance),
        ),
        _mdns_record(first_instance, 33, _mdns_srv("first.local", 7000)),
        _mdns_record(second_instance, 33, _mdns_srv("second.local", 7000)),
        _mdns_record(first_instance, 16, _mdns_txt("model=Mac14,9")),
        _mdns_record(second_instance, 16, _mdns_txt("model=Mac15,6")),
    )

    attributed = server_protocol_probe._parse_mdns_packet(
        packet, source_host="192.168.50.51"
    )

    assert attributed == {}


def test_mdns_packet_parser_falls_back_single_target_to_udp_source():
    instance = "Only._airplay._tcp.local"
    packet = _mdns_packet(
        _mdns_record(
            "_airplay._tcp.local",
            12,
            server_protocol_probe._encode_dns_name(instance),
        ),
        _mdns_record(instance, 33, _mdns_srv("only.local", 7000)),
        _mdns_record(instance, 16, _mdns_txt("model=Mac15,6")),
    )

    attributed = server_protocol_probe._parse_mdns_packet(
        packet, source_host="192.168.50.61"
    )

    assert set(attributed) == {"192.168.50.61"}
    assert "mdns-txt:model=Mac15,6" in attributed["192.168.50.61"]
    assert "mdns-host:192.168.50.61" in attributed["192.168.50.61"]
    assert "mdns-port:7000" in attributed["192.168.50.61"]


def test_dhcp_lease_parser_keeps_only_unexpired_private_hostname_and_mac(tmp_path, monkeypatch):
    lease_path = tmp_path / "dnsmasq.leases"
    expired = int(server_protocol_probe.time.time()) - 1
    lease_path.write_text(
        "4102444800 64:1B:2F:FE:00:06 192.168.50.20 HOME-PC *\n"
        f"{expired} AA:BB:CC:DD:EE:23 192.168.50.23 EXPIRED-TV *\n"
        "4102444800 00:00:00:00:00:00 192.168.50.21 * *\n"
        "4102444800 invalid 192.168.50.22 BAD *\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(server_protocol_probe, "DHCP_LEASE_PATHS", (str(lease_path),))

    entries = server_protocol_probe._dhcp_lease_entries()

    assert entries == {
        "192.168.50.20": {"mac": "64:1B:2F:FE:00:06", "hostname": "HOME-PC"},
    }


def test_server_neighbor_probe_recovers_netbios_name_without_open_smb_ports(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.44"],
    )
    monkeypatch.setattr(server_protocol_probe, "_routing_interface", lambda _context: "eth0")
    monkeypatch.setattr(
        server_protocol_probe,
        "_local_neighbor_entries",
        lambda _interface: {"192.168.50.44": "AA:BB:CC:DD:EE:44"},
    )
    monkeypatch.setattr(server_protocol_probe, "_dhcp_lease_entries", lambda: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(server_protocol_probe, "_discover_mdns", lambda _binding: {})
    monkeypatch.setattr(server_protocol_probe, "_discover_ssdp", lambda _binding: {})
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_netbios_name",
        lambda _host, _binding: ("IOT-HUB", True),
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert observed[0]["discovery_sources"] == ["server-neighbor", "netbios"]
    assert "netbios-name:IOT-HUB" in observed[0]["fingerprints"]


def test_http_model_evidence_is_allowed_to_match_catalog_only():
    resolved = resolve_device_identity(
        {
            "ip_address": "192.168.50.20",
            "manufacturer": "",
            "model": "",
            "device_type": "router",
            "mac_address": "64:1B:2F:FE:00:06",
            "open_ports": [80],
            "services": ["http"],
            "discovery_sources": ["server-tcp-probe"],
            "fingerprints": ["http-title:ipTIME A3004NS-M", "http-model:A3004NS-M"],
        }
    )
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"


def test_http_structured_json_fields_are_kept_as_separate_identity_evidence():
    evidence = server_protocol_probe._structured_http_fingerprints(
        '{"manufacturerName":"ipTIME",'
        '"productName":"ipTIME A3004NS-M",'
        '"deviceType":"router"}',
        {"content-type": "application/json"},
    )
    assert evidence == [
        "http-manufacturer:ipTIME",
        "http-product:ipTIME A3004NS-M",
        "http-device-type:router",
    ]


def test_http_structured_product_name_can_resolve_catalog_model_without_device_hardcoding():
    resolved = resolve_device_identity(
        {
            "ip_address": "192.168.50.21",
            "manufacturer": "",
            "model": "",
            "device_type": "router",
            "mac_address": "64:1B:2F:FE:00:07",
            "open_ports": [80],
            "services": ["http"],
            "discovery_sources": ["server-tcp-probe"],
            "fingerprints": [
                "http-manufacturer:ipTIME",
                "http-product:ipTIME A3004NS-M",
                "http-device-type:router",
            ],
        }
    )
    assert resolved["identity_status"] == "resolved"
    assert resolved["model"] == "A3004NS-M"
    assert resolved["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"


def test_http_html_title_does_not_create_structured_manufacturer_evidence():
    evidence = server_protocol_probe._structured_http_fingerprints(
        "<html><title>ipTIME A3004NS-M</title></html>",
        {"content-type": "text/html"},
    )
    assert evidence == []


def test_ssdp_description_is_merged_as_private_product_evidence(monkeypatch):
    monkeypatch.setenv("HG_SERVER_PROTOCOL_PROBE", "1")
    _use_test_route_binding(monkeypatch)
    monkeypatch.setattr(
        server_protocol_probe,
        "_probe_hosts",
        lambda _context: ["192.168.50.1", "192.168.50.30"],
    )
    monkeypatch.setattr(server_protocol_probe, "_local_neighbor_entries", lambda _interface: {})
    monkeypatch.setattr(
        server_protocol_probe, "_scan_tcp_ports", lambda _hosts, _binding: ({}, True)
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_discover_ssdp",
        lambda _binding: {
            "192.168.50.30": [
                "ssdp-location:http://192.168.50.30:8001/device.xml",
                "ssdp-st:urn:schemas-upnp-org:device:Basic:1",
            ]
        },
    )
    monkeypatch.setattr(
        server_protocol_probe,
        "_upnp_evidence",
        lambda _host, _location, _binding: (
            [
                "upnp-manufacturer:Samsung",
                "upnp-model:RF85C90",
                "upnp-name:Family Hub",
            ],
            True,
        ),
    )
    monkeypatch.setattr(
        server_protocol_probe, "_probe_one", lambda _host, _binding: (None, True)
    )

    observed = server_protocol_probe.augment_android_observations(
        [], {"subnet_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1", "local_ip": "192.168.50.10"}
    )

    assert len(observed) == 1
    assert "upnp-manufacturer:Samsung" in observed[0]["fingerprints"]
    assert "upnp-model:RF85C90" in observed[0]["fingerprints"]
    resolved = resolve_device_identity(observed[0])
    assert resolved["identity_status"] == "resolved"
    assert resolved["canonical_name"] == "삼성 냉장고 (RF85C90)"


def test_upnp_xml_parser_keeps_only_short_fields():
    assert server_protocol_probe._xml_text(
        "<root><manufacturer>Samsung</manufacturer><modelName>RF85C90</modelName></root>",
        "manufacturer",
    ) == "Samsung"
    assert server_protocol_probe._xml_text(
        "<root><manufacturer>Samsung</manufacturer><modelName>RF85C90</modelName></root>",
        "modelName",
    ) == "RF85C90"


def test_server_resolves_airplay_mac_model_as_apple_computer_not_audio():
    resolved = resolve_device_identity(
        {
            "name": "愛しい私の金リンゴ",
            "manufacturer": "",
            "model": "",
            "device_type": "audio",
            "fingerprints": [
                "mdns-type:._airplay._tcp.local",
                "mdns-type:._raop._tcp.local",
                "mdns-txt:am=Mac14,9",
                "mdns-txt:md=0,1,2",
                "mdns-txt:model=Mac14,9",
            ],
            "discovery_sources": ["mdns", "tcp-port-probe"],
        }
    )

    assert resolved["identity_status"] == "resolved"
    assert resolved["manufacturer"] == "Apple"
    assert resolved["device_type"] == "computer"
    assert resolved["model"] == "Mac14,9"
    assert resolved["canonical_name"] == "애플 컴퓨터 (Mac14,9)"


def test_server_resolves_legacy_macbook_companion_model_from_structured_mdns():
    resolved = resolve_device_identity(
        {
            "name": "LEE의 MacBook Pro",
            "manufacturer": "",
            "model": "",
            "device_type": "unknown",
            "fingerprints": [
                "mdns-type:._companion-link._tcp.local",
                "mdns-txt:model=MacBookPro11,5",
                "mdns-txt:osxvers=21",
            ],
            "discovery_sources": ["mdns"],
        }
    )

    assert resolved["identity_status"] == "resolved"
    assert resolved["manufacturer"] == "Apple"
    assert resolved["device_type"] == "computer"
    assert resolved["model"] == "MacBookPro11,5"
    assert resolved["canonical_name"] == "애플 컴퓨터 (MacBookPro11,5)"


def test_audio_protocol_without_product_model_is_not_public_audio_device():
    from app.services.device_presentation import apply_device_presentation

    assert (
        apply_device_presentation(
            {
                "name": "오디오 기기",
                "device_type": "audio",
                "manufacturer": "",
                "model": "",
                "fingerprints": ["mdns-type:._raop._tcp.local"],
                "discovery_sources": ["mdns"],
            }
        )
        is None
    )


def test_server_does_not_promote_unverified_broad_model_to_product():
    resolved = resolve_device_identity(
        {
            "manufacturer": "Samsung",
            "model": "X123",
            "device_type": "fridge",
            "fingerprints": ["mdns-txt:manufacturer=Samsung"],
        }
    )
    assert resolved["identity_status"] == "enriching"
    assert not resolved["canonical_name"]
    assert resolved["identity_candidates"]


def test_server_keeps_verified_category_pending_without_vendor_and_model():
    resolved = resolve_device_identity(
        {
            "manufacturer": "",
            "model": "",
            "device_type": "",
            "fingerprints": ["ws-discovery device:NetworkVideoTransmitter"],
            "services": ["onvif"],
        }
    )
    assert resolved["identity_status"] == "enriching"
    assert resolved["canonical_name"] == ""
    assert resolved["manufacturer"] == ""
    assert resolved["model"] == ""
    assert resolved["device_type"] == "camera"


def test_catalog_candidates_require_more_than_a_vendor_string():
    resolved = resolve_device_identity(
        {
            "manufacturer": "Samsung",
            "model": "RF85C90",
            "device_type": "web-device",
            "fingerprints": ["mdns-txt:manufacturer=Samsung", "mdns-txt:model=RF85C90"],
        }
    )
    labels = [str(item.get("label") or "") for item in resolved["identity_candidates"]]
    assert labels == ["삼성 냉장고 (RF85C90)"]


def test_identity_finding_counts_and_history_survive_sqlite_reopen(tmp_path: Path):
    db_path = tmp_path / "identity.db"
    repo = SQLiteRepository(db_path=db_path)
    result = repo.create_scan(
        scan_source="android-native",
        network_context=NETWORK,
        discovered_devices=[
            {
                "ip_address": "192.168.90.1",
                "mac_address": "AA:BB:CC:90:00:01",
                "manufacturer": "EFM Networks",
                "model": "A3004NS-M",
                "device_type": "web-device",
                "fingerprints": ["upnp-manufacturer:EFM Networks", "upnp-model:A3004NS-M"],
                "discovery_sources": ["ssdp"],
                "open_ports": [80],
            },
            {
                "ip_address": "192.168.90.44",
                "mac_address": "UNKNOWN-192.168.90.44",
                "device_type": "web-device",
                "fingerprints": ["http-server:Boa/0.94"],
                "discovery_sources": ["tcp-port-probe"],
                "open_ports": [80],
            },
        ],
    )
    assert result["devices_found"] == 1
    assert result["identified_count"] == 1
    assert result["identity_pending_count"] == 0
    # Repository results retain private research evidence.  Only public cards
    # and aggregates exclude the generic HTTP-only observation.
    assert len(result["identity_findings"]) == 1

    raw_findings = repo.identity_findings()
    assert len(raw_findings) == 1
    assert raw_findings == result["identity_findings"]
    assert raw_findings[0]["detected"] is True
    assert "192.168" not in str(raw_findings)

    history = repo.identity_history(device_id=raw_findings[0]["device_id"])
    assert history and history[0]["identity_status"] in {"enriching", "unresolved"}
    assert history[0]["device_id"] == raw_findings[0]["device_id"]

    reopened = SQLiteRepository(db_path=db_path)
    assert reopened.identity_history(device_id=raw_findings[0]["device_id"])
    assert reopened.dashboard()["home"]["identity_pending_count"] == 0
